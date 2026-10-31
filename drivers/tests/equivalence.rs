//! Every driver must produce the same traffic as the sans-IO driver.
//!
//! sanstun derives all randomness from seeds and takes time as an input, and tokio's paused
//! clock makes time deterministic for the drivers too. Equal transcripts therefore mean equal
//! ciphertexts, timings, decrypted packets and events, not just similar behaviour.
//!
//! The async driver implements the whitepaper's timers itself rather than sanstun's, so its
//! handshakes and keepalives may happen at other times. It must still deliver exactly the same
//! packets and report the same establishments and expiries.
//!
//! Scripted scenarios also check the reference transcript against the protocol, so that a bug
//! in the shared per-tunnel logic cannot hide behind every driver agreeing with it.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use proptest::prelude::*;
use sanstun_drivers::Driver;
use sanstun_drivers::NodeEvent;
use sanstun_drivers::net::{Record, Transcript};
use sanstun_drivers::scenario::{self, Star, Step};

const LATENCY: Duration = Duration::from_millis(3);
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_JITTER: Duration = Duration::from_millis(333);

const fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn send(from: usize, to: usize, payload: &str) -> Step {
    Step::Send {
        from,
        to,
        payload: payload.as_bytes().to_vec(),
    }
}

/// Runs `steps` on a fresh paused runtime.
fn run(driver: Driver, star: &Star, steps: &[Step]) -> Transcript {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .start_paused(true)
        .build()
        .unwrap()
        .block_on(scenario::run(driver, star, LATENCY, steps))
}

/// Checks that every driver agrees with the sans-IO driver, and returns each one's transcript
/// for protocol checks.
#[track_caller]
fn assert_equivalent(star: &Star, steps: &[Step]) -> Vec<(Driver, Transcript)> {
    let reference = run(Driver::SansIo, star, steps);
    let mut transcripts = Vec::new();

    for driver in Driver::ALL {
        let transcript = run(driver, star, steps);
        if let Some(diff) = divergence(driver, star, &reference, &transcript) {
            panic!(
                "{} diverges from {}:\n{diff}",
                driver.name(),
                Driver::SansIo.name()
            );
        }
        transcripts.push((driver, transcript));
    }

    transcripts
}

/// Compares a driver's transcript with the reference, as closely as the driver promises.
fn divergence(
    driver: Driver,
    star: &Star,
    reference: &Transcript,
    transcript: &Transcript,
) -> Option<String> {
    if driver.runs_tunnel() {
        return first_difference(reference, transcript);
    }

    first_difference(
        &outcomes(star, reference, &[]),
        &outcomes(star, transcript, &[]),
    )
}

/// Returns the spoke at the other end of a node's tunnel to `peer`.
fn spoke_of(star: &Star, node: SocketAddr, peer: usize) -> usize {
    if node == star.addr(0) {
        peer + 1
    } else {
        (1..=star.spokes()).find(|&s| star.addr(s) == node).unwrap()
    }
}

/// Returns, for each spoke, when either end of its tunnel to the hub first expired in any of
/// `transcripts`.
fn first_expiries<'a>(
    star: &Star,
    transcripts: impl IntoIterator<Item = &'a Transcript>,
) -> Vec<Option<Duration>> {
    let mut expiries = vec![None; star.spokes() + 1];
    for (at, record) in transcripts.into_iter().flatten() {
        if let Record::Event {
            node,
            peer,
            event: NodeEvent::Expired,
        } = record
        {
            let first = &mut expiries[spoke_of(star, *node, *peer)];
            *first = Some(first.map_or(*at, |first: Duration| first.min(*at)));
        }
    }

    expiries
}

/// Keeps decrypted packets and establishments, without their times. Expiries are left to the
/// protocol checks.
///
/// Drops what happens on a tunnel after `until` for its spoke. Drivers expire idle tunnels under
/// different policies, and a node that has expired its end drops whatever arrives afterwards.
fn outcomes(star: &Star, transcript: &Transcript, until: &[Option<Duration>]) -> Transcript {
    let before_expiry = |at: Duration, node, peer| {
        until
            .get(spoke_of(star, node, peer))
            .copied()
            .flatten()
            .is_none_or(|until| at < until)
    };
    let mut outcomes = transcript
        .iter()
        .filter(|(at, record)| match record {
            Record::Tun { node, peer, .. } => before_expiry(*at, *node, *peer),
            Record::Event { node, peer, event } => {
                *event == NodeEvent::Established && before_expiry(*at, *node, *peer)
            }
            Record::Wire { .. } => false,
        })
        .map(|(_, record)| (Duration::ZERO, record.clone()))
        .collect::<Transcript>();
    outcomes.sort_by_key(|(_, record)| match record {
        Record::Tun { node, peer, .. } | Record::Event { node, peer, .. } => {
            (*node, *peer, matches!(record, Record::Event { .. }))
        }
        Record::Wire { .. } => unreachable!(),
    });

    outcomes
}

fn first_difference(expected: &Transcript, actual: &Transcript) -> Option<String> {
    let i = expected
        .iter()
        .zip(actual)
        .position(|(e, a)| e != a)
        .or_else(|| (expected.len() != actual.len()).then(|| expected.len().min(actual.len())))?;
    let context = |t: &Transcript| {
        t[i.saturating_sub(3)..(i + 3).min(t.len())]
            .iter()
            .map(|(at, record)| format!("  {at:?} {}", describe(record)))
            .collect::<Vec<_>>()
            .join("\n")
    };

    Some(format!(
        "first difference at record {i} (of {} expected, {} actual)\nexpected:\n{}\nactual:\n{}",
        expected.len(),
        actual.len(),
        context(expected),
        context(actual),
    ))
}

fn describe(record: &Record) -> String {
    match record {
        Record::Wire { from, to, bytes } => {
            format!("{from} -> {to} {:?} ({} bytes)", kind(bytes), bytes.len())
        }
        Record::Tun { node, peer, bytes } => {
            format!("{node} decrypted {} bytes from peer {peer}", bytes.len())
        }
        Record::Event { node, peer, event } => format!("{node} peer {peer}: {event:?}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Init,
    Response,
    CookieReply,
    Keepalive,
    Data,
}

fn kind(datagram: &[u8]) -> Kind {
    match (datagram[0], datagram.len()) {
        (1, 148) => Kind::Init,
        (2, 92) => Kind::Response,
        (3, 64) => Kind::CookieReply,
        (4, 32) => Kind::Keepalive,
        (4, _) => Kind::Data,
        other => panic!("unexpected datagram {other:?}"),
    }
}

/// Returns when `from` sent datagrams of `kind`.
fn sent(transcript: &Transcript, from: SocketAddr, of: Kind) -> Vec<Duration> {
    transcript
        .iter()
        .filter_map(|(at, record)| match record {
            Record::Wire { from: f, bytes, .. } if *f == from && kind(bytes) == of => Some(*at),
            _ => None,
        })
        .collect()
}

fn decrypted(transcript: &Transcript, node: SocketAddr) -> Vec<Vec<u8>> {
    transcript
        .iter()
        .filter_map(|(_, record)| match record {
            Record::Tun { node: n, bytes, .. } if *n == node => Some(bytes.clone()),
            _ => None,
        })
        .collect()
}

fn events(transcript: &Transcript, node: SocketAddr) -> Vec<(Duration, NodeEvent)> {
    transcript
        .iter()
        .filter_map(|(at, record)| match record {
            Record::Event { node: n, event, .. } if *n == node => Some((*at, event.clone())),
            _ => None,
        })
        .collect()
}

#[test]
fn handshake_then_data_both_ways() {
    let star = Star::new(1, 1);
    let (hub, spoke) = (star.addr(0), star.addr(1));

    for (driver, t) in assert_equivalent(
        &star,
        &[
            send(1, 0, "first"),
            send(1, 0, "queued behind the handshake"),
            Step::Wait(ms(100)),
            send(0, 1, "reply"),
            Step::Wait(ms(100)),
        ],
    ) {
        eprintln!("checking {}", driver.name());

        assert_eq!(sent(&t, spoke, Kind::Init), [ms(0)]);
        assert_eq!(sent(&t, hub, Kind::Response), [LATENCY]);
        assert_eq!(
            decrypted(&t, hub),
            [
                scenario::ip_packet(b"first"),
                scenario::ip_packet(b"queued behind the handshake")
            ]
        );
        assert_eq!(decrypted(&t, spoke), [scenario::ip_packet(b"reply")]);
        assert_eq!(events(&t, spoke), [(LATENCY * 2, NodeEvent::Established)]);
    }
}

#[test]
fn unanswered_data_gets_a_passive_keepalive() {
    let star = Star::new(1, 2);

    for (driver, t) in assert_equivalent(&star, &[send(1, 0, "hello"), Step::Wait(secs(15))]) {
        eprintln!("checking {}", driver.name());

        // The hub received data at 3 * LATENCY, after the handshake, and never replied.
        assert_eq!(
            sent(&t, star.addr(0), Kind::Keepalive),
            [LATENCY * 3 + secs(10)]
        );
    }
}

#[test]
fn replies_suppress_keepalives_and_handshakes() {
    let star = Star::new(1, 10);

    for (driver, t) in assert_equivalent(
        &star,
        &[
            send(1, 0, "question"),
            Step::Wait(secs(1)),
            send(0, 1, "answer"),
            Step::Wait(secs(1)),
            send(1, 0, "thanks"),
            Step::Wait(ms(500)),
            send(0, 1, "welcome"),
            Step::Wait(secs(60)),
        ],
    ) {
        eprintln!("checking {}", driver.name());
        // Each side answered the other's data before KEEPALIVE_TIMEOUT, and heard back before
        // KEEPALIVE_TIMEOUT + REKEY_TIMEOUT. Only the spoke owes a keepalive, for "welcome".
        assert_eq!(sent(&t, star.addr(0), Kind::Keepalive), []);
        assert_eq!(
            sent(&t, star.addr(1), Kind::Keepalive),
            [LATENCY * 2, ms(2500) + LATENCY + secs(10)],
        );
        assert_eq!(sent(&t, star.addr(1), Kind::Init), [ms(0)]);
        assert_eq!(sent(&t, star.addr(0), Kind::Init), []);
    }
}

#[test]
fn unanswered_data_starts_a_new_handshake() {
    let star = Star::new(1, 11);

    for (driver, t) in assert_equivalent(
        &star,
        &[
            send(1, 0, "hello"),
            Step::Wait(secs(1)),
            Step::Cut,
            send(1, 0, "anyone?"),
            Step::Wait(secs(20)),
        ],
    ) {
        eprintln!("checking {}", driver.name());
        // KEEPALIVE_TIMEOUT + REKEY_TIMEOUT after the first unanswered packet, plus jitter.
        // "hello" went out once the handshake completed and was never answered.
        let inits = sent(&t, star.addr(1), Kind::Init);
        assert!(inits.len() >= 2, "{inits:?}");
        let expected = LATENCY * 2 + secs(15);
        assert!(
            inits[1] >= expected && inits[1] <= expected + MAX_JITTER,
            "{inits:?}"
        );
    }
}

/// The whitepaper zeroes key material `REJECT_AFTER_TIME * 3` after the last handshake. sanstun
/// instead keeps an idle initiator's session fresh, so only the async driver gets there.
#[test]
fn idle_keys_are_zeroed_after_three_reject_times() {
    let star = Star::new(1, 12);

    for (driver, t) in assert_equivalent(&star, &[send(1, 0, "once"), Step::Wait(secs(600))]) {
        if driver.runs_tunnel() {
            continue;
        }
        let expiries = |node| {
            events(&t, star.addr(node))
                .into_iter()
                .filter(|(_, e)| *e == NodeEvent::Expired)
                .map(|(at, _)| at)
                .collect::<Vec<_>>()
        };
        // Each side derived its session when the handshake reached it.
        assert_eq!(expiries(0), [LATENCY + secs(540)]);
        assert_eq!(expiries(1), [LATENCY * 2 + secs(540)]);
    }
}

#[test]
fn steady_traffic_rekeys_after_two_minutes() {
    let star = Star::new(1, 3);
    let mut steps = Vec::new();
    for _ in 0..30 {
        steps.extend([send(1, 0, "tick"), Step::Wait(secs(5)), send(0, 1, "tock")]);
        steps.push(Step::Wait(secs(5)));
    }

    for (driver, t) in assert_equivalent(&star, &steps) {
        eprintln!("checking {}", driver.name());

        let inits = sent(&t, star.addr(1), Kind::Init);
        assert_eq!(
            inits.len(),
            3,
            "initial handshake plus two rekeys: {inits:?}"
        );
        assert!(inits[1] >= secs(120) && inits[1] < secs(131), "{inits:?}");
        assert_eq!(decrypted(&t, star.addr(0)).len(), 30);
        assert_eq!(decrypted(&t, star.addr(1)).len(), 30);
    }
}

#[test]
fn lost_link_retries_handshakes_then_expires() {
    let star = Star::new(1, 4);

    for (driver, t) in assert_equivalent(
        &star,
        &[
            Step::Cut,
            send(1, 0, "into the void"),
            Step::Wait(secs(100)),
        ],
    ) {
        eprintln!("checking {}", driver.name());

        let inits = sent(&t, star.addr(1), Kind::Init);
        // REKEY_TIMEOUT retries, with up to 333ms of jitter each, until REKEY_ATTEMPT_TIME.
        assert!((17..=19).contains(&inits.len()), "{inits:?}");
        assert!(inits.last().unwrap() < &secs(90));
        assert_eq!(
            events(&t, star.addr(1))
                .into_iter()
                .map(|(_, e)| e)
                .collect::<Vec<_>>(),
            [NodeEvent::Expired]
        );
    }
}

#[test]
fn healed_link_recovers() {
    let star = Star::new(1, 5);

    for (driver, t) in assert_equivalent(
        &star,
        &[
            send(1, 0, "before"),
            Step::Wait(secs(1)),
            Step::Cut,
            send(1, 0, "lost"),
            Step::Wait(secs(30)),
            Step::Heal,
            send(1, 0, "after"),
            Step::Wait(secs(30)),
        ],
    ) {
        eprintln!("checking {}", driver.name());

        let received = decrypted(&t, star.addr(0));
        assert_eq!(received.first(), Some(&scenario::ip_packet(b"before")));
        assert_eq!(received.last(), Some(&scenario::ip_packet(b"after")));
    }
}

#[test]
fn hub_serves_many_spokes_at_once() {
    let star = Star::new(8, 6);
    let keys = star
        .nodes
        .iter()
        .map(|n| n.public_key())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(keys.len(), 9, "every node has its own key");
    let mut steps = Vec::new();
    for spoke in 1..=8 {
        steps.push(send(spoke, 0, "up"));
        steps.push(send(0, spoke, "down"));
    }
    steps.push(Step::Wait(secs(20)));

    for (driver, t) in assert_equivalent(&star, &steps) {
        eprintln!("checking {}", driver.name());

        assert_eq!(decrypted(&t, star.addr(0)).len(), 8);
        for spoke in 1..=8 {
            assert_eq!(decrypted(&t, star.addr(spoke)).len(), 1);
        }
    }
}

#[test]
fn hub_under_load_requires_cookies() {
    let mut star = Star::new(2, 7);
    star.nodes[0].handshake_limit = 0;

    for (driver, t) in assert_equivalent(
        &star,
        &[send(1, 0, "a"), send(2, 0, "b"), Step::Wait(secs(10))],
    ) {
        eprintln!("checking {}", driver.name());

        assert_eq!(sent(&t, star.addr(0), Kind::CookieReply).len(), 2);
        assert_eq!(decrypted(&t, star.addr(0)).len(), 2);
    }
}

#[test]
fn persistent_keepalives_flow_while_idle() {
    let mut star = Star::new(1, 8);
    star.nodes[1].peers[0].persistent_keepalive = Some(secs(25));

    for driver in Driver::ALL {
        let t = run(driver, &star, &[send(1, 0, "start"), Step::Wait(secs(110))]);

        // The first keepalive confirms the handshake; the rest are 25s apart.
        let keepalives = sent(&t, star.addr(1), Kind::Keepalive);
        assert!(keepalives.len() >= 4, "{}: {keepalives:?}", driver.name());
        for gap in keepalives[1..].windows(2).map(|w| w[1] - w[0]) {
            assert_eq!(gap, secs(25), "{}: {keepalives:?}", driver.name());
        }
    }
    assert_equivalent(&star, &[send(1, 0, "start"), Step::Wait(secs(110))]);
}

/// Simulated time is free: hours of protocol time run in milliseconds.
#[test]
fn simulating_an_hour_is_fast() {
    let star = Star::new(4, 9);
    let mut steps = Vec::new();
    for minute in 0..60 {
        let spoke = minute % 4 + 1;
        steps.extend([send(spoke, 0, "ping"), send(0, spoke, "pong")]);
        steps.push(Step::Wait(secs(60)));
    }

    let started = Instant::now();
    let transcripts = assert_equivalent(&star, &steps);
    let elapsed = started.elapsed();

    for (_, t) in transcripts {
        assert!(t.last().unwrap().0 >= secs(59 * 60));
    }
    assert!(elapsed < secs(10), "simulating took {elapsed:?}");
}

fn step(spokes: usize) -> impl Strategy<Value = Step> {
    let spoke = 1..=spokes;
    prop_oneof![
        6 => (spoke.clone(), any::<bool>(), proptest::collection::vec(any::<u8>(), 0..64)).prop_map(
            |(spoke, up, payload)| {
                let (from, to) = if up { (spoke, 0) } else { (0, spoke) };
                Step::Send { from, to, payload }
            }
        ),
        // Multiples of 10ms keep inputs off the latency and the timers it offsets.
        4 => (1u64..=3_000).prop_map(|n| Step::Wait(ms(n * 10))),
        1 => (1u64..=30).prop_map(|n| Step::Wait(secs(n * 10))),
        1 => Just(Step::Cut),
        1 => Just(Step::Heal),
    ]
}

/// Cuts and heals take effect for datagrams sent from that instant, so they must not share
/// an instant with sends whose datagrams they would race.
fn separate_link_changes(steps: Vec<Step>) -> Vec<Step> {
    let mut separated = Vec::with_capacity(steps.len());
    for step in steps {
        if matches!(step, Step::Cut | Step::Heal) {
            separated.push(Step::Wait(ms(10)));
        }
        let is_link_change = matches!(step, Step::Cut | Step::Heal);
        separated.push(step);
        if is_link_change {
            separated.push(Step::Wait(ms(10)));
        }
    }

    separated
}

/// Waiting long enough for a queued packet's handshake to be retried and complete.
const SETTLE: Duration = REKEY_TIMEOUT
    .saturating_add(MAX_JITTER)
    .saturating_add(ms(100));

/// A packet a scenario sends.
struct Sent {
    at: Duration,
    spoke: usize,
    packet: Vec<u8>,
    /// Whether the link was cut within `SETTLE` of sending it.
    near_cut: bool,
}

/// Makes every payload unique and returns what each step sends.
fn number_payloads(steps: &mut [Step]) -> Vec<Sent> {
    let mut now = Duration::ZERO;
    let mut cuts = Vec::<(Duration, Duration)>::new();
    let mut sends = Vec::new();
    for (i, step) in steps.iter_mut().enumerate() {
        match step {
            Step::Wait(duration) => now += *duration,
            Step::Cut => cuts.push((now, Duration::MAX)),
            Step::Heal => {
                if let Some((_, end)) = cuts.last_mut().filter(|(_, end)| *end == Duration::MAX) {
                    *end = now;
                }
            }
            Step::Send { from, to, payload } => {
                payload.splice(0..0, (i as u32).to_be_bytes());
                sends.push(Sent {
                    at: now,
                    spoke: (*from).max(*to),
                    packet: scenario::ip_packet(payload),
                    near_cut: false,
                });
            }
        }
    }
    for sent in &mut sends {
        sent.near_cut = cuts
            .iter()
            .any(|&(start, end)| start < sent.at + SETTLE && sent.at < end);
    }

    sends
}

/// Returns the packets whose delivery depends on timer policy.
///
/// A packet sent while the link is cut is either sent into the void or queued behind a
/// handshake that completes once the link heals, depending on whether a session existed. A
/// packet queued shortly before a cut, or before its tunnel expires, waits for a handshake
/// retry that may come too late. Drivers with different timers may legitimately disagree on
/// those, so only packets followed by enough uptime and lifetime to retry a handshake must
/// arrive.
fn timing_dependent(sends: &[Sent], until: &[Option<Duration>]) -> Vec<Vec<u8>> {
    sends
        .iter()
        .filter(|sent| {
            sent.near_cut || until[sent.spoke].is_some_and(|until| sent.at + SETTLE > until)
        })
        .map(|sent| sent.packet.clone())
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn random_scenarios_are_equivalent(
        seed in any::<u8>(),
        (spokes, steps) in (1usize..=4).prop_flat_map(|spokes| {
            (Just(spokes), proptest::collection::vec(step(spokes), 1..60))
        }),
    ) {
        let star = Star::new(spokes, seed);
        let mut steps = separate_link_changes(steps);
        let sends = number_payloads(&mut steps);
        steps.push(Step::Wait(secs(200)));

        let reference = run(Driver::SansIo, &star, &steps);
        for driver in Driver::ALL {
            let transcript = run(driver, &star, &steps);
            let diff = if driver.runs_tunnel() {
                first_difference(&reference, &transcript)
            } else {
                let until = first_expiries(&star, [&reference, &transcript]);
                let skip = timing_dependent(&sends, &until);
                let compared = |t: &Transcript| -> Transcript {
                    let t = t
                        .iter()
                        .filter(|(_, r)| !matches!(r, Record::Tun { bytes, .. } if skip.contains(bytes)))
                        .cloned()
                        .collect();
                    outcomes(&star, &t, &until)
                };
                first_difference(&compared(&reference), &compared(&transcript))
            };
            if let Some(diff) = diff {
                prop_assert!(false, "{} diverges from sans-io:\n{diff}", driver.name());
            }
        }
    }
}
