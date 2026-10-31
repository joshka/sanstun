//! Every driver must produce the same traffic as the sans-IO driver.
//!
//! sanstun derives all randomness from seeds and takes time as an input, and tokio's paused
//! clock makes time deterministic for the drivers too. Equal transcripts therefore mean equal
//! ciphertexts, timings, decrypted packets and events, not just similar behaviour.
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

fn ms(n: u64) -> Duration {
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

/// Checks that every driver produces the reference transcript and returns it.
#[track_caller]
fn assert_equivalent(star: &Star, steps: &[Step]) -> Transcript {
    let reference = run(Driver::SansIo, star, steps);

    for driver in Driver::ALL {
        let transcript = run(driver, star, steps);
        if let Some(diff) = first_difference(&reference, &transcript) {
            panic!(
                "{} diverges from {}:\n{diff}",
                driver.name(),
                Driver::SansIo.name()
            );
        }
    }

    reference
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

    let t = assert_equivalent(
        &star,
        &[
            send(1, 0, "first"),
            send(1, 0, "queued behind the handshake"),
            Step::Wait(ms(100)),
            send(0, 1, "reply"),
            Step::Wait(ms(100)),
        ],
    );

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

#[test]
fn unanswered_data_gets_a_passive_keepalive() {
    let star = Star::new(1, 2);

    let t = assert_equivalent(&star, &[send(1, 0, "hello"), Step::Wait(secs(15))]);

    // The hub received data at 3 * LATENCY, after the handshake, and never replied.
    assert_eq!(
        sent(&t, star.addr(0), Kind::Keepalive),
        [LATENCY * 3 + secs(10)]
    );
}

#[test]
fn steady_traffic_rekeys_after_two_minutes() {
    let star = Star::new(1, 3);
    let mut steps = Vec::new();
    for _ in 0..30 {
        steps.extend([send(1, 0, "tick"), Step::Wait(secs(5)), send(0, 1, "tock")]);
        steps.push(Step::Wait(secs(5)));
    }

    let t = assert_equivalent(&star, &steps);

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

#[test]
fn lost_link_retries_handshakes_then_expires() {
    let star = Star::new(1, 4);

    let t = assert_equivalent(
        &star,
        &[
            Step::Cut,
            send(1, 0, "into the void"),
            Step::Wait(secs(100)),
        ],
    );

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

#[test]
fn healed_link_recovers() {
    let star = Star::new(1, 5);

    let t = assert_equivalent(
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
    );

    let received = decrypted(&t, star.addr(0));
    assert_eq!(received.first(), Some(&scenario::ip_packet(b"before")));
    assert_eq!(received.last(), Some(&scenario::ip_packet(b"after")));
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

    let t = assert_equivalent(&star, &steps);

    assert_eq!(decrypted(&t, star.addr(0)).len(), 8);
    for spoke in 1..=8 {
        assert_eq!(decrypted(&t, star.addr(spoke)).len(), 1);
    }
}

#[test]
fn hub_under_load_requires_cookies() {
    let mut star = Star::new(2, 7);
    star.nodes[0].handshake_limit = 0;

    let t = assert_equivalent(
        &star,
        &[send(1, 0, "a"), send(2, 0, "b"), Step::Wait(secs(10))],
    );

    assert_eq!(sent(&t, star.addr(0), Kind::CookieReply).len(), 2);
    assert_eq!(decrypted(&t, star.addr(0)).len(), 2);
}

#[test]
fn persistent_keepalives_flow_while_idle() {
    let mut star = Star::new(1, 8);
    star.nodes[1].peers[0].persistent_keepalive = Some(secs(25));

    let t = assert_equivalent(&star, &[send(1, 0, "start"), Step::Wait(secs(100))]);

    assert_eq!(sent(&t, star.addr(1), Kind::Keepalive).len(), 1 + 4);
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
    let t = assert_equivalent(&star, &steps);
    let elapsed = started.elapsed();

    assert!(t.last().unwrap().0 >= secs(59 * 60));
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
        steps.push(Step::Wait(secs(200)));

        let reference = run(Driver::SansIo, &star, &steps);
        for driver in Driver::ALL {
            let transcript = run(driver, &star, &steps);
            if let Some(diff) = first_difference(&reference, &transcript) {
                prop_assert!(false, "{} diverges from sans-io:\n{diff}", driver.name());
            }
        }
    }
}
