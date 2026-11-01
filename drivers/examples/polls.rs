//! Reports how long each driver's tasks run between `.await`s.
//!
//! Tokio's guidance is to stay under 10–100µs between `.await`s, so that one task cannot
//! hold up others on the same thread. Run with `cargo run --release -p sanstun-drivers
//! --features polls --example polls`.

use sanstun_drivers::net::{Network, NodeHandle};
use sanstun_drivers::scenario::{Running, Star};
use sanstun_drivers::{Driver, polls, pool};

const BATCH: usize = 64;

fn send(node: &NodeHandle, peer: usize, size: usize) {
    let mut packet = pool::take(size);
    packet[..20].copy_from_slice(&[
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
    ]);
    packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    node.tun_in.send((peer, packet)).unwrap();
}

async fn receive(node: &mut NodeHandle, count: usize) {
    for _ in 0..count {
        let (_, packet) = node.tun_out.as_mut().unwrap().recv().await.unwrap();
        pool::recycle(packet);
    }
}

/// Starts a star and returns once every spoke's first packet reached the hub.
async fn handshakes(driver: Driver, spokes: usize, offload: bool) -> (Star, Running) {
    let mut star = Star::new(spokes, 3);
    for node in &mut star.nodes {
        node.offload = offload;
    }
    let mut running = star.spawn(driver, Network::builder());
    for spoke in 1..=spokes {
        send(&running.handles[spoke], 0, 64);
    }
    receive(&mut running.handles[0], spokes).await;

    (star, running)
}

async fn traffic(star: &Star, running: &mut Running, size: usize, batches: usize) {
    for _ in 0..batches {
        for spoke in 1..=star.spokes() {
            for _ in 0..BATCH {
                send(&running.handles[spoke], 0, size);
                send(&running.handles[0], star.peer(0, spoke), size);
            }
        }
        let (hub, spokes) = running.handles.split_first_mut().unwrap();
        receive(hub, star.spokes() * BATCH).await;
        for spoke in spokes {
            receive(spoke, BATCH).await;
        }
    }
}

fn report(scenario: &str, driver: Driver) {
    let s = polls::stats();
    println!(
        "{scenario:22} {:12} polls {:>8}  p50 <{:>6}ns  p99 <{:>7}ns  p99.9 <{:>8}ns  max {:>8}ns  >=10µs {:>6}  >=100µs {:>5}  >=1ms {:>3}",
        driver.name(),
        s.polls,
        s.p50_nanos,
        s.p99_nanos,
        s.p999_nanos,
        s.max_nanos,
        s.over_10us,
        s.over_100us,
        s.over_1ms,
    );
}

fn main() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .build_global()
        .unwrap();
    for offload in [false, true] {
        println!(
            "== crypto {}",
            if offload {
                "offloaded to 4 rayon threads"
            } else {
                "inline"
            }
        );
        for driver in Driver::ALL {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            rt.block_on(async {
                for spokes in [64, 256] {
                    polls::enable();
                    let (star, mut running) = handshakes(driver, spokes, offload).await;
                    report(&format!("handshakes/{spokes}"), driver);

                    for size in [64, 1280] {
                        polls::enable();
                        traffic(&star, &mut running, size, 20).await;
                        report(&format!("traffic/{spokes}x{size}B"), driver);
                    }
                    polls::disable();
                }
            });
        }
    }
}
