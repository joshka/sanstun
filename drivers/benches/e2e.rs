//! End-to-end cost of each driver: IP packets in, through encryption, an in-memory network and
//! decryption, IP packets out.
//!
//! Every driver runs the same per-tunnel code, so the differences are the cost of the
//! concurrency design: task hops, channel sends, locks and timer bookkeeping.
//!
//! - `throughput`: every spoke and the hub send a batch of packets to each other.
//! - `latency`: one packet from a spoke to the hub and a reply back, through every hop.
//! - `handshakes`: fresh nodes until every spoke's first packet arrives at the hub.
//!
//! Each runs on a current-thread runtime and on a multi-threaded one, where only the drivers
//! with more than one task can spread work across threads.

use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput};
use sanstun_drivers::Driver;
use sanstun_drivers::net::{Network, NodeHandle};
use sanstun_drivers::scenario::{Running, Star, ip_packet};
use tokio::runtime::Runtime;

const TUNNELS: [usize; 3] = [1, 16, 256];
const SIZES: [usize; 2] = [64, 1280];
/// Packets each spoke sends to the hub, and the hub to each spoke, per iteration.
const BATCH: usize = 64;
const WORKER_THREADS: usize = 4;

#[derive(Clone, Copy)]
enum Flavor {
    CurrentThread,
    MultiThread,
}

impl Flavor {
    fn name(self) -> &'static str {
        match self {
            Flavor::CurrentThread => "current_thread",
            Flavor::MultiThread => "multi_thread",
        }
    }

    fn runtime(self) -> Runtime {
        match self {
            Flavor::CurrentThread => tokio::runtime::Builder::new_current_thread(),
            Flavor::MultiThread => {
                let mut builder = tokio::runtime::Builder::new_multi_thread();
                builder.worker_threads(WORKER_THREADS);
                builder
            }
        }
        .enable_time()
        .build()
        .unwrap()
    }
}

const FLAVORS: [Flavor; 2] = [Flavor::CurrentThread, Flavor::MultiThread];

/// Spawns a star and completes every handshake.
async fn established(driver: Driver, spokes: usize) -> (Star, Running) {
    let star = Star::new(spokes, 42);
    let mut running = star.spawn(driver, Network::builder());

    for spoke in 1..=spokes {
        send(&running.handles[spoke], 0, 1);
    }
    receive(&mut running.handles[0], spokes).await;

    (star, running)
}

fn send(node: &NodeHandle, peer: usize, size: usize) {
    let packet = ip_packet(&vec![0xab; size.saturating_sub(20)]);
    node.tun_in.send((peer, packet)).unwrap();
}

async fn receive(node: &mut NodeHandle, count: usize) {
    let tun_out = node.tun_out.as_mut().unwrap();
    for _ in 0..count {
        tun_out.recv().await.expect("the node is running");
    }
}

fn throughput(c: &mut Criterion) {
    for flavor in FLAVORS {
        for tunnels in TUNNELS {
            for size in SIZES {
                let mut group =
                    c.benchmark_group(format!("throughput/{}/{tunnels}x{size}B", flavor.name()));
                group.throughput(Throughput::Elements((2 * tunnels * BATCH) as u64));

                for driver in Driver::ALL {
                    let rt = flavor.runtime();
                    let (star, mut running) = rt.block_on(established(driver, tunnels));

                    group.bench_function(BenchmarkId::from_parameter(driver.name()), |b| {
                        b.iter_custom(|iters| {
                            rt.block_on(async {
                                let start = Instant::now();
                                for _ in 0..iters {
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
                                start.elapsed()
                            })
                        })
                    });
                }

                group.finish();
            }
        }
    }
}

fn latency(c: &mut Criterion) {
    for flavor in FLAVORS {
        let mut group = c.benchmark_group(format!("latency/{}", flavor.name()));

        for driver in Driver::ALL {
            let rt = flavor.runtime();
            let (_, mut running) = rt.block_on(established(driver, 1));

            group.bench_function(BenchmarkId::from_parameter(driver.name()), |b| {
                b.iter_custom(|iters| {
                    rt.block_on(async {
                        let start = Instant::now();
                        for _ in 0..iters {
                            send(&running.handles[1], 0, 64);
                            receive(&mut running.handles[0], 1).await;
                            send(&running.handles[0], 0, 64);
                            receive(&mut running.handles[1], 1).await;
                        }
                        start.elapsed()
                    })
                })
            });
        }

        group.finish();
    }
}

fn handshakes(c: &mut Criterion) {
    for flavor in FLAVORS {
        for tunnels in [1, 64] {
            let mut group = c.benchmark_group(format!("handshakes/{}/{tunnels}", flavor.name()));
            group.throughput(Throughput::Elements(tunnels as u64));

            for driver in Driver::ALL {
                let rt = flavor.runtime();

                group.bench_function(BenchmarkId::from_parameter(driver.name()), |b| {
                    b.iter_custom(|iters| {
                        rt.block_on(async {
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                let star = Star::new(tunnels, 7);
                                let mut running = star.spawn(driver, Network::builder());

                                let start = Instant::now();
                                for spoke in 1..=tunnels {
                                    send(&running.handles[spoke], 0, 64);
                                }
                                receive(&mut running.handles[0], tunnels).await;
                                total += start.elapsed();
                            }
                            total
                        })
                    })
                });
            }

            group.finish();
        }
    }
}

criterion::criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = throughput, latency, handshakes
}
criterion::criterion_main!(benches);
