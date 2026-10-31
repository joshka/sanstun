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
//! with more than one task can spread work across threads. Throughput also runs sharded: a
//! separate star on each of several threads, each with its own current-thread runtime, which
//! gives every driver the same parallelism.

use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput};
use sanstun_drivers::Driver;
use sanstun_drivers::net::{Network, NodeHandle};
use sanstun_drivers::scenario::{Running, Star};
use tokio::runtime::Runtime;

const TUNNELS: [usize; 3] = [1, 16, 256];
const SIZES: [usize; 2] = [64, 1280];
/// Packets each spoke sends to the hub, and the hub to each spoke, per iteration.
const BATCH: usize = 64;
const WORKER_THREADS: usize = 4;
/// Threads for the sharded runs, matching the multi-threaded runtime's workers.
const SHARDS: usize = WORKER_THREADS;

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
async fn established(driver: Driver, spokes: usize, offload: bool) -> (Star, Running) {
    established_star(driver, Star::new(spokes, 42), offload).await
}

async fn established_star(driver: Driver, mut star: Star, offload: bool) -> (Star, Running) {
    for node in &mut star.nodes {
        node.offload = offload;
    }
    let mut running = star.spawn(driver, Network::builder());

    for spoke in 1..=star.spokes() {
        send(&running.handles[spoke], 0, 1);
    }
    receive(&mut running.handles[0], star.spokes()).await;

    (star, running)
}

fn send(node: &NodeHandle, peer: usize, size: usize) {
    // Equal for every driver: reuse buffers rather than allocating each packet.
    let len = size.max(20);
    let mut packet = sanstun_drivers::pool::take(len);
    packet[..20].copy_from_slice(&[
        0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 192, 0, 2, 1, 192, 0, 2, 2,
    ]);
    packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    packet[20..].fill(0xab);
    node.tun_in.send((peer, packet)).unwrap();
}

async fn receive(node: &mut NodeHandle, count: usize) {
    let tun_out = node.tun_out.as_mut().unwrap();
    for _ in 0..count {
        let (_, packet) = tun_out.recv().await.expect("the node is running");
        sanstun_drivers::pool::recycle(packet);
    }
}

/// Sends a batch of packets each way between the hub and every spoke, and waits for them all.
async fn batch(star: &Star, running: &mut Running, size: usize) {
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

/// Independent stars, each on its own thread with a current-thread runtime.
///
/// This is how a thread-per-core server would shard tunnels, for example with one
/// `SO_REUSEPORT` socket per thread. Every driver gets the same threads.
struct Shards {
    commands: Vec<tokio::sync::mpsc::UnboundedSender<u64>>,
    done: std::sync::mpsc::Receiver<()>,
}

impl Shards {
    fn spawn(driver: Driver, tunnels: usize, size: usize, offload: bool) -> Self {
        let (done_tx, done) = std::sync::mpsc::channel();
        let commands = (0..SHARDS)
            .map(|shard| {
                let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<u64>();
                let done = done_tx.clone();
                std::thread::spawn(move || {
                    Flavor::CurrentThread.runtime().block_on(async move {
                        let star = Star::new(tunnels / SHARDS, 42 + shard as u8);
                        let (star, mut running) = established_star(driver, star, offload).await;
                        done.send(()).unwrap();
                        while let Some(iters) = rx.recv().await {
                            for _ in 0..iters {
                                batch(&star, &mut running, size).await;
                            }
                            done.send(()).unwrap();
                        }
                    })
                });
                tx
            })
            .collect();
        let shards = Shards { commands, done };
        shards.wait();

        shards
    }

    fn run(&self, iters: u64) -> Duration {
        let start = Instant::now();
        for commands in &self.commands {
            commands.send(iters).unwrap();
        }
        self.wait();
        start.elapsed()
    }

    fn wait(&self) {
        for _ in 0..SHARDS {
            self.done.recv().unwrap();
        }
    }
}

/// Runtimes to compare, and whether crypto runs on rayon's pool.
const SETUPS: [(Flavor, bool); 3] = [
    (Flavor::CurrentThread, false),
    (Flavor::MultiThread, false),
    (Flavor::CurrentThread, true),
];

fn setup_name(flavor: Flavor, offload: bool) -> String {
    format!("{}{}", flavor.name(), if offload { "+offload" } else { "" })
}

/// Sizes rayon's pool to match the sharded threads, so offloading adds as many threads as
/// sharding does.
fn init_rayon() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(SHARDS)
            .build_global()
            .unwrap();
    });
}

fn throughput(c: &mut Criterion) {
    init_rayon();
    for (flavor, offload) in SETUPS {
        for tunnels in TUNNELS {
            for size in SIZES {
                let mut group = c.benchmark_group(format!(
                    "throughput/{}/{tunnels}x{size}B",
                    setup_name(flavor, offload)
                ));
                group.throughput(Throughput::Elements((2 * tunnels * BATCH) as u64));

                for driver in Driver::ALL {
                    // Set up lazily, so that benchmarks a filter skips cost nothing.
                    let mut setup = None;

                    group.bench_function(BenchmarkId::from_parameter(driver.name()), |b| {
                        let (rt, star, running) = setup.get_or_insert_with(|| {
                            let rt = flavor.runtime();
                            let (star, running) =
                                rt.block_on(established(driver, tunnels, offload));
                            (rt, star, running)
                        });
                        b.iter_custom(|iters| {
                            rt.block_on(async {
                                let start = Instant::now();
                                for _ in 0..iters {
                                    batch(star, running, size).await;
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

    for offload in [false, true] {
        for tunnels in TUNNELS.into_iter().filter(|&tunnels| tunnels >= SHARDS) {
            for size in SIZES {
                let name = if offload {
                    "sharded+offload"
                } else {
                    "sharded"
                };
                let mut group = c.benchmark_group(format!("throughput/{name}/{tunnels}x{size}B"));
                group.throughput(Throughput::Elements((2 * tunnels * BATCH) as u64));

                for driver in Driver::ALL {
                    let mut shards = None;
                    group.bench_function(BenchmarkId::from_parameter(driver.name()), |b| {
                        let shards = shards
                            .get_or_insert_with(|| Shards::spawn(driver, tunnels, size, offload));
                        b.iter_custom(|iters| shards.run(iters))
                    });
                }

                group.finish();
            }
        }
    }
}

fn latency(c: &mut Criterion) {
    init_rayon();
    for (flavor, offload) in SETUPS {
        let mut group = c.benchmark_group(format!("latency/{}", setup_name(flavor, offload)));

        for driver in Driver::ALL {
            let mut setup = None;

            group.bench_function(BenchmarkId::from_parameter(driver.name()), |b| {
                let (rt, running) = setup.get_or_insert_with(|| {
                    let rt = flavor.runtime();
                    let (_, running) = rt.block_on(established(driver, 1, offload));
                    (rt, running)
                });
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
