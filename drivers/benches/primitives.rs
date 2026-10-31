//! The cost of the building blocks each driver adds per packet, to compare with the protocol
//! work in sanstun's own `data_path` benchmark.
//!
//! - Channels: a send and receive without a task switch, and a round trip between two tasks.
//! - Mutexes: an uncontended lock, which every access to shared state pays.
//! - Timers: re-arming a tokio sleep, which a task per tunnel does after every input, against
//!   updating the sans-IO driver's deadline queue.

use std::collections::BTreeSet;
use std::hint::black_box;
use std::pin::pin;
use std::sync::Mutex;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use criterion::{BatchSize, Criterion};
use tokio::sync::{Notify, mpsc};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

fn channels(c: &mut Criterion) {
    let mut group = c.benchmark_group("primitives/channel");
    let packet = || vec![0u8; 64];

    group.bench_function("unbounded_send_recv", |b| {
        let (tx, mut rx) = mpsc::unbounded_channel();
        b.iter_batched(
            packet,
            |packet| {
                tx.send(packet).unwrap();
                black_box(rx.try_recv().unwrap())
            },
            BatchSize::SmallInput,
        )
    });

    group.bench_function("bounded_send_recv", |b| {
        let (tx, mut rx) = mpsc::channel(1024);
        b.iter_batched(
            packet,
            |packet| {
                tx.try_send(packet).unwrap();
                black_box(rx.try_recv().unwrap())
            },
            BatchSize::SmallInput,
        )
    });

    // Half of this is one hop: a send that wakes another task, which then runs.
    for (name, rt) in [
        ("round_trip_current_thread", runtime()),
        (
            "round_trip_multi_thread",
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .build()
                .unwrap(),
        ),
    ] {
        let (to_echo, mut echo_rx) = mpsc::channel::<Vec<u8>>(1);
        let (echo_tx, mut from_echo) = mpsc::channel::<Vec<u8>>(1);
        rt.spawn(async move {
            while let Some(packet) = echo_rx.recv().await {
                if echo_tx.send(packet).await.is_err() {
                    return;
                }
            }
        });

        group.bench_function(name, |b| {
            b.iter_custom(|iters| {
                rt.block_on(async {
                    let start = Instant::now();
                    for _ in 0..iters {
                        to_echo.send(vec![0u8; 64]).await.unwrap();
                        black_box(from_echo.recv().await.unwrap());
                    }
                    start.elapsed()
                })
            })
        });
    }

    group.finish();
}

fn locks(c: &mut Criterion) {
    let mut group = c.benchmark_group("primitives/lock");

    group.bench_function("std_mutex_uncontended", |b| {
        let mutex = Mutex::new(0u64);
        b.iter(|| *black_box(&mutex).lock().unwrap() += 1)
    });

    group.bench_function("notify_one_then_notified", |b| {
        let notify = Notify::new();
        let mut cx = Context::from_waker(Waker::noop());
        b.iter(|| {
            notify.notify_one();
            let notified = pin!(notify.notified());
            assert!(notified.poll(&mut cx).is_ready());
        })
    });

    group.finish();
}

fn timers(c: &mut Criterion) {
    let mut group = c.benchmark_group("primitives/timer");
    let rt = runtime();
    let _guard = rt.enter();

    // What the channel and mutex drivers do on every loop iteration.
    group.bench_function("tokio_sleep_until_register", |b| {
        let mut cx = Context::from_waker(Waker::noop());
        let mut deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        b.iter(|| {
            deadline += Duration::from_micros(1);
            let sleep = pin!(tokio::time::sleep_until(deadline));
            assert!(sleep.poll(&mut cx) == Poll::Pending);
        })
    });

    group.bench_function("tokio_sleep_reset", |b| {
        let mut cx = Context::from_waker(Waker::noop());
        let mut deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let mut sleep = pin!(tokio::time::sleep_until(deadline));
        b.iter(|| {
            deadline += Duration::from_micros(1);
            sleep.as_mut().reset(deadline);
            assert!(sleep.as_mut().poll(&mut cx) == Poll::Pending);
        })
    });

    // What the sans-IO driver does after touching a tunnel among 256.
    group.bench_function("btreeset_deadline_update_256", |b| {
        let start = Instant::now();
        let mut queue = (0..256usize)
            .map(|id| (start + Duration::from_millis(id as u64), id))
            .collect::<BTreeSet<_>>();
        let mut deadlines = (0..256u64)
            .map(|id| start + Duration::from_millis(id))
            .collect::<Vec<_>>();
        let mut id = 0;
        b.iter(|| {
            id = (id + 97) % 256;
            queue.remove(&(deadlines[id], id));
            deadlines[id] += Duration::from_secs(1);
            queue.insert((deadlines[id], id));
            black_box(queue.first());
        })
    });

    group.finish();
}

criterion::criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = channels, locks, timers
}
criterion::criterion_main!(benches);
