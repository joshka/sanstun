# sanstun-drivers

Event loops that run the same WireGuard node with different concurrency designs, to compare
sans-IO with async. Not published.

| Driver     | Design                                                                        |
| ---------- | ----------------------------------------------------------------------------- |
| `sans-io`  | One task owns the `Interface` and every `Tunnel`                              |
| `channels` | A demultiplexer owns the `Interface` and feeds one task per tunnel            |
| `mutex`    | Network, TUN and per-tunnel timer tasks share state behind mutexes            |

## Correctness

sanstun is deterministic given seeds and time, and tokio's paused clock makes time
deterministic for the drivers too. `tests/equivalence.rs` runs scripted and random scenarios
through every driver. Each must produce a transcript identical to `sans-io`: every datagram's
bytes and timestamp, every decrypted packet and every event. Every scripted scenario also checks
the transcripts against the protocol's timers, so a bug in the shared per-tunnel logic can't hide
behind every driver agreeing with it.

```sh
cargo test -p sanstun-drivers --release
PROPTEST_CASES=2000 cargo test -p sanstun-drivers --release --test equivalence random
```

## Benchmarks

```sh
cargo bench -p sanstun-drivers --bench e2e          # every driver, end to end
cargo bench -p sanstun-drivers --bench e2e -- latency
cargo bench -p sanstun-drivers --bench primitives   # channel, lock and timer costs
cargo bench --bench data_path                       # sanstun's per-packet steps
```

Throughput runs on a current-thread runtime, a multi-threaded one, and sharded: an independent
star on each of four threads, each with its own current-thread runtime, which gives every
driver the same parallelism.

`+offload` setups set `NodeConfig::offload`, which encrypts and decrypts data messages in
batches on a 4-thread rayon pool, as Firezone does. The tunnels' owners only reserve counters
and commit results.

Every driver runs in the same benchmark binary, so one run compares them all. To compare a
change to a driver, save a baseline first:

```sh
cargo bench -p sanstun-drivers --bench e2e -- --save-baseline before
# change something
cargo bench -p sanstun-drivers --bench e2e -- --baseline before
```

## Time between `.await`s

```sh
cargo run --release -p sanstun-drivers --features polls --example polls
```

Prints, for each driver, how long its tasks' polls run during handshake bursts and steady
traffic, with crypto inline and offloaded. Tokio's guidance is 10–100µs between `.await`s.
