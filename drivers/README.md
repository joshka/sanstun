# sanstun-drivers

Event loops that run the same WireGuard node with different concurrency designs, to compare
sans-IO with async. Not published.

| Driver     | Design                                                                        |
| ---------- | ----------------------------------------------------------------------------- |
| `sans-io`  | One task owns the `Interface` and every `Tunnel`                              |
| `channels` | A demultiplexer owns the `Interface` and feeds one task per tunnel            |
| `mutex`    | Network, TUN and per-tunnel timer tasks share state behind mutexes            |
| `async`    | The `channels` demultiplexer, feeding `aio::AsyncTunnel` actors in their own tasks |
| `async-local` | The same `AsyncTunnel`s, hosted as futures in the router's task           |

The async drivers only exist on top of the `aio` change.

## Correctness

sanstun is deterministic given seeds and time, and tokio's paused clock makes time
deterministic for the drivers too. `tests/equivalence.rs` runs scripted and random scenarios
through every driver. The drivers that run sanstun's `Tunnel` must produce transcripts identical
to `sans-io`: every datagram's bytes and timestamp, every decrypted packet and every event.

`AsyncTunnel` implements the whitepaper's timers rather than sanstun's, so its handshakes and
keepalives can happen at other times. The async drivers must deliver exactly the same packets
and report the same establishments, except for packets whose fate depends on timer policy:
those sent near a link cut, or shortly before a tunnel expires. Every scripted scenario also
checks every driver's transcript against the protocol's timers.

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

Every driver runs in the same benchmark binary, so one run compares them all. To compare a
change to a driver, save a baseline first:

```sh
cargo bench -p sanstun-drivers --bench e2e -- --save-baseline before
# change something
cargo bench -p sanstun-drivers --bench e2e -- --baseline before
```
