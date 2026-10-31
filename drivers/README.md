# sanstun-drivers

Event loops that run the same WireGuard node with different concurrency designs, to compare
sans-IO with async. Not published.

| Driver     | Design                                                                        |
| ---------- | ----------------------------------------------------------------------------- |
| `sans-io`  | One task owns the `Interface` and every `Tunnel`                              |
| `channels` | A demultiplexer owns the `Interface` and feeds one task per tunnel            |
| `mutex`    | Network, TUN and per-tunnel timer tasks share state behind mutexes            |
| `async`    | The `channels` demultiplexer, with tunnels whose timers are async loops (`aio`) |

The `async` driver only exists on top of the `aio` change.

## Correctness

sanstun is deterministic given seeds and time, and tokio's paused clock makes time
deterministic for the drivers too. `tests/equivalence.rs` runs scripted and random scenarios
through every driver and requires transcripts identical to `sans-io`: every datagram's bytes and
timestamp, every decrypted packet and every event. Scripted scenarios also check the reference
against the protocol's timers.

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

Every driver runs in the same benchmark binary, so one run compares them all. To compare a
change to a driver, save a baseline first:

```sh
cargo bench -p sanstun-drivers --bench e2e -- --save-baseline before
# change something
cargo bench -p sanstun-drivers --bench e2e -- --baseline before
```
