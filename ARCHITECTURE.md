# Architecture

`zroute` is a forward HTTP/CONNECT proxy built on Zig 0.16's `std.Io`
interface. It has three design commitments that shape everything below:

- **Data-oriented, not object-oriented.** Connections are rows in a
  struct-of-arrays table, identified by a `u32` slot index, not heap objects.
- **No hidden event loop.** Concurrency comes entirely from `std.Io`'s
  backend (`Io.Threaded`): a bounded OS-thread pool, not epoll/io_uring
  multiplexing (io_uring is currently non-functional for networking in this
  Zig build — see [I/O model](#io-model) below).
- **Opaque tunneling, not a MITM proxy.** `CONNECT` splices bytes; TLS is
  never terminated or inspected.

## Module layout

```
src/
  main.zig                  wiring: build Io, Telemetry, ConnectionPool,
                             Resolver, Listener — then block in run()
  root.zig                  re-export surface (no logic)
  config.zig                CLI args + JSON file -> Config
  proxy/
    listener.zig             accept loop, dispatches one task per connection
    connection.zig            per-connection entry point / state machine
    pool.zig                  ConnectionPool: SoA slot table, lock-free free list
    target.zig                 "host:port" / absolute-URI parsing
    resolver.zig                DNS: system resolver, or custom UDP resolver
    forward.zig                 plain HTTP relay (parse -> connect -> relay)
    tunnel.zig                  CONNECT relay (parse -> connect -> splice)
    relay.zig                   shared byte-copy primitives
    timeout_reader.zig          Io.Reader over a stream with a sliding idle deadline
    log.zig                     trace_id/slot-tagged structured logging
  telemetry/
    telemetry.zig              bundles Metrics + trace-id generation
    span.zig                    TraceId type + generator
    metrics.zig                  atomic counters + snapshot()
    reporter.zig                 periodic snapshot -> log line
```

Each file has one job. `forward.zig` and `tunnel.zig` both do
parse-target -> resolve -> connect -> relay, but the relay shape differs
enough (single request/response vs. bidirectional splice) that sharing one
file would just add branching.

## Startup

```
main()
  ├─ config.load(gpa, io, argv)        compiled defaults -> zroute.json -> CLI flags
  ├─ Io.Threaded.init(gpa, .{})        the only working Io backend (see below)
  ├─ Telemetry.init(random_node_prefix)
  ├─ if cfg.metricsInterval(): metrics_group.async(reporter.run)   opt-in, off by default
  ├─ ConnectionPool.init(gpa, cfg.max_connections)   one fixed allocation, never grows
  ├─ build dns_servers: []IpAddress    parses cfg.dns_servers, port 53
  ├─ Resolver.init(dns_servers, ...)   .system if empty, .custom otherwise
  ├─ Listener.init(listen_address, io, &pool, &telemetry, deps)
  └─ proxy_listener.run(io)            blocks forever; this is the whole program
```

Everything the request path touches (`pool`, `telemetry`, `resolver`) is
built once here and handed down by pointer/value through `connection.Deps`.
Nothing below `main` allocates from `gpa` again — see
[Zero-allocation hot path](#zero-allocation-hot-path).

## Request lifecycle

### Plain HTTP

```
client                 listener              connection.handle          forward.handle              upstream
  │                       │                        │                          │                         │
  │──TCP connect─────────▶│                        │                          │                         │
  │                       │ accept()               │                          │                         │
  │                       │ pool.acquire(slot)     │                          │                         │
  │                       │ group.async ──────────▶│ (own task/thread)        │                          │
  │──GET http://…HTTP/1.1▶│                        │ server.receiveHead()     │                          │
  │                       │                        │ pool.setState(parsing_head)                        │
  │                       │                        │ pool.setState(relaying_http)                       │
  │                       │                        │ forward.handle ─────────▶│                          │
  │                       │                        │                          │ parseHttpTarget()        │
  │                       │                        │                          │ resolver.connect() ─────▶│ TCP connect
  │                       │                        │                          │ forwardRequest():        │
  │                       │                        │                          │   write head, flush      │
  │                       │                        │                          │   copy body, flush ─────▶│──▶
  │                       │                        │                          │ relayResponse():         │
  │                       │                        │                          │   read head ◀─────────────│
  │                       │                        │                          │   write head to client   │
  │◀──status line + headers───────────────────────────────────────────────────│   copy body ◀────────────│
  │◀──body────────────────────────────────────────────────────────────────────│   flush                  │
  │                       │                        │◀── upstream.close() ─────│                          │
  │◀──TCP close───────────────────────────────────│ stream.close(), pool.release(slot)                  │
```

Single request per connection: `forward.zig` always sends `Connection:
close` on both legs and the client socket is closed once the response body
is fully relayed. There is no keep-alive/connection reuse in this pass —
it keeps body-framing bookkeeping (`Content-Length` vs chunked vs
close-delimited) unambiguous.

Header handling: hop-by-hop headers (`Connection`, `TE`, `Upgrade`,
`Proxy-Authenticate`, ...) are stripped per RFC 7230 §6.1. `Transfer-Encoding`
is **not** stripped — it describes the body's actual wire framing, which is
relayed byte-for-byte (`relay.copyChunkedVerbatim`) rather than decoded and
re-encoded, so the next hop needs it to parse the body it receives.

### CONNECT tunnel

```
client                 listener              connection.handle          tunnel.handle               upstream
  │                       │                        │                          │                         │
  │──CONNECT host:443────▶│  (same accept/acquire/dispatch as above)          │                          │
  │                       │                        │ pool.setState(tunneling) │                          │
  │                       │                        │ tunnel.handle ──────────▶│                          │
  │                       │                        │                          │ parseConnectTarget()     │
  │                       │                        │                          │ resolver.connect() ─────▶│ TCP connect
  │◀──200 Connection Established───────────────────────────────────────────────│                          │
  │                       │                        │                          │ splice():                │
  │                       │                        │                          │  ┌─ Io.concurrent ───────▶│ task A: client → upstream
  │◀═══════════════════════════ opaque bytes (e.g. TLS handshake) ════════════▶│  └─ calling task ────────▶│ task B: upstream → client
  │                       │                        │                          │                          │
  │  (either side EOF/err) ─────────────────────────────────────────────────▶ pump() calls peer.shutdown(.both)
  │                       │                        │                          │  unblocks whichever pump is still blocked in read()
  │                       │                        │                          │ future.await()           │
  │                       │                        │◀── upstream.close() ─────│                          │
  │◀──TCP close────────────────────────────────────│ stream.close(), pool.release(slot)                  │
```

The splice is two independent byte pumps, not one loop selecting between
two sockets — `std.Io` has no readiness-multiplexing primitive exposed here,
so full-duplex traffic needs two blocking readers running concurrently.
`Io.concurrent` runs the client→upstream pump (falls back to running it
inline, sequentially, if the runtime can't spin up a concurrent task — see
`tunnel.zig`'s `splice`), while the calling task runs upstream→client
directly. Whichever direction hits EOF or an error first calls
`Stream.shutdown(io, .both)` on its peer socket rather than `close` —
`shutdown` is safe to call while another task is blocked in a `read()` on
that same socket, so it reliably unblocks the other pump instead of leaving
it stuck until its own side happens to close.

## ConnectionPool: data-oriented slot table

```
ConnectionPool (fixed capacity, allocated once from Config.max_connections)
  trace_ids        [u128; N]
  remote_addrs     [IpAddress; N]
  states           [atomic ConnState; N]     idle → accepted → parsing_head → {relaying_http|tunneling} → idle
  next_free        [atomic u32; N]           intrusive singly-linked free list
  free_head        atomic u64                Treiber-stack head: high 32 bits generation tag, low 32 bits slot index
```

A connection's identity for its whole lifetime is the `u32` slot returned
by `acquire()` — cheap to copy into a spawned task's argument list, no
pointer, no allocation. `acquire()`/`release()` are lock-free CAS loops over
`free_head`/`next_free` (a Treiber stack), so many connection tasks can
concurrently acquire/release slots without a mutex. The generation tag
packed into `free_head` is bumped on every push and every pop, making the
stack genuinely ABA-safe under true multi-producer/multi-consumer
acquire/release — a stale head word read by one thread can never
spuriously CAS-match after other threads have popped and re-pushed the
same slot in between. A full pool (`acquire`
returns `null`) makes the listener reject the connection immediately
(`connections_rejected` metric, socket closed) rather than blocking or
growing the table.

## I/O model

**Backend:** `Io.Threaded` is the only backend that works here. `Io.Uring`'s
network vtable entries are stubbed to unconditionally fail in this Zig
0.16.0 stdlib build, and several of its `Dir` operations don't even
type-check against this target — there's currently nothing to select
between, so `main.zig` constructs `Io.Threaded` directly.

**Not thread-per-connection, and not an event loop either — a bounded
worker pool with synchronous fallback:**

- The listener's `accept()` loop runs on a single thread (the one that
  calls `proxy_listener.run(io)` from `main`). Each `accept()` is a
  blocking call — it physically blocks that OS thread until a connection
  arrives.
- Each accepted connection is dispatched via `Io.Group.async`
  (`listener.zig`), which under `Io.Threaded` schedules the task onto a
  worker thread pool sized `async_limit` (default: **logical CPU count −
  1**, from `Io.Threaded.InitOptions`). Up to that limit, a new OS thread is
  spawned per busy pool and reused afterward.
- **Once the pool is saturated, `Io.Threaded` does not queue the task — it
  runs it *eagerly, inline, on the accept thread itself*.** That means under
  sustained load beyond `cpu_count - 1` concurrent connections, the accept
  loop stalls handling one connection to completion before it can `accept()`
  the next. This is a real backpressure mechanism (bounded threads, no
  unbounded thread spawning, no silent queueing), but it's also a latency
  cliff worth knowing about: it is not "N threads then fair queueing," it's
  "N threads then synchronous."
- The tunnel splice's second pump direction uses `Io.concurrent` instead of
  `Io.Group`, which has its own, separate limit (`concurrent_limit`,
  default **unlimited** — it always spawns another worker rather than
  falling back to inline execution). `tunnel.zig` still codes a fallback
  path for the rare case `Io.concurrent` fails outright (e.g. thread
  creation failure), running both pump directions sequentially on the
  calling thread instead.

**Reads:** every reader wraps a fixed stack-allocated buffer — 16 KiB for
parsing the client's request head, 4–64 KiB for relaying bodies/tunneling.
The client and upstream stream readers are `timeout_reader.TimeoutReader`,
not the stdlib `net.Stream.Reader` — see **Timeouts**, below. A read call
blocks the OS thread executing that task until data arrives, the buffer is
satisfied, or the idle deadline elapses; there is no async/await suspension
point here, blocking is real and threads are the unit of concurrency.

**Writes and flush timing — two different strategies for two different
shapes of traffic:**

- **Bounded HTTP bodies** (`forward.zig`'s `forwardRequest`/`relayResponse`,
  using `relay.copyExact`/`copyChunkedVerbatim`): data accumulates in the
  writer's fixed buffer and is only flushed (an actual `write()`/`send()`
  syscall) when that buffer fills, or explicitly once after the head and
  once after the body. A request/response with a body smaller than the
  buffer becomes exactly two syscalls (head, then body) instead of one per
  `print`/`writeAll` call — batching is intentional and safe here because
  the exchange is a known-length, one-shot unit.
- **CONNECT tunnel splicing** (`relay.copyUntilEof`, used by both pump
  directions in `tunnel.zig`): the writer is flushed **after every single
  read**, not just when its buffer fills. This is required, not just an
  optimization choice — a live duplex stream (e.g. a TLS ClientHello sitting
  in the tunnel) can be far smaller than the write buffer, and the peer on
  the other end is blocked waiting for exactly those bytes. Batching on
  buffer-fill would deadlock the handshake. This was a real bug found via
  manual `curl -x ... https://...` testing (see git history), not a
  hypothetical.

**Timeouts:** upstream `connect()` calls in `forward.zig`/`tunnel.zig` pass
`.timeout = .none` deliberately — passing any other value currently hits an
unimplemented path (`@panic("TODO implement netConnectIpPosix with
timeout")`) in this Zig 0.16.0 stdlib, and there's no non-panicking way to
race a connect against `Io.sleep` yet.

Everywhere else data is read off a socket, there is a timeout, because
those are `recv()`s on sockets the proxy already owns, not the
stdlib-internal connect path that panics: the DNS resolver's UDP
`receiveTimeout`, bounded by `Config.dns_timeout_ms` (default 3000 ms), and
every read of the client and upstream TCP streams, bounded by
`Config.idle_timeout_ms` (default 60000 ms; `0` disables). The latter is
`proxy/timeout_reader.zig`'s `TimeoutReader` — an `Io.Reader` wrapping a
`net.Stream` that calls `Socket.receiveTimeout` (the same primitive the
resolver uses) instead of an unbounded `netRead` on every read. It's a
*sliding* idle window, not a total-request budget: the timeout is measured
fresh on each call, so a steady trickle of bytes keeps a connection alive
indefinitely while a silent peer — e.g. a `CONNECT` that sends nothing —
is torn down within one window. `Io.Reader`'s vtable error set is fixed
(`error.ReadFailed`, not open), so `TimeoutReader` stashes the real error
(`error.IdleTimeout`, or whatever `receiveTimeout` returned) in a field and
callers recover it via `timeout_reader.unwrap()`. An idle timeout is
treated as ordinary connection teardown, not a fault: it's logged at
`warn`, counted in `relay_errors`, and the peer socket is shut down the
same way any other relay error is (see `tunnel.zig`'s `pump`).

Writes are not bounded by any of this — only reads. `ConnectionPool` used
to carry a `last_activity_at` timestamp per slot, written on `acquire()`
but read by nothing; there was no reaper. It's been removed rather than
wired up: a real reaper needs the pool to hold a live `net.Stream` handle
per slot plus cross-task-safe shutdown coordination, which is a larger and
riskier change than a per-read idle timeout justifies. The per-read timeout
already closes the actual gap — a connection sitting open, sending
nothing, forever, pinning a slot and up to two worker threads — across
header-parsing, HTTP relay, and CONNECT splicing, on both the client and
upstream leg.

## Telemetry

- **Trace IDs** (`telemetry/span.zig`): a `u128` = `(random node_prefix:
  u64) << 64 | (monotonic per-process counter: u64)`. Generated with one
  atomic `fetchAdd` — no allocation, no locking. `log.zig` prefixes every
  log line for a connection with `trace_id=... slot=...`, so
  `grep trace_id=<x>` reconstructs one request's full path (accept → parse
  → resolve → connect → relay/tunnel → close) across log output alone.
- **Metrics** (`telemetry/metrics.zig`): one process-wide `Metrics` struct —
  a struct-of-arrays of atomic counters (`connections_total/active/rejected`,
  `requests_http/connect`, `upstream_connect_errors`, `relay_errors`).
  `incr`/`decr`/`add`/`get` are all single atomic ops on a shared pointer;
  no per-request allocation or locking. `upstream_connect_errors` is
  incremented in `forward.zig`/`tunnel.zig` on the `resolver.connect(...)
  catch` branch, right before the client gets its 502. `relay_errors`
  covers any post-connect relay failure, including idle-timeout teardowns
  (see I/O model → Timeouts) — `tunnel.zig`'s `pump()` used to swallow
  these silently; it now logs and counts them like every other relay
  error.
- **Export** (`telemetry/reporter.zig`): `Metrics.snapshot()` returns a
  `[Counter.count]u64` (one atomic `load` per counter, not a consistent
  point-in-time view). When `Config.metrics_interval_ms` is non-zero,
  `main.zig` spawns `reporter.run` in its own `Io.Group`; it wakes every
  interval and logs one `name=value ...` line via `formatSnapshot`. Default
  is `0` (disabled) — this is the only place any counter is ever read back.

## Zero-allocation hot path

After startup (`ConnectionPool.init`, the DNS server address array,
`Telemetry.init`), nothing in the connection-handling path calls the
general-purpose allocator:

- Connection identity is a `u32` slot, not a heap object.
- Read/write buffers (`in_buf`, `out_buf`, `upstream_read_buf`,
  `upstream_write_buf`) are stack arrays sized per call.
- `TraceId` generation and `Metrics` updates are atomics on pre-allocated,
  process-wide arrays.
- The custom DNS resolver (`resolver.zig`) uses fixed-size stack buffers for
  both the query (320 bytes) and response (512 bytes) — no allocation per
  lookup.

## Configuration layering

```
compiled-in Config{} defaults
        │
        ▼ (if --config <path>, else ./zroute.json if it exists)
JSON file (std.json.parseFromSlice, missing fields keep their default)
        │
        ▼
CLI flags (--listen, --max-connections, --metrics-interval-ms; unknown flags are a hard error)
```

Each layer only needs to mention the fields it wants to change; later
layers win field-by-field, not wholesale.
