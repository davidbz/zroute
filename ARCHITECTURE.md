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
    egress.zig                  SSRF egress policy: deny-list + CIDR allowlist,
                                 CONNECT port allowlist, shared deny-response helper
    forward.zig                 plain HTTP relay (parse -> connect -> relay)
    tunnel.zig                  CONNECT relay (parse -> connect -> splice)
    relay.zig                   shared byte-copy primitives
    timeout_reader.zig          Io.Reader over a stream with a sliding idle deadline
    log.zig                     trace_id/slot-tagged structured logging
  telemetry/
    telemetry.zig              trace-id generation
    span.zig                    TraceId type + generator
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
  ├─ ConnectionPool.init(gpa, cfg.max_connections)   one fixed allocation, never grows
  ├─ build dns_servers: []IpAddress    parses cfg.dns_servers, port 53
  ├─ Resolver.init(dns_servers, ...)   .system if empty, .custom otherwise
  ├─ cfg.egressPolicy(gpa)             parses egress_allow CIDRs once; held in Deps for process lifetime
  ├─ Listener.init(listen_address, io, &pool, &telemetry, deps)
  └─ proxy_listener.run(io)            blocks forever; this is the whole program
```

Everything the request path touches (`pool`, `telemetry`, `resolver`,
`egress_policy`) is built once here and handed down by pointer/value through
`connection.Deps`.
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
  │                       │                        │                          │ resolver.connect():      │
  │                       │                        │                          │  resolve → egress.Policy │
  │                       │                        │                          │  .allowsTarget() per addr│
  │                       │                        │                          │  → TCP connect ──────────▶│
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

If every resolved address is denied by the egress policy, `resolver.connect`
returns `error.EgressDenied` and `forward.handle` responds `403 Forbidden`
via `egress.denyEgress` instead of the `502 Bad Gateway` used for an
ordinary connect failure — see [Egress policy](#egress-policy-ssrf-defense).

### CONNECT tunnel

```
client                 listener              connection.handle          tunnel.handle               upstream
  │                       │                        │                          │                         │
  │──CONNECT host:443────▶│  (same accept/acquire/dispatch as above)          │                          │
  │                       │                        │ pool.setState(tunneling) │                          │
  │                       │                        │ tunnel.handle ──────────▶│                          │
  │                       │                        │                          │ parseConnectTarget()     │
  │                       │                        │                          │ egress.Policy            │
  │                       │                        │                          │  .allowsConnectPort()    │
  │                       │                        │                          │ resolver.connect():      │
  │                       │                        │                          │  resolve → egress.Policy │
  │                       │                        │                          │  .allowsTarget() per addr│
  │                       │                        │                          │  → TCP connect ──────────▶│
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
`Io.concurrent` runs the client→upstream pump while the calling task runs
upstream→client directly. If `Io.concurrent` fails to spawn, the tunnel is
aborted — both sockets are shut down and `tunnel_concurrency_errors` is
incremented — rather than falling back to running both pumps sequentially,
which would deadlock any duplex protocol (see `tunnel.zig`'s `splice`).
Whichever direction hits EOF or an error first calls
`Stream.shutdown(io, .both)` on its peer socket rather than `close` —
`shutdown` is safe to call while another task is blocked in a `read()` on
that same socket, so it reliably unblocks the other pump instead of leaving
it stuck until its own side happens to close.

## Egress policy (SSRF defense)

`egress.zig` is a self-contained policy module: it classifies `IpAddress`
values and CONNECT ports, and knows nothing about resolvers, sockets, or
config file parsing. Two things call into it:

- **`resolver.connect`** (`resolver.zig`) applies `Policy.allowsTarget` to
  every address returned by DNS resolution, *before* attempting a TCP
  connect, and only to that resolved list — never to the hostname string
  itself. Checking the hostname would be bypassable by DNS rebinding: an
  attacker-controlled name that resolves to a public IP at request-parse
  time but a denied one (e.g. `169.254.169.254`) at connect time. Denying
  post-resolution closes that gap regardless of which resolver path
  (`.system` via `HostName.lookup`, or `.custom` UDP) produced the
  addresses. If every candidate address is denied, `connect` returns
  `error.EgressDenied`; if at least one passed the policy but none of them
  could actually be connected to, it returns `error.AllConnectAttemptsFailed`
  instead (ordinary connect failure, not a policy outcome).
- **`tunnel.handle`** additionally checks `Policy.allowsConnectPort` against
  the parsed `CONNECT` target port before any DNS resolution happens at all
  — a cheap rejection for the "wrong port" case that doesn't need a
  resolved address to decide.

Both denial paths — and the equivalent one in `forward.handle` — converge on
`egress.denyEgress`: log the reason and respond `403 Forbidden`. One shared
function instead of three separate log/respond blocks, since all three are
the same terminal action for different trigger conditions.

**Classification** (`isDeniedRange` / `isDeniedIp4` / `isDeniedIp6`): denies
loopback, link-local (including `169.254.169.254`, the cloud metadata
endpoint reachable from inside most cloud VMs/containers), RFC1918/ULA
private ranges, and multicast, by default. IPv4-mapped IPv6 addresses
(`::ffff:a.b.c.d`) are unwrapped via `net.Ip4Address.fromIp6` and classified
as IPv4 first — otherwise an attacker could reach a denied IPv4 range
through its IPv6-mapped form, since the raw IPv6 bytes alone don't look like
any denied IPv6 range.

**Allowlist** (`AllowEntry`, hand-rolled CIDR match): `Config.egress_allow`
carves out specific ranges that bypass `deny_private` even though they fall
inside a denied range (e.g. permit `10.0.0.0/8` while still denying loopback
and link-local). Parsed once in `Config.egressPolicy` at startup, not
per-connection — the policy handed to every connection task is a plain
value (`[]const AllowEntry` slice + two `bool`/`[]u16` fields), no
allocation or parsing on the hot path.

`Config.listen_host` defaults to `127.0.0.1` for the same underlying reason
this module exists: `zroute` has no built-in authentication, so an
unrestricted egress policy on a publicly reachable listener is a ready-made
open SSRF relay. All three defaults (loopback-only bind, private-range
egress deny, CONNECT port allowlist) are restrictive out of the box;
loosening any of them is an explicit config opt-in — see
[README → Security defaults](README.md#security-defaults).

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
(socket closed) rather than blocking or growing the table.

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
  falling back to inline execution). For the rare case `Io.concurrent` fails
  outright (e.g. thread creation failure), `tunnel.zig` aborts the tunnel
  instead of falling back to running both pump directions sequentially on
  the calling thread: the first pump would block reading from the client
  until EOF, but a live client won't send EOF until it receives the
  server's half of the handshake, which is stuck in the second pump that
  never started — a deadlock, not a degraded mode.

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

There is no metrics/counters subsystem at the moment — request lifecycle
events are only observable via the structured logs above.

## Zero-allocation hot path

After startup (`ConnectionPool.init`, the DNS server address array,
`Telemetry.init`), nothing in the connection-handling path calls the
general-purpose allocator:

- Connection identity is a `u32` slot, not a heap object.
- Read/write buffers (`in_buf`, `out_buf`, `upstream_read_buf`,
  `upstream_write_buf`) are stack arrays sized per call.
- `TraceId` generation is an atomic on a pre-allocated, process-wide
  counter.
- The custom DNS resolver (`resolver.zig`) uses fixed-size stack buffers for
  both the query (320 bytes) and response (512 bytes) — no allocation per
  lookup.
- `egress.Policy` is a plain value (slice + scalars) parsed once from config
  at startup and copied through `Deps` into every connection task; checking
  it (`allowsTarget`/`allowsConnectPort`) is pure comparison, no allocation.

## Configuration layering

```
compiled-in Config{} defaults
        │
        ▼ (if --config <path>, else ./zroute.json if it exists)
JSON file (std.json.parseFromSlice, missing fields keep their default)
        │
        ▼
CLI flags (--listen, --max-connections, --idle-timeout-ms; unknown flags are a hard error)
```

Each layer only needs to mention the fields it wants to change; later
layers win field-by-field, not wholesale.
