# Architecture

`zroute` is a forward HTTP/CONNECT proxy built on Zig 0.16's `std.Io`
interface. It has three design commitments that shape everything below:

- **Data-oriented, not object-oriented.** Connections are rows in a
  struct-of-arrays table, identified by a `u32` slot index, not heap objects.
- **No hidden event loop.** Concurrency comes entirely from `std.Io`'s
  backend (`Io.Threaded`): real OS threads doing blocking I/O, not
  epoll/io_uring multiplexing (io_uring is currently non-functional for
  networking in this Zig build — see [I/O model](#io-model) below).
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

## Execution model

Direct answers, expanded in [I/O model](#io-model):

- **Single-, multi-, or hybrid-threaded?** Hybrid. One dedicated thread (the
  one that calls `main`) runs the accept loop forever. Every accepted
  connection runs its entire lifecycle — parse, resolve, connect, relay,
  cleanup — synchronously on its own OS thread. There is no thread-per-CPU
  worker model and no coroutine/green-thread scheduling.
- **How are threads created and managed?** Entirely by `Io.Threaded`, not by
  zroute. `main.zig` calls `Io.Threaded.init(gpa, .{})` with default options
  and never touches threads directly again. Every `Group.concurrent`/
  `Io.concurrent` call either hands the task to an idle previously-spawned
  thread or, if none is idle, calls `std.Thread.spawn` for a new one.
  Threads are never told to exit early — a worker parks on a condition
  variable when it runs out of work and waits to be reused. Nothing shrinks
  the pool until `Io.Threaded.deinit()` runs, which it does via `main`'s
  `defer` on a normal graceful-shutdown return (see [Shutdown
  semantics](#shutdown-semantics)).
- **What owns the main event loop?** Nothing does, by design — see the
  "No hidden event loop" commitment above. `Listener.run(io)` is the closest
  thing to a "loop": a single thread blocking on `accept()` in sequence,
  dispatching and moving on. Each dispatched connection is a fully blocking,
  synchronous sequence of syscalls on its own thread; there is no
  scheduler multiplexing partial I/O across connections.
- **Concurrency primitives:** `Io.Group` (`.concurrent`, used once per
  accepted connection) and the bare `Io.concurrent` (used once per CONNECT
  tunnel, for the second splice direction) are the only concurrency-spawning
  primitives in the codebase. Cross-thread shared state uses lock-free CAS
  (`ConnectionPool`'s Treiber-stack free list, `std.atomic.Value` connection
  states) and one atomic counter (`Telemetry`'s trace-id generator) — there
  are no mutexes, no channels, and no async/await suspension points
  anywhere in zroute's own code.

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
[Memory model](#memory-model).

## Connection lifecycle

Every connection passes through the same seven steps regardless of path;
only steps 4–6 branch on `CONNECT` vs. plain HTTP:

1. **Accept** — `Listener.run` blocks in `server.accept(io)`.
2. **Acquire connection state** — `pool.acquire(trace_id, remote_addr)` pops
   a slot off the lock-free free list; `invalid_slot`/`null` means the pool
   is full and the connection is rejected immediately.
3. **Parse the request head** — `connection.handle` builds a
   `TimeoutReader`-backed `http.Server` over the accepted stream and calls
   `receiveHead()`.
4. **DNS resolution** — `resolver.connect` resolves the target hostname
   (system or custom resolver — see [DNS architecture](#dns-architecture))
   and filters candidates through the egress policy.
5. **Establish the upstream connection** — the first policy-allowed address
   that accepts a TCP connect wins; policy-denied or connect-failed
   candidates are each other's fallback.
6. **Forward data** — plain HTTP: one request/response relay
   (`forward.zig`). `CONNECT`: bidirectional byte splice (`tunnel.zig`).
7. **Cleanup and resource release** — `connection.handle`'s `defer` chain
   closes the client stream, releases the pool slot, and logs "connection
   closed", regardless of which branch above returned or errored.

### Plain HTTP

```
client                 listener              connection.handle          forward.handle              upstream
  │                       │                        │                          │                         │
  │──TCP connect─────────▶│                        │                          │                         │
  │                       │ accept()               │                          │                         │
  │                       │ pool.acquire(slot)     │                          │                         │
  │                       │ group.concurrent ─────▶│ (own OS thread)          │                          │
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
re-encoded, so the next hop needs it to parse the body it receives. A
request/response carrying both `Content-Length` and `Transfer-Encoding:
chunked` has its `Content-Length` dropped rather than relayed, so an
upstream/downstream pair that resolve that ambiguity differently than
zroute can't be smuggled a hidden request past the boundary implied by the
other header.

If every resolved address is denied by the egress policy, `resolver.connect`
returns `error.EgressDenied` and `forward.handle` responds `403 Forbidden`
via `egress.denyEgress` instead of the `502 Bad Gateway` used for an
ordinary connect failure — see [Security architecture](#security-architecture).

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
`Io.concurrent` runs the client→upstream pump on a second OS thread while
the calling task runs upstream→client directly. If `Io.concurrent` fails to
spawn, the tunnel is aborted — both sockets are shut down and the failure is
logged at `err` — rather than falling back to running both pumps
sequentially, which would deadlock any duplex protocol (see `tunnel.zig`'s
`splice`; every TLS handshake is exactly this kind of protocol, since
`CONNECT` never terminates TLS here).

Whichever direction hits EOF or an error first calls
`Stream.shutdown(io, .both)` on its peer socket rather than `close` —
`shutdown` is safe to call while another task is blocked in a `read()` on
that same socket, so it reliably unblocks the other pump instead of leaving
it stuck until its own side happens to close. A non-EOF pump failure (most
commonly an idle timeout, see [Timeouts](#io-model)) is treated as an
ordinary way for a tunnel to end, not a fault, and is logged at `warn`.

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
same slot in between. A full pool (`acquire` returns `null`) makes the
listener reject the connection immediately (socket closed) rather than
blocking or growing the table.

## I/O model

**Backend:** `Io.Threaded` is the only backend that works here. `Io.Uring`'s
network vtable entries are stubbed to unconditionally fail in this Zig
0.16.0 stdlib build, and several of its `Dir` operations don't even
type-check against this target — there's currently nothing to select
between, so `main.zig` constructs `Io.Threaded` directly.

**Effectively thread-per-connection, not a CPU-bounded worker pool —
and that distinction was the subject of a real production bug:**

- The listener's `accept()` loop runs on a single thread (the one that
  calls `proxy_listener.run(io)` from `main`). Each `accept()` is a blocking
  call — it physically blocks that one OS thread until a connection
  arrives.
- Each accepted connection is dispatched via `Io.Group.concurrent`
  (`listener.zig`). Under `Io.Threaded`, `Group.concurrent`/the bare
  `Io.concurrent` (used identically by the tunnel splice's second pump) are
  gated by `Io.Threaded.InitOptions.concurrent_limit`, **which defaults to
  `.unlimited`** and is never overridden by `main.zig`'s
  `Io.Threaded.init(gpa, .{})`. In practice this means: reuse an idle thread
  already in the pool if one exists, otherwise spawn a brand new OS thread
  — with no configured ceiling on that spawning. Spawned threads are never
  retired; once idle, a worker just parks on a condition variable waiting
  to be handed the next task, for the remainder of the process's life (see
  [Memory model](#memory-model) for the standing-thread-count consequence
  of that).
- **The actual concurrency ceiling is `ConnectionPool.capacity`
  (`Config.max_connections`, default 8192), not the thread pool.** A
  connection is only ever dispatched to `Group.concurrent` after
  `pool.acquire()` has already succeeded; when the pool is full, the
  connection is rejected (socket closed) before a thread is ever considered.
  `Group.concurrent` failing on its own (`error.ConcurrencyUnavailable`) is
  an exceptional condition — allocation failure building the task, or the
  OS itself refusing `std.Thread.spawn` (e.g. a process thread-count
  `ulimit`) — not a designed backpressure signal; when it does happen, the
  listener logs it, releases the pool slot, and keeps accepting.
- **This is a deliberate fix, not the original design.** An earlier revision
  dispatched connections via `Io.Group.async`, which is gated by a
  *different*, CPU-sized limit (`async_limit`, defaulting to logical CPU
  count − 1) and — critically — falls back to running the task **eagerly,
  inline, on the caller's own thread** once that limit is hit, rather than
  spawning or rejecting. For a short HTTP relay that's a latency blip; for
  a long-lived `CONNECT` tunnel it meant the accept loop itself got pinned
  running one tunnel's entire splice loop, unable to `accept()` anything
  else for that tunnel's whole lifetime. Switching the dispatch call from
  `.async` to `.concurrent` trades a low, CPU-shaped thread ceiling for a
  high, connection-pool-shaped one, in exchange for the accept loop never
  blocking on a live connection's I/O. The regression test
  `test_listener_stays_responsive_under_concurrent_tunnels`
  (`test/e2e_test.py`) opens enough concurrent idle tunnels to exceed what
  a CPU-sized pool could serve concurrently, then asserts a fresh request
  is still served promptly — i.e., it depends on `.concurrent` actually
  spawning past that ceiling rather than queuing behind it.
- **Rejected alternative:** capping `concurrent_limit` to something
  CPU-shaped (mirroring `async_limit`) was not done, because zroute's
  connection tasks spend almost all their time blocked on socket I/O, not
  running on CPU — a CPU-sized cap would reintroduce exactly the
  head-of-line stalling the `.async`→`.concurrent` switch was meant to
  fix, just with a rejection instead of inline execution once past it.
  `ConnectionPool.capacity` is the intentional, explicit ceiling instead:
  operator-configured, sized for expected concurrent connections rather
  than CPU count.

**Reads:** every reader wraps a fixed stack-allocated buffer — 16 KiB for
parsing the client's request head, 4–64 KiB for relaying bodies/tunneling.
Both client and upstream stream readers are `timeout_reader.TimeoutReader`,
not the stdlib `net.Stream.Reader` — see **Timeouts**, below. A read call
blocks the OS thread executing that task until data arrives, the buffer is
satisfied, or the idle deadline elapses; there is no async/await suspension
point here — blocking real threads is the unit of concurrency.

**Writes — flush timing uses two different strategies for two different
shapes of traffic:**

- **Bounded HTTP bodies** (`forward.zig`'s `forwardRequest`/`relayResponse`,
  using `relay.copyExact`/`copyChunkedVerbatim`): data accumulates in the
  writer's fixed buffer and is only flushed (an actual `write()`/`send()`
  syscall) when the buffer fills, plus explicitly once after the head and
  once after the body. A request/response body smaller than the buffer
  becomes exactly two syscalls (head, then body) instead of one per
  `print`/`writeAll` call — batching is intentional and safe here because
  the exchange is a known-length, one-shot unit.
- **CONNECT tunnel splicing** (`relay.copyUntilEof`, used by both pump
  directions in `tunnel.zig`): the writer is flushed **after every single
  read**, not just when the buffer fills. This is required, not just an
  optimization choice — on a live duplex stream (e.g. a TLS ClientHello
  sitting in the tunnel) waiting for the buffer to fill before flushing
  means the peer, who is blocked waiting for exactly those bytes, never
  gets them: a deadlock, not a slow path. (This was an actual bug hit via
  `curl -x https://...` testing, not a hypothetical — see git history.)

**Timeouts:** upstream `connect()` calls in `forward.zig`/`tunnel.zig` pass
`.timeout = .none` deliberately — passing any other value currently hits an
unimplemented path (`@panic("TODO implement netConnectIpPosix with
timeout")`) in this Zig 0.16.0 stdlib build, and there is no non-panicking
way to race a connect against `Io.sleep` yet.

Everywhere else data is read off a socket the proxy already owns — not the
stdlib-internal connect path that panics — there is a timeout: the DNS
resolver's UDP `receiveTimeout`, bounded by `Config.dns_timeout_ms` (default
3000 ms), and every read on the client/upstream TCP streams, bounded by
`Config.idle_timeout_ms` (default 60000 ms; `0` disables). The latter is
`proxy/timeout_reader.zig`'s `TimeoutReader` — an `Io.Reader` wrapping
`net.Stream` that calls `Socket.receiveTimeout` (the same primitive the
resolver uses) instead of the unbounded `netRead` on every read. It's a
*sliding* idle window, not a total-request budget: the timeout is measured
fresh on each call, so a steady trickle of bytes keeps a connection alive
indefinitely while a silent peer — e.g. a `CONNECT` client that sends
nothing — is torn down within one window. `Io.Reader`'s vtable error set is
fixed (`error.ReadFailed`, not open), so `TimeoutReader` stashes the real
error (`error.IdleTimeout`, or whatever `receiveTimeout` returned) in a
field that callers recover via `timeout_reader.unwrap()`. An idle timeout is
treated as an ordinary connection teardown, not a fault: it's logged at
`warn` and the peer socket is shut down the same way as any other relay
error (see `tunnel.zig`'s `pump`).

Idle timeouts are per-read, not connection-lifetime — there is no
separate watchdog task and no `ConnectionPool` involvement in enforcing
them; each blocking read call carries its own deadline. That's sufficient
because the gap this closes is exactly "a connection sitting open, sending
nothing, forever, pinning a slot (and, per the point above, a standing OS
thread) indefinitely" — across header-parsing, HTTP relay, and CONNECT
splicing, on both the client and upstream leg. This is zroute's slowloris
defense — see [Security architecture](#security-architecture).

## Memory model

**Fixed-capacity structures.** The two things sized at startup from config
and never resized afterward:

- `ConnectionPool`: struct-of-arrays over `Config.max_connections` slots
  (`trace_ids`, `remote_addrs`, `states`, `next_free` — see
  [ConnectionPool](#connectionpool-data-oriented-slot-table)). One
  allocation per array, made once in `main`, freed by `pool.deinit(gpa)`
  during the graceful-shutdown sequence (see [Shutdown
  semantics](#shutdown-semantics)).
- The DNS server address list (`[]Io.net.IpAddress`, parsed from
  `Config.dns_servers` once) and the egress allowlist (`[]egress.AllowEntry`,
  parsed from `Config.egress_allow` once).

**Buffer ownership.** Every per-connection I/O buffer is a stack array,
owned by the task's own stack frame, sized per call site — never heap
allocated, never shared across tasks:

| Buffer | Size | Owner |
| --- | --- | --- |
| `in_buf` (client request head) | 16 KiB | `connection.handle` |
| `out_buf` (client response) | 4 KiB | `connection.handle` |
| `upstream_read_buf` (plain HTTP) | 16 KiB | `forward.handle` |
| `upstream_write_buf` (plain HTTP) | 4 KiB | `forward.handle` |
| `upstream_read_buf`/`write_buf` (tunnel) | 64 KiB each | `tunnel.handle` |
| DNS query/response scratch | 320 B / 512 B | `resolver.CustomResolver.queryServer` |

Because these live on the stack, their lifetime is exactly the call that
declared them — there is no reference counting, no arena, and no
possibility of a buffer outliving the connection that owns it (or vice
versa: a slow connection can't pin someone else's buffer).

**Allocation strategy.** `gpa` (the general-purpose allocator passed into
`main`) is used exactly once, at startup, to build the fixed structures
above. After `Listener.init` returns, **nothing in the connection-handling
path calls a general-purpose allocator**:

- Connection identity is a `u32` slot, not a heap object.
- `TraceId` generation is an atomic `fetchAdd` on a pre-allocated,
  process-wide counter (`telemetry/span.zig`).
- The custom DNS resolver (`resolver.zig`) builds queries and parses
  responses entirely in fixed-size stack buffers — no allocation per
  lookup, regardless of query volume.
- `egress.Policy`, once built, is a plain value (a slice + two scalar
  fields) copied by value through `connection.Deps` into every connection
  task; checking it (`allowsTarget`/`allowsConnectPort`) is a pure
  comparison, no allocation.

**Why heap allocations are avoided on the hot path.** Two independent
reasons converge on the same design: (1) a heap allocation under load is a
mutex/allocator-lock contention point and a source of allocation-failure
error paths that would otherwise not exist, both undesirable on a path that
already has real concurrency (many OS threads, one per live connection);
(2) fixed, stack-based sizing makes the proxy's peak memory footprint a
function of configuration (`max_connections` × per-connection buffer sizes)
rather than of traffic shape, which is what makes the `ConnectionPool`'s
"reject when full" behavior (see below) a meaningful, predictable
backpressure signal instead of an approximation.

**Tradeoffs of this design.**

- A fixed-size `ConnectionPool` means load beyond `max_connections` is
  rejected outright (immediate socket close) rather than queued — there is
  no bounded-but-elastic buffering of excess connections. That is the
  point (predictable worst-case memory), but it does mean a traffic spike
  that would have been fine with a slower, queued admission gets a hard
  failure instead.
- Per-connection stack buffers are sized for the common case (16 KiB
  request heads, 4–64 KiB relay chunks) at compile time. An HTTP request or
  response head larger than 16 KiB is rejected with a clean error
  (`error.HttpHeadersOversize` → `502`/closed connection) rather than
  handled via a growable buffer — trading a rare-but-hard failure mode for
  never needing a heap-backed growth path in the common case.
- Standing thread count (see [I/O model](#io-model)) is a memory cost that
  doesn't show up in the "zero allocation on the hot path" story: every OS
  thread `Io.Threaded` has ever spawned keeps its stack resident until
  process exit, even once idle. A traffic burst that peaks at, say, 3,000
  concurrent connections leaves roughly 3,000 parked threads (and their
  stacks) alive for the rest of the process's life, not just for the
  burst's duration. This is a consequence of `concurrent_limit` defaulting
  to `.unlimited` (see [I/O model](#io-model)), not something zroute's own
  code controls.

## DNS architecture

**Resolver ownership.** One `Resolver` value (`resolver.zig`) is built once
in `main` from `Config.dns_servers` and held for the process lifetime,
copied by value into every connection's `Deps`. It is a tagged union with
exactly two variants — there is no per-connection resolver state and no
resolver-level cache; every request re-resolves its target from scratch.

- **`.system`** (the default, when `Config.dns_servers` is empty): delegates
  to `net.HostName.lookup`, the stdlib OS-resolver path (`/etc/resolv.conf`
  and whatever mechanism the platform's resolver uses underneath it).
  Results are drained synchronously into a fixed 16-slot queue on the
  calling task — `HostName.lookup`'s own contract guarantees it never
  blocks trying to push a result into a queue that size, so no separate
  producer task is needed.
- **`.custom`** (used whenever `Config.dns_servers` is non-empty): a
  hand-rolled resolver that speaks DNS-over-UDP directly to the configured
  nameservers, bypassing the OS resolver entirely. Chosen because stdlib has
  no API to point hostname lookup at specific nameservers — this exists
  purely to fill that gap, not to replace `.system` generally.

**Threading model.** Resolution happens synchronously, inline, on the
connection's own task/thread — a lookup blocks that connection's thread
until it completes or times out, exactly like every other I/O in this
codebase (see [Execution model](#execution-model)). There is no dedicated
resolver thread, thread pool, or async resolution path; concurrent
resolutions across connections just mean concurrently-blocked threads, one
per in-flight lookup, same as any other socket operation here.

**Timeouts.** `.system` resolution has no explicit zroute-side timeout — it
inherits whatever `HostName.lookup`/the OS resolver's own behavior is.
`.custom` resolution uses a hard, absolute deadline
(`Config.dns_timeout_ms`, default 3000 ms) computed once per query
(`c.timeout.toDeadline(io)`), not a per-packet duration that resets on
every received datagram. That distinction matters against an off-path
attacker: a fixed deadline bounds the *total* time spent on one query no
matter how many junk/spoofed UDP datagrams arrive in the meantime, whereas
a per-packet timer re-armed on every datagram would let an attacker flood
the socket with noise to stall the query indefinitely.

**IPv4/IPv6 behavior.** `.system` resolution returns whatever address
families `HostName.lookup` yields (IPv4 and IPv6). `.custom` resolution is
**IPv4-only** — it queries `A` records exclusively and has no `AAAA`
support. This is a stated limitation of the custom path, not a silent gap:
anyone needing IPv6 resolution against specific nameservers must currently
use `.system` instead (i.e. leave `dns_servers` empty and rely on
`/etc/resolv.conf`).

**Failure handling.** `resolver.connect` (the shared entry point both
`forward.zig` and `tunnel.zig` call) resolves up to 16 candidate addresses
into a stack buffer, then tries each one in order against the egress
policy and a TCP connect:

- If the resolver itself fails outright (`.system`: `error.UnknownHostName`
  when zero addresses came back; `.custom`: `error.NameServerFailure` after
  every configured server has failed or timed out — servers are tried in
  order, first success wins), that error propagates up as an ordinary
  connect failure (`502 Bad Gateway` in `forward.zig`, an aborted tunnel
  setup in `tunnel.zig`).
- If resolution succeeds but every returned address is denied by the egress
  policy, the result is `error.EgressDenied` — a distinct outcome from a
  resolver or connect failure, mapped to `403 Forbidden` instead of `502`
  (see [Security architecture](#security-architecture)).
- If at least one address passed the policy but none of them could actually
  be connected to, the result is `error.AllConnectAttemptsFailed` — ordinary
  connect failure, not a policy outcome, also mapped to `502`.

The custom resolver's spoofing defense is the transaction ID: `isValidResponse`
rejects any UDP datagram that doesn't match the query's random 16-bit ID,
isn't marked as a response (QR bit), or carries a nonzero RCODE — an
off-path attacker guessing that 16-bit value is the only thing the wire
protocol itself gives them to work with, so this check is the primary
defense against a spoofed answer.

## Shutdown semantics

`SIGTERM`/`SIGINT` trigger a graceful drain: stop accepting new connections
immediately, let in-flight connections finish on their own up to
`Config.shutdown_timeout_ms` (default 30s), then force-cancel whatever's
still running and exit. Concretely:

- **Trigger:** `src/proxy/shutdown.zig`'s `install` registers a `sigaction`
  handler for `SIGTERM`/`SIGINT` (with `SA.RESTART`) that does exactly one
  thing: call the raw `shutdown(2)` syscall directly on the listening
  socket's fd (`std.os.linux.shutdown`, bypassing `Io.Threaded`'s own
  `netShutdown`/`Stream.shutdown` wrappers, which track per-thread
  cancellation state that a signal handler can't safely re-enter). Per
  `Io.net.Server.accept`'s documented contract, `shutdown`-ing a listening
  socket makes any blocked or future `accept()` call return
  `error.SocketNotListening` — this is an intentional, documented
  concurrent-cancellation mechanism in the stdlib, not a hack. `SA.RESTART`
  matters because the signal can land on *any* thread, including one
  blocked in a live connection's read/write: the kernel transparently
  resumes that thread's own syscall instead of failing it with `EINTR`,
  since the handler only ever touches the listening socket's fd.
- **Accept loop exit:** `Listener.run` (`src/proxy/listener.zig`) treats
  `error.SocketNotListening` as a clean drain request — it returns instead
  of logging and looping — rather than the generic "log and keep accepting"
  treatment every other `accept` error gets.
- **Drain wait:** `main` (not `Listener`) owns the grace period, because
  `Io.Group.await`/`Group.cancel` are documented "not threadsafe" to call
  concurrently from two threads on the same group — only the thread already
  holding `proxy_listener` may touch `.group`. After `run` returns, `main`
  polls `ConnectionPool.isDrained()` (an O(capacity) scan of `states[]` for
  all-`.idle`) on a short interval up to `shutdown_timeout_ms`. Whether or
  not it drains in time, `main` then calls `proxy_listener.deinit(io)`
  unconditionally: its `l.group.cancel(io)` is idempotent and a no-op if the
  group is already empty, or force-cancels any stragglers left after a
  timed-out drain — either way, `connection.handle`'s existing `defer` chain
  (release pool slot, close socket, log) runs correctly during unwind.
- **Worker thread teardown:** because `run` now actually returns, `main`'s
  `defer threaded.deinit()` finally executes (previously dead code, since
  `run` never returned). `Io.Threaded.deinit` joins every worker thread —
  since the drain/cancel sequence above already brought every connection
  task to completion first, this returns promptly instead of hanging, and
  the process exits cleanly rather than needing an external `SIGKILL`.

## Security architecture

zroute has no built-in authentication, so its network exposure and the set
of destinations it will proxy to are the only things standing between a
client that can reach the listener and an SSRF pivot into internal
infrastructure. All defaults below are the restrictive choice; loosening
any of them is an explicit config opt-in (see [README → Security
defaults](README.md#security-defaults)).

- **Loopback default.** `Config.listen_host` defaults to `127.0.0.1`.
  Binding to a routable address (`0.0.0.0` or a specific interface) is an
  explicit `--listen`/config change — a publicly reachable listener with no
  authentication is otherwise a ready-made open relay.
- **SSRF protections and DNS rebinding defenses** — see [Egress policy
  (SSRF defense)](#egress-policy-ssrf-defense) below for the full
  mechanism. In summary: every resolved target IP (never the hostname
  string) is checked against a deny-list of loopback/link-local (including
  the `169.254.169.254` cloud metadata endpoint)/RFC1918/ULA/multicast
  ranges, with an operator-configurable CIDR allowlist to carve out
  exceptions. Checking the *resolved* address rather than the hostname is
  specifically what defeats DNS rebinding — a name that resolves to a
  public IP at parse time and an internal one at connect time is caught at
  connect time, regardless of which resolver path produced the answer.
- **CONNECT restrictions.** `Config.connect_allowed_ports` (default `[443,
  80]`) restricts which ports a `CONNECT` tunnel may target, checked before
  any DNS resolution happens at all (`tunnel.handle` calls
  `Policy.allowsConnectPort` first — a cheap rejection that doesn't need a
  resolved address). This does not apply to plain HTTP forwarding, which is
  scoped by the egress deny check alone; the asymmetry exists because
  `CONNECT` establishes an opaque tunnel to an arbitrary TCP service (SMTP
  relays, internal admin ports, ...), where the egress IP check alone
  doesn't constrain which *service* on that IP gets reached.
- **Slowloris mitigations.** `Config.idle_timeout_ms` (default 60000 ms)
  bounds the gap between bytes on any client or upstream read — see
  [Timeouts](#io-model) for the mechanism (`TimeoutReader`, a sliding
  window, not a total-request budget). This is what keeps a connection that
  opens and then sends nothing (or trickles bytes deliberately slowly) from
  pinning a `ConnectionPool` slot — and, per [Memory model](#memory-model),
  a standing OS thread — indefinitely. Setting `idle_timeout_ms: 0`
  disables this and restores unbounded blocking reads.

### Egress policy (SSRF defense)

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

## Observability

- **Trace IDs** (`telemetry/span.zig`): `u128` = `(random node_prefix:
  u64) << 64 | (monotonic per-process counter: u64)`. Generated with one
  atomic `fetchAdd` — no allocation, no locking. `log.zig` prefixes every
  log line for a connection with `trace_id=... slot=...`, so
  `grep trace_id=<x>` reconstructs one request's full path (accept → parse
  → resolve → connect → relay/tunnel → close) across log output alone,
  without any log aggregation infrastructure.
- **Logging philosophy:** structured, per-connection, and terminal-action
  oriented — every guard-clause failure (bad request, egress denial,
  connect failure, idle timeout, tunnel spawn failure) logs once at the
  point where the decision is made (`warn`/`err`), tagged with the same
  `trace_id`/`slot` as every other line for that connection, then the
  connection unwinds through its normal `defer` cleanup. There's no
  separate "error reporting" path distinct from the log line that records
  the decision.
- **Error propagation:** Zig error unions all the way up — `forward.handle`/
  `tunnel.handle` return `!void`, and `connection.handle` catches at the top
  with a single `log.warn` per branch rather than propagating further
  (there is nothing above `connection.handle` that could do anything with
  the error besides log it — the task's return value is discarded by
  `Io.Group.concurrent`). Errors that need to reach the *client* (bad
  request, egress denial, bad gateway) are converted to HTTP responses
  inline at the point of failure, not derived from the propagated Zig error
  afterward.
- **No metrics/counters subsystem.** A prior revision had one (atomic
  counters plus a periodic snapshot reporter, `--metrics-interval-ms`); it
  was dropped ("for now" — see commit `de07f8e`), on the basis that
  request lifecycle stays observable through the existing trace-id-tagged
  structured logs without it. Request-lifecycle events are observable via
  structured logs only, today.
- **Future extensibility:** the trace-id/slot log tagging convention
  (`log.zig`) is the natural seam for adding a metrics/tracing subsystem
  back if operational need reappears — every call site already has the
  `trace_id`/`slot` a metrics event would need to key on. Any reintroduction
  should learn from the previous removal: keep counters mechanically tied
  to the log call sites that already exist (e.g. incremented in the same
  place a `warn`/`err` is logged) rather than maintained as parallel,
  independently-updated state.

## Configuration layering

```
compiled-in Config{} defaults
        │
        ▼ (if --config <path>, else ./zroute.json exists)
JSON file (std.json.parseFromSlice, missing fields keep their default)
        │
        ▼
CLI flags (--listen, --max-connections, --idle-timeout-ms; unknown flags are a hard error)
```

Each layer only needs to mention the fields it wants to change; later
layers win field-by-field, not wholesale.
