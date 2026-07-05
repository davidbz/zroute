const std = @import("std");
const Io = std.Io;
const net = Io.net;

const pool_mod = @import("pool.zig");
const ConnectionPool = pool_mod.ConnectionPool;
const connection = @import("connection.zig");
const telemetry_mod = @import("../telemetry/telemetry.zig");
const Telemetry = telemetry_mod.Telemetry;

const log = std.log.scoped(.listener);

/// Owns the listening socket and the single `Io.Group` that every accepted
/// connection's task belongs to for the lifetime of the process. One task
/// per connection; the listener itself never blocks on any of them.
pub const Listener = struct {
    server: net.Server,
    pool: *ConnectionPool,
    telemetry: *Telemetry,
    deps: connection.Deps,
    group: Io.Group = .init,

    pub fn init(address: net.IpAddress, io: Io, pool: *ConnectionPool, telemetry: *Telemetry, deps: connection.Deps) net.IpAddress.ListenError!Listener {
        const server = try net.IpAddress.listen(&address, io, .{ .reuse_address = true });
        return .{ .server = server, .pool = pool, .telemetry = telemetry, .deps = deps };
    }

    /// Cancels every in-flight connection task before tearing down the
    /// listening socket, so no task is left touching a socket after this
    /// returns.
    pub fn deinit(l: *Listener, io: Io) void {
        l.group.cancel(io);
        l.server.deinit(io);
    }

    /// Accepts connections forever. Guard-clauses on accept/acquire failure
    /// just log and keep looping — a single bad accept or a momentarily full
    /// pool never brings the listener down.
    pub fn run(l: *Listener, io: Io) void {
        while (true) {
            const stream = l.server.accept(io) catch |e| {
                log.warn("accept failed err={t}", .{e});
                continue;
            };

            const trace_id = l.telemetry.nextTraceId();
            const slot = l.pool.acquire(trace_id, stream.socket.address) orelse {
                l.telemetry.metrics.incr(.connections_rejected);
                stream.close(io);
                continue;
            };

            // `Group.concurrent`, not `Group.async`: under `Io.Threaded`,
            // `Group.async` silently runs the task inline on the caller's
            // thread once the worker pool is saturated (`async_limit`
            // reached) instead of queueing or rejecting it. The caller here
            // is this accept loop, so that fallback would block accept()
            // for the duration of whatever connection got inlined — fatal
            // for a proxy, since CONNECT tunnels routinely outlive the
            // pool's thread budget. `Group.concurrent` fails loudly instead,
            // so a saturated pool is handled the same way as an exhausted
            // connection pool: reject this one connection and keep accepting.
            l.group.concurrent(io, connection.handle, .{ stream, slot, trace_id, io, l.deps }) catch |e| {
                log.warn("concurrent spawn failed err={t}", .{e});
                l.telemetry.metrics.incr(.connections_rejected);
                l.pool.release(slot);
                stream.close(io);
                continue;
            };
        }
    }
};
