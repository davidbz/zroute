const std = @import("std");
const Io = std.Io;
const http = std.http;
const net = Io.net;

const pool_mod = @import("pool.zig");
const ConnectionPool = pool_mod.ConnectionPool;
const forward = @import("forward.zig");
const tunnel = @import("tunnel.zig");
const log = @import("log.zig");
const timeout_reader = @import("timeout_reader.zig");
const TimeoutReader = timeout_reader.TimeoutReader;
const telemetry_mod = @import("../telemetry/telemetry.zig");
const Telemetry = telemetry_mod.Telemetry;
const TraceId = telemetry_mod.TraceId;
const Resolver = @import("resolver.zig").Resolver;
const egress = @import("egress.zig");

const head_buffer_size = 16 * 1024;
const relay_buffer_size = 4 * 1024;

/// Everything a connection task needs, borrowed from the listener for its
/// whole lifetime. All fields are shared, pre-allocated process-wide state
/// (or cheap value types) — nothing here is per-connection.
pub const Deps = struct {
    pool: *ConnectionPool,
    telemetry: *Telemetry,
    resolver: Resolver,
    /// Max gap between bytes on any read before the connection is torn down
    /// as stalled. `.none` disables idle enforcement. See `Config.idle_timeout_ms`.
    idle_timeout: Io.Timeout,
    /// Egress deny policy (link-local/loopback/RFC1918/ULA/multicast +
    /// CONNECT port allowlist) applied to every resolved target.
    egress_policy: egress.Policy,
};

/// Owns one accepted connection end-to-end: parses the request head,
/// dispatches to the CONNECT tunnel path or the plain HTTP forward path,
/// then always releases the pool slot and closes the socket, even on error.
/// Entirely stack-based — no allocation once the listener has accepted the
/// stream.
pub fn handle(stream: net.Stream, slot: u32, trace_id: TraceId, io: Io, deps: Deps) void {
    defer stream.close(io);
    defer deps.pool.release(slot);
    defer deps.telemetry.metrics.decr(.connections_active);

    deps.telemetry.metrics.incr(.connections_total);
    deps.telemetry.metrics.incr(.connections_active);

    var in_buf: [head_buffer_size]u8 = undefined;
    var out_buf: [relay_buffer_size]u8 = undefined;
    var stream_reader: TimeoutReader = .init(stream, io, &in_buf, deps.idle_timeout);
    var stream_writer = stream.writer(io, &out_buf);
    var server: http.Server = .init(&stream_reader.interface, &stream_writer.interface);

    deps.pool.setState(slot, .parsing_head);
    var request = server.receiveHead() catch |e| {
        log.warn(trace_id, slot, "receive head failed err={t}", .{timeout_reader.unwrap(&stream_reader.interface, e)});
        return;
    };

    log.debug(trace_id, slot, "{t} {s}", .{ request.head.method, request.head.target });

    if (request.head.method == .CONNECT) {
        deps.pool.setState(slot, .tunneling);
        deps.telemetry.metrics.incr(.requests_connect);
        tunnel.handle(&request, stream, io, deps.resolver, &deps.telemetry.metrics, trace_id, slot, deps.idle_timeout, deps.egress_policy) catch |e| {
            log.warn(trace_id, slot, "tunnel error err={t}", .{e});
            deps.telemetry.metrics.incr(.relay_errors);
        };
        return;
    }

    deps.pool.setState(slot, .relaying_http);
    deps.telemetry.metrics.incr(.requests_http);
    forward.handle(&request, io, deps.resolver, &deps.telemetry.metrics, trace_id, slot, deps.idle_timeout, deps.egress_policy) catch |e| {
        log.warn(trace_id, slot, "forward error err={t}", .{e});
        deps.telemetry.metrics.incr(.relay_errors);
    };
}
