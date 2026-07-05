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
    /// Absolute cap on receiving the request head, on top of `idle_timeout`.
    /// `.none` disables it. See `Config.head_timeout_ms`.
    head_timeout: Io.Timeout,
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
    defer log.debug(trace_id, slot, "connection closed", .{});

    log.debug(trace_id, slot, "accepted from={f}", .{stream.socket.address});

    var in_buf: [head_buffer_size]u8 = undefined;
    var out_buf: [relay_buffer_size]u8 = undefined;
    var stream_reader: TimeoutReader = .init(stream, io, &in_buf, deps.idle_timeout);
    var stream_writer = stream.writer(io, &out_buf);
    var server: http.Server = .init(&stream_reader.interface, &stream_writer.interface);

    deps.pool.setState(slot, .parsing_head);
    stream_reader.armHeadDeadline(deps.head_timeout);
    const head_buffer = server.reader.receiveHead() catch |e| {
        const unwrapped = timeout_reader.unwrap(&stream_reader.interface, e);
        log.warn(trace_id, slot, "receive head failed err={t}", .{unwrapped});
        // Only an oversized head is cleanly classifiable here (the client is
        // still speaking HTTP, just over budget); a truncated head, a closed
        // keep-alive connection, or a raw read failure carry no framing we
        // could safely answer, so those stay a silent close.
        if (unwrapped == error.HttpHeadersOversize) {
            writeMinimalResponse(&stream_writer.interface, "431 Request Header Fields Too Large");
        }
        return;
    };
    var request: http.Server.Request = .{
        .server = &server,
        .head_buffer = head_buffer,
        .head = http.Server.Request.Head.parse(head_buffer) catch |e| {
            log.warn(trace_id, slot, "receive head failed err={t}", .{e});
            writeMinimalResponse(&stream_writer.interface, if (e == error.UnknownHttpMethod)
                "501 Not Implemented"
            else
                "400 Bad Request");
            return;
        },
    };
    stream_reader.clearHeadDeadline();

    log.debug(trace_id, slot, "{t} {s}", .{ request.head.method, request.head.target });

    if (request.head.method == .CONNECT) {
        deps.pool.setState(slot, .tunneling);
        tunnel.handle(&request, stream, io, deps.resolver, trace_id, slot, deps.idle_timeout, deps.egress_policy) catch |e| {
            log.warn(trace_id, slot, "tunnel error err={t}", .{e});
        };
        return;
    }

    deps.pool.setState(slot, .relaying_http);
    forward.handle(&request, io, deps.resolver, trace_id, slot, deps.idle_timeout, deps.egress_policy) catch |e| {
        log.warn(trace_id, slot, "forward error err={t}", .{e});
    };
}

/// Writes a fixed, bodyless response for a request head that failed to parse
/// (so `request.respond` isn't available). Best-effort: if the write itself
/// fails, the caller returns right after and `handle`'s defer closes the
/// socket anyway.
fn writeMinimalResponse(w: *std.Io.Writer, status_line: []const u8) void {
    w.print("HTTP/1.1 {s}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", .{status_line}) catch {};
    w.flush() catch {};
}
