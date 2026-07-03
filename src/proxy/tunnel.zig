const std = @import("std");
const Io = std.Io;
const http = std.http;
const net = Io.net;

const target_mod = @import("target.zig");
const relay = @import("relay.zig");
const Resolver = @import("resolver.zig").Resolver;
const egress = @import("egress.zig");
const log = @import("log.zig");
const http_compat = @import("http_compat.zig");
const timeout_reader = @import("timeout_reader.zig");
const TimeoutReader = timeout_reader.TimeoutReader;
const TraceId = @import("../telemetry/span.zig").TraceId;
const Metrics = @import("../telemetry/metrics.zig").Metrics;

/// Handles a CONNECT request: resolves and connects to the target, replies
/// with a tunnel-established response, then splices raw bytes in both
/// directions until either side closes. No TLS termination — the proxy never
/// sees plaintext past this point.
pub fn handle(
    request: *http.Server.Request,
    client_stream: net.Stream,
    io: Io,
    resolver: Resolver,
    metrics: *Metrics,
    trace_id: TraceId,
    slot: u32,
    idle_timeout: Io.Timeout,
    egress_policy: egress.Policy,
) !void {
    const target = target_mod.parseConnectTarget(request.head.target) catch |e| {
        log.warn(trace_id, slot, "bad connect target={s} err={t}", .{ request.head.target, e });
        try request.respond("Bad Request", .{ .status = .bad_request, .keep_alive = false });
        return;
    };

    if (!egress_policy.allowsConnectPort(target.port)) {
        try egress.denyEgress(request, metrics, trace_id, slot, "connect port not allowlisted", target.host, target.port);
        return;
    }

    const host_name = net.HostName.init(target.host) catch {
        log.warn(trace_id, slot, "invalid host={s}", .{target.host});
        try request.respond("Bad Request", .{ .status = .bad_request, .keep_alive = false });
        return;
    };

    log.debug(trace_id, slot, "connect {s}:{d}", .{ target.host, target.port });

    // `.timeout` is intentionally left `.none` — see the matching comment in
    // forward.zig for why (a stdlib panic, not an oversight).
    const upstream = resolver.connect(host_name, io, target.port, .{
        .mode = .stream,
        .protocol = .tcp,
    }, egress_policy) catch |e| {
        if (e == error.EgressDenied) {
            try egress.denyEgress(request, metrics, trace_id, slot, "egress denied", target.host, target.port);
            return;
        }
        metrics.incr(.upstream_connect_errors);
        log.warn(trace_id, slot, "upstream connect failed host={s} port={d} err={t}", .{
            target.host, target.port, e,
        });
        try request.respond("Bad Gateway", .{ .status = .bad_gateway, .keep_alive = false });
        return;
    };
    defer upstream.close(io);

    try request.respond("", .{
        .status = .ok,
        .reason = "Connection Established",
        .transfer_encoding = .none,
        .keep_alive = false,
    });

    var upstream_read_buf: [64 * 1024]u8 = undefined;
    var upstream_write_buf: [64 * 1024]u8 = undefined;
    var upstream_reader: TimeoutReader = .init(upstream, io, &upstream_read_buf, idle_timeout);
    var upstream_writer = upstream.writer(io, &upstream_write_buf);

    splice(
        http_compat.clientBodyReader(request),
        http_compat.clientResponseWriter(request),
        client_stream,
        &upstream_reader.interface,
        &upstream_writer.interface,
        upstream,
        io,
        metrics,
        trace_id,
        slot,
    );
}

/// Pumps `client -> upstream` concurrently while pumping `upstream -> client`
/// on the calling task, so both directions make progress at once. Whichever
/// side reaches EOF/error first shuts down its peer stream (rather than
/// closing it outright — `shutdown` is safe to call while another task is
/// blocked in a read on the same socket, unlike `close`), which unblocks the
/// other direction promptly instead of leaving it stuck until its own side
/// happens to close.
fn splice(
    client_in: *Io.Reader,
    client_out: *Io.Writer,
    client_stream: net.Stream,
    upstream_in: *Io.Reader,
    upstream_out: *Io.Writer,
    upstream_stream: net.Stream,
    io: Io,
    metrics: *Metrics,
    trace_id: TraceId,
    slot: u32,
) void {
    // If `Io.concurrent` can't spawn the client->upstream pump, running both
    // pumps back-to-back on the calling task is NOT a valid fallback: a
    // duplex protocol (every TLS handshake, since CONNECT never terminates
    // TLS here) needs both directions pumping at once. The first pump would
    // block reading from the client until the client reaches EOF, but a live
    // client won't send EOF until it has received the server's half of the
    // handshake — which is stuck in the second pump that hasn't started yet.
    // That's a deadlock, not a degraded mode, so tear the tunnel down instead.
    var future = Io.concurrent(io, pump, .{ client_in, upstream_out, upstream_stream, io, metrics, trace_id, slot, "client->upstream" }) catch |e| {
        log.err(trace_id, slot, "tunnel concurrent spawn failed, aborting tunnel err={t}", .{e});
        metrics.incr(.tunnel_concurrency_errors);
        client_stream.shutdown(io, .both) catch {};
        upstream_stream.shutdown(io, .both) catch {};
        return;
    };
    pump(upstream_in, client_out, client_stream, io, metrics, trace_id, slot, "upstream->client");
    future.await(io);
}

/// Copies `r` into `w` until EOF or error, then shuts down `peer` so whatever
/// is blocked reading/writing on the other end of the tunnel is released.
/// A non-EOF failure (most commonly an idle timeout — see `TimeoutReader`) is
/// a normal way for a tunnel to end, not a bug, but previously vanished
/// silently here; it's now logged and counted like every other relay error.
fn pump(r: *Io.Reader, w: *Io.Writer, peer: net.Stream, io: Io, metrics: *Metrics, trace_id: TraceId, slot: u32, direction: []const u8) void {
    if (relay.copyUntilEof(r, w)) |_| {} else |e| {
        log.warn(trace_id, slot, "tunnel relay error dir={s} err={t}", .{ direction, timeout_reader.unwrap(r, e) });
        metrics.incr(.relay_errors);
    }
    peer.shutdown(io, .both) catch {};
}
