const std = @import("std");
const Io = std.Io;
const http = std.http;
const net = Io.net;

const target_mod = @import("target.zig");
const relay = @import("relay.zig");
const Resolver = @import("resolver.zig").Resolver;
const log = @import("log.zig");
const TraceId = @import("../telemetry/span.zig").TraceId;

/// Handles a CONNECT request: resolves and connects to the target, replies
/// with a tunnel-established response, then splices raw bytes in both
/// directions until either side closes. No TLS termination — the proxy never
/// sees plaintext past this point.
pub fn handle(
    request: *http.Server.Request,
    client_stream: net.Stream,
    io: Io,
    resolver: Resolver,
    trace_id: TraceId,
    slot: u32,
) !void {
    const target = target_mod.parseConnectTarget(request.head.target) catch |e| {
        log.warn(trace_id, slot, "bad connect target={s} err={t}", .{ request.head.target, e });
        try request.respond("Bad Request", .{ .status = .bad_request, .keep_alive = false });
        return;
    };

    const host_name = net.HostName.init(target.host) catch {
        log.warn(trace_id, slot, "invalid host={s}", .{target.host});
        try request.respond("Bad Request", .{ .status = .bad_request, .keep_alive = false });
        return;
    };

    log.info(trace_id, slot, "connect {s}:{d}", .{ target.host, target.port });

    // `.timeout` is intentionally left `.none` — see the matching comment in
    // forward.zig for why (a stdlib panic, not an oversight).
    const upstream = resolver.connect(host_name, io, target.port, .{
        .mode = .stream,
        .protocol = .tcp,
    }) catch |e| {
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
    var upstream_reader = upstream.reader(io, &upstream_read_buf);
    var upstream_writer = upstream.writer(io, &upstream_write_buf);

    splice(
        request.server.reader.in,
        request.server.out,
        client_stream,
        &upstream_reader.interface,
        &upstream_writer.interface,
        upstream,
        io,
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
) void {
    var future = Io.concurrent(io, pump, .{ client_in, upstream_out, upstream_stream, io }) catch {
        pump(client_in, upstream_out, upstream_stream, io);
        pump(upstream_in, client_out, client_stream, io);
        return;
    };
    pump(upstream_in, client_out, client_stream, io);
    future.await(io);
}

/// Copies `r` into `w` until EOF or error, then shuts down `peer` so whatever
/// is blocked reading/writing on the other end of the tunnel is released.
fn pump(r: *Io.Reader, w: *Io.Writer, peer: net.Stream, io: Io) void {
    _ = relay.copyUntilEof(r, w) catch {};
    peer.shutdown(io, .both) catch {};
}
