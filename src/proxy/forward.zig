const std = @import("std");
const Io = std.Io;
const http = std.http;
const net = Io.net;

const target_mod = @import("target.zig");
const relay = @import("relay.zig");
const Resolver = @import("resolver.zig").Resolver;
const log = @import("log.zig");
const TraceId = @import("../telemetry/span.zig").TraceId;
const Metrics = @import("../telemetry/metrics.zig").Metrics;

/// RFC 7230 6.1 hop-by-hop headers: meaningful only for one transport leg,
/// never forwarded to the next one. Everything else (including
/// content-length/transfer-encoding, which we mirror rather than strip)
/// passes through unchanged.
const hop_by_hop_headers = [_][]const u8{
    "connection",
    "proxy-connection",
    "keep-alive",
    "te",
    "trailers",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
};

fn isHopByHop(name: []const u8) bool {
    for (hop_by_hop_headers) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

fn findHeaderValue(request: *http.Server.Request, name: []const u8) ?[]const u8 {
    var it = request.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

fn writeFilteredHeaders(w: *Io.Writer, head_buffer: []const u8) !void {
    var it = http.HeaderIterator.init(head_buffer);
    while (it.next()) |h| {
        if (isHopByHop(h.name)) continue;
        try w.print("{s}: {s}\r\n", .{ h.name, h.value });
    }
}

/// Handles one plain (non-CONNECT) HTTP request: resolves and connects to
/// the target, forwards the request line/headers/body, then mirrors the
/// upstream response back to the client. Single-request-per-connection: the
/// client connection is always closed afterward (no keep-alive pooling in
/// this pass), which keeps framing bookkeeping simple and correct.
pub fn handle(
    request: *http.Server.Request,
    io: Io,
    resolver: Resolver,
    metrics: *Metrics,
    trace_id: TraceId,
    slot: u32,
) !void {
    const host_header = findHeaderValue(request, "host");
    const parsed = target_mod.parseHttpTarget(request.head.target, host_header) catch |e| {
        log.warn(trace_id, slot, "bad http target={s} err={t}", .{ request.head.target, e });
        try request.respond("Bad Request", .{ .status = .bad_request, .keep_alive = false });
        return;
    };

    const host_name = net.HostName.init(parsed.target.host) catch {
        log.warn(trace_id, slot, "invalid host={s}", .{parsed.target.host});
        try request.respond("Bad Request", .{ .status = .bad_request, .keep_alive = false });
        return;
    };

    log.debug(trace_id, slot, "http {s} {s}:{d}{s}", .{
        @tagName(request.head.method), parsed.target.host, parsed.target.port, parsed.path,
    });

    // `.timeout` is intentionally left `.none`: passing any other value hits
    // `@panic("TODO implement netConnectIpPosix with timeout")` in this Zig
    // 0.16.0 stdlib build (Io/Threaded.zig), and there is no `Select`-style
    // primitive yet to build a non-panicking race against `Io.sleep`
    // ourselves without adding latency to the common case.
    const upstream = resolver.connect(host_name, io, parsed.target.port, .{
        .mode = .stream,
        .protocol = .tcp,
    }) catch |e| {
        metrics.incr(.upstream_connect_errors);
        log.warn(trace_id, slot, "upstream connect failed host={s} port={d} err={t}", .{
            parsed.target.host, parsed.target.port, e,
        });
        try request.respond("Bad Gateway", .{ .status = .bad_gateway, .keep_alive = false });
        return;
    };
    defer upstream.close(io);

    var upstream_read_buf: [16 * 1024]u8 = undefined;
    var upstream_write_buf: [4 * 1024]u8 = undefined;
    var upstream_reader = upstream.reader(io, &upstream_read_buf);
    var upstream_writer = upstream.writer(io, &upstream_write_buf);

    try forwardRequest(request, &upstream_writer.interface, parsed.path);
    try relayResponse(request, &upstream_reader.interface);
}

fn forwardRequest(request: *http.Server.Request, w: *Io.Writer, path: []const u8) !void {
    try w.print("{s} {s} HTTP/1.1\r\n", .{ @tagName(request.head.method), path });
    try writeFilteredHeaders(w, request.head_buffer);
    try w.writeAll("Connection: close\r\n\r\n");
    try w.flush();

    const client_body = request.server.reader.in;
    if (request.head.transfer_encoding == .chunked) {
        try relay.copyChunkedVerbatim(client_body, w);
    } else if (request.head.content_length) |len| {
        if (len > 0) try relay.copyExact(client_body, w, len);
    }
    try w.flush();
}

fn relayResponse(request: *http.Server.Request, upstream_in: *Io.Reader) !void {
    var upstream_head: http.Reader = .{
        .in = upstream_in,
        .interface = undefined,
        .state = .ready,
        .max_head_len = upstream_in.buffer.len,
    };
    const head_bytes = try upstream_head.receiveHead();
    const resp_head = try http.Client.Response.Head.parse(head_bytes);

    const client_out = request.server.out;
    try client_out.print("{t} {d} {s}\r\n", .{ resp_head.version, @intFromEnum(resp_head.status), resp_head.reason });
    try writeFilteredHeaders(client_out, head_bytes);
    try client_out.writeAll("Connection: close\r\n\r\n");

    if (resp_head.transfer_encoding == .chunked) {
        try relay.copyChunkedVerbatim(upstream_in, client_out);
    } else if (resp_head.content_length) |len| {
        if (len > 0) try relay.copyExact(upstream_in, client_out, len);
    } else {
        _ = try relay.copyUntilEof(upstream_in, client_out);
    }
    try client_out.flush();
}

test "isHopByHop matches RFC 7230 hop-by-hop headers case-insensitively" {
    try std.testing.expect(isHopByHop("Connection"));
    try std.testing.expect(isHopByHop("TE"));
    try std.testing.expect(!isHopByHop("Content-Type"));
    try std.testing.expect(!isHopByHop("Host"));
    // transfer-encoding describes the body's actual wire framing, which we
    // relay byte-for-byte (see copyChunkedVerbatim) rather than decode and
    // re-encode — so unlike true hop-by-hop headers, it must be forwarded,
    // not stripped, or the next hop can't parse the body it receives.
    try std.testing.expect(!isHopByHop("TRANSFER-ENCODING"));
}

test "writeFilteredHeaders strips hop-by-hop headers and forwards the rest" {
    const head = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nX-Custom: yes\r\n\r\n";

    var out_buf: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);

    try writeFilteredHeaders(&writer, head);
    const written = writer.buffered();

    try std.testing.expect(std.mem.indexOf(u8, written, "Host: example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "X-Custom: yes\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Connection") == null);
}
