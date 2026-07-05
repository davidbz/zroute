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

/// RFC 7230 6.1 hop-by-hop headers: meaningful only for one transport leg,
/// never forwarded to the next one. Everything else passes through
/// unchanged, except Content-Length, which writeFilteredHeaders drops
/// whenever Transfer-Encoding: chunked is also present (see forwardRequest /
/// relayResponse) to avoid CL.TE / TE.CL request-smuggling desyncs.
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

/// `strip_content_length` must be set whenever the message also carries
/// Transfer-Encoding: chunked. RFC 7230 §3.3.3 requires the chunked framing
/// to win, but an upstream that resolves CL/TE conflicts differently than we
/// do could desync on a smuggled request/response hidden past the boundary
/// implied by the other header — so the ambiguous header is dropped instead
/// of relayed.
fn writeFilteredHeaders(w: *Io.Writer, head_buffer: []const u8, strip_content_length: bool) !void {
    var it = http.HeaderIterator.init(head_buffer);
    while (it.next()) |h| {
        if (isHopByHop(h.name)) continue;
        if (strip_content_length and std.ascii.eqlIgnoreCase(h.name, "content-length")) continue;
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
    trace_id: TraceId,
    slot: u32,
    idle_timeout: Io.Timeout,
    egress_policy: egress.Policy,
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
    }, egress_policy) catch |e| {
        if (e == error.EgressDenied) {
            try egress.denyEgress(request, trace_id, slot, "egress denied", parsed.target.host, parsed.target.port);
            return;
        }
        log.warn(trace_id, slot, "upstream connect failed host={s} port={d} err={t}", .{
            parsed.target.host, parsed.target.port, e,
        });
        try request.respond("Bad Gateway", .{ .status = .bad_gateway, .keep_alive = false });
        return;
    };
    defer upstream.close(io);
    log.debug(trace_id, slot, "upstream connected host={s} port={d}", .{ parsed.target.host, parsed.target.port });

    var upstream_read_buf: [16 * 1024]u8 = undefined;
    var upstream_write_buf: [4 * 1024]u8 = undefined;
    var upstream_reader: TimeoutReader = .init(upstream, io, &upstream_read_buf, idle_timeout);
    var upstream_writer = upstream.writer(io, &upstream_write_buf);

    try forwardRequest(request, &upstream_writer.interface, parsed.path, trace_id, slot);
    try relayResponse(request, &upstream_reader.interface, trace_id, slot);
}

fn forwardRequest(request: *http.Server.Request, w: *Io.Writer, path: []const u8, trace_id: TraceId, slot: u32) !void {
    try w.print("{s} {s} HTTP/1.1\r\n", .{ @tagName(request.head.method), path });
    try writeFilteredHeaders(w, request.head_buffer, request.head.transfer_encoding == .chunked);
    try w.writeAll("Connection: close\r\n\r\n");
    try w.flush();

    const client_body = http_compat.clientBodyReader(request);
    var bytes: usize = 0;
    if (request.head.transfer_encoding == .chunked) {
        bytes = relay.copyChunkedVerbatim(client_body, w) catch |e| return timeout_reader.unwrap(client_body, e);
    } else if (request.head.content_length) |len| {
        if (len > 0) {
            relay.copyExact(client_body, w, len) catch |e| return timeout_reader.unwrap(client_body, e);
            bytes = len;
        }
    }
    try w.flush();
    log.debug(trace_id, slot, "relay dir=client->upstream bytes={d}", .{bytes});
}

fn relayResponse(request: *http.Server.Request, upstream_in: *Io.Reader, trace_id: TraceId, slot: u32) !void {
    const head_bytes = http_compat.upstreamResponseHead(upstream_in) catch |e| {
        const unwrapped = timeout_reader.unwrap(upstream_in, e);
        // An upstream response head that doesn't fit in `upstream_read_buf`
        // would otherwise bubble up as a bare error and leave the client with
        // nothing but an abrupt close; respond with a proper 502 instead.
        if (unwrapped == error.HttpHeadersOversize) {
            log.warn(trace_id, slot, "upstream response head exceeds {d} bytes", .{upstream_in.buffer.len});
            try request.respond("Bad Gateway", .{ .status = .bad_gateway, .keep_alive = false });
            return;
        }
        return unwrapped;
    };
    const resp_head = http.Client.Response.Head.parse(head_bytes) catch |e| {
        // Malformed upstream response head (e.g. conflicting duplicate
        // Content-Length, non-final chunked, duplicate Transfer-Encoding).
        // Nothing has been written to the client yet, so reject cleanly
        // instead of relaying an ambiguous framing downstream.
        log.warn(trace_id, slot, "malformed upstream response head err={t}", .{e});
        try request.respond("Bad Gateway", .{ .status = .bad_gateway, .keep_alive = false });
        return;
    };

    log.debug(trace_id, slot, "upstream response status={d}", .{@intFromEnum(resp_head.status)});

    const client_out = http_compat.clientResponseWriter(request);
    try client_out.print("{t} {d} {s}\r\n", .{ resp_head.version, @intFromEnum(resp_head.status), resp_head.reason });
    try writeFilteredHeaders(client_out, head_bytes, resp_head.transfer_encoding == .chunked);
    try client_out.writeAll("Connection: close\r\n\r\n");

    var bytes: usize = 0;
    if (resp_head.transfer_encoding == .chunked) {
        bytes = relay.copyChunkedVerbatim(upstream_in, client_out) catch |e| return timeout_reader.unwrap(upstream_in, e);
    } else if (resp_head.content_length) |len| {
        if (len > 0) {
            relay.copyExact(upstream_in, client_out, len) catch |e| return timeout_reader.unwrap(upstream_in, e);
            bytes = len;
        }
    } else {
        bytes = relay.copyUntilEof(upstream_in, client_out) catch |e| return timeout_reader.unwrap(upstream_in, e);
    }
    try client_out.flush();
    log.debug(trace_id, slot, "relay dir=upstream->client bytes={d}", .{bytes});
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
    const head = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\nContent-Length: 5\r\nX-Custom: yes\r\n\r\n";

    var out_buf: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);

    try writeFilteredHeaders(&writer, head, false);
    const written = writer.buffered();

    try std.testing.expect(std.mem.indexOf(u8, written, "Host: example.com\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "X-Custom: yes\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Content-Length: 5\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Connection") == null);
}

test "writeFilteredHeaders drops Content-Length when asked to strip it" {
    const head = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";

    var out_buf: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);

    try writeFilteredHeaders(&writer, head, true);
    const written = writer.buffered();

    try std.testing.expect(std.mem.indexOf(u8, written, "Content-Length") == null);
    try std.testing.expect(std.mem.indexOf(u8, written, "Transfer-Encoding: chunked\r\n") != null);
}

// Empirical check for the smuggling-relevant question: does std.http.Server's
// head parser (the same one `Server.receiveHead` uses) reject a request that
// carries both Content-Length and Transfer-Encoding? As of Zig 0.16.0, no —
// the two fields are populated independently with no cross-check, so a
// CL.TE-ambiguous request head parses cleanly. That is exactly the case
// writeFilteredHeaders's strip_content_length guards against above: we must
// not blindly relay both headers to upstream.
test "std.http.Server.Request.Head.parse does not reject conflicting CL+TE" {
    const head = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n";
    const parsed = try http.Server.Request.Head.parse(head);
    try std.testing.expectEqual(@as(?u64, 100), parsed.content_length);
    try std.testing.expectEqual(http.TransferEncoding.chunked, parsed.transfer_encoding);
}

test "forwardRequest strips Content-Length from the upstream head when Transfer-Encoding is chunked" {
    const client_head = "POST /x HTTP/1.1\r\nHost: example.com\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";

    var client_in: Io.Reader = .fixed(client_head);
    var client_out_buf: [256]u8 = undefined;
    var client_out: Io.Writer = .fixed(&client_out_buf);
    var server: http.Server = .init(&client_in, &client_out);
    var request = try server.receiveHead();

    // Sanity: the client head we crafted is indeed the CL+TE-ambiguous case.
    try std.testing.expectEqual(@as(?u64, 100), request.head.content_length);
    try std.testing.expectEqual(http.TransferEncoding.chunked, request.head.transfer_encoding);

    var upstream_buf: [512]u8 = undefined;
    var upstream_out: Io.Writer = .fixed(&upstream_buf);
    try forwardRequest(&request, &upstream_out, "/x", 0, 0);

    const forwarded = upstream_out.buffered();
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Content-Length") == null);
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "Transfer-Encoding: chunked\r\n") != null);
    // Chunked body is still relayed verbatim.
    try std.testing.expect(std.mem.indexOf(u8, forwarded, "5\r\nhello\r\n0\r\n\r\n") != null);
}

test "relayResponse rejects a malformed upstream response head with 502 instead of relaying it" {
    const client_head = "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var client_in: Io.Reader = .fixed(client_head);
    var client_out_buf: [256]u8 = undefined;
    var client_out: Io.Writer = .fixed(&client_out_buf);
    var server: http.Server = .init(&client_in, &client_out);
    var request = try server.receiveHead();

    const upstream_head = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Length: 5\r\n\r\nbody";
    var upstream_in: Io.Reader = .fixed(upstream_head);

    try relayResponse(&request, &upstream_in, 0, 0);

    const written = client_out.buffered();
    try std.testing.expect(std.mem.startsWith(u8, written, "HTTP/1.1 502 "));
}

test "relayResponse converts an oversized upstream response head into a 502 instead of a silent close" {
    const client_head = "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n";
    var client_in: Io.Reader = .fixed(client_head);
    var client_out_buf: [256]u8 = undefined;
    var client_out: Io.Writer = .fixed(&client_out_buf);
    var server: http.Server = .init(&client_in, &client_out);
    var request = try server.receiveHead();

    // A `.fixed` reader's buffer capacity equals its data length, so a head
    // with no terminating blank line anywhere in a 16 KiB buffer reproduces
    // exactly what a real upstream_read_buf (also 16 KiB, in forward.handle)
    // does when the actual response headers exceed it: receiveHead runs out
    // of buffer before finding the end of the head and returns
    // error.HttpHeadersOversize.
    var upstream_head_buf: [16 * 1024]u8 = undefined;
    @memset(&upstream_head_buf, 'a');
    const prefix = "HTTP/1.1 200 OK\r\nX-Pad: ";
    @memcpy(upstream_head_buf[0..prefix.len], prefix);
    var upstream_in: Io.Reader = .fixed(&upstream_head_buf);

    try relayResponse(&request, &upstream_in, 0, 0);

    const written = client_out.buffered();
    try std.testing.expect(std.mem.startsWith(u8, written, "HTTP/1.1 502 "));
}
