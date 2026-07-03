const std = @import("std");
const Io = std.Io;
const http = std.http;

/// Copies exactly `n` bytes verbatim. Used for Content-Length-framed bodies.
pub fn copyExact(r: *Io.Reader, w: *Io.Writer, n: u64) Io.Reader.StreamError!void {
    return r.streamExact64(w, n);
}

/// Copies until the reader reaches EOF (EOF is success, not an error). Used
/// for CONNECT tunnel splicing and framing-by-close HTTP bodies.
///
/// Flushes `w` after every read instead of using `Io.Reader.streamRemaining`
/// directly, which only drains `w` once its buffer fills. On a live duplex
/// socket (e.g. a TLS handshake inside a CONNECT tunnel) that means small
/// reads — a ClientHello, say — sit in `w`'s buffer indefinitely while the
/// peer blocks waiting for exactly those bytes: a deadlock, not a slow path.
pub fn copyUntilEof(r: *Io.Reader, w: *Io.Writer) Io.Reader.StreamRemainingError!usize {
    var total: usize = 0;
    while (true) {
        total += r.stream(w, .unlimited) catch |err| switch (err) {
            error.EndOfStream => {
                try w.flush();
                return total;
            },
            else => |e| return e,
        };
        try w.flush();
    }
}

pub const ChunkedError = error{InvalidChunkedEncoding};

/// Copies a `transfer-encoding: chunked` body byte-for-byte — chunk-size
/// lines, chunk data, and any trailers — without decoding or re-encoding.
/// The proxy only needs to find where the body ends, not see its content.
pub fn copyChunkedVerbatim(r: *Io.Reader, w: *Io.Writer) !usize {
    var total: usize = 0;
    while (true) {
        const chunk_len = try feedChunkHead(r, w);
        if (chunk_len == 0) {
            try copyTrailers(r, w);
            return total;
        }
        try r.streamExact64(w, chunk_len);
        try feedChunkSuffix(r, w);
        total += chunk_len;
    }
}

/// Reads and echoes bytes one at a time until the chunk-size line is fully
/// consumed, returning the parsed chunk length.
fn feedChunkHead(r: *Io.Reader, w: *Io.Writer) !u64 {
    var parser: http.ChunkParser = .init;
    while (true) {
        const byte = try r.takeByte();
        try w.writeByte(byte);
        _ = parser.feed(&.{byte});
        if (parser.state == .invalid) return error.InvalidChunkedEncoding;
        if (parser.state == .data) return parser.chunk_len;
    }
}

/// Consumes and echoes the CRLF that follows a chunk's data.
fn feedChunkSuffix(r: *Io.Reader, w: *Io.Writer) !void {
    var parser: http.ChunkParser = .{ .state = .data_suffix, .chunk_len = 0 };
    while (true) {
        const byte = try r.takeByte();
        try w.writeByte(byte);
        _ = parser.feed(&.{byte});
        if (parser.state == .invalid) return error.InvalidChunkedEncoding;
        if (parser.state == .head_size) return;
    }
}

/// Echoes the trailer section (zero or more header lines) up to and
/// including the terminating blank line.
fn copyTrailers(r: *Io.Reader, w: *Io.Writer) !void {
    while (true) {
        const line = try r.takeDelimiterInclusive('\n');
        try w.writeAll(line);
        if (std.mem.eql(u8, line, "\r\n") or std.mem.eql(u8, line, "\n")) return;
    }
}

test "copyChunkedVerbatim passes through chunk framing byte-for-byte" {
    const input = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    var reader: Io.Reader = .fixed(input);

    var out_buf: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);

    _ = try copyChunkedVerbatim(&reader, &writer);
    try std.testing.expectEqualStrings(input, writer.buffered());
}

test "copyChunkedVerbatim passes through trailers" {
    const input = "3\r\nfoo\r\n0\r\nX-Trailer: bar\r\n\r\n";
    var reader: Io.Reader = .fixed(input);

    var out_buf: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);

    _ = try copyChunkedVerbatim(&reader, &writer);
    try std.testing.expectEqualStrings(input, writer.buffered());
}

test "copyChunkedVerbatim rejects malformed chunk size" {
    const input = "5\rX\r\n"; // '\r' must be followed by '\n', not 'X'
    var reader: Io.Reader = .fixed(input);

    var out_buf: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);

    try std.testing.expectError(error.InvalidChunkedEncoding, copyChunkedVerbatim(&reader, &writer));
}

test "copyExact copies precisely n bytes" {
    const input = "hello world";
    var reader: Io.Reader = .fixed(input);

    var out_buf: [16]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);

    try copyExact(&reader, &writer, 5);
    try std.testing.expectEqualStrings("hello", writer.buffered());
}

test "copyUntilEof copies remaining bytes and treats EOF as success" {
    const input = "the rest of the stream";
    var reader: Io.Reader = .fixed(input);

    var out_buf: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&out_buf);

    const n = try copyUntilEof(&reader, &writer);
    try std.testing.expectEqual(input.len, n);
    try std.testing.expectEqualStrings(input, writer.buffered());
}
