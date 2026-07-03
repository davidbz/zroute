const std = @import("std");
const Io = std.Io;
const net = Io.net;

/// Wraps a `net.Stream` so every read is bounded by an idle deadline instead
/// of blocking forever. Mirrors `net.Stream.Reader`'s vtable shape exactly,
/// swapping the underlying unbounded `netRead` for `Socket.receiveTimeout`
/// (the same bounded-receive primitive the custom DNS resolver already uses
/// against UDP sockets) — `recvmsg` is generic over socket type, so it works
/// against a connected TCP socket the same way.
///
/// `idle_timeout` is a *duration*, not a fixed deadline: it is measured fresh
/// from each call, so a steady trickle of bytes keeps the connection alive
/// indefinitely while a silent peer is torn down within one window. This is
/// the deliberate opposite of the resolver's fixed absolute deadline, which
/// bounds one query's total retry budget rather than gaps between bytes.
pub const TimeoutReader = struct {
    io: Io,
    stream: net.Stream,
    idle_timeout: Io.Timeout,
    interface: Io.Reader,
    err: ?Error = null,

    pub const Error = net.Socket.ReceiveTimeoutError || error{IdleTimeout};

    pub fn init(stream: net.Stream, io: Io, buffer: []u8, idle_timeout: Io.Timeout) TimeoutReader {
        return .{
            .io = io,
            .stream = stream,
            .idle_timeout = idle_timeout,
            .interface = .{
                .vtable = &.{ .stream = streamImpl, .readVec = readVec },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn streamImpl(io_r: *Io.Reader, io_w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try io_w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(io_r, &data);
        io_w.advance(n);
        return n;
    }

    // Matches `net.Stream.Reader`'s own sizing: `writableVector` can write one
    // slot per `data` entry plus one more for the reader's internal scratch
    // buffer, so a single-element `iovecs_buffer` panics (index out of
    // bounds) as soon as the internal buffer slot is appended.
    const max_iovecs_len = 8;

    fn readVec(io_r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const r: *TimeoutReader = @alignCast(@fieldParentPtr("interface", io_r));

        var iovecs_buffer: [max_iovecs_len][]u8 = undefined;
        const dest_n, const data_size = try io_r.writableVector(&iovecs_buffer, data);
        const dest = iovecs_buffer[0..dest_n];
        std.debug.assert(dest[0].len > 0);

        const msg = r.stream.socket.receiveTimeout(r.io, dest[0], r.idle_timeout) catch |err| {
            r.err = switch (err) {
                error.Timeout => error.IdleTimeout,
                else => |e| e,
            };
            return error.ReadFailed;
        };

        // `dest[0]` may be our own internal buffer rather than caller data
        // (e.g. `fillMore`'s empty placeholder) — bytes landing there must
        // advance `io_r.end`, or they're invisible to `buffered()` forever.
        const n = msg.data.len;
        if (n == 0) return error.EndOfStream;
        if (n > data_size) {
            io_r.end += n - data_size;
            return data_size;
        }
        return n;
    }
};

/// Recovers the concrete error hiding behind the generic `error.ReadFailed`
/// sentinel that `Io.Reader`'s fixed vtable error set forces `TimeoutReader`
/// to return, given the `*Io.Reader` known (by construction at the call
/// site) to be backed by a `TimeoutReader`. Errors other than `ReadFailed`
/// (e.g. a write-side failure) pass through unchanged.
pub fn unwrap(r: *Io.Reader, err: anyerror) anyerror {
    if (err != error.ReadFailed) return err;
    const reader: *TimeoutReader = @alignCast(@fieldParentPtr("interface", r));
    return reader.err orelse err;
}

/// `net.Socket.createPair` shells out to the POSIX `socketpair()` syscall,
/// which on Linux only supports `AF_UNIX` — the default `.ip4` family always
/// fails with `EOPNOTSUPP`. A real loopback listen/connect/accept gives two
/// genuinely connected TCP sockets without depending on that.
fn connectedLoopbackPair(io: Io) !struct { server: net.Server, client: net.Stream, accepted: net.Stream } {
    const bind_addr = try net.IpAddress.parse("127.0.0.1", 0);
    var server = try net.IpAddress.listen(&bind_addr, io, .{ .reuse_address = true });
    errdefer server.deinit(io);

    const client = try net.IpAddress.connect(&server.socket.address, io, .{ .mode = .stream, .protocol = .tcp });
    errdefer client.close(io);

    const accepted = try server.accept(io);
    return .{ .server = server, .client = client, .accepted = accepted };
}

test "readVec called via fillMore advances end so a fully-buffered request is visible without a second read" {
    // Regression test: `fillMore` (which `http.Server.receiveHead` uses)
    // passes an empty external `data` slice, so the whole read lands in
    // TimeoutReader's own internal buffer. `readVec` must advance
    // `io_r.end` by that spillover, or the bytes stay physically buffered
    // but invisible to `buffered()` — every request would then look
    // incomplete forever and stall until idle_timeout, no matter how much
    // data the peer actually sent.
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try connectedLoopbackPair(io);
    defer pair.server.deinit(io);
    defer pair.client.close(io);
    defer pair.accepted.close(io);

    var client_write_buf: [64]u8 = undefined;
    var client_writer = pair.client.writer(io, &client_write_buf);
    try client_writer.interface.writeAll("hello world");
    try client_writer.interface.flush();

    var buf: [64]u8 = undefined;
    var reader: TimeoutReader = .init(pair.accepted, io, &buf, .{
        .duration = .{ .raw = .fromSeconds(5), .clock = .awake },
    });

    try reader.interface.fillMore();
    try std.testing.expectEqualStrings("hello world", reader.interface.buffered());
}

test "readVec returns IdleTimeout when the peer sends nothing within the deadline" {
    const gpa = std.testing.allocator;
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var pair = try connectedLoopbackPair(io);
    defer pair.server.deinit(io);
    defer pair.client.close(io);
    defer pair.accepted.close(io);

    var buf: [64]u8 = undefined;
    var reader: TimeoutReader = .init(pair.accepted, io, &buf, .{
        .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake },
    });

    var sink_buf: [64]u8 = undefined;
    var sink: Io.Writer = .fixed(&sink_buf);

    const relay = @import("relay.zig");
    try std.testing.expectError(error.ReadFailed, relay.copyUntilEof(&reader.interface, &sink));
    try std.testing.expectEqual(error.IdleTimeout, reader.err.?);
}

test "unwrap surfaces IdleTimeout and passes through unrelated errors" {
    // `unwrap` only reads `TimeoutReader.err` and `err != error.ReadFailed`
    // passthrough — no live socket or Io backend is ever touched, so none is
    // needed here.
    var buf: [64]u8 = undefined;
    var reader: TimeoutReader = .init(undefined, undefined, &buf, .none);
    reader.err = error.IdleTimeout;

    try std.testing.expectEqual(error.IdleTimeout, unwrap(&reader.interface, error.ReadFailed));
    try std.testing.expectEqual(error.OutOfMemory, unwrap(&reader.interface, error.OutOfMemory));
}
