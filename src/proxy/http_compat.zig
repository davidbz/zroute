//! Named accessors for the parts of `std.http.Server`'s internal layout that
//! forward.zig and tunnel.zig depend on but that aren't public API. Verified
//! against Zig 0.16.0 (lib/std/http.zig, lib/std/http/Server.zig). If this
//! file fails to compile after a toolchain bump, that's std.http's private
//! layout having changed — reconcile the accessors below rather than
//! chasing call sites across the proxy.

const std = @import("std");
const http = std.http;
const Io = std.Io;

/// The raw connection reader beneath `request`, positioned right after the
/// request head. forward.zig and tunnel.zig read from it directly (instead
/// of through `request.server.reader.bodyReader`) to do their own
/// content-length/chunked/splice handling.
pub fn clientBodyReader(request: *http.Server.Request) *Io.Reader {
    return request.server.reader.in;
}

/// The raw connection writer beneath `request`, for writing bytes (a
/// forwarded response, a tunnel splice, ...) straight to the client without
/// going through `request.respond`/`respondStreaming`.
pub fn clientResponseWriter(request: *http.Server.Request) *Io.Writer {
    return request.server.out;
}

/// Parses a standalone upstream HTTP response head out of `in`, without a
/// backing `http.Server`/connection on the upstream side.
///
/// Constructs an `http.Reader` the same way `http.Server.init` does, using
/// `in`'s buffer capacity as the head-size limit. `http.Reader.receiveHead`
/// only ever touches `.in`, `.max_head_len`, `.state`, and `.trailers` — never
/// `.interface` (that's populated lazily by `bodyReader`, which is never
/// called here since forward.zig relays the body itself). `.interface` is
/// still seeded with `std.Io.Reader.failing` instead of `undefined`: if a
/// future stdlib version starts reading it before `bodyReader` runs, that
/// turns into a clean `error.ReadFailed` instead of undefined behavior.
pub fn upstreamResponseHead(in: *Io.Reader) http.Reader.HeadError![]const u8 {
    var reader: http.Reader = .{
        .in = in,
        .interface = Io.Reader.failing,
        .state = .ready,
        .max_head_len = in.buffer.len,
    };
    return reader.receiveHead();
}
