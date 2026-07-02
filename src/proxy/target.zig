const std = @import("std");

pub const Target = struct { host: []const u8, port: u16 };

pub const ParseError = error{ EmptyTarget, MissingPort, InvalidPort, MissingHost, UnsupportedScheme };

/// For CONNECT requests: target is "host:port" (RFC 7231 authority-form).
/// CONNECT always requires an explicit port; there is no default to fall
/// back on.
pub fn parseConnectTarget(target: []const u8) ParseError!Target {
    if (target.len == 0) return error.EmptyTarget;
    return parseAuthority(target, null);
}

/// For plain HTTP requests: target is either absolute-form
/// ("http://host[:port]/path", per RFC 7230 5.3.2 — what real proxy clients
/// send) or origin-form ("/path", requiring a Host header — tolerated for
/// leniency). Default port is 80, overridden only if the authority
/// specifies one. The returned path is the exact original bytes (no
/// percent-decoding round trip), so it's forwarded to upstream verbatim.
pub fn parseHttpTarget(target: []const u8, host_header: ?[]const u8) ParseError!struct { target: Target, path: []const u8 } {
    if (target.len == 0) return error.EmptyTarget;

    if (target[0] == '/') {
        const header = host_header orelse return error.MissingHost;
        return .{ .target = try parseAuthority(header, 80), .path = target };
    }

    const scheme_end = std.mem.indexOf(u8, target, "://") orelse return error.UnsupportedScheme;
    if (!std.mem.eql(u8, target[0..scheme_end], "http")) return error.UnsupportedScheme;

    const authority_start = scheme_end + 3;
    const path_start = std.mem.indexOfScalarPos(u8, target, authority_start, '/') orelse target.len;
    const authority = target[authority_start..path_start];
    const path = if (path_start == target.len) "/" else target[path_start..];

    return .{ .target = try parseAuthority(authority, 80), .path = path };
}

/// Parses "host:port" or, when `default_port` is non-null, bare "host"
/// (port omitted). Handles bracketed IPv6 literals ("[::1]:8080").
/// Default-first: assumes `default_port` unless the input overrides it.
fn parseAuthority(text: []const u8, default_port: ?u16) ParseError!Target {
    if (text.len == 0) return error.MissingHost;

    if (text[0] == '[') {
        const close = std.mem.indexOfScalar(u8, text, ']') orelse return error.MissingHost;
        if (close + 1 >= text.len or text[close + 1] != ':') {
            const port = default_port orelse return error.MissingPort;
            return .{ .host = text[1..close], .port = port };
        }
        const port = std.fmt.parseInt(u16, text[close + 2 ..], 10) catch return error.InvalidPort;
        return .{ .host = text[1..close], .port = port };
    }

    const colon = std.mem.lastIndexOfScalar(u8, text, ':') orelse {
        const port = default_port orelse return error.MissingPort;
        return .{ .host = text, .port = port };
    };
    if (colon == 0) return error.MissingHost;
    const port = std.fmt.parseInt(u16, text[colon + 1 ..], 10) catch return error.InvalidPort;
    return .{ .host = text[0..colon], .port = port };
}

test "parseConnectTarget requires explicit port" {
    try std.testing.expectError(error.MissingPort, parseConnectTarget("example.com"));
    const t = try parseConnectTarget("example.com:443");
    try std.testing.expectEqualStrings("example.com", t.host);
    try std.testing.expectEqual(@as(u16, 443), t.port);
}

test "parseConnectTarget handles bracketed IPv6" {
    const t = try parseConnectTarget("[::1]:8443");
    try std.testing.expectEqualStrings("::1", t.host);
    try std.testing.expectEqual(@as(u16, 8443), t.port);
}

test "parseHttpTarget absolute-form defaults to port 80" {
    const r = try parseHttpTarget("http://example.com/foo?bar=1", null);
    try std.testing.expectEqualStrings("example.com", r.target.host);
    try std.testing.expectEqual(@as(u16, 80), r.target.port);
    try std.testing.expectEqualStrings("/foo?bar=1", r.path);
}

test "parseHttpTarget absolute-form with explicit port and no path" {
    const r = try parseHttpTarget("http://example.com:8080", null);
    try std.testing.expectEqual(@as(u16, 8080), r.target.port);
    try std.testing.expectEqualStrings("/", r.path);
}

test "parseHttpTarget origin-form uses Host header" {
    const r = try parseHttpTarget("/foo", "example.com:9000");
    try std.testing.expectEqualStrings("example.com", r.target.host);
    try std.testing.expectEqual(@as(u16, 9000), r.target.port);
    try std.testing.expectEqualStrings("/foo", r.path);
}

test "parseHttpTarget origin-form requires Host header" {
    try std.testing.expectError(error.MissingHost, parseHttpTarget("/foo", null));
}

test "parseHttpTarget rejects non-http scheme" {
    try std.testing.expectError(error.UnsupportedScheme, parseHttpTarget("ftp://example.com/", null));
}
