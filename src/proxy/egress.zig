const std = @import("std");
const net = std.Io.net;
const http = std.http;
const Metrics = @import("../telemetry/metrics.zig").Metrics;
const TraceId = @import("../telemetry/span.zig").TraceId;
const log = @import("log.zig");

/// A CIDR entry in the egress allowlist ("10.0.0.0/8", "fc00::/7", or a bare
/// address meaning a /32 or /128). Family-matched against candidate
/// addresses in `contains` — an IPv4 entry never matches an IPv6 address and
/// vice versa (no implicit IPv4-mapped unwrapping here; that unwrapping
/// already happens once, in `isDeniedRange`, before any allowlist check).
pub const AllowEntry = struct {
    base: net.IpAddress,
    prefix_len: u8,

    pub const ParseError = error{ InvalidAddress, InvalidPrefixLength };

    pub fn parse(text: []const u8) ParseError!AllowEntry {
        const slash = std.mem.indexOfScalar(u8, text, '/') orelse text.len;
        const base = net.IpAddress.parse(text[0..slash], 0) catch return error.InvalidAddress;
        const max_prefix: u8 = switch (base) {
            .ip4 => 32,
            .ip6 => 128,
        };
        if (slash == text.len) return .{ .base = base, .prefix_len = max_prefix };

        const prefix_len = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return error.InvalidPrefixLength;
        if (prefix_len > max_prefix) return error.InvalidPrefixLength;
        return .{ .base = base, .prefix_len = prefix_len };
    }

    pub fn contains(e: AllowEntry, addr: net.IpAddress) bool {
        return switch (e.base) {
            .ip4 => |base| switch (addr) {
                .ip4 => |a| matchesPrefix(&base.bytes, &a.bytes, e.prefix_len),
                .ip6 => false,
            },
            .ip6 => |base| switch (addr) {
                .ip6 => |a| matchesPrefix(&base.bytes, &a.bytes, e.prefix_len),
                .ip4 => false,
            },
        };
    }
};

fn matchesPrefix(base: []const u8, addr: []const u8, prefix_len: u8) bool {
    var bits = prefix_len;
    var i: usize = 0;
    while (bits >= 8) : (bits -= 8) {
        if (base[i] != addr[i]) return false;
        i += 1;
    }
    if (bits == 0) return true;
    const mask: u8 = @as(u8, 0xff) << @intCast(8 - bits);
    return (base[i] & mask) == (addr[i] & mask);
}

/// Egress policy applied to a *resolved* target address (never just the
/// hostname — a DNS answer that rebinds a public-looking name to a denied
/// range must be caught here, after resolution) and, for CONNECT, to the
/// requested destination port.
pub const Policy = struct {
    /// Master switch. `false` restores fully open egress (documented in the
    /// README as the insecure, "unrestricted proxy" choice) — every other
    /// field is ignored.
    deny_private: bool = true,
    /// Overrides the deny check for addresses that fall inside one of these
    /// CIDRs even though they're in a normally-denied range.
    allow: []const AllowEntry = &.{},
    /// CONNECT destination ports permitted. Empty means allow any port
    /// (documented as the insecure choice). Not applied to plain HTTP
    /// forwarding, which is scoped by the egress deny check alone.
    connect_ports: []const u16 = &.{ 443, 80 },

    pub fn allowsTarget(p: Policy, addr: net.IpAddress) bool {
        if (!p.deny_private) return true;
        if (!isDeniedRange(addr)) return true;
        for (p.allow) |entry| {
            if (entry.contains(addr)) return true;
        }
        return false;
    }

    pub fn allowsConnectPort(p: Policy, port: u16) bool {
        if (p.connect_ports.len == 0) return true;
        for (p.connect_ports) |allowed| {
            if (allowed == port) return true;
        }
        return false;
    }
};

/// Shared terminal action for every egress-deny path (CONNECT port not
/// allowlisted, resolved address denied for CONNECT, resolved address denied
/// for plain HTTP forwarding): count it, log it, and respond 403.
pub fn denyEgress(
    request: *http.Server.Request,
    metrics: *Metrics,
    trace_id: TraceId,
    slot: u32,
    reason: []const u8,
    host: []const u8,
    port: u16,
) !void {
    metrics.incr(.egress_denied);
    log.warn(trace_id, slot, "{s} host={s} port={d}", .{ reason, host, port });
    try request.respond("Forbidden", .{ .status = .forbidden, .keep_alive = false });
}

/// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped and classified
/// as their IPv4 form first — otherwise a target could dodge the IPv4 deny
/// ranges (e.g. `::ffff:169.254.169.254`) just by being resolved to that
/// form instead of a bare A record.
fn isDeniedRange(addr: net.IpAddress) bool {
    return switch (addr) {
        .ip4 => |a| isDeniedIp4(a.bytes),
        .ip6 => |a| if (net.Ip4Address.fromIp6(a)) |mapped|
            isDeniedIp4(mapped.bytes)
        else
            isDeniedIp6(a.bytes),
    };
}

fn isDeniedIp4(b: [4]u8) bool {
    if (b[0] == 0) return true; // "this network" / unspecified
    if (b[0] == 127) return true; // loopback
    if (b[0] == 169 and b[1] == 254) return true; // link-local
    if (b[0] == 10) return true; // RFC1918
    if (b[0] == 172 and b[1] >= 16 and b[1] <= 31) return true; // RFC1918
    if (b[0] == 192 and b[1] == 168) return true; // RFC1918
    if (b[0] >= 224 and b[0] <= 239) return true; // multicast
    return false;
}

fn isDeniedIp6(b: [16]u8) bool {
    if (isZero(&b)) return true; // ::
    if (isZero(b[0..15]) and b[15] == 1) return true; // ::1 loopback
    if (b[0] == 0xfe and (b[1] & 0xc0) == 0x80) return true; // fe80::/10 link-local
    if ((b[0] & 0xfe) == 0xfc) return true; // fc00::/7 ULA
    if (b[0] == 0xff) return true; // ff00::/8 multicast
    return false;
}

fn isZero(b: []const u8) bool {
    for (b) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn ip4(a: u8, b: u8, c: u8, d: u8, port: u16) net.IpAddress {
    return .{ .ip4 = .{ .bytes = .{ a, b, c, d }, .port = port } };
}

test "denies loopback, link-local, RFC1918, and multicast IPv4 targets" {
    const policy: Policy = .{};
    try std.testing.expect(!policy.allowsTarget(ip4(169, 254, 169, 254, 80))); // cloud metadata
    try std.testing.expect(!policy.allowsTarget(ip4(127, 0, 0, 1, 80)));
    try std.testing.expect(!policy.allowsTarget(ip4(10, 0, 0, 5, 80)));
    try std.testing.expect(!policy.allowsTarget(ip4(172, 16, 0, 1, 80)));
    try std.testing.expect(!policy.allowsTarget(ip4(192, 168, 1, 1, 80)));
    try std.testing.expect(!policy.allowsTarget(ip4(224, 0, 0, 1, 80)));
}

test "allows a public IPv4 target" {
    const policy: Policy = .{};
    try std.testing.expect(policy.allowsTarget(ip4(93, 184, 216, 34, 443)));
}

test "allowlist re-permits a specific denied-range CIDR" {
    var allow = [_]AllowEntry{try AllowEntry.parse("10.0.0.0/8")};
    const policy: Policy = .{ .allow = &allow };
    try std.testing.expect(policy.allowsTarget(ip4(10, 1, 2, 3, 80)));
    // A neighboring denied range not covered by the allowlist stays denied.
    try std.testing.expect(!policy.allowsTarget(ip4(192, 168, 1, 1, 80)));
}

test "deny_private = false disables the policy entirely" {
    const policy: Policy = .{ .deny_private = false };
    try std.testing.expect(policy.allowsTarget(ip4(169, 254, 169, 254, 80)));
}

test "IPv4-mapped IPv6 metadata address is still denied" {
    const policy: Policy = .{};
    // ::ffff:169.254.169.254
    const addr: net.IpAddress = .{ .ip6 = .{
        .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 169, 254, 169, 254 },
        .port = 80,
    } };
    try std.testing.expect(!policy.allowsTarget(addr));
}

test "CONNECT port allowlist rejects a non-allowlisted port by default" {
    const policy: Policy = .{};
    try std.testing.expect(policy.allowsConnectPort(443));
    try std.testing.expect(policy.allowsConnectPort(80));
    try std.testing.expect(!policy.allowsConnectPort(22));
    try std.testing.expect(!policy.allowsConnectPort(25));
}

test "empty CONNECT port allowlist means allow all" {
    const policy: Policy = .{ .connect_ports = &.{} };
    try std.testing.expect(policy.allowsConnectPort(22));
}

test "AllowEntry.parse handles bare address, CIDR, and rejects an out-of-range prefix" {
    const bare = try AllowEntry.parse("10.1.2.3");
    try std.testing.expectEqual(@as(u8, 32), bare.prefix_len);

    const cidr = try AllowEntry.parse("fc00::/7");
    try std.testing.expectEqual(@as(u8, 7), cidr.prefix_len);

    try std.testing.expectError(error.InvalidPrefixLength, AllowEntry.parse("10.0.0.0/33"));
}
