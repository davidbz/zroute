const std = @import("std");
const Io = std.Io;
const net = Io.net;
const HostName = net.HostName;

/// Default-first: `.system` delegates straight to `HostName.connect`, which
/// already does DNS lookup + connect + address-racing via the OS resolver
/// (`/etc/resolv.conf`) — zero extra code. Only overridden to `.custom` when
/// `Config.dns_servers` is non-empty, since stdlib has no way to point
/// `HostName.connect` at specific nameservers.
pub const Resolver = union(enum) {
    system,
    custom: CustomResolver,

    pub fn init(dns_servers: []const net.IpAddress, timeout: Io.Timeout) Resolver {
        if (dns_servers.len == 0) return .system;
        return .{ .custom = .{ .servers = dns_servers, .timeout = timeout } };
    }

    pub fn connect(r: Resolver, host: HostName, io: Io, port: u16, options: net.IpAddress.ConnectOptions) !net.Stream {
        return switch (r) {
            .system => HostName.connect(host, io, port, options),
            .custom => |c| c.connect(host, io, port, options),
        };
    }
};

/// Queries the configured nameservers in order (guard-clause: try the next
/// server on any failure or timeout). Reuses stdlib's public DNS
/// wire-format parsing (`HostName.DnsResponse`) rather than duplicating a
/// parser; only the query side is hand-built, since stdlib has no
/// query-builder to reuse. No allocation: fixed-size stack buffers
/// throughout. IPv4 (`A` records) only — a stated limitation, not a silent
/// gap; the system resolver path already handles IPv6.
pub const CustomResolver = struct {
    servers: []const net.IpAddress,
    timeout: Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } },

    pub fn connect(c: CustomResolver, host: HostName, io: Io, port: u16, options: net.IpAddress.ConnectOptions) !net.Stream {
        var addr_buf: [8]net.IpAddress = undefined;
        const addrs = try c.resolve(io, host, &addr_buf);
        for (addrs) |addr| {
            var a = addr;
            a.setPort(port);
            return net.IpAddress.connect(&a, io, options) catch continue;
        }
        return error.UnknownHostName;
    }

    /// Tries each configured server in turn; returns as soon as one answers
    /// with at least one address.
    fn resolve(c: CustomResolver, io: Io, host: HostName, out: []net.IpAddress) ![]net.IpAddress {
        for (c.servers) |server| {
            const n = c.queryServer(io, server, host, out) catch continue;
            if (n > 0) return out[0..n];
        }
        return error.NameServerFailure;
    }

    fn queryServer(c: CustomResolver, io: Io, server: net.IpAddress, host: HostName, out: []net.IpAddress) !usize {
        const bind_addr = try net.IpAddress.parse("0.0.0.0", 0);
        const socket = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram, .protocol = .udp });
        defer socket.close(io);

        var query_buf: [320]u8 = undefined;
        const query = try buildQuery(host, &query_buf, io);
        try socket.send(io, &server, query);

        var resp_buf: [512]u8 = undefined;
        const msg = try socket.receiveTimeout(io, &resp_buf, c.timeout);
        return parseAAnswers(msg.data, out);
    }
};

const QueryError = error{ NoSpaceLeft, LabelTooLong };

/// Standard 12-byte DNS header (random transaction ID, recursion-desired
/// flag set, QDCOUNT=1) followed by the QNAME label encoding of `host` and
/// QTYPE=A(1)/QCLASS=IN(1).
fn buildQuery(host: HostName, buf: []u8, io: Io) QueryError![]const u8 {
    const header_and_footer_len = 12 + 1 + 4; // header + root label + qtype/qclass
    if (buf.len < header_and_footer_len + host.bytes.len) return error.NoSpaceLeft;

    Io.random(io, buf[0..2]); // ID
    std.mem.writeInt(u16, buf[2..4], 0x0100, .big); // flags: recursion desired
    std.mem.writeInt(u16, buf[4..6], 1, .big); // QDCOUNT
    std.mem.writeInt(u16, buf[6..8], 0, .big); // ANCOUNT
    std.mem.writeInt(u16, buf[8..10], 0, .big); // NSCOUNT
    std.mem.writeInt(u16, buf[10..12], 0, .big); // ARCOUNT
    var w: usize = 12;

    var labels = std.mem.splitScalar(u8, host.bytes, '.');
    while (labels.next()) |label| {
        if (label.len == 0) continue;
        if (label.len > 63) return error.LabelTooLong;
        buf[w] = @intCast(label.len);
        w += 1;
        @memcpy(buf[w..][0..label.len], label);
        w += label.len;
    }
    buf[w] = 0; // root label
    w += 1;

    std.mem.writeInt(u16, buf[w..][0..2], 1, .big); // QTYPE = A
    w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], 1, .big); // QCLASS = IN
    w += 2;

    return buf[0..w];
}

/// Walks the answer section, keeping only `A` records, decoding each 4-byte
/// RDATA into an `IpAddress`. Malformed trailing answers are treated as
/// "no more answers" (guard clause) rather than failing the whole query, so
/// a partial-but-valid answer set is still usable.
fn parseAAnswers(packet: []const u8, out: []net.IpAddress) !usize {
    var response = try HostName.DnsResponse.init(packet);
    var count: usize = 0;
    while (count < out.len) {
        const answer = (response.next() catch break) orelse break;
        if (answer.rr != .A) continue;
        if (answer.data_len != 4) continue;
        const bytes = answer.packet[answer.data_off..][0..4];
        out[count] = .{ .ip4 = .{ .bytes = bytes.*, .port = 0 } };
        count += 1;
    }
    return count;
}

test "buildQuery produces a well-formed packet for a known hostname" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const host = try HostName.init("example.com");
    var buf: [320]u8 = undefined;
    const query = try buildQuery(host, &buf, io);

    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, query[4..6], .big));
    try std.testing.expectEqual(@as(u16, 0), std.mem.readInt(u16, query[6..8], .big));

    // QNAME: 7"example"3"com"0
    try std.testing.expectEqual(@as(u8, 7), query[12]);
    try std.testing.expectEqualStrings("example", query[13..20]);
    try std.testing.expectEqual(@as(u8, 3), query[20]);
    try std.testing.expectEqualStrings("com", query[21..24]);
    try std.testing.expectEqual(@as(u8, 0), query[24]);

    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, query[25..27], .big));
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, query[27..29], .big));
    try std.testing.expectEqual(@as(usize, 29), query.len);
}

test "parseAAnswers decodes a canned A-record response" {
    var packet: [512]u8 = undefined;
    var w: usize = 0;

    // Header: 1 question, 1 answer.
    std.mem.writeInt(u16, packet[0..2], 0x1234, .big);
    std.mem.writeInt(u16, packet[2..4], 0x8180, .big);
    std.mem.writeInt(u16, packet[4..6], 1, .big);
    std.mem.writeInt(u16, packet[6..8], 1, .big);
    std.mem.writeInt(u16, packet[8..10], 0, .big);
    std.mem.writeInt(u16, packet[10..12], 0, .big);
    w = 12;

    // Question: example.com A IN
    const host = try HostName.init("example.com");
    var labels = std.mem.splitScalar(u8, host.bytes, '.');
    while (labels.next()) |label| {
        packet[w] = @intCast(label.len);
        w += 1;
        @memcpy(packet[w..][0..label.len], label);
        w += label.len;
    }
    packet[w] = 0;
    w += 1;
    std.mem.writeInt(u16, packet[w..][0..2], 1, .big);
    w += 2;
    std.mem.writeInt(u16, packet[w..][0..2], 1, .big);
    w += 2;

    // Answer: pointer to name at offset 12, TYPE=A, CLASS=IN, TTL, RDLENGTH=4, RDATA
    std.mem.writeInt(u16, packet[w..][0..2], 0xC00C, .big);
    w += 2;
    std.mem.writeInt(u16, packet[w..][0..2], 1, .big); // TYPE A
    w += 2;
    std.mem.writeInt(u16, packet[w..][0..2], 1, .big); // CLASS IN
    w += 2;
    std.mem.writeInt(u32, packet[w..][0..4], 300, .big); // TTL
    w += 4;
    std.mem.writeInt(u16, packet[w..][0..2], 4, .big); // RDLENGTH
    w += 2;
    packet[w..][0..4].* = .{ 93, 184, 216, 34 };
    w += 4;

    var out: [4]net.IpAddress = undefined;
    const n = try parseAAnswers(packet[0..w], &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &out[0].ip4.bytes);
}
