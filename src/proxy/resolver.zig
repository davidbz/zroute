const std = @import("std");
const Io = std.Io;
const net = Io.net;
const HostName = net.HostName;
const egress = @import("egress.zig");

/// Default-first: `.system` uses the OS resolver (`/etc/resolv.conf`).
/// Only overridden to `.custom` when `Config.dns_servers` is non-empty,
/// since stdlib has no way to point address lookup at specific nameservers.
pub const Resolver = union(enum) {
    system,
    custom: CustomResolver,

    pub fn init(dns_servers: []const net.IpAddress, timeout: Io.Timeout) Resolver {
        if (dns_servers.len == 0) return .system;
        return .{ .custom = .{ .servers = dns_servers, .timeout = timeout } };
    }

    /// Resolves `host`, then connects to the first candidate address that
    /// passes `policy`. The deny check runs against the *resolved* IP, not
    /// the hostname — a DNS answer that rebinds a public-looking name to a
    /// denied range (loopback/link-local/RFC1918/ULA/multicast) is caught
    /// here, not before resolution, where a DNS-rebind bypass would slip
    /// past a hostname-only check.
    ///
    /// `error.EgressDenied` means every resolved address was denied by
    /// policy. If at least one address passed the policy but none of them
    /// could be connected to, `error.AllConnectAttemptsFailed` is returned.
    pub fn connect(r: Resolver, host: HostName, io: Io, port: u16, options: net.IpAddress.ConnectOptions, policy: egress.Policy) !net.Stream {
        var addr_buf: [16]net.IpAddress = undefined;
        const addrs = try r.resolveAddresses(io, host, &addr_buf);

        var any_allowed = false;
        for (addrs) |addr| {
            if (!policy.allowsTarget(addr)) continue;
            any_allowed = true;
            var a = addr;
            a.setPort(port);
            return net.IpAddress.connect(&a, io, options) catch continue;
        }
        if (!any_allowed) return error.EgressDenied;
        return error.AllConnectAttemptsFailed;
    }

    fn resolveAddresses(r: Resolver, io: Io, host: HostName, out: []net.IpAddress) ![]net.IpAddress {
        return switch (r) {
            .system => systemResolve(io, host, out),
            .custom => |c| c.resolve(io, host, out),
        };
    }
};

/// Blocking lookup via `HostName.lookup`: the queue's 16-slot capacity is
/// enough that `lookup` never blocks trying to put a result (per its own
/// doc comment), so this drains synchronously in the same task rather than
/// needing a concurrent producer/consumer pair.
fn systemResolve(io: Io, host: HostName, out: []net.IpAddress) HostName.LookupError![]net.IpAddress {
    var queue_buf: [16]HostName.LookupResult = undefined;
    var queue: Io.Queue(HostName.LookupResult) = .init(&queue_buf);
    const lookup_result = host.lookup(io, &queue, .{ .port = 0 });

    var count: usize = 0;
    while (queue.getOne(io)) |result| {
        switch (result) {
            .address => |addr| {
                if (count < out.len) {
                    out[count] = addr;
                    count += 1;
                }
            },
            .canonical_name => {},
        }
    } else |_| {}

    if (count == 0) {
        try lookup_result;
        return error.UnknownHostName;
    }
    return out[0..count];
}

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
        const txid = std.mem.readInt(u16, query[0..2], .big);
        try socket.send(io, &server, query);

        // Absolute deadline, not a per-packet duration: an off-path attacker
        // racing the real server could flood us with junk datagrams, and
        // re-arming a fresh timeout for each one would let them stall us
        // indefinitely. `deadline` is a fixed point in time, so every
        // `receiveTimeout` below waits only for whatever budget remains.
        const deadline = c.timeout.toDeadline(io);
        var resp_buf: [512]u8 = undefined;
        while (true) {
            const msg = try socket.receiveTimeout(io, &resp_buf, deadline);
            if (!server.eql(&msg.from)) continue;
            if (!isValidResponse(msg.data, txid)) continue;
            return parseAAnswers(msg.data, out);
        }
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

/// Rejects anything that isn't plausibly a reply to our own query: too
/// short to hold a header, wrong transaction ID (the primary spoofing
/// defense — an off-path attacker guessing this is what we rely on), not
/// marked as a response, or a nonzero RCODE. Flags live in bytes [2..4]:
/// bit 15 is QR, the low nibble is RCODE.
fn isValidResponse(packet: []const u8, txid: u16) bool {
    if (packet.len < 12) return false;
    if (std.mem.readInt(u16, packet[0..2], .big) != txid) return false;
    const flags = std.mem.readInt(u16, packet[2..4], .big);
    const qr_set = flags & 0x8000 != 0;
    const rcode = flags & 0x000f;
    return qr_set and rcode == 0;
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

test "isValidResponse checks length, txid, QR bit, and RCODE" {
    var packet: [12]u8 = @splat(0);
    std.mem.writeInt(u16, packet[0..2], 0x1234, .big);
    std.mem.writeInt(u16, packet[2..4], 0x8180, .big); // QR=1, RCODE=0 (NOERROR)
    try std.testing.expect(isValidResponse(&packet, 0x1234));

    // Transaction ID mismatch: the primary spoofing defense.
    try std.testing.expect(!isValidResponse(&packet, 0x4321));

    // QR bit unset: this is a query, not a response.
    var not_response = packet;
    std.mem.writeInt(u16, not_response[2..4], 0x0100, .big);
    try std.testing.expect(!isValidResponse(&not_response, 0x1234));

    // Nonzero RCODE (2 = SERVFAIL).
    var servfail = packet;
    std.mem.writeInt(u16, servfail[2..4], 0x8182, .big);
    try std.testing.expect(!isValidResponse(&servfail, 0x1234));

    // Too short to contain a full header.
    try std.testing.expect(!isValidResponse(packet[0..4], 0x1234));
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

    // A spoofed/stale reply with the wrong transaction ID must be rejected
    // before we ever try to parse it.
    try std.testing.expect(!isValidResponse(packet[0..w], 0xffff));

    // The genuine reply (matching txid) is accepted and yields the address.
    try std.testing.expect(isValidResponse(packet[0..w], 0x1234));
    const n = try parseAAnswers(packet[0..w], &out);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualSlices(u8, &.{ 93, 184, 216, 34 }, &out[0].ip4.bytes);
}
