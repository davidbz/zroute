const std = @import("std");

pub const Counter = enum {
    connections_total,
    connections_active,
    connections_rejected,
    requests_http,
    requests_connect,
    upstream_connect_errors,
    relay_errors,

    pub const count = @typeInfo(Counter).@"enum".fields.len;
};

/// SoA layout: one atomic array for all counters. This is the whole
/// process's metrics state, one instance, shared by every connection task
/// via a pointer.
pub const Metrics = struct {
    counters: [Counter.count]std.atomic.Value(u64) = @splat(.init(0)),

    pub fn incr(m: *Metrics, c: Counter) void {
        m.add(c, 1);
    }

    pub fn decr(m: *Metrics, c: Counter) void {
        _ = m.counters[@intFromEnum(c)].fetchSub(1, .monotonic);
    }

    pub fn add(m: *Metrics, c: Counter, n: u64) void {
        _ = m.counters[@intFromEnum(c)].fetchAdd(n, .monotonic);
    }

    pub fn get(m: *const Metrics, c: Counter) u64 {
        return m.counters[@intFromEnum(c)].load(.monotonic);
    }
};

test "Metrics incr/decr/get" {
    var m: Metrics = .{};
    m.incr(.connections_total);
    m.incr(.connections_total);
    m.decr(.connections_total);
    try std.testing.expectEqual(@as(u64, 1), m.get(.connections_total));
}
