const std = @import("std");

pub const TraceId = u128;

/// node_prefix (high 64 bits, randomized once at process start) + a
/// monotonically increasing counter (low 64 bits) — unique within a
/// process's lifetime, cheap, no locking beyond one atomic fetchAdd.
pub fn nextTraceId(node_prefix: u64, counter: *std.atomic.Value(u64)) TraceId {
    const low = counter.fetchAdd(1, .monotonic);
    return (@as(TraceId, node_prefix) << 64) | @as(TraceId, low);
}

test "nextTraceId increments and embeds node prefix" {
    var counter: std.atomic.Value(u64) = .init(0);
    const a = nextTraceId(0xAABB, &counter);
    const b = nextTraceId(0xAABB, &counter);
    try std.testing.expectEqual(@as(u128, 0xAABB) << 64, a);
    try std.testing.expectEqual((@as(u128, 0xAABB) << 64) | 1, b);
}
