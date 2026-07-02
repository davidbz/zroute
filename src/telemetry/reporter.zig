const std = @import("std");
const Io = std.Io;

const metrics_mod = @import("metrics.zig");
const Metrics = metrics_mod.Metrics;
const Counter = metrics_mod.Counter;

const log = std.log.scoped(.telemetry);

/// Runs until canceled, waking every `interval` to log one snapshot line.
/// The only way the write-only counters in `Metrics` ever become observable
/// at runtime: nothing else reads them back. Callers should spawn this in an
/// `Io.Group` only when the configured interval is non-zero — `interval` of
/// `.none` would return from `sleep` immediately and busy-loop.
pub fn run(metrics: *const Metrics, interval: Io.Timeout, io: Io) void {
    while (true) {
        interval.sleep(io) catch return;
        logSnapshot(metrics);
    }
}

fn logSnapshot(metrics: *const Metrics) void {
    var buf: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    formatSnapshot(metrics.snapshot(), &writer) catch return;
    log.info("{s}", .{writer.buffered()});
}

/// Renders every counter as `name=value`, space separated, via reflection so
/// a new `Counter` is exported automatically.
pub fn formatSnapshot(s: [Counter.count]u64, w: *Io.Writer) !void {
    inline for (@typeInfo(Counter).@"enum".fields, 0..) |f, i| {
        if (i > 0) try w.writeByte(' ');
        try w.print("{s}={d}", .{ f.name, s[i] });
    }
}

test "formatSnapshot renders every Counter field once" {
    const s: [Counter.count]u64 = .{ 1, 2, 3, 4, 5, 6, 7 };

    var buf: [256]u8 = undefined;
    var writer: Io.Writer = .fixed(&buf);
    try formatSnapshot(s, &writer);
    const out = writer.buffered();

    inline for (@typeInfo(Counter).@"enum".fields) |f| {
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, out, f.name ++ "="));
    }
}
