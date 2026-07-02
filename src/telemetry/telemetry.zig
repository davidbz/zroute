const std = @import("std");

const span_mod = @import("span.zig");
pub const TraceId = span_mod.TraceId;

const metrics_mod = @import("metrics.zig");
pub const Metrics = metrics_mod.Metrics;
pub const Counter = metrics_mod.Counter;

pub const reporter = @import("reporter.zig");

pub const Telemetry = struct {
    metrics: Metrics = .{},
    node_prefix: u64,
    trace_counter: std.atomic.Value(u64) = .init(0),

    pub fn init(node_prefix: u64) Telemetry {
        return .{ .node_prefix = node_prefix };
    }

    pub fn nextTraceId(t: *Telemetry) TraceId {
        return span_mod.nextTraceId(t.node_prefix, &t.trace_counter);
    }
};
