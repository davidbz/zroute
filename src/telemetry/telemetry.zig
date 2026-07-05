const std = @import("std");

const span_mod = @import("span.zig");
pub const TraceId = span_mod.TraceId;

pub const Telemetry = struct {
    node_prefix: u64,
    trace_counter: std.atomic.Value(u64) = .init(0),

    pub fn init(node_prefix: u64) Telemetry {
        return .{ .node_prefix = node_prefix };
    }

    pub fn nextTraceId(t: *Telemetry) TraceId {
        return span_mod.nextTraceId(t.node_prefix, &t.trace_counter);
    }
};
