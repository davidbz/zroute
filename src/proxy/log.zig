const std = @import("std");
const TraceId = @import("../telemetry/span.zig").TraceId;

const scoped = std.log.scoped(.proxy);

/// Every log line from the request lifecycle is tagged with `trace_id=` and
/// `slot=` first, so a single request's full path (accept -> parse ->
/// resolve -> connect -> relay/tunnel -> close) is reconstructible with
/// `grep trace_id=<x>` across log output alone, no log aggregation needed.
pub fn debug(trace_id: TraceId, slot: u32, comptime fmt: []const u8, args: anytype) void {
    scoped.debug("trace_id={x:0>32} slot={d} " ++ fmt, .{ trace_id, slot } ++ args);
}

pub fn info(trace_id: TraceId, slot: u32, comptime fmt: []const u8, args: anytype) void {
    scoped.info("trace_id={x:0>32} slot={d} " ++ fmt, .{ trace_id, slot } ++ args);
}

pub fn warn(trace_id: TraceId, slot: u32, comptime fmt: []const u8, args: anytype) void {
    scoped.warn("trace_id={x:0>32} slot={d} " ++ fmt, .{ trace_id, slot } ++ args);
}

pub fn err(trace_id: TraceId, slot: u32, comptime fmt: []const u8, args: anytype) void {
    scoped.err("trace_id={x:0>32} slot={d} " ++ fmt, .{ trace_id, slot } ++ args);
}
