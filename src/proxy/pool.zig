const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const TraceId = @import("../telemetry/span.zig").TraceId;

pub const ConnState = enum(u8) {
    idle,
    accepted,
    parsing_head,
    relaying_http,
    tunneling,
};

/// Sentinel marking "no next slot" in the free list / "pool full".
pub const invalid_slot: u32 = std.math.maxInt(u32);

/// Struct-of-arrays, fixed-capacity connection table. Allocated once at
/// startup from `Config.max_connections`; never grows. A connection's
/// identity for its whole lifetime is a plain `u32` slot index — no
/// pointer, no per-connection heap object. Free slots are tracked via an
/// intrusive, lock-free (CAS-based) Treiber stack over `next_free`.
pub const ConnectionPool = struct {
    capacity: u32,
    trace_ids: []TraceId,
    remote_addrs: []Io.net.IpAddress,
    states: []std.atomic.Value(ConnState),
    last_activity_at: []Io.Timestamp,
    next_free: []std.atomic.Value(u32),
    free_head: std.atomic.Value(u32),

    pub fn init(gpa: Allocator, capacity: u32) Allocator.Error!ConnectionPool {
        const trace_ids = try gpa.alloc(TraceId, capacity);
        errdefer gpa.free(trace_ids);
        const remote_addrs = try gpa.alloc(Io.net.IpAddress, capacity);
        errdefer gpa.free(remote_addrs);
        const states = try gpa.alloc(std.atomic.Value(ConnState), capacity);
        errdefer gpa.free(states);
        const last_activity_at = try gpa.alloc(Io.Timestamp, capacity);
        errdefer gpa.free(last_activity_at);
        const next_free = try gpa.alloc(std.atomic.Value(u32), capacity);
        errdefer gpa.free(next_free);

        for (states) |*s| s.* = .init(.idle);
        for (next_free, 0..) |*n, i| {
            const next: u32 = if (i + 1 < capacity) @intCast(i + 1) else invalid_slot;
            n.* = .init(next);
        }

        return .{
            .capacity = capacity,
            .trace_ids = trace_ids,
            .remote_addrs = remote_addrs,
            .states = states,
            .last_activity_at = last_activity_at,
            .next_free = next_free,
            .free_head = .init(if (capacity == 0) invalid_slot else 0),
        };
    }

    pub fn deinit(pool: *ConnectionPool, gpa: Allocator) void {
        gpa.free(pool.trace_ids);
        gpa.free(pool.remote_addrs);
        gpa.free(pool.states);
        gpa.free(pool.last_activity_at);
        gpa.free(pool.next_free);
        pool.* = undefined;
    }

    /// Pops a free slot off the lock-free free list. Returns null (guard
    /// clause: pool exhausted) instead of growing — callers must reject the
    /// connection.
    pub fn acquire(pool: *ConnectionPool, trace_id: TraceId, remote_addr: Io.net.IpAddress, io: Io) ?u32 {
        while (true) {
            const head = pool.free_head.load(.acquire);
            if (head == invalid_slot) return null;
            const next = pool.next_free[head].load(.monotonic);
            if (pool.free_head.cmpxchgWeak(head, next, .acq_rel, .acquire) != null) continue;

            pool.trace_ids[head] = trace_id;
            pool.remote_addrs[head] = remote_addr;
            pool.last_activity_at[head] = .now(io, .awake);
            pool.states[head].store(.accepted, .release);
            return head;
        }
    }

    /// Returns a slot to the free list.
    pub fn release(pool: *ConnectionPool, slot: u32) void {
        pool.states[slot].store(.idle, .release);

        while (true) {
            const head = pool.free_head.load(.monotonic);
            pool.next_free[slot].store(head, .monotonic);
            if (pool.free_head.cmpxchgWeak(head, slot, .acq_rel, .monotonic) == null) return;
        }
    }

    pub fn setState(pool: *ConnectionPool, slot: u32, state: ConnState) void {
        pool.states[slot].store(state, .release);
    }

    pub fn touchActivity(pool: *ConnectionPool, slot: u32, io: Io) void {
        pool.last_activity_at[slot] = .now(io, .awake);
    }
};

test "acquire/release cycle exhausts and refills capacity" {
    const gpa = std.testing.allocator;
    var pool: ConnectionPool = try .init(gpa, 2);
    defer pool.deinit(gpa);

    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    const a = pool.acquire(1, addr, io) orelse return error.TestUnexpectedResult;
    const b = pool.acquire(2, addr, io) orelse return error.TestUnexpectedResult;
    try std.testing.expect(pool.acquire(3, addr, io) == null);

    pool.release(a);
    const c = pool.acquire(4, addr, io) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(a, c);

    pool.release(b);
    pool.release(c);
}

test "released slot state resets to idle" {
    const gpa = std.testing.allocator;
    var pool: ConnectionPool = try .init(gpa, 1);
    defer pool.deinit(gpa);

    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr: Io.net.IpAddress = try .parse("127.0.0.1", 0);
    const slot = pool.acquire(1, addr, io) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(ConnState.accepted, pool.states[slot].load(.monotonic));
    pool.release(slot);
    try std.testing.expectEqual(ConnState.idle, pool.states[slot].load(.monotonic));
}
