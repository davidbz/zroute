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

/// Extracts the slot index (low 32 bits) from a packed free-list head word.
inline fn index(word: u64) u32 {
    return @truncate(word);
}

/// Extracts the ABA generation tag (high 32 bits) from a packed free-list head word.
inline fn tag(word: u64) u32 {
    return @truncate(word >> 32);
}

/// Packs a generation tag and slot index into a single free-list head word.
inline fn pack(tag_: u32, index_: u32) u64 {
    return (@as(u64, tag_) << 32) | @as(u64, index_);
}

/// Struct-of-arrays, fixed-capacity connection table. Allocated once at
/// startup from `Config.max_connections`; never grows. A connection's
/// identity for its whole lifetime is a plain `u32` slot index — no
/// pointer, no per-connection heap object. Free slots are tracked via an
/// intrusive, lock-free (CAS-based) Treiber stack over `next_free`, with a
/// generation tag packed into `free_head` to make it ABA-safe under true
/// multi-producer/multi-consumer acquire/release: the tag is bumped on
/// every push and every pop, so a stale head word read by one thread can
/// never spuriously CAS-match after other threads have popped and
/// re-pushed the same slot in between.
pub const ConnectionPool = struct {
    capacity: u32,
    trace_ids: []TraceId,
    remote_addrs: []Io.net.IpAddress,
    states: []std.atomic.Value(ConnState),
    last_activity_at: []Io.Timestamp,
    next_free: []std.atomic.Value(u32),
    free_head: std.atomic.Value(u64),

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
            .free_head = .init(pack(0, if (capacity == 0) invalid_slot else 0)),
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
            const word = pool.free_head.load(.acquire);
            const head = index(word);
            if (head == invalid_slot) return null;
            const next = pool.next_free[head].load(.monotonic);
            if (pool.free_head.cmpxchgWeak(word, pack(tag(word) +% 1, next), .acq_rel, .acquire) != null) continue;

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
            const word = pool.free_head.load(.monotonic);
            pool.next_free[slot].store(index(word), .monotonic);
            if (pool.free_head.cmpxchgWeak(word, pack(tag(word) +% 1, slot), .release, .monotonic) == null) return;
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

test "concurrent acquire/release is ABA-safe under true MPMC stress" {
    const capacity: u32 = 4;
    const num_threads: usize = 16;
    const iterations: usize = 500;

    const gpa = std.testing.allocator;
    var pool: ConnectionPool = try .init(gpa, capacity);
    defer pool.deinit(gpa);

    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr: Io.net.IpAddress = try .parse("127.0.0.1", 0);

    // Slot indices are bounded by `capacity`, so "is this slot currently
    // held twice" is a fixed-size array of atomic flags, not a locked set:
    // each flag's own CAS is the double-hold check, with no separate lock.
    const Shared = struct {
        pool: *ConnectionPool,
        io: Io,
        addr: Io.net.IpAddress,
        held: [capacity]std.atomic.Value(bool) = @splat(.init(false)),
        failed: std.atomic.Value(bool) = .init(false),

        fn worker(shared: *@This()) void {
            var i: usize = 0;
            while (i < iterations) : (i += 1) {
                const slot = shared.pool.acquire(1, shared.addr, shared.io) orelse continue;
                if (slot >= capacity) {
                    shared.failed.store(true, .monotonic);
                    continue;
                }

                if (shared.held[slot].cmpxchgStrong(false, true, .acq_rel, .monotonic) != null) {
                    shared.failed.store(true, .monotonic);
                }

                std.Thread.yield() catch {};

                shared.held[slot].store(false, .release);
                shared.pool.release(slot);
            }
        }
    };

    var shared: Shared = .{ .pool = &pool, .io = io, .addr = addr };

    var threads: [num_threads]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Shared.worker, .{&shared});
    for (threads) |t| t.join();

    try std.testing.expect(!shared.failed.load(.monotonic));

    var slots: [capacity]u32 = undefined;
    for (&slots) |*s| s.* = pool.acquire(1, addr, io) orelse return error.TestUnexpectedResult;
    try std.testing.expect(pool.acquire(1, addr, io) == null);
    for (slots) |s| pool.release(s);
}
