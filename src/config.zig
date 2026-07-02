const std = @import("std");
const Io = std.Io;

pub const Config = struct {
    listen_host: []const u8 = "0.0.0.0",
    listen_port: u16 = 8080,
    max_connections: u32 = 8192,
    /// Empty = use the OS resolver (/etc/resolv.conf) as-is. Non-empty =
    /// switch to the custom UDP resolver, querying only these servers.
    dns_servers: []const []const u8 = &.{},
    dns_timeout_ms: u64 = 3_000,
    /// 0 = disabled: no periodic metrics snapshot is logged. Non-zero starts
    /// a background task that logs one snapshot line every this many ms.
    metrics_interval_ms: u64 = 0,
    /// Max gap between bytes on a client or upstream connection before it is
    /// torn down as stalled (slowloris defense). 0 disables idle enforcement
    /// entirely, restoring unbounded blocking reads.
    idle_timeout_ms: u64 = 60_000,

    pub fn listenAddress(cfg: Config) !Io.net.IpAddress {
        return Io.net.IpAddress.parse(cfg.listen_host, cfg.listen_port);
    }

    pub fn dnsTimeout(cfg: Config) Io.Timeout {
        return msTimeout(cfg.dns_timeout_ms);
    }

    pub fn metricsInterval(cfg: Config) ?Io.Timeout {
        if (cfg.metrics_interval_ms == 0) return null;
        return msTimeout(cfg.metrics_interval_ms);
    }

    pub fn idleTimeout(cfg: Config) Io.Timeout {
        if (cfg.idle_timeout_ms == 0) return .none;
        return msTimeout(cfg.idle_timeout_ms);
    }

    fn msTimeout(ms: u64) Io.Timeout {
        return .{ .duration = .{ .raw = .fromMilliseconds(@intCast(ms)), .clock = .awake } };
    }
};

pub const ParseError = error{ InvalidArgument, InvalidPort, InvalidNumber, ConfigFileInvalid } || Io.File.OpenError || Io.Reader.LimitedAllocError || std.mem.Allocator.Error;

/// Loads config from (in override order) compiled-in defaults, an optional
/// JSON file, then CLI flags. `args` excludes argv[0].
pub fn load(gpa: std.mem.Allocator, io: Io, args: []const []const u8) ParseError!Config {
    var cfg: Config = .{};

    const config_path = findConfigPathArg(args) orelse defaultConfigPathIfExists(io);
    if (config_path) |path| {
        try applyConfigFile(gpa, io, &cfg, path);
    }

    try applyArgs(&cfg, args);
    return cfg;
}

fn findConfigPathArg(args: []const []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (!std.mem.eql(u8, args[i], "--config")) continue;
        if (i + 1 >= args.len) return null;
        return args[i + 1];
    }
    return null;
}

fn defaultConfigPathIfExists(io: Io) ?[]const u8 {
    const default_path = "zroute.json";
    Io.Dir.cwd().access(io, default_path, .{}) catch return null;
    return default_path;
}

fn applyConfigFile(gpa: std.mem.Allocator, io: Io, cfg: *Config, path: []const u8) ParseError!void {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var small_buf: [1024]u8 = undefined;
    var file_reader: Io.File.Reader = .init(file, io, &small_buf);
    const contents = try file_reader.interface.allocRemaining(gpa, .limited(1024 * 1024));
    defer gpa.free(contents);

    const parsed = std.json.parseFromSlice(Config, gpa, contents, .{ .ignore_unknown_fields = true }) catch return error.ConfigFileInvalid;
    defer parsed.deinit();
    cfg.* = try dupeConfig(gpa, parsed.value);
}

fn dupeConfig(gpa: std.mem.Allocator, src: Config) !Config {
    var dst = src;
    dst.listen_host = try gpa.dupe(u8, src.listen_host);
    const servers = try gpa.alloc([]const u8, src.dns_servers.len);
    for (src.dns_servers, 0..) |server, i| servers[i] = try gpa.dupe(u8, server);
    dst.dns_servers = servers;
    return dst;
}

/// Guard-clause flag loop: each recognized flag overrides the current
/// value (already seeded from defaults and/or the config file); unknown
/// flags return an error immediately.
fn applyArgs(cfg: *Config, args: []const []const u8) ParseError!void {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "--config")) {
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "--listen")) {
            i += 1;
            if (i >= args.len) return error.InvalidArgument;
            try applyListenSpec(cfg, args[i]);
            continue;
        }
        if (std.mem.eql(u8, arg, "--max-connections")) {
            i += 1;
            if (i >= args.len) return error.InvalidArgument;
            cfg.max_connections = std.fmt.parseInt(u32, args[i], 10) catch return error.InvalidNumber;
            continue;
        }
        if (std.mem.eql(u8, arg, "--metrics-interval-ms")) {
            i += 1;
            if (i >= args.len) return error.InvalidArgument;
            cfg.metrics_interval_ms = std.fmt.parseInt(u64, args[i], 10) catch return error.InvalidNumber;
            continue;
        }
        if (std.mem.eql(u8, arg, "--idle-timeout-ms")) {
            i += 1;
            if (i >= args.len) return error.InvalidArgument;
            cfg.idle_timeout_ms = std.fmt.parseInt(u64, args[i], 10) catch return error.InvalidNumber;
            continue;
        }
        return error.InvalidArgument;
    }
}

/// `spec` is "host:port". Overrides only what's present.
fn applyListenSpec(cfg: *Config, spec: []const u8) ParseError!void {
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.InvalidArgument;
    if (colon == 0 or colon == spec.len - 1) return error.InvalidArgument;
    cfg.listen_host = spec[0..colon];
    cfg.listen_port = std.fmt.parseInt(u16, spec[colon + 1 ..], 10) catch return error.InvalidPort;
}

test "applyArgs overrides listen spec" {
    var cfg: Config = .{};
    try applyArgs(&cfg, &.{ "--listen", "127.0.0.1:3128" });
    try std.testing.expectEqualStrings("127.0.0.1", cfg.listen_host);
    try std.testing.expectEqual(@as(u16, 3128), cfg.listen_port);
}

test "applyArgs rejects unknown flag" {
    var cfg: Config = .{};
    try std.testing.expectError(error.InvalidArgument, applyArgs(&cfg, &.{"--bogus"}));
}

test "applyArgs rejects malformed listen spec" {
    var cfg: Config = .{};
    try std.testing.expectError(error.InvalidArgument, applyArgs(&cfg, &.{ "--listen", "no-colon" }));
}
