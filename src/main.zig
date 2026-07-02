const std = @import("std");
const Io = std.Io;

const zroute = @import("zroute");

pub fn main(init: std.process.Init) !void {
    const gpa = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(gpa);
    const cfg = try zroute.config.load(gpa, init.io, argv[1..]);

    // `Io.Uring` doesn't type-check against this target in this Zig 0.16.0
    // stdlib build (several `Dir` ops return mismatched error sets) and its
    // network vtable entries are separately stubbed to fail — `Io.Threaded`
    // is the only backend that can run a TCP proxy today.
    var threaded: Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var node_prefix_bytes: [8]u8 = undefined;
    Io.random(io, &node_prefix_bytes);
    const node_prefix = std.mem.readInt(u64, &node_prefix_bytes, .little);

    var telemetry: zroute.Telemetry = .init(node_prefix);

    var metrics_group: Io.Group = .init;
    if (cfg.metricsInterval()) |interval| {
        metrics_group.async(io, zroute.telemetry.reporter.run, .{ &telemetry.metrics, interval, io });
    }

    var pool: zroute.ConnectionPool = try .init(gpa, cfg.max_connections);

    const dns_servers = try gpa.alloc(Io.net.IpAddress, cfg.dns_servers.len);
    for (cfg.dns_servers, 0..) |server, i| {
        dns_servers[i] = try Io.net.IpAddress.parse(server, 53);
    }
    const resolver = zroute.resolver.Resolver.init(dns_servers, cfg.dnsTimeout());

    const deps: zroute.connection.Deps = .{
        .pool = &pool,
        .telemetry = &telemetry,
        .resolver = resolver,
    };

    const listen_address = try cfg.listenAddress();
    var proxy_listener: zroute.listener.Listener = try .init(listen_address, io, &pool, &telemetry, deps);

    const resolver_name: []const u8 = if (cfg.dns_servers.len == 0) "system" else "custom";
    std.log.info("zroute listening on {s}:{d} backend=threaded capacity={d} resolver={s}", .{
        cfg.listen_host, cfg.listen_port, cfg.max_connections, resolver_name,
    });

    proxy_listener.run(io);
}
