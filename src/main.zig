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

    var pool: zroute.ConnectionPool = try .init(gpa, cfg.max_connections);

    const dns_servers = try gpa.alloc(Io.net.IpAddress, cfg.dns_servers.len);
    for (cfg.dns_servers, 0..) |server, i| {
        dns_servers[i] = try Io.net.IpAddress.parse(server, 53);
    }
    const resolver = zroute.resolver.Resolver.init(dns_servers, cfg.dnsTimeout());
    const egress_policy = try cfg.egressPolicy(gpa);

    const deps: zroute.connection.Deps = .{
        .pool = &pool,
        .telemetry = &telemetry,
        .resolver = resolver,
        .idle_timeout = cfg.idleTimeout(),
        .head_timeout = cfg.headTimeout(),
        .egress_policy = egress_policy,
    };

    const listen_address = try cfg.listenAddress();
    var proxy_listener: zroute.listener.Listener = try .init(listen_address, io, &pool, &telemetry, deps);
    zroute.shutdown.install(proxy_listener.server.socket.handle);

    std.log.info("zroute listening on {s}:{d} backend=threaded capacity={d} resolver={s} egress_deny_private={} connect_port_allowlist_len={d}", .{
        cfg.listen_host, cfg.listen_port, cfg.max_connections, resolver.kindName(), cfg.egress_deny_private, cfg.connect_allowed_ports.len,
    });

    proxy_listener.run(io);

    std.log.info("shutdown requested, draining up to {d}ms", .{cfg.shutdown_timeout_ms});
    const poll_interval_ms = 50;
    var waited_ms: u64 = 0;
    while (!pool.isDrained() and waited_ms < cfg.shutdown_timeout_ms) {
        Io.sleep(io, .fromMilliseconds(poll_interval_ms), .awake) catch {};
        waited_ms += poll_interval_ms;
    }
    if (!pool.isDrained()) {
        std.log.warn("drain timeout exceeded, force-cancelling remaining connections", .{});
    }
    proxy_listener.deinit(io);
    pool.deinit(gpa);
}
