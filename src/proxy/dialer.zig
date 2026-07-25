const std = @import("std");
const Io = std.Io;
const net = Io.net;
const HostName = net.HostName;
const Resolver = @import("resolver.zig").Resolver;
const egress = @import("egress.zig");

/// Resolves `host`, then connects to the first candidate address that
/// passes `policy`. The deny check runs against the *resolved* IP, not
/// the hostname — a DNS answer that rebinds a public-looking name to a
/// denied range (loopback/link-local/RFC1918/ULA/multicast) is caught
/// here, not before resolution, where a DNS-rebind bypass would slip
/// past a hostname-only check.
///
/// `error.EgressDenied` means every resolved address was denied by
/// policy. If at least one address passed the policy but none of them
/// could be connected to, `error.AllConnectAttemptsFailed` is returned.
pub fn connect(resolver: Resolver, host: HostName, io: Io, port: u16, options: net.IpAddress.ConnectOptions, policy: egress.Policy) !net.Stream {
    var addr_buf: [16]net.IpAddress = undefined;
    const addrs = try resolver.resolveAddresses(io, host, &addr_buf);

    var any_allowed = false;
    for (addrs) |addr| {
        if (!policy.allowsTarget(addr)) continue;
        any_allowed = true;
        var a = addr;
        a.setPort(port);
        return net.IpAddress.connect(&a, io, options) catch continue;
    }
    if (!any_allowed) return error.EgressDenied;
    return error.AllConnectAttemptsFailed;
}
