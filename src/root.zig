//! Public re-export surface for the zroute module. main.zig depends only on
//! this file; nothing here does any work itself.
const std = @import("std");

pub const config = @import("config.zig");

pub const telemetry = @import("telemetry/telemetry.zig");

pub const pool = @import("proxy/pool.zig");
pub const target = @import("proxy/target.zig");
pub const resolver = @import("proxy/resolver.zig");
pub const relay = @import("proxy/relay.zig");
pub const proxy_log = @import("proxy/log.zig");
pub const forward = @import("proxy/forward.zig");
pub const tunnel = @import("proxy/tunnel.zig");
pub const connection = @import("proxy/connection.zig");
pub const listener = @import("proxy/listener.zig");

pub const Config = config.Config;
pub const ConnectionPool = pool.ConnectionPool;
pub const Telemetry = telemetry.Telemetry;

test {
    std.testing.refAllDecls(@This());
}
