# zroute

A lightweight HTTP forward proxy written in Zig 0.16.0. Proxies plain HTTP
requests directly and tunnels HTTPS via `CONNECT` (opaque byte splicing, no
TLS termination). Built on Zig's `std.Io` interface with a data-oriented,
fixed-capacity connection pool and no per-connection heap allocation.

## Requirements

- Zig 0.16.0

## Build

```bash
zig build              # compiles to zig-out/bin/zroute
zig build test         # run unit tests
zig build check        # fast compile-only check, no binary written
```

## Run

```bash
zig build run -- --listen 127.0.0.1:8080
```

Or run the compiled binary directly:

```bash
zig-out/bin/zroute --listen 127.0.0.1:8080
```

`zroute` binds loopback-only by default. Binding to `0.0.0.0` (or any other
routable address) exposes the proxy to the network — since there's no
built-in authentication, only do this on a network you trust, or in front of
your own access control (see [Security defaults](#security-defaults)):

```bash
zig-out/bin/zroute --listen 0.0.0.0:8080
```

### CLI flags

| Flag | Description |
| --- | --- |
| `--config <path>` | Load configuration from a JSON file. |
| `--listen <host:port>` | Address to listen on. |
| `--max-connections <n>` | Maximum concurrent connections. |
| `--metrics-interval-ms <n>` | Log a metrics snapshot every `n` ms. `0` (default) disables it. |
| `--idle-timeout-ms <n>` | Tear down a connection after `n` ms with no bytes read (slowloris defense). `0` disables idle enforcement. |

CLI flags override values from a config file, which override compiled-in
defaults.

## Configuration

If no `--config` flag is given, `zroute` looks for `zroute.json` in the
current directory. All fields are optional; only include the ones you want
to override.

```json
{
  "listen_host": "127.0.0.1",
  "listen_port": 8080,
  "max_connections": 8192,
  "dns_servers": ["1.1.1.1", "1.0.0.1"],
  "dns_timeout_ms": 3000,
  "metrics_interval_ms": 0,
  "idle_timeout_ms": 60000,
  "egress_deny_private": true,
  "egress_allow": [],
  "connect_allowed_ports": [443, 80]
}
```

- `dns_servers` — empty (default) uses the OS resolver (`/etc/resolv.conf`).
  If set, DNS queries go directly to these servers instead.
- `idle_timeout_ms` — max gap between bytes on a client or upstream
  connection before it's torn down as stalled (slowloris defense). `0`
  disables idle enforcement entirely.

## Security defaults

`zroute` has no authentication of its own, so its network exposure and the
set of destinations it will proxy to are the only things standing between a
client that can reach the listener and an SSRF pivot into internal
infrastructure. Three defaults address that:

- **`listen_host` defaults to `127.0.0.1`.** Binding to a routable address —
  `0.0.0.0` or a specific interface — is an explicit opt-in via
  `--listen <host:port>` or the `listen_host` config field. There is no
  built-in authentication, so a publicly reachable listener is an open relay
  for anyone who can reach it.

- **`egress_deny_private` (default `true`) blocks proxying to internal
  address ranges.** This applies to both `CONNECT` tunnels and plain HTTP
  forwarding, and — critically — to the *resolved* IP address, not just the
  hostname in the request. Checking only the hostname would let an attacker
  bypass the filter via DNS rebinding (resolving an innocuous-looking name to
  an internal IP after the check). Denied by default:
  - loopback (`127.0.0.0/8`, `::1`)
  - link-local, including the `169.254.169.254` cloud metadata endpoint
    (`169.254.0.0/16`, `fe80::/10`)
  - private ranges (RFC1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`;
    IPv6 ULA `fc00::/7`)
  - multicast (`224.0.0.0/4`, `ff00::/8`)

  A denied target gets a `403 Forbidden` and increments the `egress_denied`
  metric. Set `egress_deny_private: false` to run `zroute` as a fully
  unrestricted proxy — **this is the insecure choice**; only do it if the
  proxy's network is already trusted/isolated. To carve out a specific
  exception without disabling the whole policy, add its CIDR to
  `egress_allow` (e.g. `"10.0.0.0/8"` to permit one internal range while
  still denying loopback/link-local/etc.).

- **`connect_allowed_ports` (default `[443, 80]`) restricts which ports a
  `CONNECT` tunnel may target.** This only applies to `CONNECT`; plain HTTP
  forwarding is scoped by the egress deny check alone. Without it, `CONNECT`
  can be used to reach arbitrary TCP services (SMTP relays on 25, internal
  admin ports, etc.) through the proxy. An empty list disables the
  allowlist and permits any port — **the insecure choice**. A rejected port
  also gets `403 Forbidden` and increments `egress_denied`.

## Usage

Once running, point a client at the proxy:

```bash
curl -x http://127.0.0.1:8080 http://example.com/
curl -x http://127.0.0.1:8080 https://example.com/   # CONNECT tunnel
```
