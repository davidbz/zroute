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
zig-out/bin/zroute --listen 0.0.0.0:8080
```

### CLI flags

| Flag | Description |
| --- | --- |
| `--config <path>` | Load configuration from a JSON file. |
| `--listen <host:port>` | Address to listen on. |
| `--max-connections <n>` | Maximum concurrent connections. |

CLI flags override values from a config file, which override compiled-in
defaults.

## Configuration

If no `--config` flag is given, `zroute` looks for `zroute.json` in the
current directory. All fields are optional; only include the ones you want
to override.

```json
{
  "listen_host": "0.0.0.0",
  "listen_port": 8080,
  "max_connections": 8192,
  "dns_servers": ["1.1.1.1", "1.0.0.1"],
  "dns_timeout_ms": 3000
}
```

- `dns_servers` — empty (default) uses the OS resolver (`/etc/resolv.conf`).
  If set, DNS queries go directly to these servers instead.

## Usage

Once running, point a client at the proxy:

```bash
curl -x http://127.0.0.1:8080 http://example.com/
curl -x http://127.0.0.1:8080 https://example.com/   # CONNECT tunnel
```
