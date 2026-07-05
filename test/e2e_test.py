#!/usr/bin/env python3
"""Naive end-to-end test for zroute.

Starts a real zroute binary plus small stdlib-only origin/echo servers on
loopback, then drives the proxy over raw sockets to check a handful of real
use cases: plain HTTP forwarding, CONNECT tunneling, and the egress/port
policy enforcement described in the README.

Standalone usage:
    python3 test/e2e_test.py [--binary PATH]

Defaults to zig-out/bin/zroute relative to the repo root (run `zig build`
first). No third-party dependencies.
"""
from __future__ import annotations

import argparse
import http.server
import json
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = REPO_ROOT / "zig-out" / "bin" / "zroute"

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 5.0


class OriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_GET(self):
        if self.path == "/hello":
            body = b"hello from origin\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/big":
            body = (b"0123456789abcdef" * 4096)  # 64KB, several relay buffers
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"not found\n"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _EchoHandler(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            data = self.connection.recv(4096)
            if not data:
                return
            self.connection.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    """Raw TCP echo server, used as a CONNECT tunnel target."""

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), _EchoHandler)
        self.port = self.server_address[1]
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()
        self._thread.join(timeout=2)


class Proxy:
    """Manages a zroute subprocess with a temp JSON config."""

    def __init__(self, binary: Path, config: dict, name: str):
        self.name = name
        self.config_path = Path(tempfile.mkstemp(suffix=f"-{name}.json")[1])
        self.config_path.write_text(json.dumps(config))
        self.log_path = Path(tempfile.mkstemp(suffix=f"-{name}.log")[1])
        self.host = config["listen_host"]
        self.port = config["listen_port"]
        self._log_file = open(self.log_path, "w")
        self.proc = subprocess.Popen(
            [str(binary), "--config", str(self.config_path)],
            stdout=self._log_file,
            stderr=subprocess.STDOUT,
        )
        self._wait_ready()

    def _wait_ready(self):
        deadline = time.monotonic() + CONNECT_TIMEOUT
        last_err = None
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    f"{self.name}: proxy exited early (code={self.proc.returncode}), "
                    f"log:\n{self.log_path.read_text()}"
                )
            try:
                with socket.create_connection((self.host, self.port), timeout=0.2):
                    return
            except OSError as e:
                last_err = e
                time.sleep(0.05)
        raise RuntimeError(f"{self.name}: proxy never became ready: {last_err}")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
        self._log_file.close()
        self.config_path.unlink(missing_ok=True)
        self.log_path.unlink(missing_ok=True)


# --- raw HTTP helpers over the proxy's TCP socket -------------------------

def raw_request(host: str, port: int, request: bytes, read_timeout: float = READ_TIMEOUT) -> bytes:
    with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
        sock.sendall(request)
        sock.settimeout(read_timeout)
        chunks = []
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        except socket.timeout:
            pass
        return b"".join(chunks)


def status_code(response: bytes) -> int:
    line = response.split(b"\r\n", 1)[0]
    return int(line.split(b" ")[1])


def split_head_body(response: bytes) -> tuple[bytes, bytes]:
    head, _, body = response.partition(b"\r\n\r\n")
    return head, body


def http_get(proxy: Proxy, target_port: int, path: str) -> bytes:
    return raw_request(
        proxy.host, proxy.port,
        f"GET http://127.0.0.1:{target_port}{path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{target_port}\r\nConnection: close\r\n\r\n".encode(),
    )


def connect_tunnel(proxy: Proxy, target_port: int) -> socket.socket:
    sock = socket.create_connection((proxy.host, proxy.port), timeout=CONNECT_TIMEOUT)
    sock.sendall(f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode())
    sock.settimeout(READ_TIMEOUT)
    head = b""
    while b"\r\n\r\n" not in head:
        head += sock.recv(4096)
    assert head.startswith(b"HTTP/1.1 200"), head
    return sock


# --- test cases -------------------------------------------------------------

@dataclass
class TestContext:
    insecure: Proxy       # egress_deny_private=false, reaches loopback origin
    secure: Proxy         # default policy, used to prove SSRF guard fires
    connect_ok: Proxy     # egress_deny_private=false, echo's port allowlisted
    origin_port: int
    echo: EchoServer


def test_plain_http_get(ctx: TestContext):
    resp = http_get(ctx.insecure, ctx.origin_port, "/hello")
    assert status_code(resp) == 200, resp
    assert resp.endswith(b"hello from origin\n"), resp


def test_plain_http_post_echo(ctx: TestContext):
    body = b"the quick brown fox"
    req = (
        f"POST http://127.0.0.1:{ctx.origin_port}/echo HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{ctx.origin_port}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    resp = raw_request(ctx.insecure.host, ctx.insecure.port, req)
    assert status_code(resp) == 200, resp
    assert resp.endswith(body), resp


def test_plain_http_large_body(ctx: TestContext):
    resp = http_get(ctx.insecure, ctx.origin_port, "/big")
    assert status_code(resp) == 200, resp[:200]
    _, body = split_head_body(resp)
    assert len(body) == 64 * 1024, len(body)
    assert body == (b"0123456789abcdef" * 4096)


def test_plain_http_404_passthrough(ctx: TestContext):
    resp = http_get(ctx.insecure, ctx.origin_port, "/missing")
    assert status_code(resp) == 404, resp


def test_connect_tunnel_echo(ctx: TestContext):
    with connect_tunnel(ctx.connect_ok, ctx.echo.port) as sock:
        payload = b"ping through the tunnel"
        sock.sendall(payload)
        echoed = b""
        while len(echoed) < len(payload):
            echoed += sock.recv(4096)
        assert echoed == payload, echoed


def test_malformed_request_closes_connection(ctx: TestContext):
    # No well-formed request line means receiveHead() fails before any
    # response can be written - the proxy just drops the connection.
    resp = raw_request(ctx.insecure.host, ctx.insecure.port, b"NOT A REQUEST\r\n\r\n")
    assert resp == b"", resp


def test_egress_denied_loopback_http(ctx: TestContext):
    resp = http_get(ctx.secure, ctx.origin_port, "/hello")
    assert status_code(resp) == 403, resp


def test_egress_denied_loopback_connect(ctx: TestContext):
    resp = raw_request(
        ctx.secure.host, ctx.secure.port,
        f"CONNECT 127.0.0.1:{ctx.echo.port} HTTP/1.1\r\nHost: 127.0.0.1:{ctx.echo.port}\r\n\r\n".encode(),
    )
    assert status_code(resp) == 403, resp


def test_connect_port_not_allowlisted(ctx: TestContext):
    # insecure proxy allows loopback egress but keeps the default port
    # allowlist ([443, 80]) - the echo server's random port isn't on it.
    resp = raw_request(
        ctx.insecure.host, ctx.insecure.port,
        f"CONNECT 127.0.0.1:{ctx.echo.port} HTTP/1.1\r\nHost: 127.0.0.1:{ctx.echo.port}\r\n\r\n".encode(),
    )
    assert status_code(resp) == 403, resp


def test_listener_stays_responsive_under_concurrent_tunnels(ctx: TestContext):
    # Regression test: Listener.run used to dispatch each connection via
    # Io.Group.async, which silently runs the task inline on the accept
    # loop's own thread once the worker pool is saturated - blocking accept()
    # for as long as that one connection lives. Long-lived CONNECT tunnels
    # trigger this reliably. Open enough concurrent tunnels to exceed the
    # thread pool, then confirm a brand new request still gets served
    # promptly instead of queueing behind them.
    num_tunnels = 50
    sockets = []
    try:
        for _ in range(num_tunnels):
            sockets.append(connect_tunnel(ctx.connect_ok, ctx.echo.port))  # left open and idle - ties up a relay thread/task for the rest of the test

        start = time.monotonic()
        resp = http_get(ctx.connect_ok, ctx.origin_port, "/hello")
        elapsed = time.monotonic() - start

        assert status_code(resp) == 200, resp
        assert elapsed < 2.0, (
            f"accept loop took {elapsed:.2f}s to serve a new request with {num_tunnels} tunnels open "
            "- looks like a saturated connection got dispatched inline instead of concurrently"
        )
    finally:
        for sock in sockets:
            sock.close()


def test_upstream_connection_refused(ctx: TestContext):
    closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed.bind(("127.0.0.1", 0))
    dead_port = closed.getsockname()[1]
    closed.close()  # bound then closed: nothing listens there now

    resp = http_get(ctx.insecure, dead_port, "/hello")
    assert status_code(resp) == 502, resp


TESTS = [
    test_plain_http_get,
    test_plain_http_post_echo,
    test_plain_http_large_body,
    test_plain_http_404_passthrough,
    test_connect_tunnel_echo,
    test_listener_stays_responsive_under_concurrent_tunnels,
    test_malformed_request_closes_connection,
    test_egress_denied_loopback_http,
    test_egress_denied_loopback_connect,
    test_connect_port_not_allowlisted,
    test_upstream_connection_refused,
]


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY, help="path to zroute binary")
    args = parser.parse_args()

    if not args.binary.exists():
        print(f"error: zroute binary not found at {args.binary} (run `zig build` first)", file=sys.stderr)
        return 1

    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    origin_port = origin.server_address[1]

    echo = EchoServer()

    def base_config() -> dict:
        return {
            "listen_host": "127.0.0.1",
            "listen_port": find_free_port(),
            "max_connections": 64,
            "dns_servers": [],
            "dns_timeout_ms": 3000,
            "idle_timeout_ms": 5000,
            "egress_deny_private": True,
            "egress_allow": [],
            "connect_allowed_ports": [443, 80],
        }

    insecure = Proxy(args.binary, {**base_config(), "egress_deny_private": False}, "insecure")
    secure = Proxy(args.binary, base_config(), "secure")
    connect_ok = Proxy(args.binary, {
        **base_config(),
        "egress_deny_private": False,
        "connect_allowed_ports": [443, 80, echo.port],
    }, "connect-ok")

    ctx = TestContext(insecure=insecure, secure=secure, connect_ok=connect_ok, origin_port=origin_port, echo=echo)

    failures = []
    try:
        for test in TESTS:
            name = test.__name__
            try:
                test(ctx)
                print(f"ok   {name}")
            except AssertionError as e:
                failures.append(name)
                print(f"FAIL {name}: {e}")
            except Exception as e:
                failures.append(name)
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    finally:
        insecure.stop()
        secure.stop()
        connect_ok.stop()
        echo.stop()
        origin.shutdown()
        origin_thread.join(timeout=2)

    if failures:
        print(f"\n{len(failures)}/{len(TESTS)} failed: {', '.join(failures)}", file=sys.stderr)
        return 1

    print(f"\nall {len(TESTS)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
