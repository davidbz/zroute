"""Shared e2e test infra: stdlib-only origin/echo servers, a Proxy subprocess
wrapper, raw-socket HTTP/CONNECT helpers, and pytest fixtures wiring them
together. No third-party dependencies beyond pytest itself.
"""

from __future__ import annotations

import http.server
import json
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = REPO_ROOT / "zig-out" / "bin" / "zroute"

CONNECT_TIMEOUT = 5.0
READ_TIMEOUT = 5.0


class OriginHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:
        pass

    def do_GET(self):
        if self.path == "/hello":
            body = b"hello from origin\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/big":
            body = b"0123456789abcdef" * 4096  # 64KB, several relay buffers
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
        self._log_file = open(self.log_path, "w")  # noqa: SIM115 — kept open for the process's lifetime
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


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- raw HTTP helpers over the proxy's TCP socket -------------------------


def raw_request(
    host: str, port: int, request: bytes, read_timeout: float = READ_TIMEOUT
) -> bytes:
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
        except TimeoutError:
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
        proxy.host,
        proxy.port,
        f"GET http://127.0.0.1:{target_port}{path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{target_port}\r\nConnection: close\r\n\r\n".encode(),
    )


def connect_tunnel(proxy: Proxy, target_port: int) -> socket.socket:
    sock = socket.create_connection((proxy.host, proxy.port), timeout=CONNECT_TIMEOUT)
    sock.sendall(
        f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode()
    )
    sock.settimeout(READ_TIMEOUT)
    head = b""
    while b"\r\n\r\n" not in head:
        head += sock.recv(4096)
    assert head.startswith(b"HTTP/1.1 200"), head
    return sock


# --- fixtures ---------------------------------------------------------------


def pytest_addoption(parser):
    parser.addoption(
        "--binary", type=Path, default=DEFAULT_BINARY, help="path to zroute binary"
    )


@pytest.fixture(scope="session")
def binary(request) -> Path:
    path = request.config.getoption("--binary")
    if not path.exists():
        pytest.exit(f"zroute binary not found at {path} (run `zig build` first)")
    return path


@pytest.fixture(scope="session")
def origin():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), OriginHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    thread.join(timeout=2)


@pytest.fixture(scope="session")
def origin_port(origin) -> int:
    return origin.server_address[1]


@pytest.fixture(scope="session")
def echo():
    server = EchoServer()
    yield server
    server.stop()


@pytest.fixture(scope="session")
def insecure(binary):
    proxy = Proxy(binary, {**base_config(), "egress_deny_private": False}, "insecure")
    yield proxy
    proxy.stop()


@pytest.fixture(scope="session")
def secure(binary):
    proxy = Proxy(binary, base_config(), "secure")
    yield proxy
    proxy.stop()


@pytest.fixture(scope="session")
def connect_ok(binary, echo):
    proxy = Proxy(
        binary,
        {
            **base_config(),
            "egress_deny_private": False,
            "connect_allowed_ports": [443, 80, echo.port],
        },
        "connect-ok",
    )
    yield proxy
    proxy.stop()
