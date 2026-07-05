"""End-to-end tests for zroute.

Starts the real zroute binary against small stdlib-only origin/echo servers
on loopback and drives the proxy over raw sockets to check plain HTTP
forwarding, CONNECT tunneling, and egress/port policy enforcement described
in the README. Servers, the Proxy subprocess wrapper, and raw-socket
helpers live in conftest.py.

Run with: uv run pytest test/ [--binary PATH]
"""

from __future__ import annotations

import socket
import time

from conftest import (
    CONNECT_TIMEOUT,
    Proxy,
    base_config,
    connect_tunnel,
    http_get,
    raw_request,
    recv_until_closed,
    split_head_body,
    status_code,
)


def test_plain_http_get(insecure, origin_port):
    resp = http_get(insecure, origin_port, "/hello")
    assert status_code(resp) == 200, resp
    assert resp.endswith(b"hello from origin\n"), resp


def test_plain_http_post_echo(insecure, origin_port):
    body = b"the quick brown fox"
    req = (
        f"POST http://127.0.0.1:{origin_port}/echo HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{origin_port}\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode() + body
    resp = raw_request(insecure.host, insecure.port, req)
    assert status_code(resp) == 200, resp
    assert resp.endswith(body), resp


def test_plain_http_large_body(insecure, origin_port):
    resp = http_get(insecure, origin_port, "/big")
    assert status_code(resp) == 200, resp[:200]
    _, body = split_head_body(resp)
    assert len(body) == 64 * 1024, len(body)
    assert body == (b"0123456789abcdef" * 4096)


def test_plain_http_404_passthrough(insecure, origin_port):
    resp = http_get(insecure, origin_port, "/missing")
    assert status_code(resp) == 404, resp


def test_connect_tunnel_echo(connect_ok, echo):
    sock = connect_tunnel(connect_ok, echo.port)
    try:
        payload = b"ping through tunnel"
        sock.sendall(payload)
        echoed = b""
        while len(echoed) < len(payload):
            echoed += sock.recv(4096)
        assert echoed == payload, echoed
    finally:
        sock.close()


def test_malformed_request_closes_connection(insecure):
    # No well-formed request line: receiveHead() fails before any
    # response can be written - proxy just drops the connection.
    resp = raw_request(insecure.host, insecure.port, b"NOT A REQUEST\r\n\r\n")
    assert resp == b"", resp


def test_egress_denied_loopback_http(secure, origin_port):
    resp = http_get(secure, origin_port, "/hello")
    assert status_code(resp) == 403, resp


def test_egress_denied_loopback_connect(secure, echo):
    resp = raw_request(
        secure.host,
        secure.port,
        f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: 127.0.0.1:{echo.port}\r\n\r\n".encode(),
    )
    assert status_code(resp) == 403, resp


def test_connect_port_not_allowlisted(insecure, echo):
    # insecure allows loopback egress but only the default ports (443, 80);
    # echo's port isn't in connect_allowed_ports so CONNECT must be denied.
    resp = raw_request(
        insecure.host,
        insecure.port,
        f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: 127.0.0.1:{echo.port}\r\n\r\n".encode(),
    )
    assert status_code(resp) == 403, resp


def test_listener_stays_responsive_under_concurrent_tunnels(
    connect_ok, echo, origin_port
):
    # Regression guard: Listener.run dispatches each accepted connection via
    # Io.Group.concurrent specifically so a saturated worker pool never runs
    # a task inline on the accept loop's own thread - which would block
    # accept() for as long as that one connection lives. Long-lived CONNECT
    # tunnels trigger saturation reliably. Open enough concurrent tunnels to
    # exceed the thread pool, then confirm a brand new request still gets
    # served promptly instead of queueing behind them.
    num_tunnels = 50
    sockets = []
    try:
        for _ in range(num_tunnels):
            sockets.append(
                connect_tunnel(connect_ok, echo.port)
            )  # left open idle - ties up a relay thread/task for the rest of the test

        start = time.monotonic()
        resp = http_get(connect_ok, origin_port, "/hello")
        elapsed = time.monotonic() - start

        assert status_code(resp) == 200, resp
        assert elapsed < 2.0, (
            f"accept loop took {elapsed:.2f}s to serve new request with {num_tunnels} tunnels open "
            "- looks like a saturated connection got dispatched inline instead of concurrently"
        )
    finally:
        for sock in sockets:
            sock.close()


def test_upstream_connection_refused(insecure):
    closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed.bind(("127.0.0.1", 0))
    dead_port = closed.getsockname()[1]
    closed.close()  # bound then closed: nothing listens now

    resp = http_get(insecure, dead_port, "/hello")
    assert status_code(resp) == 502, resp


def test_head_timeout_closes_slow_trickle(binary):
    # head_timeout_ms is an absolute cap on the head-parse phase, separate
    # from idle_timeout_ms's sliding inter-byte window. Trickle the request
    # one byte at a time with gaps well under the idle window but whose sum
    # blows past the (short) head deadline - the connection must be torn
    # down before the request is ever fully sent.
    proxy = Proxy(
        binary,
        {**base_config(), "idle_timeout_ms": 5000, "head_timeout_ms": 300},
        "head-timeout-kill",
    )
    try:
        request = b"GET /hello HTTP/1.1\r\nHost: x\r\n\r\n"
        sock = socket.create_connection(
            (proxy.host, proxy.port), timeout=CONNECT_TIMEOUT
        )
        try:
            sent = 0
            try:
                for b in request:
                    sock.sendall(bytes([b]))
                    sent += 1
                    time.sleep(
                        0.05
                    )  # 33 bytes * 50ms ~= 1.65s, past the 300ms head deadline
            except OSError:
                pass  # proxy may have already closed its end

            resp = recv_until_closed(sock)
        finally:
            sock.close()

        assert resp == b"", resp
        assert sent < len(request), (
            f"sent all {len(request)} bytes before the connection closed - "
            "head_timeout_ms doesn't appear to be enforced"
        )
    finally:
        proxy.stop()


def test_head_timeout_does_not_bound_a_slow_request_body(binary, origin_port):
    # Once the head is parsed, head_timeout_ms must be cleared - a slow
    # request body (relayed through the same reader) should only be bound
    # by the generous idle window, never the short head deadline.
    proxy = Proxy(
        binary,
        {
            **base_config(),
            "egress_deny_private": False,
            "idle_timeout_ms": 5000,
            "head_timeout_ms": 300,
        },
        "head-timeout-body-ok",
    )
    try:
        body = b"trickle"
        head = (
            f"POST http://127.0.0.1:{origin_port}/echo HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{origin_port}\r\n"
            f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
        ).encode()
        sock = socket.create_connection(
            (proxy.host, proxy.port), timeout=CONNECT_TIMEOUT
        )
        try:
            sock.sendall(head)  # arrives in one shot, well inside the head deadline
            for b in body:
                sock.sendall(bytes([b]))
                time.sleep(0.05)  # 7 bytes * 50ms = 350ms, past the 300ms head deadline

            resp = recv_until_closed(sock)
        finally:
            sock.close()

        assert status_code(resp) == 200, resp
        assert resp.endswith(body), resp
    finally:
        proxy.stop()


def test_graceful_shutdown_drains_open_tunnel(binary, echo):
    # SIGTERM should stop accepting new connections immediately but let an
    # already-open tunnel keep relaying until it closes on its own, well
    # inside the configured grace period.
    proxy = Proxy(
        binary,
        {
            **base_config(),
            "egress_deny_private": False,
            "connect_allowed_ports": [443, 80, echo.port],
            "shutdown_timeout_ms": 5000,
        },
        "drain-graceful",
    )
    try:
        sock = connect_tunnel(proxy, echo.port)
        try:
            proxy.proc.terminate()  # SIGTERM
            time.sleep(0.2)  # let the signal handler/accept loop react

            payload = b"still alive"
            sock.sendall(payload)
            echoed = b""
            while len(echoed) < len(payload):
                echoed += sock.recv(4096)
            assert echoed == payload, echoed
        finally:
            sock.close()  # closing client-side lets the drain finish; process should
            # exit well before the 5s grace period elapses.
            proxy.proc.wait(timeout=3)
            assert proxy.proc.returncode == 0, proxy.log_path.read_text()
    finally:
        proxy.stop()


def test_shutdown_force_cancels_after_grace_period(binary, echo):
    # A tunnel that never closes on its own should be force-cancelled once
    # the (short, test-configured) grace period elapses - not instantly,
    # not left hanging on the default 30s.
    proxy = Proxy(
        binary,
        {
            **base_config(),
            "egress_deny_private": False,
            "connect_allowed_ports": [443, 80, echo.port],
            "shutdown_timeout_ms": 500,
        },
        "drain-forced",
    )
    try:
        sock = connect_tunnel(proxy, echo.port)
        try:
            start = time.monotonic()
            proxy.proc.terminate()  # SIGTERM
            proxy.proc.wait(timeout=4)
            elapsed = time.monotonic() - start

            assert proxy.proc.returncode == 0, proxy.log_path.read_text()
            assert elapsed >= 0.35, (
                f"exited after {elapsed:.2f}s - looks like it force-cancelled "
                "immediately instead of honoring shutdown_timeout_ms"
            )
            assert elapsed < 3.0, (
                f"exited after {elapsed:.2f}s - looks like it ignored "
                "shutdown_timeout_ms and hung"
            )
        finally:
            sock.close()
    finally:
        proxy.stop()
