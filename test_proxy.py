import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

import proxy

HERE = os.path.dirname(os.path.abspath(__file__))


# ---------- helpers -------------------------------------------------------
def serve(handler, family=socket.AF_INET, host="127.0.0.1"):
    """Start a throwaway TCP server running handler(conn) per connection."""
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, 0))
    srv.listen(128)

    def loop():
        while True:
            try:
                c, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(c,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv


def echo(conn):
    with conn:
        while True:
            d = conn.recv(4096)
            if not d:
                return
            conn.sendall(d)


def reply_after_eof(conn):
    """Reads until the client half-closes, then answers. Needs half-close support."""
    with conn:
        buf = b""
        while True:
            d = conn.recv(4096)
            if not d:
                break
            buf += d
        conn.sendall(b"got:" + buf)


@pytest.fixture
def proxy_addr():
    server = proxy.make_server("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address
    server.shutdown()
    server.server_close()


def auth(sock, user=b"user", pw=b"pass"):
    sock.sendall(b"\x05\x01\x02")
    assert sock.recv(2) == b"\x05\x02"
    sock.sendall(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
    return sock.recv(2)


def request(sock, cmd, atyp, addr_bytes, port):
    sock.sendall(struct.pack("!BBBB", 5, cmd, 0, atyp) + addr_bytes + struct.pack("!H", port))


def read_reply(sock):
    head = b""
    while len(head) < 4:
        head += sock.recv(4 - len(head))
    atyp = head[3]
    n = {1: 4, 4: 16}[atyp] + 2
    body = b""
    while len(body) < n:
        body += sock.recv(n - len(body))
    return head[1]


def open_tunnel(proxy_addr, target, atyp=1):
    s = socket.create_connection(proxy_addr, timeout=5)
    assert auth(s) == b"\x01\x00"
    host, port = target
    if atyp == 1:
        request(s, 1, 1, socket.inet_aton(host), port)
    elif atyp == 3:
        request(s, 1, 3, bytes([len(host)]) + host.encode(), port)
    else:
        request(s, 1, 4, socket.inet_pton(socket.AF_INET6, host), port)
    return s, read_reply(s)


# ---------- tests ---------------------------------------------------------
def test_connect_ipv4_echo(proxy_addr):
    srv = serve(echo)
    s, rep = open_tunnel(proxy_addr, srv.getsockname())
    assert rep == 0
    s.sendall(b"hello")
    assert s.recv(5) == b"hello"


def test_connect_domain_name(proxy_addr):
    srv = serve(echo)
    s, rep = open_tunnel(proxy_addr, ("localhost", srv.getsockname()[1]), atyp=3)
    assert rep == 0
    s.sendall(b"ping")
    assert s.recv(4) == b"ping"


def test_connect_ipv6():
    try:
        srv = serve(echo, socket.AF_INET6, "::1")
    except OSError:
        pytest.skip("no IPv6 loopback")
    server = proxy.make_server("127.0.0.1", 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        s, rep = open_tunnel(server.server_address, ("::1", srv.getsockname()[1]), atyp=4)
        assert rep == 0
        s.sendall(b"v6")
        assert s.recv(2) == b"v6"
    finally:
        server.shutdown()
        server.server_close()


def test_bad_password_rejected(proxy_addr):
    s = socket.create_connection(proxy_addr, timeout=5)
    assert auth(s, pw=b"wrong") == b"\x01\x01"
    assert s.recv(1) == b""          # proxy closed the connection


def test_no_acceptable_auth_method(proxy_addr):
    s = socket.create_connection(proxy_addr, timeout=5)
    s.sendall(b"\x05\x01\x00")       # offers only "no auth"
    assert s.recv(2) == b"\x05\xff"


def test_bind_command_not_supported(proxy_addr):
    s = socket.create_connection(proxy_addr, timeout=5)
    assert auth(s) == b"\x01\x00"
    request(s, 2, 1, socket.inet_aton("127.0.0.1"), 80)
    assert read_reply(s) == proxy.REP_COMMAND_NOT_SUPPORTED


def test_unknown_address_type(proxy_addr):
    s = socket.create_connection(proxy_addr, timeout=5)
    assert auth(s) == b"\x01\x00"
    s.sendall(struct.pack("!BBBB", 5, 1, 0, 9))
    assert read_reply(s) == proxy.REP_ADDRESS_TYPE_NOT_SUPPORTED


def test_connection_refused(proxy_addr):
    tmp = socket.socket()
    tmp.bind(("127.0.0.1", 0))
    port = tmp.getsockname()[1]
    tmp.close()                      # nothing listens here now
    s, rep = open_tunnel(proxy_addr, ("127.0.0.1", port))
    assert rep == proxy.REP_CONNECTION_REFUSED


def test_handshake_split_across_tiny_packets(proxy_addr):
    """TCP may deliver a message in pieces; parsing must not assume full reads."""
    srv = serve(echo)
    host, port = srv.getsockname()
    s = socket.create_connection(proxy_addr, timeout=5)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    msg = (b"\x05\x01\x02" + b"\x01\x04user\x04pass" +
           struct.pack("!BBBB", 5, 1, 0, 1) + socket.inet_aton(host) + struct.pack("!H", port))
    for b in msg:
        s.sendall(bytes([b]))
        time.sleep(0.005)
    assert s.recv(2) == b"\x05\x02"
    assert s.recv(2) == b"\x01\x00"
    assert read_reply(s) == 0
    s.sendall(b"ok")
    assert s.recv(2) == b"ok"


def test_half_close_returns_full_response(proxy_addr):
    srv = serve(reply_after_eof)
    s, rep = open_tunnel(proxy_addr, srv.getsockname())
    assert rep == 0
    s.sendall(b"request")
    s.shutdown(socket.SHUT_WR)       # "I'm done sending" - must not truncate the reply
    data = b""
    while chunk := s.recv(4096):
        data += chunk
    assert data == b"got:request"


def test_large_transfer_integrity(proxy_addr):
    srv = serve(echo)
    s, rep = open_tunnel(proxy_addr, srv.getsockname())
    assert rep == 0
    payload = os.urandom(2_000_000)
    received = bytearray()
    t = threading.Thread(target=lambda: s.sendall(payload))
    t.start()
    while len(received) < len(payload):
        chunk = s.recv(65536)
        assert chunk
        received += chunk
    t.join()
    assert bytes(received) == payload


def test_concurrent_tunnels(proxy_addr):
    srv = serve(echo)
    socks = []
    for _ in range(150):
        s, rep = open_tunnel(proxy_addr, srv.getsockname())
        assert rep == 0
        socks.append(s)
    for i, s in enumerate(socks):    # all 150 tunnels are open simultaneously
        s.sendall(b"%03d" % i)
    for i, s in enumerate(socks):
        assert s.recv(3) == b"%03d" % i


def test_ip_whitelist_drops_unlisted_client(monkeypatch, proxy_addr):
    monkeypatch.setattr(proxy, "ALLOWED_IPS", {"10.9.9.9"})
    s = socket.create_connection(proxy_addr, timeout=5)
    s.sendall(b"\x05\x01\x02")
    assert s.recv(2) == b""          # closed without a greeting reply


@pytest.mark.parametrize("sig", [signal.SIGTERM, signal.SIGINT])
def test_graceful_shutdown_on_signal(sig):
    """Regression: calling server.shutdown() inside the signal handler deadlocks."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = dict(os.environ, SOCKS_PORT=str(port), SOCKS_HOST="127.0.0.1")
    p = subprocess.Popen([sys.executable, os.path.join(HERE, "proxy.py")], env=env,
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        assert b"listening" in p.stdout.readline()
        p.send_signal(sig)
        assert p.wait(timeout=5) == 0
    finally:
        if p.poll() is None:
            p.kill()
