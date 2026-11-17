"""SOCKS5 proxy (RFC 1928) with username/password auth (RFC 1929).

Thread-per-connection, with an epoll/kqueue-based relay (selectors) so that
high file-descriptor numbers do not break the data path. Only CONNECT is
supported. Configuration comes from environment variables (see below).
"""
import hmac
import logging
import os
import selectors
import signal
import socket
import struct
import sys
import threading
import time
from socketserver import StreamRequestHandler, ThreadingMixIn, TCPServer

SOCKS_VERSION = 5

# --- configuration (environment variables, with safe-for-local-testing defaults)
HOST = os.environ.get("SOCKS_HOST", "0.0.0.0")
PORT = int(os.environ.get("SOCKS_PORT", "9000"))
USERNAME = os.environ.get("SOCKS_USER", "user")
PASSWORD = os.environ.get("SOCKS_PASS", "pass")
# Comma-separated; empty string means "allow everyone".
ALLOWED_IPS = {ip for ip in os.environ.get("SOCKS_ALLOWED_IPS", "127.0.0.1").split(",") if ip}
LOG_FILE = os.environ.get("SOCKS_LOG")  # default: log to stderr

HANDSHAKE_TIMEOUT = 30    # seconds to finish the SOCKS handshake
CONNECT_TIMEOUT = 10      # seconds to reach the target
IDLE_TIMEOUT = 300        # seconds of silence before a tunnel is torn down
BUFSIZE = 65536

# RFC 1928 reply codes
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

log = logging.getLogger("socks5")


def recv_exact(sock, n):
    """Read exactly n bytes (TCP may deliver fewer per recv call)."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("peer closed during handshake")
        buf += chunk
    return bytes(buf)


def make_reply(rep, bound=None):
    """Build a SOCKS5 reply. `bound` is the (host, port, family) of our outgoing socket."""
    if bound is None:
        return struct.pack("!BBBB4sH", SOCKS_VERSION, rep, 0, 1, b"\x00" * 4, 0)
    host, port, family = bound
    if family == socket.AF_INET6:
        return struct.pack("!BBBB16sH", SOCKS_VERSION, rep, 0, 4,
                           socket.inet_pton(socket.AF_INET6, host), port)
    return struct.pack("!BBBB4sH", SOCKS_VERSION, rep, 0, 1,
                       socket.inet_pton(socket.AF_INET, host), port)


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    allow_reuse_address = True
    daemon_threads = True  # don't let live tunnels block process exit
    request_queue_size = 1024  # default is 5: bursts of connections get SYN-dropped


class SocksProxy(StreamRequestHandler):
    def handle(self):
        client_ip = self.client_address[0]
        if ALLOWED_IPS and client_ip not in ALLOWED_IPS:
            log.warning("dropped %s: not in whitelist", client_ip)
            return

        conn = self.connection
        conn.settimeout(HANDSHAKE_TIMEOUT)
        remote = None
        try:
            ver, nmethods = struct.unpack("!BB", recv_exact(conn, 2))
            if ver != SOCKS_VERSION:
                return
            methods = recv_exact(conn, nmethods)
            if 2 not in methods:                       # only user/pass accepted
                conn.sendall(struct.pack("!BB", SOCKS_VERSION, 0xFF))
                return
            conn.sendall(struct.pack("!BB", SOCKS_VERSION, 2))
            if not self.verify_credentials():
                return

            ver, cmd, _, atyp = struct.unpack("!BBBB", recv_exact(conn, 4))
            if ver != SOCKS_VERSION:
                return
            if atyp == 1:
                host = socket.inet_ntoa(recv_exact(conn, 4))
            elif atyp == 3:
                length = recv_exact(conn, 1)[0]
                host = recv_exact(conn, length).decode("ascii", errors="strict")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(conn, 16))
            else:
                conn.sendall(make_reply(REP_ADDRESS_TYPE_NOT_SUPPORTED))
                return
            port = struct.unpack("!H", recv_exact(conn, 2))[0]

            if cmd != 1:                               # BIND / UDP ASSOCIATE
                conn.sendall(make_reply(REP_COMMAND_NOT_SUPPORTED))
                return

            try:
                remote = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
            except ConnectionRefusedError:
                conn.sendall(make_reply(REP_CONNECTION_REFUSED))
                return
            except (socket.gaierror, socket.timeout, TimeoutError):
                conn.sendall(make_reply(REP_HOST_UNREACHABLE))
                return
            except OSError as err:
                log.error("connect to %s:%s failed: %s", host, port, err)
                conn.sendall(make_reply(REP_GENERAL_FAILURE))
                return

            bhost, bport = remote.getsockname()[:2]
            conn.sendall(make_reply(REP_SUCCESS, (bhost, bport, remote.family)))
            log.info("tunnel %s -> %s:%s", client_ip, host, port)

            conn.settimeout(None)
            remote.settimeout(None)
            self.relay(conn, remote)
        except (ConnectionError, struct.error, UnicodeDecodeError, socket.timeout) as err:
            log.warning("handshake aborted for %s: %s", client_ip, err)
        finally:
            if remote is not None:
                remote.close()

    def verify_credentials(self):
        conn = self.connection
        ver = recv_exact(conn, 1)[0]
        if ver != 1:
            return False
        user = recv_exact(conn, recv_exact(conn, 1)[0])
        pw = recv_exact(conn, recv_exact(conn, 1)[0])
        ok = hmac.compare_digest(user, USERNAME.encode()) & hmac.compare_digest(pw, PASSWORD.encode())
        conn.sendall(struct.pack("!BB", 1, 0 if ok else 1))
        if not ok:
            log.warning("auth failed from %s", self.client_address[0])
        return ok

    def relay(self, client, remote):
        """Shuttle bytes both ways. An EOF on one side half-closes the other, so
        a client that sends a request and shuts down its write side still gets
        the full response."""
        started = time.time()
        up = down = 0
        sel = selectors.DefaultSelector()
        sel.register(client, selectors.EVENT_READ, remote)
        sel.register(remote, selectors.EVENT_READ, client)
        try:
            while sel.get_map():
                events = sel.select(timeout=IDLE_TIMEOUT)
                if not events:
                    log.info("idle timeout for %s", self.client_address[0])
                    break
                for key, _ in events:
                    src, dst = key.fileobj, key.data
                    data = src.recv(BUFSIZE)
                    if not data:                       # EOF: propagate as half-close
                        sel.unregister(src)
                        try:
                            dst.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        continue
                    dst.sendall(data)
                    if src is client:
                        up += len(data)
                    else:
                        down += len(data)
        except OSError as err:                         # reset by peer, broken pipe, ...
            log.info("relay ended: %s", err)
        finally:
            sel.close()
            log.info("closed %s duration=%.2fs up=%d down=%d",
                     self.client_address[0], time.time() - started, up, down)


def make_server(host=HOST, port=PORT):
    return ThreadingTCPServer((host, port), SocksProxy)


def main():
    logging.basicConfig(level=logging.INFO, filename=LOG_FILE,
                        format="%(asctime)s %(levelname)s %(message)s")
    server = make_server()
    stop = threading.Event()

    def on_signal(signum, _frame):
        stop.set()                                     # never call shutdown() here

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # serve_forever() runs on its own thread so shutdown() can be called from
    # this one. (Calling shutdown() from the thread running serve_forever()
    # deadlocks.)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    log.info("listening on %s:%s", *server.server_address[:2])
    print("SOCKS5 proxy listening on %s:%s" % server.server_address[:2], flush=True)
    stop.wait()
    server.shutdown()
    server.server_close()
    log.info("stopped")


if __name__ == "__main__":
    sys.exit(main())
