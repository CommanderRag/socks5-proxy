# SOCKS5 Proxy Server

A multi-threaded SOCKS5 proxy server built from scratch in Python, following [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928). It handles the full handshake, username/password authentication, the `CONNECT` command, and bidirectional data relay between client and destination — with IP whitelisting and per-session traffic metrics on top.

## Features

- **RFC 1928-compliant handshake** — negotiates the SOCKS version and auth method before doing anything else.
- **Username/password authentication (Sub-negotiation, RFC 1929)** — rejects any client that doesn't offer method `0x02`, and verifies credentials before allowing a connection through.
- **IP whitelisting** — connections from IPs outside `ALLOWED_IPS` are dropped immediately, before any bytes are read off the socket.
- **`CONNECT` command support** — resolves the target (IPv4 or domain name) and opens a connection to it on the client's behalf. `BIND` and `UDP ASSOCIATE` are not implemented.
- **Threaded connection handling** — built on `ThreadingMixIn`, so each client connection is handled on its own thread and multiple sessions can run concurrently.
- **Non-blocking relay loop** — once the tunnel is established, `select()` multiplexes reads between the client and the remote socket so data flows in both directions without busy-waiting.
- **Per-session metrics** — logs session duration, bytes uploaded, and bytes downloaded once a connection closes.
- **Graceful shutdown** — `SIGINT` / `SIGTERM` are caught to shut the server down cleanly instead of dropping connections abruptly.

## Requirements

- Python 3 (standard library only — no external dependencies)

## Usage

1. **Set your whitelist** (optional). By default, only `127.0.0.1` is allowed:
   ```python
   ALLOWED_IPS = {'127.0.0.1'}
   ```
   Add more IPs as needed, or set `ALLOWED_IPS = set()` to allow all incoming connections.

2. **Set credentials.** The proxy currently uses a single hardcoded username/password pair in the `SocksProxy` class:
   ```python
   username = 'user'
   password = 'pass'
   ```
   Change these before running anywhere outside a local test environment (see [Known Limitations](#known-limitations)).

3. **Set the log path.** Logs are written to `/var/www/html/proxy3.log` by default — update the `filename` in the `logging.basicConfig()` call to a path that exists on your system.

4. **Run the server:**
   ```bash
   python3 proxie.py
   ```
   The server listens on `0.0.0.0:9000` by default.

5. **Point a SOCKS5 client at it**, e.g. with `curl`:
   ```bash
   curl --socks5 user:pass@127.0.0.1:9000 https://example.com
   ```

## Stopping the Server

`Ctrl+C` (or a `SIGTERM`) triggers a graceful shutdown — the server stops accepting new connections, closes the listening socket, and exits cleanly.

## Known Limitations

- **Credentials and log path are hardcoded** in source rather than pulled from a config file or environment variables — fine for local testing, but should be externalized before any real deployment.
- **Single shared credential pair** — there's no per-user account system; every client authenticates with the same username/password.
- **No TLS** — traffic between the client and this proxy is not encrypted at the proxy layer.
- **Only `CONNECT` is implemented** — `BIND` and `UDP ASSOCIATE` requests are rejected.

## How It Works

Each incoming connection is handled by `SocksProxy.handle()`:

1. Checks the client IP against `ALLOWED_IPS`, dropping unauthorized connections immediately.
2. Performs the SOCKS5 greeting/method-negotiation handshake, requiring username/password auth.
3. Verifies the supplied credentials.
4. Parses the client's request (address type + target address/port).
5. Opens a `CONNECT` to the target and relays data between the client and target sockets using `select()` until either side closes the connection.
6. Logs session metrics (duration, bytes sent/received) once the exchange loop ends.

## Contributing

Issues and PRs welcome — a config-driven credential/whitelist system and TLS support would be natural next steps.

## License

MIT
