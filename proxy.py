import logging
import select
import signal
import socket
import struct
import sys
import time
from socketserver import StreamRequestHandler, ThreadingMixIn, TCPServer

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, 
    filename='/var/www/html/proxy3.log', 
    filemode='w', 
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

SOCKS_VERSION = 5
PORT = 9000

# FEATURE 2: Define your whitelisted IPs here. 
# Leave the set empty (ALLOWED_IPS = set()) to allow all incoming connections.
ALLOWED_IPS = {'127.0.0.1'} 

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    # Allow the port to be immediately reused when the server restarts
    allow_reuse_address = True

class SocksProxy(StreamRequestHandler):
    username = 'user'
    password = 'pass'

    def handle(self):
        client_ip = self.client_address[0]
        logging.info('Incoming connection request from %s:%s' % self.client_address)
        
        # FEATURE 2: IP Whitelist Enforcement
        if ALLOWED_IPS and (client_ip not in ALLOWED_IPS):
            logging.warning(f"Unauthorized connection dropped: {client_ip} is not in the whitelist.")
            return  # Dropping connection instantly before allocating more resources

        try:
            # greeting header
            # read and unpack 2 bytes from a client
            header = self.connection.recv(2)
            if not header or len(header) < 2:
                return
                
            version, nmethods = struct.unpack("!BB", header)
            # socks 5
            assert version == SOCKS_VERSION
            assert nmethods > 0

            # get available methods
            methods = self.get_available_methods(nmethods)

            # accept only USERNAME/PASSWORD auth
            if 2 not in set(methods):
                # close connection
                self.server.close_request(self.request)
                return

            # send welcome message
            self.connection.sendall(struct.pack("!BB", SOCKS_VERSION, 2))

            if not self.verify_credentials():
                return

            # request
            request_header = self.connection.recv(4)
            if not request_header or len(request_header) < 4:
                return
                
            version, cmd, _, address_type = struct.unpack("!BBBB", request_header)
            assert version == SOCKS_VERSION

            if address_type == 1:  # IPv4
                address = socket.inet_ntoa(self.connection.recv(4))
            elif address_type == 3:  # Domain name
                domain_length = self.connection.recv(1)[0]
                address = self.connection.recv(domain_length)
                address = socket.gethostbyname(address)
            port = struct.unpack('!H', self.connection.recv(2))[0]

            # reply
            try:
                if cmd == 1:  # CONNECT
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((address, port))
                    remote.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
                    bind_address = remote.getsockname()
                    logging.info('Connected to remote target: %s:%s' % (address, port))
                else:
                    self.server.close_request(self.request)
                    return

                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
                port_num = bind_address[1]
                reply = struct.pack("!BBBBIH", SOCKS_VERSION, 0, 0, 1, addr, port_num)
            except Exception as err:
                logging.error(f"Failed to connect to target: {err}")
                # return connection refused error
                reply = self.generate_failed_reply(address_type, 5)

            self.connection.sendall(reply)

            # establish data exchange
            if reply[1] == 0 and cmd == 1:
                self.exchange_loop(self.connection, remote)

        except (AssertionError, struct.error) as e:
            logging.error(f"Protocol violation or bad packet formatting: {e}")
        finally:
            self.server.close_request(self.request)

    def get_available_methods(self, n):
        methods = []
        for i in range(n):
            byte = self.connection.recv(1)
            if byte:
                methods.append(ord(byte))
        return methods

    def verify_credentials(self):
        version_byte = self.connection.recv(1)
        if not version_byte:
            return False
        version = ord(version_byte)
        assert version == 1

        username_len_byte = self.connection.recv(1)
        if not username_len_byte:
            return False
        username_len = ord(username_len_byte)
        username = self.connection.recv(username_len).decode('utf-8')

        password_len_byte = self.connection.recv(1)
        if not password_len_byte:
            return False
        password_len = ord(password_len_byte)
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    # FEATURE 4: Tracking metrics and dynamic performance tracking
    def exchange_loop(self, client, remote):
        start_time = time.time()
        bytes_sent_to_remote = 0
        bytes_received_from_remote = 0

        while True:
            # Wait until client or remote is available for reading
            r, w, e = select.select([client, remote], [], [])
            
            if client in r:
                data = client.recv(8192)
                if not data:  # Catch cleanly closed connection
                    break
                bytes_sent_to_remote += len(data)
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(8192)
                if not data:  # Catch cleanly closed connection
                    break
                bytes_received_from_remote += len(data)
                if client.send(data) <= 0:
                    break

        duration = time.time() - start_time
        
        # Log aggregated performance telemetry
        logging.info(
            f"[METRICS] Session Closed for client {self.client_address[0]}. "
            f"Active Duration: {duration:.2f}s | "
            f"Bytes Uploaded: {bytes_sent_to_remote} | "
            f"Bytes Downloaded: {bytes_received_from_remote}"
        )


if __name__ == '__main__':
    server = ThreadingTCPServer(('0.0.0.0', PORT), SocksProxy)

    # FEATURE 3: Graceful Shutdown & POSIX Signal Handling
    def graceful_shutdown(signum, frame):
        logging.info(f"System received shutdown signal ({signum}). Terminating threads cleanly...")
        print(f"\n[!] Signal {signum} caught. Closing active server sockets gracefully...")
        server.shutdown()       # Stops the serve_forever loop running on the main thread
        server.server_close()   # Cleanly closes the listening socket binding
        logging.info("Server completely stopped. Goodbye.")
        sys.exit(0)

    # Register handlers for Ctrl+C (SIGINT) and termination demands (SIGTERM)
    signal.signal(signal.SIGINT, graceful_shutdown)
    signal.signal(signal.SIGTERM, graceful_shutdown)

    print("SOCKS5 Proxy Server listening on port {}".format(PORT))
    logging.info(f"SOCKS5 Engine Initialized on port {PORT}. Active loop starting.")
    
    server.serve_forever()
