"""Local HTTP target for load testing (python3 -m http.server has a listen backlog of 5)."""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


class Server(ThreadingHTTPServer):
    request_queue_size = 1024


if __name__ == "__main__":
    print("target on 127.0.0.1:8000", flush=True)
    Server(("127.0.0.1", 8000), SimpleHTTPRequestHandler).serve_forever()
