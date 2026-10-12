#!/usr/bin/env python3
"""HTTP/1.1-only server that records every request it receives.

It never upgrades: an `Upgrade: h2c` header is ignored and the request is
answered as plain HTTP/1.1.  Each request it receives is logged on one line,

    request GET /a upgrade=h2c connection=Upgrade, HTTP2-Settings

so tools/validate/cleartext-live.sh can count how many copies of a request
reached the peer.  Usage: h1_counter_server.py --log FILE --port N
It prints "ready" once the listener is up.
"""
import argparse
import http.server
import socketserver
import threading

LOG_LOCK = threading.Lock()
LOG_PATH = None


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle_any(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length:
            self.rfile.read(length)
        with LOG_LOCK:
            with open(LOG_PATH, "a") as f:
                f.write("request %s %s upgrade=%s connection=%s\n" % (
                    self.command, self.path,
                    self.headers.get("Upgrade", "-"),
                    self.headers.get("Connection", "-")))
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = handle_any

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global LOG_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--port", type=int, required=True)
    args = ap.parse_args()
    LOG_PATH = args.log
    open(LOG_PATH, "w").close()
    s = Server(("127.0.0.1", args.port), Handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    print("ready", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
