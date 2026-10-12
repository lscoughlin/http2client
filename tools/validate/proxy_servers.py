#!/usr/bin/env python3
"""Reference origins and proxies for the opt-in live proxy gate.

One dependency-free process hosts everything the gate needs on loopback:

  * an HTTPS origin (HTTP/1.1 over TLS, certificate test/certs/other.crt,
    which names only other.example) and a plain HTTP origin;
  * an HTTP CONNECT proxy, optionally requiring Basic credentials;
  * the same CONNECT proxy behind TLS (an "https proxy", certificate
    test/certs/localhost.crt);
  * a SOCKS5 proxy (RFC 1928), optionally requiring username/password
    (RFC 1929).

The proxies refuse every target except the names in --map, and rewrite those
names to the loopback origins above, so a client can ask for
https://other.example/ and reach the local origin only by going through a
proxy.  Every decision is appended to the --log file, one line each, which the
gate script greps to prove WHICH route a request took:

    http-connect other.example:443 auth=ok
    socks5 atyp=3 other.example:443 auth=none
    origin tls host=other.example
    origin plain host=localhost:8483

It prints "ready" on stdout once every listener is up.  See
doc/design/proxy.md and tools/validate/proxy-live.sh.
"""

import argparse
import base64
import socket
import socketserver
import ssl
import struct
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG_LOCK = threading.Lock()
LOG_PATH = None


def log(line):
    with LOG_LOCK:
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")


def pipe(a, b):
    """Copy a -> b until either side closes."""
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def tunnel(client, target):
    t = threading.Thread(target=pipe, args=(target, client), daemon=True)
    t.start()
    pipe(client, target)
    t.join(timeout=2)


def open_target(args, host, port):
    """Resolve an allowed name to a loopback origin, or None."""
    mapped = args.target_map.get((host.lower(), port))
    if mapped is None:
        return None
    return socket.create_connection(("127.0.0.1", mapped), timeout=5)


class ConnectHandler(socketserver.BaseRequestHandler):
    """HTTP CONNECT proxy; wraps the socket in TLS first when --tls."""

    def handle(self):
        args = self.server.args
        conn = self.request
        try:
            if self.server.tls_context is not None:
                conn = self.server.tls_context.wrap_socket(conn, server_side=True)
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = conn.recv(1)
                if not chunk:
                    return
                head += chunk
            lines = head.decode("latin-1").split("\r\n")
            parts = lines[0].split()
            if len(parts) < 2 or parts[0] != "CONNECT":
                conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
                return
            host, _, port = parts[1].rpartition(":")
            host = host.strip("[]")
            auth = "none"
            if args.user is not None:
                want = base64.b64encode(
                    f"{args.user}:{args.password}".encode()).decode()
                got = ""
                for line in lines[1:]:
                    if line.lower().startswith("proxy-authorization:"):
                        got = line.split(":", 1)[1].strip()
                if got == "Basic " + want:
                    auth = "ok"
                else:
                    log(f"{self.server.label} {host}:{port} auth=bad")
                    conn.sendall(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                        b"Proxy-Authenticate: Basic realm=\"live\"\r\n"
                        b"Content-Length: 0\r\n\r\n")
                    return
            target = open_target(args, host, int(port))
            if target is None:
                log(f"{self.server.label} {host}:{port} refused")
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                return
            log(f"{self.server.label} {host}:{port} auth={auth}")
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            tunnel(conn, target)
            target.close()
        except (OSError, ssl.SSLError):
            pass


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise OSError("closed")
        data += chunk
    return data


class Socks5Handler(socketserver.BaseRequestHandler):
    def handle(self):
        args = self.server.args
        s = self.request
        try:
            ver, nmethods = struct.unpack("!BB", read_exact(s, 2))
            methods = read_exact(s, nmethods)
            if ver != 5:
                return
            auth = "none"
            if args.user is not None:
                if 2 not in methods:
                    s.sendall(b"\x05\xff")
                    return
                s.sendall(b"\x05\x02")
                _ = read_exact(s, 1)
                ulen = read_exact(s, 1)[0]
                user = read_exact(s, ulen).decode()
                plen = read_exact(s, 1)[0]
                pw = read_exact(s, plen).decode()
                if user == args.user and pw == args.password:
                    s.sendall(b"\x01\x00")
                    auth = "ok"
                else:
                    log("socks5 auth=bad")
                    s.sendall(b"\x01\x01")
                    return
            else:
                if 0 not in methods:
                    s.sendall(b"\x05\xff")
                    return
                s.sendall(b"\x05\x00")
            ver, cmd, _rsv, atyp = struct.unpack("!BBBB", read_exact(s, 4))
            if atyp == 1:
                host = socket.inet_ntoa(read_exact(s, 4))
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, read_exact(s, 16))
            elif atyp == 3:
                n = read_exact(s, 1)[0]
                host = read_exact(s, n).decode()
            else:
                s.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
                return
            (port,) = struct.unpack("!H", read_exact(s, 2))
            if cmd != 1:
                s.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
                return
            target = open_target(args, host, port)
            if target is None:
                log(f"socks5 atyp={atyp} {host}:{port} refused")
                s.sendall(b"\x05\x02\x00\x01" + b"\x00" * 6)
                return
            log(f"socks5 atyp={atyp} {host}:{port} auth={auth}")
            s.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            tunnel(s, target)
            target.close()
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_origin(label, body, port, ctx):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            log(f"origin {label} host={self.headers.get('Host', '')}")
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    srv.daemon_threads = True
    if ctx is not None:
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv


def main():
    global LOG_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--certs", default="test/certs")
    ap.add_argument("--origin-tls-port", type=int, default=8481)
    ap.add_argument("--origin-plain-port", type=int, default=8482)
    ap.add_argument("--http-proxy-port", type=int, default=8483)
    ap.add_argument("--https-proxy-port", type=int, default=8484)
    ap.add_argument("--socks-port", type=int, default=8485)
    ap.add_argument("--user", default=None)
    ap.add_argument("--password", default="")
    ap.add_argument("--name", default="other.example")
    ap.add_argument("--external-tls-origin", action="store_true",
                    help="do not start the TLS origin: --origin-tls-port names "
                         "an HTTP/2 server (nghttpd) started elsewhere")
    ap.add_argument("--external-plain-origin", action="store_true",
                    help="do not start the plain origin: --origin-plain-port "
                         "names a server (a WebSocket echo) started elsewhere")
    args = ap.parse_args()
    LOG_PATH = args.log
    open(LOG_PATH, "w").close()
    args.target_map = {
        (args.name, 443): args.origin_tls_port,
        (args.name, 80): args.origin_plain_port,
    }

    origin_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    origin_ctx.load_cert_chain(f"{args.certs}/other.crt", f"{args.certs}/other.key")
    proxy_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    proxy_ctx.load_cert_chain(f"{args.certs}/localhost.crt",
                              f"{args.certs}/localhost.key")

    servers = []
    if not args.external_plain_origin:
        servers.append(make_origin("plain", "origin-plain",
                                   args.origin_plain_port, None))
    if not args.external_tls_origin:
        servers.insert(0, make_origin("tls", "origin-tls",
                                      args.origin_tls_port, origin_ctx))
    for port, tls, label in ((args.http_proxy_port, None, "http-connect"),
                             (args.https_proxy_port, proxy_ctx, "https-connect")):
        s = Server(("127.0.0.1", port), ConnectHandler)
        s.args, s.tls_context, s.label = args, tls, label
        servers.append(s)
    s = Server(("127.0.0.1", args.socks_port), Socks5Handler)
    s.args = args
    servers.append(s)

    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print("ready", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    sys.exit(main())
