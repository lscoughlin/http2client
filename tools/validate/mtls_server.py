#!/usr/bin/env python3
"""A TLS server that requires a client certificate, for the mutual TLS gate.

Built on Python's `ssl` with CERT_REQUIRED and the fixture CA as the only
trust anchor.  It speaks HTTP/1.1 (ALPN `http/1.1`) and has three routes:

    GET /          200 "ok"
    GET /events    a text/event-stream with one event, then closes
    GET /ws        a WebSocket upgrade; sends the text message "hello", then
                   answers the client's close frame

It logs one line per TLS connection to the file given with --log:

    accept subject=<client subject>     the handshake finished
    reject <reason>                     the handshake was refused

and `request <path>` for each request, so the gate can prove what the server
saw.  Usage:

    python3 tools/validate/mtls_server.py --port 8661 \
        --cert test/certs/mtls/server.crt --key test/certs/mtls/server.key \
        --ca test/certs/mtls/ca.crt --log /tmp/mtls.log [--tls 1.2|1.3]

It prints "ready" on stdout once it listens.  See doc/design/mtls.md.
"""

import argparse
import base64
import hashlib
import socket
import ssl
import sys
import threading

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def read_head(conn):
    data = b""
    while b"\r\n\r\n" not in data and len(data) < 16384:
        chunk = conn.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("latin-1")


def subject_of(cert):
    parts = []
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            parts.append("%s=%s" % (key, value))
    return ",".join(parts)


def serve_ws(conn, head):
    key = ""
    for line in head.split("\r\n"):
        if line.lower().startswith("sec-websocket-key:"):
            key = line.split(":", 1)[1].strip()
    accept = base64.b64encode(
        hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
    conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n"
                  % accept).encode() + b"\x81\x05hello")
    while True:
        hdr = conn.recv(2)
        if len(hdr) < 2:
            return
        length = hdr[1] & 0x7F
        if hdr[1] & 0x80:
            conn.recv(4)
        if 0 < length < 126:
            conn.recv(length)
        if hdr[0] & 0x0F == 8:
            conn.sendall(b"\x88\x00")
            return


def handle(raw, ctx, log, lock):
    def note(text):
        with lock:
            with open(log, "a") as f:
                f.write(text + "\n")

    try:
        conn = ctx.wrap_socket(raw, server_side=True)
    except (ssl.SSLError, OSError) as e:
        note("reject %s" % (getattr(e, "reason", None) or e))
        raw.close()
        return
    try:
        note("accept subject=%s" % subject_of(conn.getpeercert()))
        head = read_head(conn)
        if not head:
            return
        path = head.split(" ", 2)[1] if " " in head else "/"
        note("request %s" % path)
        if path.startswith("/ws"):
            serve_ws(conn, head)
        elif path.startswith("/events"):
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                         b"Connection: close\r\n\r\ndata: hello\n\n")
        else:
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                         b"Connection: close\r\n\r\nok")
    except (ssl.SSLError, OSError):
        pass
    finally:
        try:
            conn.unwrap()      # send close_notify so a read-to-EOF ends cleanly
        except (ssl.SSLError, OSError, ValueError):
            pass
        try:
            conn.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--tls", choices=("1.2", "1.3"), default=None)
    args = ap.parse_args()

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(args.cert, args.key)
    ctx.load_verify_locations(args.ca)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.set_alpn_protocols(["http/1.1"])
    if args.tls:
        version = (ssl.TLSVersion.TLSv1_2 if args.tls == "1.2"
                   else ssl.TLSVersion.TLSv1_3)
        ctx.minimum_version = version
        ctx.maximum_version = version

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.port))
    srv.listen(16)
    open(args.log, "w").close()
    lock = threading.Lock()
    print("ready", flush=True)
    while True:
        raw, _ = srv.accept()
        raw.settimeout(5)
        threading.Thread(target=handle, args=(raw, ctx, args.log, lock),
                         daemon=True).start()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
