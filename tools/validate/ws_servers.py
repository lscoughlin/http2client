#!/usr/bin/env python3
"""Reference WebSocket server for the opt-in live WebSocket gate.

One dependency-free process (standard library only) serves RFC 6455 on
loopback, plain and over TLS, and records WHAT IT SAW so the gate script can
prove the client's behaviour from the server's side instead of trusting the
client's own report:

    handshake path=/echo host=127.0.0.1:8601 protocols=chat,superchat
    ping-answered len=3
    close code=1000 reason=bye
    conn-summary path=/echo frames=12 unmasked=0

Behaviour is chosen by the request path:

  /echo         echo every data frame as received (fragmentation preserved),
                answer pings, echo a close and end
  /delay        like /echo but waits 300 ms before each echo
  /serverping   send a ping first and log when the pong arrives, then echo
  /serverclose  send close 1001 'going', log the client's answer, end
  /frag         send "he", a ping, then "llo" as one fragmented text message
  /badutf8      send a text frame that is not UTF-8, log the close code
  /drop         close the TCP connection right after the handshake
  /protocol     select the first subprotocol the client offered
  /getCaseCount, /runCase, /updateReports
                the Autobahn fuzzing-server endpoints, enough (three trivial
                echo cases) to exercise tools/validate/autobahn_client.pas

Usage: ws_servers.py --log FILE --plain-port N [--tls-port N --cert C --key K]
It prints "ready" once every listener is up.  See doc/design/websocket.md and
tools/validate/websocket-live.sh.
"""

import argparse
import base64
import hashlib
import socket
import socketserver
import ssl
import struct
import sys
import threading
import time

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
LOG_LOCK = threading.Lock()
LOG_PATH = None


def log(line):
    with LOG_LOCK:
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def read_frame(sock):
    b0, b1 = recv_exact(sock, 2)
    fin = bool(b0 & 0x80)
    op = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", recv_exact(sock, 2))
    elif length == 127:
        (length,) = struct.unpack("!Q", recv_exact(sock, 8))
    key = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length)
    if masked:
        payload = bytes(b ^ key[i & 3] for i, b in enumerate(payload)) \
            if length < 4096 else unmask_big(payload, key)
    return fin, op, masked, payload


def unmask_big(payload, key):
    n = len(payload)
    mask = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(mask, "big")) \
        .to_bytes(n, "big")


def send_frame(sock, op, payload=b"", fin=True):
    head = bytes([(0x80 if fin else 0) | op])
    n = len(payload)
    if n < 126:
        head += bytes([n])
    elif n < 65536:
        head += bytes([126]) + struct.pack("!H", n)
    else:
        head += bytes([127]) + struct.pack("!Q", n)
    sock.sendall(head + payload)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        frames = 0
        unmasked = 0
        path = "?"
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
            path = lines[0].split()[1]
            hdr = {}
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    hdr[k.strip().lower()] = v.strip()
            key = hdr.get("sec-websocket-key", "")
            protos = [p.strip() for p in hdr.get("sec-websocket-protocol", "").split(",") if p.strip()]
            alpn = conn.selected_alpn_protocol() if isinstance(conn, ssl.SSLSocket) else "-"
            log(f"handshake path={path} host={hdr.get('host', '')} alpn={alpn} "
                f"protocols={','.join(protos)} version={hdr.get('sec-websocket-version', '')} "
                f"keylen={len(base64.b64decode(key)) if key else 0} "
                f"upgrade={hdr.get('upgrade', '')} connection={hdr.get('connection', '')}")
            accept = base64.b64encode(
                hashlib.sha1((key + GUID).encode()).digest()).decode()
            resp = ("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    "Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n")
            if path.startswith("/protocol") and protos:
                resp += "Sec-WebSocket-Protocol: " + protos[0] + "\r\n"
            conn.sendall((resp + "\r\n").encode())
            route = path.split("?")[0]

            if route == "/drop":
                return
            if route == "/getCaseCount":
                send_frame(conn, 1, b"3")
                send_frame(conn, 8, struct.pack("!H", 1000))
                read_frame(conn)
                return
            if route == "/runCase":
                send_frame(conn, 1, b"echo me")
                read_frame(conn)
                send_frame(conn, 8, struct.pack("!H", 1000))
                read_frame(conn)
                return
            if route == "/updateReports":
                send_frame(conn, 8, struct.pack("!H", 1000))
                read_frame(conn)
                return
            if route == "/serverclose":
                send_frame(conn, 8, struct.pack("!H", 1001) + b"going")
                fin, op, masked, payload = read_frame(conn)
                frames += 1
                unmasked += 0 if masked else 1
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                log(f"close-echo code={code}")
                return
            if route == "/badutf8":
                send_frame(conn, 1, b"\xff\xfe")
                fin, op, masked, payload = read_frame(conn)
                frames += 1
                unmasked += 0 if masked else 1
                code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                log(f"close code={code} reason=")
                return
            if route == "/frag":
                send_frame(conn, 1, b"he", fin=False)
                send_frame(conn, 9, b"p")
                send_frame(conn, 0, b"llo", fin=True)
            if route == "/serverping":
                send_frame(conn, 9, b"srv")

            while True:
                fin, op, masked, payload = read_frame(conn)
                frames += 1
                if not masked:
                    unmasked += 1
                if op == 8:
                    code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else 1005
                    log(f"close code={code} reason={payload[2:].decode('utf-8', 'replace')}")
                    send_frame(conn, 8, payload)
                    return
                if op == 9:
                    send_frame(conn, 10, payload)
                    log(f"ping-answered len={len(payload)}")
                elif op == 10:
                    log(f"pong len={len(payload)} data={payload.decode('latin-1')}")
                else:
                    if route == "/delay":
                        time.sleep(0.3)
                    send_frame(conn, op, payload, fin)
        except (ConnectionError, OSError, ssl.SSLError):
            pass
        finally:
            log(f"conn-summary path={path} frames={frames} unmasked={unmasked}")
            try:
                conn.close()
            except OSError:
                pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global LOG_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--plain-port", type=int, default=0)
    ap.add_argument("--tls-port", type=int, default=0)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--no-alpn", action="store_true",
                    help="serve TLS without ALPN support, as many WebSocket servers do")
    args = ap.parse_args()
    LOG_PATH = args.log
    open(LOG_PATH, "w").close()
    servers = []
    if args.plain_port:
        s = Server(("127.0.0.1", args.plain_port), Handler)
        s.tls_context = None
        servers.append(s)
    if args.tls_port:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(args.cert, args.key)
        # the client offers http/1.1 alone, so the answer is http/1.1 or none
        if not args.no_alpn:
            ctx.set_alpn_protocols(["http/1.1"])
        s = Server(("127.0.0.1", args.tls_port), Handler)
        s.tls_context = ctx
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
