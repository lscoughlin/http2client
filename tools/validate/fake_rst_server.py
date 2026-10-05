#!/usr/bin/env python3
"""Fabricated HTTP/2 server that speaks just enough TLS+h2 to force a
STREAM-level error on the client's request stream. It replies with a valid
200 response HEADERS (HPACK static index 8 = :status 200), then sends
RST_STREAM(CANCEL) so the client surfaces EHttpStreamError while reading the
body. Used only by tools/validate/h2probe-sanity.sh to prove the probe returns
exit 3 for a stream error (verifier class ExpectStreamError). Not part of the
client."""
import socket, ssl, struct, sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 18445
CERT = sys.argv[2]
KEY = sys.argv[3]

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def frame(ftype, flags, stream_id, payload=b""):
    return struct.pack(">I", (len(payload) << 8) | ftype)[1:] + \
        bytes([flags]) + struct.pack(">I", stream_id & 0x7fffffff) + payload

def read_frame(sock):
    hdr = b""
    while len(hdr) < 9:
        c = sock.recv(9 - len(hdr))
        if not c:
            return None
        hdr += c
    ln = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
    ftype, flags = hdr[3], hdr[4]
    sid = struct.unpack(">I", hdr[5:9])[0] & 0x7fffffff
    body = b""
    while len(body) < ln:
        c = sock.recv(ln - len(body))
        if not c:
            break
        body += c
    return ftype, flags, sid, body

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(CERT, KEY)
ctx.set_alpn_protocols(["h2"])

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", PORT))
srv.listen(1)
sys.stderr.write("fabricated h2 server listening on %d\n" % PORT)
sys.stderr.flush()

conn, _ = srv.accept()
tc = ctx.wrap_socket(conn, server_side=True)
pref = b""
while len(pref) < len(PREFACE):
    pref += tc.recv(len(PREFACE) - len(pref))
read_frame(tc)                          # client SETTINGS
tc.sendall(frame(0x4, 0, 0))            # server SETTINGS
# wait for the client HEADERS on a stream, then answer 200 + RST
while True:
    f = read_frame(tc)
    if f is None:
        break
    ftype, flags, sid, body = f
    if ftype == 0x1:                    # HEADERS
        # HEADERS, END_HEADERS, :status 200 (HPACK static index 8 -> 0x88)
        tc.sendall(frame(0x1, 0x04, sid, b"\x88"))
        # RST_STREAM(CANCEL = 0x8) on the same stream
        tc.sendall(frame(0x3, 0x00, sid, struct.pack(">I", 0x8)))
        break
# keep the socket open briefly so the client can process both frames
import time
time.sleep(1.0)
tc.close()
srv.close()
