#!/usr/bin/env python3
"""Deterministic local HTTP/2 peer that forces a STREAM-level error.

Used only by tools/validate/h2probe-sanity.sh. It speaks just enough TLS+h2 to
drive the probe: it reads the client preface and SETTINGS, sends its own
SETTINGS, then answers the request with a valid 200 response HEADERS (HPACK
static index 8 = :status 200) followed by RST_STREAM(CANCEL) on the same
stream, and finally holds the socket open (default 2 s) so the client's
connection thread never observes an EOF while the request thread is still
processing HEADERS + RST_STREAM.

That ordering is the whole point. RST_STREAM *after* a response is
unambiguously a stream error, so the probe must return exit 3. A peer that
closed the socket immediately would instead race the reset against the EOF,
which is what made the old harness-backed check flaky (see the note in
h2probe-sanity.sh). Not part of the client.

Usage: fake_rst_server.py <port> <cert> <key> [hold_seconds]
"""
import socket
import ssl
import struct
import sys
import time

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def frame(ftype, flags, stream_id, payload=b""):
    # Frame header is: 24-bit length, 8-bit type, 8-bit flags, 32-bit stream id.
    return (len(payload).to_bytes(3, "big") + bytes([ftype]) + bytes([flags])
            + struct.pack(">I", stream_id & 0x7FFFFFFF) + payload)


def read_frame(sock):
    hdr = b""
    while len(hdr) < 9:
        chunk = sock.recv(9 - len(hdr))
        if not chunk:
            return None
        hdr += chunk
    length = int.from_bytes(hdr[0:3], "big")
    ftype, flags = hdr[3], hdr[4]
    sid = struct.unpack(">I", hdr[5:9])[0] & 0x7FFFFFFF
    body = b""
    while len(body) < length:
        chunk = sock.recv(length - len(body))
        if not chunk:
            break
        body += chunk
    return ftype, flags, sid, body


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 18445
    cert = sys.argv[2]
    key = sys.argv[3]
    hold = float(sys.argv[4]) if len(sys.argv) > 4 else 2.0

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    ctx.set_alpn_protocols(["h2"])

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    sys.stderr.write("fabricated h2 server listening on %d\n" % port)
    sys.stderr.flush()

    conn, _ = srv.accept()
    tc = ctx.wrap_socket(conn, server_side=True)
    pref = b""
    while len(pref) < len(PREFACE):
        chunk = tc.recv(len(PREFACE) - len(pref))
        if not chunk:
            break
        pref += chunk
    read_frame(tc)                          # client SETTINGS
    tc.sendall(frame(0x4, 0x00, 0x00))      # our SETTINGS

    while True:
        got = read_frame(tc)
        if got is None:
            break
        ftype, flags, sid, body = got
        if ftype == 0x1:                    # client HEADERS
            # HEADERS, END_HEADERS, :status 200, then RST_STREAM(CANCEL).
            tc.sendall(frame(0x1, 0x04, sid, b"\x88"))
            tc.sendall(frame(0x3, 0x00, sid, struct.pack(">I", 0x8)))
            break

    # Hold the socket open: the client must see HEADERS + RST_STREAM and no
    # EOF, so its classification (stream error) cannot depend on a close race.
    time.sleep(hold)
    try:
        tc.unwrap()                         # TLS close_notify, not a bare FIN
    except Exception:
        pass
    tc.close()
    srv.close()


if __name__ == "__main__":
    main()
