#!/usr/bin/env python3
"""A minimal, dependency-free Server-Sent Events server for interop testing.

Serves `text/event-stream` on GET /events and emits a deterministic scripted
sequence that exercises the parser's grammar (comment keep-alive, multi-line
data, a named event, `id`, `retry`, and a multi-byte UTF-8 sequence split
across writes), then closes the stream so a reconnecting client can resume
with `last-event-id`.

Usage:
    python3 tools/validate/sse_server.py [--port 8port] [--rounds 3]

It prints one line per request to stderr (method, path, last-event-id), so an
interop run can confirm the resume header arrived. There is no TLS here: run
it behind a TLS terminator, or point an `http://` cleartext-policy client at
it. This is the opt-in live gate described in doc/design/server-sent-events.md
("Testing"); the unit tests do not need it.

    # terminal 1
    python3 tools/validate/sse_server.py --port 8091
    # terminal 2
    bin/sse_stream http://127.0.0.1:8091/events
"""

import argparse
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def scripted_events(resume_from: str) -> str:
    """The deterministic event script, as raw bytes.

    A round ends with `retry: 250` plus an `id`, so a client that reconnects
    resumes from that id and the server can skip the events it already sent.
    """
    lines = [
        ": keep-alive\n\n",                       # comment: fires nothing
        "event: greeting\n",
        "data: hello\n",
        "data: world\n\n",                        # multi-line data
        "id: 1\n",
        "data: first\n\n",
        "retry: 250\n",
        "id: 2\n",
        "data: caf\u00e9 \u2014 na\u00efve\n\n",  # multi-byte UTF-8
        ": keep-alive\n\n",
        "id: 3\n",
        "data: last\n\n",
    ]
    text = "".join(lines)
    # resume support: a client that already saw id N gets only the tail
    if resume_from.isdigit():
        seen = int(resume_from)
        if seen >= 3:
            # the client already saw everything: prove the resume header was
            # honoured by sending only a fresh event
            return ": keep-alive\n\nretry: 250\nid: 4\ndata: after-resume\n\n"
    return text


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):        # keep the console readable
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        if self.path.split("?")[0] != "/events":
            self.send_response(404)
            self.send_header("content-length", "0")
            self.end_headers()
            return

        resume = self.headers.get("last-event-id", "") or ""
        sys.stderr.write("GET %s last-event-id=%r\n" % (self.path, resume))

        body = scripted_events(resume).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "text/event-stream; charset=utf-8")
        self.send_header("cache-control", "no-store")
        # no content-length: the stream is delimited by the connection close
        self.send_header("connection", "close")
        self.end_headers()

        # write in small pieces with a pause, so the client must assemble
        # events across reads (and across a split multi-byte sequence)
        chunk = 7
        try:
            for i in range(0, len(body), chunk):
                self.wfile.write(body[i:i + chunk])
                self.wfile.flush()
                time.sleep(0.01)
        except (BrokenPipeError, ConnectionResetError):
            # the client disconnected (its retry bound was reached, or the
            # caller stopped reading). That is a normal end for an SSE stream,
            # not an error worth a traceback.
            pass
        self.close_connection = True


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--port", type=int, default=8091)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    sys.stderr.write("SSE server on http://%s:%d/events\n"
                     % (args.host, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
