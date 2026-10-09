# Examples

Six small programs showing how to use `http2client`. They are smoke builds:
the build compiles them, it does not run them.

## Build

```sh
make examples      # or: task examples
```

The binaries land in `bin/` (gitignored).

## Run

Every example needs the OpenSSL library path at runtime. Without it the first
request fails with
`EHttpConnectionError: OpenSSL is not available: set OPENSSL_LIBPATH ...`.

```sh
export OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib   # macOS / Homebrew
```

Then run any of them:

```sh
bin/basic_get      https://nghttp2.org/
bin/post_text      https://nghttp2.org/httpbin/post
bin/json_request   https://nghttp2.org/httpbin/post
bin/xml_request    https://nghttp2.org/httpbin/xml
bin/threaded_get   https://nghttp2.org/ 8 25
bin/sse_stream     https://example.com/events
# or against the reference event-stream server (cleartext; an http:// URL
# enables the h2c-upgrade policy automatically):
#   python3 tools/validate/sse_server.py --port 8091 &
#   bin/sse_stream http://127.0.0.1:8091/events
```

| Program | Shows |
|---|---|
| `basic_get.pas` | The factory, one GET, `StatusCode`, `Headers`, `ReadText`. |
| `post_text.pas` | `WithTextBody` attaches a text body and defaults the content-type. |
| `json_request.pas` | `WithJsonBody` sends JSON; `ReadJsonObject` reads `TJSONObject` directly. |
| `xml_request.pas` | `WithXmlBody` / `ReadXmlDocument` for XML. |
| `threaded_get.pas` | Eight threads sharing one client and its connection pool. |
| `sse_stream.pas` | `SseRequest` + `TSseReconnectLoop`: read an event stream and resume from `last-event-id`. |

## Notes

- On Unix, `cthreads` must be the first unit in the program's `uses` clause,
  or threads do not start ("no thread support compiled in").
- `Http2.Readers` (JSON and XML) is an optional unit, outside the core
  library. `basic_get`, `post_text`, and `threaded_get` never link it.
- The helpers that read a body return an object **you own** — free it. The
  examples do so in a `finally`.
- The endpoints above are public services used for illustration. Point the
  programs at your own server for anything real.
