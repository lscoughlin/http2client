REPO: /Users/liamcoughlin/Source/lscoughlin/http2client
STORY: plan/stories/09-public-api.md   (read it first, in full)
SPEC: doc/design/client-api.md (all of it), doc/design/messages.md (all of it),
      doc/design/transport.md (connection lifecycle), doc/design/protocol.md

## CRITICAL ENVIRONMENT FACTS (do not re-derive, do not compile in the repo)
- FPC 3.2.4. Compile in your OWN private directory:
    mkdir -p /tmp/h2agents/s09
    fpc -O2 -Mdelphi -Fu./src -Fu./test \
        -Fu/usr/local/lib/fpc/3.2.4/units/aarch64-darwin/fcl-fpcunit \
        -Futhird_party/mORMot2/src/core -Futhird_party/mORMot2/src/lib \
        -Futhird_party/mORMot2/src/net -Futhird_party/mORMot2/src/crypt \
        -FU/tmp/h2agents/s09 -FE/tmp/h2agents/s09 test/Http2.RunTests.pas
  then run /tmp/h2agents/s09/Http2.RunTests --all --format=plain --sparse
  NEVER leave .o/.ppu in src/ or test/ (they break other lanes).
- Export OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib when running tests.
- DO NOT run `make`. DO NOT `git add` / `git commit`. I (the parent) do that.
- Files you may edit: src/Http2.Client.pas, test/Http2.Client.Test.pas,
  test/Http2.Request.Test.pas, test/testclient.pas, and appending unit names to
  test/Http2.TestRunner.pas's uses clause. Touch nothing else.
- MULTI-WRITER repo: another lane may edit other units concurrently.
- NO network, NO `find /`, no filesystem searching.

## WHAT ALREADY EXISTS (READ THESE FILES BEFORE WRITING)
- src/Http2.Errors.pas — EHttpError hierarchy. THttp2ErrorCode has: ecNoError,
  ecProtocolError, ecInternalError, ecFlowControlError, ecSettingsTimeout,
  ecStreamClosed, ecFrameSizeError, ecRefusedStream, ecCancel,
  ecCompressionError, ecConnectError, ecEnhanceYourCalm,
  ecInadequateSecurity, ecHttp11Required.
  THERE IS NO `ecConnectionError`. Classes: EHttpConnectionError,
  EHttpProtocolError, EHttpStreamError(has FStreamId), EHttpTimeout,
  EHttpConnectionClosed, EHttpTooManyRedirects, EHttpNotReplayable.
- src/Http2.Headers.pas — IHttpHeaders: Add, SetValue, GetValues, GetFirst,
  Contains, Remove, Names, AddPseudo, GetPseudo; NewHttpHeaders.
  Header names are lowercased; 5 connection-specific headers are rejected.
- src/Http2.Hpack.pas — THpackCodec(Encode(THeaderBlock):TBytes,
  Decode(TBytes):THeaderBlock, ApplySettings(LongWord), Huffman);
  THttpHeaderField{Name,Value,Sensitive}; THeaderBlock=TArray<THttpHeaderField>.
- src/Http2.Tls.pas — IHttp2Socket(Read/Write/Close/Connected + timeouts);
  TPlainSocket; TTlsSocket (ALPN h2; RequireH2Alpn). Use these to open sockets.
- src/Http2.Connection.pas —
    TConnectionState = (csOpening, csOpen, csGoAway, csClosed);
    TConnection(ASocket: IHttp2Socket[, ALocalSettings: TConnectionSettings]):
      Start / Close / PostFrame(AFrame):Boolean / CanOpenStream /
      IsStreamRetryable / WaitForState / MarkGoAway / FailWith /
      RegisterStream(AStreamId, IConnectionStream) / UnregisterStream(id) /
      StreamCount / DispatchStreamFrame / PeerSettings / State / Outbound /
      Inbound / HighestStreamId (read+write) / GoAwayLastStreamId / Socket.
    IConnectionStream = OnConnectionFailed / OnConnectionGoAway / OnStreamFrame.
    TConnectionSettings{Defaults, Encode, Decode} incl.
      SETTINGS_MAX_CONCURRENT_STREAMS, MAX_FRAME_SIZE, HEADER_TABLE_SIZE.
- src/Http2.Stream.pas — the lease you MUST drive:
    TStreamRequest = record
      Method, Scheme, Authority, Path: string; Headers: IHttpHeaders;
      Body: THttpBody; BodyWriter: IBodyWriter;
      class function Create(const AMethod, AAuthority: string): TStreamRequest;
      class function WithMethod(const AMethod: THttpMethod; const AAuthority: string): TStreamRequest;
      WithScheme / WithPath / WithHeader / WithBody / WithBodyWriter
    end;
    TStreamIdAllocator: Create; Next: LongWord (odd, monotonic, 0 = exhausted)
    TStreamLease: Create(Conn, Allocator, Request[, Encoder, Decoder])
      Start / SendHeaders / SendData / SendBody / EndSend /
      WaitForResponseHeader(ATimeoutMs):Boolean / ReleaseLease /
      BodyEof:Boolean / ReadBody(var ABuffer; ACount):LongInt
      properties StreamId / StatusCode / ResponseHeaders / Body /
      RequestMethod / TimeoutMs / LocalState / ResponseState.
  NOTE: use the 5-arg constructor and pass CONNECTION-SCOPED THpackCodec
  instances (one encoder + one decoder per connection). A per-lease codec
  produces a broken HPACK table across streams.
- src/Http2.FlowControl.pas — TWindow / TFlowControl (send windows, receive
  credit). S08 deferred per-stream send-window integration to S09.

## YOUR DELIVERABLE — src/Http2.Client.pas (implement all of S09)
09.1 THttpClientFactory: a PURE VALUE RECORD (every WithX returns a new record;
     no shared mutable state), fields MaxConnections, MaxStreamsPerConnection,
     FollowRedirects, MaxRedirects, ConnectTimeoutMs, HeaderTimeoutMs,
     IdleTimeoutMs, ProxyHost, ProxyPort. class function Create: THttpClientFactory;
     WithMaxConnections, WithMaxStreamsPerConnection, WithFollowRedirects,
     WithMaxRedirects, WithProxy, Build: IHttpClient.
     DEFAULTS (assert these in a test): MaxConnections=4,
     MaxStreamsPerConnection=100, FollowRedirects=True, MaxRedirects=10,
     ConnectTimeoutMs=10000, HeaderTimeoutMs=30000, IdleTimeoutMs=60000.
09.2 IHttpResponse{StatusCode:LongInt, Headers:IHttpHeaders, Body:IHttpBodyStream}
     and IHttpBodyStream{Read(var ABuffer; ACount):LongInt, Eof:Boolean}.
     Implement a concrete THttpResponse / TBodyStream wrapping TStreamLease
     (ReleaseLease when the body completes).
09.3 IResponseReader<T> interface + TResponseReader<T> class under
     {$mode delphi} (a CLASS-level generic, NOT a method-level generic — FPC
     3.2.4 cannot parse generic methods under {$mode objfpc}). Provide
     class procedure Read(const AResponse: IHttpResponse; out AValue: T).
     Add a DTO-decode test (e.g. decode a TBytes or a small record/string).
09.4 THttpRequest record: class function Create(AMethod: THttpMethod; AUrl);
     WithMethod / WithMethodToken (validated + UPPERCASED) / WithHeader /
     WithBody / WithBodyWriter; body and body-writer are mutually exclusive
     (setting both raises). THttpMethod=(hmGet,hmHead,hmPost,hmPut,hmDelete,
     hmConnect,hmOptions,hmTrace,hmPatch). THttpBody: FromBytes/FromString/
     IsSet/Data. IBodyWriter.NextChunk(out ABuffer: TBytes): Boolean.
09.5 TConnectionPool: TDictionary<string, TConnectionList> under a
     TCriticalSection; global MaxConnections cap; per-host reuse; per-origin
     connection list. Needs a seam to inject a fake socket factory so pool
     tests need NO real sockets (see 09.5 acceptance: "cap test").
09.6 Lease acquisition exactly as doc/design/client-api.md §Lease acquisition:
     compute Origin (host:port, default port by scheme) -> :authority;
     choose LEAST-LOADED eligible connection (open/opening AND active streams
     < min(MaxStreamsPerConnection, peer SETTINGS_MAX_CONCURRENT_STREAMS));
     else open a new one if under MaxConnections; else wait (bounded, else
     EHttpTimeout); allocate stream id; enqueue frames via TStreamLease.
09.7 IHttpClient.Send(const ARequest: THttpRequest): IHttpResponse —
     BLOCKS until status + headers are available, then returns; does NOT wait
     for the body. Must be thread-safe and callable concurrently. A concurrent
     Send test (N threads) proving no id collisions and no pool overflow.
09.8 IHttpClient.Close — stop accepting new leases, GOAWAY open connections,
     release the pool; outstanding response bodies stay readable.
09.9 Pseudo-header mapping at encode time: :method <- method token, :scheme
     <- 'https', :path <- path+query ('/' when empty), :authority <- host[:port]
     with the DEFAULT PORT OMITTED. Assert the exact encoded block in a test.
09.10 test/testclient.pas — a small CLI that builds a client through the
     documented fluent chain and GETs a URL. It must COMPILE and, when run with
     no server, fail cleanly. Its existence proves the documented example
     compiles (see the `Done when` section).

ALSO: integrate the S08-deferred per-stream SEND window using
Http2.FlowControl.TFlowControl, if you can do so without editing
Http2.Connection.pas. If it needs a connection seam, do NOT hack it in —
report the exact seam you need instead.

## TESTS — test/Http2.Client.Test.pas and test/Http2.Request.Test.pas
Cover: factory immutability + documented defaults; fluent example compiles and
runs; pseudo-header mapping incl. default-port omission; body/bodyWriter
exclusivity raises; method token uppercasing; pool never exceeds MaxConnections
under concurrent Send; least-loaded selection; per-connection stream cap;
Close semantics (bodies still readable); response types + TResponseReader<T>
DTO decode.

## NON-VACUOUS TESTS ARE MANDATORY
Before reporting, run at least TWO mutations and confirm a test FAILS for each,
then restore: e.g. (a) make the pool ignore MaxConnections, (b) stop uppercasing
the method token or stop omitting the default port. Report the exact test that
caught each mutation. A test that still passes with the behaviour removed is
worthless and I will reject it.

## FPC QUIRKS (do not rediscover)
- {$mode objfpc} cannot parse generic methods — this project uses {$mode delphi}.
- Exception.CreateFmt takes only 2 params: use Create(Format(...), ACode).
- Cannot assign to a `const` record param: copy it first.
- Managed TBytes results warn uninitialized: set `Result := nil;` first.
- TStringList has no Remove: IndexOf + Delete.
- TCriticalSection (no TMonitor); RTLEvent (no TEvent/TSimpleEvent).
- RTLEventSetEvent wakes exactly ONE waiter: re-signal the same event to
  chain-wake a set of waiters.
- {$IFDEF UNIX}cthreads,{$ENDIF} must be first in any program using threads.
- In a record's `class function ... : TRecord; static;` you may assign Result
  fields directly; `Result := Self` copy-then-modify is the fluent pattern.

## REPORT BACK (concise)
1. Public API of src/Http2.Client.pas (exact type signatures).
2. Test names + counts; the TWO mutations and which test caught each.
3. Reproduce command + final totals (N/E/F).
4. Any seam you need in Http2.Connection.pas (do not add it yourself).
5. Deviations from plan/stories/09-public-api.md and why.
6. What you could NOT do. Keep the live GET/POST-against-nghttpd integration
   test OPT-IN (e.g. env var HTTP2_LIVE_ITEST=1) so the default suite is
   hermetic; report whether you ran it.
