// Wave 1: S02-S05 primitives lane — four independent units, all depending only on S01.
const repo = '/Users/liamcoughlin/Source/lscoughlin/http2client';
const fpcUnits = '/usr/local/lib/fpc/3.2.4/units/aarch64-darwin';
const mormot = repo + '/third_party/mORMot2/src';

const common = [
  'REPO: ' + repo + '  (a git repo; never mutate history or run destructive git commands)',
  '',
  'You are implementing ONE story of an Object Pascal HTTP/2 client (Free Pascal 3.2.4, aarch64-darwin).',
  'Work autonomously until your unit and its fpcunit tests are green, then report.',
  '',
  'READ FIRST (in this order):',
  '  plan/stories/<STORY>.md                <- your authoritative task + acceptance table',
  '  doc/design/<SPEC>.md                   <- the normative spec section named below',
  '  doc/reference/fpc-verified/README.md   <- verified FPC 3.2.4 facts; DO NOT re-derive them',
  '  src/Http2.Errors.pas, src/Http2.Frames.pas  <- the FROZEN S01 surface you build on (read-only)',
  '',
  'HARD CONSTRAINTS',
  '  - Free Pascal 3.2.4. Every unit starts with exactly:',
  '      {$mode delphi}{$H+}{$modeswitch advancedrecords}{$modeswitch typehelpers}{$interfaces com}',
  '  - Interfaces are refcounted (TInterfacedObject). Never manage interface refcounts by hand.',
  '  - FPC 3.2.4 has NO TThreadedQueue<T>, NO TMonitor; TEvent/TSimpleEvent RAISE on macOS.',
  '    Use TCriticalSection + RTLEvent. Any program/unit that touches threads must have',
  '    {$IFDEF UNIX}cthreads,{$ENDIF} as the FIRST uses entry.',
  '  - Only create/modify the files you OWN (listed below). Do NOT touch: the Makefile,',
  '    src/Http2.pas, test/Http2.RunTests.pas, test/Http2.TestRunner.pas, any other story\'s',
  '    unit or test file, doc/**, plan/**.',
  '  - Do NOT run make. Do NOT run git commit. Four agents share this working tree, so',
  '    make would clobber shared .ppu/.o files. Compile in your private scratch dir only.',
  '  - No new third-party dependencies beyond the ones your commands already include.',
  '',
  'YOU OWN',
  '  src/<UNIT>.pas            (the implementation)',
  '  test/<UNIT>.Test.pas      (fpcunit unit test; the unit name must equal the filename)',
  '',
  'BUILD + TEST (private scratch dir, safe under parallelism)',
  '  FPC_UNITS=' + fpcUnits,
  '  SCRATCH=/tmp/h2agents/<KEY>',
  '  mkdir -p "$SCRATCH"',
  '  Write a tiny program file $SCRATCH/runtests.pas containing:',
  '      program runtests;',
  '      {$mode delphi}{$H+}',
  '      uses',
  '        {$IFDEF UNIX}cthreads,{$ENDIF}',
  '        SysUtils, consoletestrunner, <UNIT>.Test;',
  '      var App: TTestRunner;',
  '      begin App := TTestRunner.Create(nil);',
  '        try App.Initialize; App.Title := \'<KEY>\'; App.Run; finally App.Free; end; end.',
  '  Then compile and run:',
  '      fpc -O2 -vw -Mdelphi -Fu"$PWD/src" -Fu"$PWD/test" -Fu"$FPC_UNITS/fcl-fpcunit" -FU"$SCRATCH" -FE"$SCRATCH" "$SCRATCH/runtests.pas"',
  '      "$SCRATCH/runtests" --all --format=plain --sparse',
  '',
  'A green run ends with "Number of errors: 0" and "Number of failures: 0".',
  'Iterate until green AND warning-free (-vw must print no Warning/Error for your files).',
  '',
  'REPORT BACK (concise, no file dumps):',
  '  status; the exact final "Number of run tests / errors / failures" lines;',
  '  files created or changed; any deviation from the plan and why; anything unverified.',
  ''
].join('\n');

function lane(key, story, spec, unitName, owns, body) {
  var t = common.replace(/<STORY>/g, story).replace(/<SPEC>/g, spec)
               .replace(/<UNIT>/g, unitName).replace(/<KEY>/g, key);
  return t + '\n' + owns + '\n' + body;
}

const s02 = lane('s02', '02-headers', 'messages.md', 'Http2.Headers',
  'YOU OWN: src/Http2.Headers.pas  and  test/Http2.Headers.Test.pas\nBUILD: use the standard command above unchanged.',
`TASK (S02.1-S02.5)
Implement IHttpHeaders and the header-name constants in src/Http2.Headers.pas.
Spec: doc/design/messages.md section "Headers and header names" gives the interface and
the constants verbatim - copy them exactly.

Requirements:
  - IHttpHeaders methods: Add, SetValue, GetValues(const AName: string): TArray<string>,
    GetFirst, Contains, Remove, Names: TArray<string>.
  - Backing store: TDictionary<string,TStringList> inside a TInterfacedObject.
  - Names are lowercased on Add/SetValue; values are preserved verbatim, in insertion order.
  - Remove must use TStringList.IndexOf + Delete (FPC 3.2.4 TStringList has NO Remove).
  - Forbidden/connection-specific headers (connection, keep-alive, transfer-encoding,
    upgrade, proxy-connection) must be REJECTED on Add/SetValue by raising
    EHttpProtocolError (from Http2.Errors, code ecProtocolError).
  - Pseudo-headers (:method,:path,:scheme,:authority,:status) must NOT appear in the
    regular map / Names; provide a separate mechanism (e.g. AddPseudo/GetPseudo or a
    documented pseudo map) so callers can still carry them, and assert absence from Names.
  - Export the header-name constants from the spec (HeaderMethod, HeaderPath, HeaderScheme,
    HeaderAuthority, HeaderStatus, HeaderContentType, HeaderContentLength,
    HeaderContentEncoding, HeaderAccept, HeaderAcceptEncoding, HeaderUserAgent,
    HeaderAuthorization, HeaderCookie, HeaderSetCookie, HeaderCacheControl, HeaderLocation,
    HeaderHost, HeaderTe).
  - This unit must stay a plain map: no HPACK, TLS, socket or thread dependency.

TESTS (test/Http2.Headers.Test.pas)
  multi-value set-cookie via GetValues; GetFirst returns the first value; Add and lookup
  are case-insensitive; value order preserved; Remove works and Contains then false;
  each forbidden header raises EHttpProtocolError; Names excludes pseudo-headers;
  every constant's literal value asserted.

DONE WHEN: the full spec header API exists and is tested; case-insensitivity and
forbidden-header rejection are covered; your scratch run is green.`);

const s03 = lane('s03', '03-hpack', 'protocol.md', 'Http2.Hpack',
  'YOU OWN: src/Http2.Hpack.pas  and  test/Http2.Hpack.Test.pas\nBUILD: use the standard command above unchanged.',
`TASK (S03.1-S03.8)
Implement a stateful, connection-scoped HPACK (RFC 7541) codec in src/Http2.Hpack.pas.
Spec: doc/design/protocol.md section "HPACK"; task table in plan/stories/03-hpack.md.

Implement:
  - Static table: RFC 7541 Appendix A, all 61 entries.
  - Dynamic table: insert with 32-byte per-entry overhead, size-based eviction (FIFO),
    cap = SETTINGS_HEADER_TABLE_SIZE, and dynamic table size updates (6.3).
  - Prefix-coded integers (5.1) with boundary cases 127/128 and the max.
  - String literals (5.2): raw and Huffman, signalled by the H bit.
  - Huffman codec (Appendix B): full encode/decode tables, EOS handling, padding rules
    (padding must be the most-significant bits of the EOS symbol; a padding longer than
    7 bits or not all ones is a COMPRESSION_ERROR).
  - All header field representations: 6.1 indexed, 6.2.1 literal with incremental
    indexing, 6.2.2 literal without indexing, 6.2.3 literal never indexed, 6.3
    dynamic table size update.
  - THpackCodec class with Encode(const AHeaders: THeaderBlock): TBytes and
    Decode(const AData: TBytes): THeaderBlock, plus ApplySettings(aMaxTableSize).
    There must be exactly one encoder and one decoder state per instance (not global).

IMPORTANT - avoid a cross-story dependency: define the header-block types INSIDE this
unit, e.g.
    THttpHeaderField = record Name, Value: string; Sensitive: Boolean; end;
    THeaderBlock = TArray<THttpHeaderField>;
Do NOT implement, stub, or "uses" Http2.Headers - another agent owns it in parallel.
(Later stories map THeaderBlock to IHttpHeaders.)

Errors: any malformed input (bad index, invalid integer, bad Huffman padding, oversized
entry) raises EHttpProtocolError with code ecCompressionError (COMPRESSION_ERROR).

TESTS (test/Http2.Hpack.Test.pas)
  - Reproduce RFC 7541 Appendix C vectors C.1, C.2, C.3, C.4, C.5, C.6 byte-for-byte:
    hardcode the RFC's hex input and expected output and assert equality both directions
    where the RFC gives both.
  - Huffman round-trip over a range of ASCII strings (include length 0 and >127 bytes).
  - Dynamic table eviction and the "oversized entry clears the table" rule.
  - A dynamic table size update mid-stream is honoured.
  - Never-indexed field round-trips with Sensitive=True.
  - Malformed index / bad padding raises EHttpProtocolError(ecCompressionError).
  - Two codec instances maintain independent dynamic tables.

DONE WHEN: Appendix C vectors pass byte-for-byte; dynamic table is provably
per-instance; malformed input is connection-fatal; scratch run green.`);

const s04 = lane('s04', '04-flow-control', 'protocol.md', 'Http2.FlowControl',
  'YOU OWN: src/Http2.FlowControl.pas  and  test/Http2.FlowControl.Test.pas\nBUILD: use the standard command above unchanged.',
`TASK (S04.1-S04.6)
Implement connection- and stream-level flow-control accounting in src/Http2.FlowControl.pas.
Spec: doc/design/protocol.md section "Flow control"; plan/stories/04-flow-control.md.

Implement:
  - TWindow record holding a signed 32-bit window value (windows can go negative after a
    SETTINGS_INITIAL_WINDOW_SIZE decrease), with:
      Defaults(initial), CanSend/CanSendN, TryConsume(AN: LongWord): Boolean,
      ApplyUpdate(AIncrement: LongWord) (WINDOW_UPDATE),
      ApplyDataSent / ApplyDataReceived(AN: LongWord),
      ApplyInitialWindowDelta(ADelta: Int64) (SETTINGS change to all open streams).
  - Overflow detection: any window exceeding 2^31-1 raises EHttpProtocolError with
    ecFlowControlError. A zero WINDOW_UPDATE increment is a PROTOCOL_ERROR.
  - Batching: a helper that decides whether to emit WINDOW_UPDATE - only once the
    consumed amount reaches at least half the configured window, or when the stream
    ends. Expose it as a pure function/record method so it is unit-testable; do not
    perform I/O here.
  - Keep the unit thread-agnostic and I/O-free: it is pure accounting. No sockets,
    no threads, no dependency on Http2.Connection.

Define also a small connection-level aggregate, e.g. TFlowControl = class holding a
connection TWindow plus a TDictionary<LongWord,TWindow> keyed by stream id, so tests can
prove per-stream isolation.

TESTS (test/Http2.FlowControl.Test.pas)
  arithmetic; consuming exactly the window leaves 0 and CanSend False; consuming beyond
  the window is refused; WINDOW_UPDATE applies the delta; overflow past 2^31-1 raises
  EHttpProtocolError(ecFlowControlError); a zero-increment update raises
  EHttpProtocolError(ecProtocolError); batching emits nothing below the half-window
  threshold and something at/above it and on stream end; SETTINGS_INITIAL_WINDOW_SIZE
  delta adjusts every open stream; a stream at a zero window blocks only that stream,
  not the connection.

DONE WHEN: stream blocking does not stall other streams; overflow and invalid updates
raise the correct error; scratch run green.`);

const s05 = lane('s05', '05-tls-alpn-socket', 'transport.md', 'Http2.Tls',
  'YOU OWN: src/Http2.Tls.pas  and  test/Http2.Tls.Test.pas\n' +
  'EXTRA ENV:   export OPENSSL_LIBPATH=/opt/homebrew/opt/openssl@3/lib\n' +
  'EXTRA FPC FLAGS: add these four to the standard fpc command:\n' +
  '  -Fu"' + mormot + '/core" -Fu"' + mormot + '/lib"\n' +
  '  -Fu"' + mormot + '/net" -Fu"' + mormot + '/crypt"',
`TASK (S05.1-S05.8)
Implement src/Http2.Tls.pas: a blocking byte-stream socket that performs a TLS handshake,
offers ALPN "h2", and FAILS LOUDLY when the peer does not select h2.
Spec: doc/design/transport.md section "TLS and ALPN"; plan/stories/05-tls-alpn-socket.md.

VERIFIED FACTS (already established - do not re-investigate):
  - FPC 3.2.4's bundled openssl/opensslsockets units expose NO ALPN symbols, so they
    cannot negotiate h2. mormot.lib.openssl11.pas is the only viable layer.
  - mormot.lib.openssl11.pas exports SSL_CTX_set_alpn_protos and SSL_get0_alpn_selected
    (see plan/toolchain.md for the line numbers) and dynamically loads libssl/libcrypto.
  - OpenSslIsAvailable is FALSE unless OPENSSL_LIBPATH points at
    /opt/homebrew/opt/openssl@3/lib (OpenSSL 3.6.5). Set it in your shell.
  - The mormot checkout is already present and revision-pinned at
    third_party/mORMot2 (see plan/toolchain.md). Do NOT vendor anything new and do NOT
    modify third_party - S05.9 is satisfied by the pinned checkout.

Implement:
  - IHttp2Socket interface: Read(var ABuffer; ACount: Integer): Integer,
    Write(const ABuffer; ACount: Integer): Integer, Close, Connected: Boolean,
    and timeout properties (connect/read/write in ms).
  - TPlainSocket implementing IHttp2Socket over fcl-net ssockets (TInetSocket).
  - TTlsSocket implementing IHttp2Socket using mormot.lib.openssl11: SSL_CTX_new,
    TLS_client_method, SSL_CTX_set_alpn_protos with the wire bytes 0x02 0x68 0x32
    (the ALPN protocol-list encoding of "h2"), SNI via SSL_set_tlsext_host_name,
    peer verification ON by default, and after the handshake SSL_get0_alpn_selected.
  - If the selected protocol is not exactly "h2", raise EHttpProtocolError (never
    silently continue on HTTP/1.1).
  - An explicit insecure/verify-off toggle (a factory flag), default secure.
  - Read/Write deadlines mapped to EHttpTimeout on expiry (SO_RCVTIMEO/SO_SNDTIMEO or
    non-blocking + select); Read must loop over short reads until ACount bytes or EOF,
    returning the byte count and never assuming one recv returns everything.

TESTS (test/Http2.Tls.Test.pas)
  - The ALPN wire vector is exactly 0x02,0x68,0x32 (assert the helper that builds it).
  - A fake/injected handshake result that selects nothing, or "http/1.1", causes
    EHttpProtocolError - test the verification function directly, not over the network.
  - SNI host is propagated to the SSL handle (test via the seam, not the network).
  - insecure toggle flips verification off; secure default rejects a self-signed cert.
  - timeout expiry maps to EHttpTimeout; short-read loop reassembles a split payload.
  - A trivial mock class satisfies IHttp2Socket (compile-time proof for later stories).
  - Integration with a real TLS listener is OPT-IN: gate any live nghttpd test behind
    env var HTTP2_TLS_ITEST=1. If you can run /opt/homebrew/bin/nghttpd locally with the
    test certs in test/certs, do it and record the ALPN result; otherwise skip and say so.

DONE WHEN: ALPN is offered and verified, a non-h2 peer raises rather than continuing,
and your scratch run is green.`);

const lanes = [
  { key: 's02', agent: 'worker', task: s02, acceptance: 'auto' },
  { key: 's03', agent: 'worker', task: s03, acceptance: 'auto' },
  { key: 's04', agent: 'worker', task: s04, acceptance: 'auto' },
  { key: 's05', agent: 'worker', task: s05, acceptance: 'auto' }
];

const results = await runs.all(lanes);
return results.map(function (r) {
  return { key: r.key, runId: r.runId, status: r.status, outputReference: r.outputReference, output: r.output };
});
