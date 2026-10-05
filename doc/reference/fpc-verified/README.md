# FPC-verified reference probes

This directory contains the minimal Free Pascal programs used to verify the
language/runtime claims in [`../../design/fpc-runtime.md`](../../design/fpc-runtime.md)
(the *Verified Free Pascal facts* table). Every claim marked "verified" in
that document is traceable to one of these files.

Toolchain used:

```
fpc 3.2.4 (ppca64), macOS/aarch64
```

## Reproduce

```sh
cd doc/reference/fpc-verified

# Individual language probes:
fpc -O2 probe2.pas  && ./probe2    # generic class + generic record
fpc -O2 probe3.pas  && ./probe3    # TQueue, interface ARC release, IndexOf+Delete
fpc -O2 probe4.pas  && ./probe4    # interface ARC release; TStringList.Remove absent
fpc -O2 probe6.pas  && ./probe6    # TCriticalSection; TEvent fails on macOS
fpc -O2 probe7.pas  && ./probe7    # RTLEvent works
fpc -O2 probe8.pas  && ./probe8    # TCriticalSection + TQueue; TMonitor absent
fpc -O2 probe9.pas  && ./probe9    # {$mode delphi} generic method compiles
fpc -O2 probe10.pas && ./probe10   # {$mode objfpc}+genericmethods still fails
fpc -O2 probe11.pas && ./probe11   # TSimpleEvent fails on macOS
fpc -O2 probe12.pas && ./probe12   # TBlockingQueue<T> + TThread, sum 5050

# The document's own API surface, compiled end to end:
fpc -O2 -Fu. -Fuh2 testclient.pas && ./testclient
```

## What each probe establishes

| File | Establishes |
| --- | --- |
| `probe.pas` | `class procedure Read<T>` **fails to parse under `{$mode objfpc}`**: `Syntax error, ";" expected but "<" found` |
| `probe2.pas` | `generic TBox<T>` class, `class procedure TBox.Read` under `{$mode objfpc}` with `specialize`, and `generic TRecBox<T>` record all compile and run |
| `probe3.pas` | `TQueue<T>` and `TDictionary<K,V>` need the `specialize` keyword in `objfpc`; interface refcount release; `TStringList` lacks `Remove` |
| `probe4.pas` | Interface ARC releases (`TThing destroyed` after `T := nil`); `TStringList.Remove` is `identifier idents no member "Remove"` |
| `probe6.pas` | `TCriticalSection` works; `TEvent.Create(..., name)` raises `ESyncObjectException: Failed to create OS basic event` (this probe **compiles and then exits non-zero on purpose** — the exception is the finding) |
| `probe7.pas` | `RTLEventCreate`/`RTLEventSetEvent`/`RTLEventWaitFor`/`RTLEventDestroy` work |
| `probe8.pas` | `TCriticalSection.Acquire/Release` and `TQueue<T>` work; `TMonitor` is `Identifier not found "TMonitor"` |
| `probe9.pas` | Under `{$mode delphi}` a generic method compiles and runs (`TUtil.Foo<Integer>`) |
| `probe10.pas` | Under `{$mode objfpc}` + `{$modeswitch genericmethods}` the same generic method still fails to parse |
| `probe11.pas` | `TSimpleEvent.Create` raises `ESyncObjectException: Failed to create OS basic event` (compiles; **runtime** failure) |
| `probe12.pas` | A hand-built `TBlockingQueue<T>` (TQueue + TCriticalSection + 2× RTLEvent) drives a `TThread` consumer; sum = 5050; requires `cthreads` in `uses` on Unix |
| `h2/Http2.Client.pas` + `testclient.pas` | The document's factory, request, body, header, and client-surface declarations compile and run (`max connections = 8`, fluent request building) |

## Caveats

- **`probe.pas`, `probe10.pas`, `probe11.pas` are expected to fail**: the
  first two fail to *compile* (that is the finding), `probe11` compiles but
  raises at run time. `probe6.pas` compiles and exits non-zero on purpose —
  the `TEvent` exception it demonstrates is the finding. A non-zero exit
  from those four is success, not a broken probe.
- These are language/runtime probes, **not** an implementation. The HTTP/2
  protocol itself (frames, HPACK, flow control, TLS/ALPN) is not exercised.
- `ESyncObjectException` for `TEvent`/`TSimpleEvent` is specific to this
  macOS install; on other platforms they may work. The design chooses
  `RTLEvent` regardless, because it is portable.
- `TThreadedQueue<T>` may exist in other FPC versions/distributions; it does
  not exist in 3.2.4.
