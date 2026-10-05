---
title: "FPC Runtime & Memory Model"
aliases:
  - "fpc-runtime"
tags:
  - http2client
  - design
  - fpc
status: draft
up: "[[http2client]]"
related:
  - "[[architecture]]"
  - "[[transport]]"
updated: 2026-10-05
---

# FPC Runtime & Memory Model

Everything is using advanced records and ARC.

## General Guidelines

In Free Pascal specifically:

- **Records are not ARC.** FPC has no automatic reference counting for
  records or `TObject`-derived classes. "ARC" in this design means
  **reference-counted interfaces** (`{$interfaces com}`, the default):
  an interface variable is released automatically when the last reference
  goes out of scope.
- **Shared, long-lived state is exposed as interfaces** (`IHttpClient`,
  `IConnection`, `IHttpResponse`, `IHttpHeaders`). A record that must share
  state holds one of these interfaces, so copying the record shares the
  reference and does not deep-copy the object.
- **Value types stay as records** (`THttpMethod`, `TFrameHeader`,
  `TWindow`, `TConnectionSettings`) — copied by value, no lifetime concerns.
- **Everything is `FunctionResult`-safe**: no global mutable state; the
  factory is an immutable record built fluently.
- `TInterfacedObject` (or `TInterfacedPersistent`) is the base for
  interface implementations. `TComponent` is *not* used (no streaming/VCL
  dependency).

Required compiler directives, once, at the top of the main unit:

```pascal
{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}
```

and on Unix the program must pull in the thread manager **before** any unit
that uses threads:

```pascal
uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Classes, SyncObjs, Generics.Collections, Http2.Client;
```

Without `cthreads` the binary aborts at runtime with
`This binary has no thread support compiled in ... Runtime error 232`.

## Verified Free Pascal facts

These were compiled and run against the actual toolchain
(`fpc 3.2.4`, `ppca64`, macOS/aarch64), and they contradict some of the
prose in the original sketch. They drive the choices in this design.

| Design assumption | FPC 3.2.4 result | Consequence |
|---|---|---|
| `{$mode objfpc}` records for the API | works, but **generic methods do not parse** under `objfpc` — even with `{$modeswitch genericmethods}`: `Syntax error, ";" expected but "<" found` | use `{$mode delphi}` for generic code |
| `TThreadedQueue<T>` for frame queues | **does not exist** in 3.2.4 (`Identifier not found "TThreadedQueue"`) | build `TBlockingQueue<T>` from `TQueue<T>` + `TCriticalSection` + `RTLEvent` (probe verified, thread sum 5050) |
| `TMonitor` for stream-id allocation | **not present** (`Identifier not found "TMonitor"`) | use a `TCriticalSection` per connection |
| `TEvent` / `TSimpleEvent` for slot signalling | constructs but raises `ESyncObjectException: Failed to create OS basic event` on macOS | use `RTLEvent` (`RTLEventCreate`/`RTLEventSetEvent`/`RTLEventWaitFor`/`RTLEventDestroy`) |
| `TStringList.Remove` | **absent**: `identifier idents no member "Remove"` | use `IndexOf` + `Delete` |
| interface ARC | verified: `TInterfacedObject.Destroy` runs when the last interface ref is set to `nil` | the memory model below is sound |
| `generic TBox<T>` + `specialize TBox<Integer>.Echo` | works | generic classes are fine |
| generic `class procedure Foo<T>` | **only under `{$mode delphi}`** (`TUtil.Foo<Integer>` compiles; `specialize TUtil.Foo<Integer>` under `objfpc` does not) | generic methods are allowed, but pin the mode |
| `specialize TDictionary<K,V>` under `objfpc` | requires the `specialize` keyword in `uses`-visible code | handled by the `delphi` mode |

Probe sources are preserved in
[`reference/fpc-verified/`](../reference/fpc-verified/README.md) (see its
README for the exact reproduce commands and expected pass/fail behavior),
and were compiled with `fpc -O2`. The document's own API surface
(`Http2.Client.pas` + `testclient.pas`) also compiles and runs there.

## Memory model and ARC in FPC

The rule for every type in this design:

| Kind | Lifetime | Example |
|---|---|---|
| Value record | copied, no heap | `THttpMethod`, `TFrameHeader`, `TWindow` |
| Interface | refcounted (ARC) | `IHttpClient`, `IHttpResponse`, `IHttpHeaders` |
| Class behind an interface | owned by its interface refs | `TConnection`, `THttpResponse` |
| Background thread | explicitly started/stopped | `TConnectionThread` |

```pascal
type
  THttpClient = class(TInterfacedObject, IHttpClient)
  private
    FPool: TConnectionPool;
    FConfig: TClientConfig;
  public
    constructor Create(const AConfig: TClientConfig);
    destructor Destroy; override;
    function Send(const ARequest: THttpRequest): IHttpResponse;
    procedure Close;
  end;
```

- `TInterfacedObject` provides `_AddRef`/`_Release`; `_Release` frees the
  object when the count reaches zero. Never hold a raw pointer to a class
  that is only kept alive by an interface.
- A record that needs to share heap state wraps it in an interface field,
  never a raw class field, e.g.:
  ```pascal
  THttpRequest = record
  private
    FHeaders: IHttpHeaders;   // shared by refcount, not copied
    ...
  end;
  ```
- **Do not mix object lifetime with interface lifetime.** A `TConnection`
  referenced by `IConnection` must *not* also be `Free`d by its creator.
- **Threads and cycles**: a thread that holds an interface to its owning
  connection creates a reference cycle that ARC cannot break. The
  `TConnectionThread` therefore holds a **weak reference** to its
  `TConnection` (see [[transport]]), or the connection explicitly
  `Terminate`+`WaitFor`s the thread before releasing state.
