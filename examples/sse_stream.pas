/// http2client example: consume a Server-Sent Events stream.
// - build: `task examples` (or see examples/README.md for a raw fpc command)
// - run:   bin/sse_stream https://example.com/events
//          bin/sse_stream http://127.0.0.1:8091/events   (also works: an
//          http:// URL enables the h2c-upgrade cleartext policy, which is
//          what tools/validate/sse_server.py speaks)
// - shows: SseRequest, TSseSource reading one event at a time, and
//   TSseReconnectLoop resuming from `last-event-id` after the stream ends or
//   the transport drops (src/Http2.Sse.pas).
//
// Ctrl-C stops it; the process exits when the reconnect bound is reached.
program example_sse_stream;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Http2.Errors, Http2.Headers, Http2.Stream, Http2.Messages,
  Http2.Client, Http2.Tls, Http2.Sse;

var
  Client: IHttpClient;
  Factory: THttpClientFactory;
  Url: string;
  Loop: TSseReconnectLoop;
  Event: TSseEvent;
begin
  if ParamCount < 1 then
  begin
    WriteLn(StdErr, 'usage: example_sse_stream <https-url>');
    Halt(2);
  end;
  Url := ParamStr(1);

  Factory := THttpClientFactory.Create
    // an SSE stream holds one stream open for as long as it lives, so a
    // generous stream budget matters more here than a large connection count
    .WithMaxConnectionsPerHost(1)
    .WithMaxTotalConnections(4)
    .WithMaxStreamsPerConnection(100);
  // the default policy rejects cleartext, which is the right default; the
  // reference test server (tools/validate/sse_server.py) speaks cleartext, so
  // enable h2c-upgrade for an http:// URL to keep the documented command
  // working
  if Pos('http://', LowerCase(Url)) = 1 then
    Factory := Factory.WithClearText(ctUpgrade).WithHttp1Fallback(True);
  Client := Factory.Build;

  // SseRequest sets the three headers an event source needs
  // (accept, cache-control: no-store, accept-encoding: identity) and, most
  // importantly, an unbounded body-read deadline: an event stream is quiet
  // between events and must not be aborted by the header timeout.
  //
  // The loop reconnects when the stream ends or the transport drops, echoing
  // `last-event-id` so the server can resume. The third argument bounds the
  // RECONNECTS; 0 would retry forever. A protocol error (the peer answers
  // with a non-200 or a different content-type) is terminal and never
  // reconnects.
  Loop := TSseReconnectLoop.Create(Client, SseRequest(Url), 5);
  try
    while Loop.Next(Event) do
    begin
      if Event.EventType = 'message' then
      begin
        if Event.Id <> '' then
          WriteLn('#', Event.Id, ': ', Event.Data)
        else
          WriteLn(Event.Data);
      end
      else
        WriteLn('[', Event.EventType, '] ', Event.Data);
      Flush(Output);
    end;
  except
    on E: EHttpTooManySseRetries do
      WriteLn(StdErr, 'gave up after ', E.Message);
    on E: EHttpError do
    begin
      WriteLn(StdErr, 'stream failed: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
  Loop.Close;
  Loop.Free;
  Client.Close;
end.
