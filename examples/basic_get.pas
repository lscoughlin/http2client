/// http2client example: one GET request.
// - build: `task examples` (or see examples/README.md for a raw fpc command)
// - run:   bin/basic_get https://nghttp2.org/
// - shows: the fluent factory, Send, StatusCode, a response header, and
//   reading the whole body as text with ReadText (src/Http2.Client.pas).
program example_basic_get;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Http2.Errors, Http2.Headers, Http2.Stream, Http2.Messages,
  Http2.Client;

var
  Client: IHttpClient;
  Url: string;
  Response: IHttpResponse;
begin
  if ParamCount < 1 then
  begin
    WriteLn(StdErr, 'usage: example_basic_get <https-url>');
    Halt(2);
  end;
  Url := ParamStr(1);

  Client := THttpClientFactory.Create
    // one connection per host is the most RFC 9113 section 9.1 conformant
    // choice; the pool still multiplexes many streams over it
    .WithMaxConnectionsPerHost(1)
    .WithMaxTotalConnections(8)
    .WithMaxStreamsPerConnection(100)
    .Build;
  try
    Response := Client.Send(
      THttpRequest.Create(hmGet, Url)
        .WithHeader('user-agent', 'http2client-example'));

    WriteLn('status: ', Response.StatusCode);
    WriteLn('content-type: ', Response.Headers.GetFirst('content-type'));

    // ReadText drains the body stream to EOF and copies the bytes verbatim.
    WriteLn('body bytes: ', Length(ReadText(Response)));
  except
    on E: EHttpError do
    begin
      WriteLn(StdErr, 'request failed: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
  Client.Close;
end.
