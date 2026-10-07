/// http2client example: a POST with a plain text body.
// - build: `task examples`
// - run:   bin/post_text https://nghttp2.org/httpbin/post
// - shows: WithTextBody (src/Http2.Client.pas) attaches the body and defaults
//   `content-type: text/plain`; ReadText reads the echoed body back. Set your
//   own content-type first and WithTextBody leaves it alone.
program example_post_text;

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
    WriteLn(StdErr, 'usage: example_post_text <url>');
    Halt(2);
  end;
  Url := ParamStr(1);

  Client := THttpClientFactory.Create.WithMaxConnectionsPerHost(1).Build;
  try
    Response := Client.Send(
      WithTextBody(
        THttpRequest.Create(hmPost, Url), 'hello from http2client'));

    WriteLn('status: ', Response.StatusCode);
    WriteLn('response: ', ReadText(Response));
  except
    on E: EHttpError do
    begin
      WriteLn(StdErr, 'request failed: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
  Client.Close;
end.
