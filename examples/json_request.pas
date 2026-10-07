/// http2client example: send JSON and read JSON directly into TJSONObject.
// - build: `task examples`
// - run:   bin/json_request https://nghttp2.org/httpbin/post
// - shows: Http2.Readers.pas. WithJsonBody serializes a TJSONData request body
//   and defaults `content-type: application/json`; ReadJsonObject parses the
//   response body straight into a TJSONObject. The reader returns a
//   CALLER-OWNED object, so it is freed in a `finally`.
// - Http2.Readers is an OPTIONAL unit: the 13-unit core library has no JSON or
//   XML dependency. Add it to your uses clause only when you need it.
program example_json;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, fpjson,
  Http2.Errors, Http2.Headers, Http2.Stream, Http2.Messages,
  Http2.Client, Http2.Readers;

var
  Client: IHttpClient;
  Url: string;
  Response: IHttpResponse;
  Request: THttpRequest;
  Sent: TJSONObject;
  Got: TJSONObject;
begin
  if ParamCount < 1 then
  begin
    WriteLn(StdErr, 'usage: example_json <url>');
    Halt(2);
  end;
  Url := ParamStr(1);

  Client := THttpClientFactory.Create.WithMaxConnectionsPerHost(1).Build;
  try
    Sent := TJSONObject.Create;
    try
      Sent.Add('name', 'widget');
      Sent.Add('count', 3);

      Request := WithJsonBody(
        THttpRequest.Create(hmPost, Url), Sent);
      Response := Client.Send(Request);
    finally
      Sent.Free;
    end;

    WriteLn('status: ', Response.StatusCode);
    WriteLn('content-type: ', Response.Headers.GetFirst('content-type'));

    // parse the body directly into a TJSONObject; we own the result.
    Got := ReadJsonObject(Response);
    try
      WriteLn('json: ', Got.AsJSON);
    finally
      Got.Free;
    end;
  except
    on E: EHttpError do
    begin
      WriteLn(StdErr, 'request failed: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
  Client.Close;
end.
