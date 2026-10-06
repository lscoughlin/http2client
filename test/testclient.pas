/// Sample CLI proving the documented fluent example compiles and runs
/// (plan story S09 task 09.10).
// - usage: testclient <https-url> [method]
// - it builds a client through the documented chain and performs one request.
//   With no reachable server it fails cleanly (a message + non-zero exit).
program testclient;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Http2.Errors, Http2.Messages, Http2.Client, Http2.Stream;

function ArgValue(const AIndex: Integer; const ADefault: string): string;
begin
  if ParamCount >= AIndex then
    Result := ParamStr(AIndex)
  else
    Result := ADefault;
end;

var
  Client: IHttpClient;
  Url, Method, Body: string;
  Request: THttpRequest;
  Response: IHttpResponse;
  Buf: array[0..1023] of Byte;
  N: LongInt;
begin
  Url := ArgValue(1, '');
  Method := UpperCase(ArgValue(2, 'GET'));
  if Url = '' then
  begin
    WriteLn('usage: testclient <https-url> [METHOD]');
    Halt(2);
  end;

  Client := THttpClientFactory.Create
    .WithMaxConnections(4)
    .WithMaxStreamsPerConnection(100)
    .WithFollowRedirects(True)
    .Build;
  try
    if Method = 'GET' then
      Request := THttpRequest.Create(hmGet, Url)
    else if Method = 'HEAD' then
      Request := THttpRequest.Create(hmHead, Url)
    else if Method = 'POST' then
      Request := THttpRequest.Create(hmPost, Url)
    else if Method = 'PUT' then
      Request := THttpRequest.Create(hmPut, Url)
    else if Method = 'DELETE' then
      Request := THttpRequest.Create(hmDelete, Url)
    else
      Request := THttpRequest.Create(hmGet, Url).WithMethodToken(Method);

    Request := Request.WithHeader('user-agent', 'http2client-testclient');

    try
      Response := Client.Send(Request);
    except
      on E: EHttpError do
      begin
        WriteLn(StdErr, 'request failed: ', E.ClassName, ': ', E.Message);
        Halt(1);
      end;
    end;

    WriteLn('status: ', Response.StatusCode);
    Body := '';
    while True do
    begin
      N := Response.Body.Read(Buf, SizeOf(Buf));
      if N <= 0 then
        Break;
      SetLength(Body, Length(Body) + N);
      Move(Buf[0], Body[Length(Body) - N + 1], N);
    end;
    if Body <> '' then
      Write(Body);
    WriteLn;
  finally
    Client.Close;
  end;
end.
