// Sends one request to a cleartext origin under a chosen cleartext policy and
// prints the status and body length.  Driven by tools/validate/cleartext-live.sh.
//
//   cleartext_probe PORT POLICY METHOD
//
// POLICY is upgrade or http1; METHOD is GET, POST, DELETE or HEAD.  The
// request carries no body, which is what makes it eligible for the h2c probe.
program cleartext_probe;

{$mode delphi}
{$interfaces com}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Http2.Errors, Http2.Tls, Http2.Stream, Http2.Messages, Http2.Client;

var
  Port, Policy, Method: string;
  Pol: TClearTextPolicy;
  M: THttpMethod;
  Client: IHttpClient;
  R: IHttpResponse;
  Buf: array[0..255] of Byte;
  N, Total: LongInt;
begin
  if ParamCount < 3 then
  begin
    WriteLn(StdErr, 'usage: cleartext_probe PORT upgrade|http1 GET|POST|DELETE|HEAD');
    Halt(2);
  end;
  Port := ParamStr(1);
  Policy := ParamStr(2);
  Method := ParamStr(3);
  if Policy = 'http1' then
    Pol := ctHttp1
  else
    Pol := ctUpgrade;
  if Method = 'POST' then M := hmPost
  else if Method = 'DELETE' then M := hmDelete
  else if Method = 'HEAD' then M := hmHead
  else M := hmGet;
  try
    Client := THttpClientFactory.Create.WithClearText(Pol)
      .WithConnectTimeout(3000).WithHeaderTimeout(5000).Build;
    R := Client.Send(THttpRequest.Create(M, 'http://127.0.0.1:' + Port + '/probe'));
    Total := 0;
    repeat
      N := R.Body.Read(Buf, SizeOf(Buf));
      if N > 0 then
        Inc(Total, N);
    until N <= 0;
    WriteLn('status=', R.StatusCode, ' body=', Total);
    Client.Close;
  except
    on E: Exception do
    begin
      WriteLn(StdErr, 'error: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
