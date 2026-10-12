/// http2client example: a GET routed by the proxy environment variables.
// - build: `make examples`
// - run:   bin/proxy_env https://nghttp2.org/ [no-proxy-list]
//   e.g.   https_proxy=http://proxy.corp:3128 bin/proxy_env https://nghttp2.org/
//          all_proxy=socks5://user:pw@127.0.0.1:1080 bin/proxy_env https://nghttp2.org/
// - shows: WithProxyEnvironmentVars (http_proxy, https_proxy, all_proxy and
//   no_proxy are read when the client is built) and WithNoProxy (hosts that
//   always connect directly).  Without any variable set the request is
//   direct.  See doc/design/proxy.md.
program example_proxy_env;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Http2.Errors, Http2.Stream, Http2.Messages, Http2.Proxy,
  Http2.Client;

var
  Client: IHttpClient;
  Response: IHttpResponse;
  F: THttpClientFactory;
begin
  if ParamCount < 1 then
  begin
    WriteLn(StdErr, 'usage: example_proxy_env <https-url> [no-proxy-list]');
    Halt(2);
  end;

  F := THttpClientFactory.Create
    .WithProxyEnvironmentVars
    // the protocol-level fallbacks keep the example working against proxies
    // and origins that do not speak HTTP/2
    .WithHttp1Fallback(True);
  if ParamCount >= 2 then
    F := F.WithNoProxy(ParamStr(2));

  try
    // an unusable proxy value (for example socks4://) raises here, before any
    // request is sent
    Client := F.Build;
    try
      Response := Client.Send(THttpRequest.Create(hmGet, ParamStr(1)));
      WriteLn('status: ', Response.StatusCode);
      WriteLn('body bytes: ', Length(ReadText(Response)));
    finally
      Client.Close;
    end;
  except
    on E: EHttpError do
    begin
      WriteLn(StdErr, 'request failed: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
