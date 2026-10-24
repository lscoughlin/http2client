/// Driver for the real-proxy gate (tools/validate/proxy-real.sh): one scenario
// per run, one machine-readable line per outcome.
// - build: tools/validate/proxy-real.sh compiles it into the work directory
// - run:   proxy_real_client <get|ws|sse> <url> [option...]
// - options (all optional):
//     proxy=URL        WithAllProxy(URL): [scheme://][user:pw@]host:port
//     env=NAME=VALUE   one proxy environment variable, served to the client
//                      through WithProxyEnvironmentLookup (repeatable) and
//                      switched on with WithProxyEnvironmentVars
//     noproxy=LIST     WithNoProxy(LIST)
//     ca=FILE          WithCACertFile
//     cert=F key=F     the origin identity (WithClientCertificateFiles)
//     pcert=F pkey=F   the proxy identity (WithProxyClientIdentity)
//     repeat=N         N sequential requests on one client (get only)
//     events=N         stop an event stream after N events (sse only)
//     timeout=MS       connect and header timeout (default 8000)
// - prints: `req I status=S bytes=B`, `ws text=T`, `sse EVENT`, then
//   `pool conns=N idle=I proto=P1,P2` and `RESULT ok` or
//   `RESULT error <class>: <message>`; exit code 0 or 1.
// - shows: WithAllProxy, WithProxyEnvironmentLookup, WithProxyClientIdentity,
//   PoolStats, the proxy error class, a WebSocket and an event stream
//   through a proxy.  See doc/verification/proxy-real.md.
program proxy_real_client;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Classes, SyncObjs, Http2.Errors, Http2.Stream, Http2.Messages,
  Http2.ClientCert, Http2.Proxy, Http2.Tls, Http2.Client, Http2.WebSocket,
  Http2.Sse;

type
  /// remembers the first text message and wakes the main thread
  TFirstText = class(TWebSocketListener)
  public
    Done: TEvent;
    Text: string;
    Failure: string;
    constructor Create;
    destructor Destroy; override;
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); override;
    procedure OnError(const ASocket: IWebSocket;
      const AError: Exception); override;
  end;

var
  Env: TStringList;   // NAME=VALUE pairs served by the lookup

constructor TFirstText.Create;
begin
  inherited Create;
  Done := TEvent.Create(nil, True, False, '');
end;

destructor TFirstText.Destroy;
begin
  Done.Free;
  inherited Destroy;
end;

procedure TFirstText.OnText(const ASocket: IWebSocket; const AText: string;
  const ALast: Boolean);
begin
  Text := AText;
  Done.SetEvent;
end;

procedure TFirstText.OnError(const ASocket: IWebSocket; const AError: Exception);
begin
  Failure := AError.ClassName + ': ' + AError.Message;
  Done.SetEvent;
end;

function EnvLookup(const AName: string): string;
begin
  Result := Env.Values[AName];
end;

function Opt(const AName, ADefault: string): string;
var
  I: Integer;
  Prefix: string;
begin
  Result := ADefault;
  Prefix := AName + '=';
  for I := 3 to ParamCount do
    if Pos(Prefix, ParamStr(I)) = 1 then
      Result := Copy(ParamStr(I), Length(Prefix) + 1, MaxInt);
end;

function ProtocolName(const AP: TNegotiatedProtocol): string;
begin
  case AP of
    npHttp2Tls: Result := 'h2';
    npHttp2Cleartext: Result := 'h2c';
    npHttp1Tls: Result := 'http/1.1+tls';
  else
    Result := 'http/1.1';
  end;
end;

procedure PrintPool(const AClient: IHttpClient);
var
  S: TPoolStats;
  I, J: Integer;
  Protos: string;
begin
  S := (AClient as THttpClient).PoolStats;
  Protos := '';
  for I := 0 to High(S.PerOrigin) do
    for J := 0 to High(S.PerOrigin[I].Details) do
    begin
      if Protos <> '' then
        Protos := Protos + ',';
      Protos := Protos + ProtocolName(S.PerOrigin[I].Details[J].Protocol);
    end;
  WriteLn('pool conns=', S.Connections, ' idle=', S.IdleConnections,
    ' proto=', Protos);
end;

var
  Mode, Url, V: string;
  Factory: THttpClientFactory;
  Client: IHttpClient;
  Response: IHttpResponse;
  Listener: TFirstText;
  ListenerRef: IWebSocketListener;
  Socket: IWebSocket;
  Loop: TSseReconnectLoop;
  Event: TSseEvent;
  I, N, Timeout: Integer;
begin
  if ParamCount < 2 then
  begin
    WriteLn(StdErr, 'usage: proxy_real_client <get|ws|sse> <url> [option=value...]');
    Halt(2);
  end;
  Mode := ParamStr(1);
  Url := ParamStr(2);
  Timeout := StrToIntDef(Opt('timeout', '8000'), 8000);
  Env := TStringList.Create;
  Env.CaseSensitive := True;   // HTTP_PROXY and http_proxy are different variables
  for I := 3 to ParamCount do
    if Pos('env=', ParamStr(I)) = 1 then
      Env.Add(Copy(ParamStr(I), 5, MaxInt));

  Factory := THttpClientFactory.Create.WithHttp1Fallback(True)
    .WithConnectTimeout(Timeout).WithHeaderTimeout(Timeout);
  // a plain http:// origin: h2c upgrade first, falling back to HTTP/1.1
  if (Pos('http://', Url) = 1) or (Pos('ws://', Url) = 1) then
    Factory := Factory.WithClearText(ctUpgrade);
  if Env.Count > 0 then
    Factory := Factory.WithProxyEnvironmentLookup(EnvLookup)
      .WithProxyEnvironmentVars;
  V := Opt('proxy', '');
  if V <> '' then
    Factory := Factory.WithAllProxy(V);
  V := Opt('noproxy', '');
  if V <> '' then
    Factory := Factory.WithNoProxy(V);
  V := Opt('ca', '');
  if V <> '' then
    Factory := Factory.WithCACertFile(V);
  V := Opt('cert', '');
  if V <> '' then
    Factory := Factory.WithClientCertificateFiles(V, Opt('key', ''));
  Client := nil;
  try
    V := Opt('pcert', '');
    if V <> '' then
      Factory := Factory.WithProxyClientIdentity(
        TClientIdentity.FromPemFiles(V, Opt('pkey', '')));
    Client := Factory.Build;
    if Mode = 'get' then
    begin
      N := StrToIntDef(Opt('repeat', '1'), 1);
      for I := 1 to N do
      begin
        Response := Client.Send(THttpRequest.Create(hmGet, Url));
        WriteLn('req ', I, ' status=', Response.StatusCode,
          ' bytes=', Length(ReadText(Response)));
      end;
      PrintPool(Client);
    end
    else if Mode = 'ws' then
    begin
      Listener := TFirstText.Create;
      ListenerRef := Listener;
      Socket := Client.Send(TWebSocketRequest.Create(Url, ListenerRef)
        .WithAutoRequest);
      Socket.SendText('hello-through-proxy');
      if Listener.Done.WaitFor(Timeout) <> wrSignaled then
        raise EHttpError.Create('no WebSocket message within the timeout');
      if Listener.Failure <> '' then
        raise EHttpError.Create(Listener.Failure);
      WriteLn('ws text=', Listener.Text);
      Socket.Close;
    end
    else if Mode = 'sse' then
    begin
      N := StrToIntDef(Opt('events', '3'), 3);
      Loop := TSseReconnectLoop.Create(Client, SseRequest(Url), 1);
      try
        I := 0;
        while (I < N) and Loop.Next(Event) do
        begin
          Inc(I);
          WriteLn('sse ', Event.EventType, ' ', Event.Data);
        end;
        if I = 0 then
          raise EHttpError.Create('no event arrived');
      finally
        Loop.Close;
        Loop.Free;
      end;
      PrintPool(Client);
    end
    else
    begin
      WriteLn(StdErr, 'unknown mode ', Mode);
      Halt(2);
    end;
    WriteLn('RESULT ok');
    Client.Close;
  except
    on E: Exception do
    begin
      WriteLn('RESULT error ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
end.
