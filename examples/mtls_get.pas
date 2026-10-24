/// http2client example: GETs, or a wss session, with a client certificate.
// - build: `make examples`
// - run:   bin/mtls_get https://localhost:8443/ client.crt client.key [ca.crt [passphrase]]
//          bin/mtls_get wss://localhost:8443/ws client.crt client.key ca.crt
//          a certificate of `-` presents no identity; the URL may be a comma
//          separated list, fetched in turn by the one client
// - env:   MTLS_SELECT=port:cert:key[;port:cert:key...] picks the identity per
//          origin port with a selector that reads the files at each dial (so a
//          replaced file is presented by the next new connection), in place of
//          the certificate arguments
//          MTLS_PROXY=port routes every request through an https proxy on
//          localhost:port (MTLS_PROXY_KIND=http makes it an HTTP CONNECT
//          proxy); MTLS_PROXY_CERT and MTLS_PROXY_KEY are the identity an
//          https proxy requires (never sent to the origin; the origin
//          identity reaches the origin through either kind)
//          MTLS_REQUEST_CERT and MTLS_REQUEST_KEY attach one identity to each
//          request (the origin identity for that request: it wins over the
//          selector and the certificate arguments, goes through any proxy to
//          the origin only, and is dropped on a redirect to another origin)
// - shows: WithClientCertificateFiles, WithClientIdentitySelector,
//   WithProxyClientIdentity, a per-request WithClientIdentity, a bad identity failing at Build, and the
//   distinct EHttpTlsClientAuthError when the server rejects the certificate.
program example_mtls_get;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, Classes, SyncObjs, Http2.Errors, Http2.Stream, Http2.Messages,
  Http2.ClientCert, Http2.Proxy, Http2.Client, Http2.WebSocket;

type
  /// MTLS_SELECT: the identity files for each origin port, read at every dial
  TFileSelector = class(TInterfacedObject, IClientIdentitySelector)
  private
    FEntries: TStringList;   // port=cert|key
  public
    constructor Create(const ASpec: string);
    destructor Destroy; override;
    function Select(const AHost: string; const APort: Word): IClientIdentity;
  end;

  /// every request goes through one proxy
  TFixedHttpsProxy = class(TInterfacedObject, IProxySelector)
  private
    FProxy: IProxy;
  public
    constructor Create(const AKind: TProxyKind; const APort: Word);
    function SelectProxy(const AUri: string): IProxy;
  end;

  /// remembers the first text message and wakes the main thread
  TFirstText = class(TWebSocketListener)
  public
    Done: TEvent;
    Text: string;
    constructor Create;
    destructor Destroy; override;
    procedure OnText(const ASocket: IWebSocket; const AText: string;
      const ALast: Boolean); override;
  end;

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

constructor TFileSelector.Create(const ASpec: string);
var
  Parts: TStringList;
  I: Integer;
  Entry: TStringList;
begin
  inherited Create;
  FEntries := TStringList.Create;
  Parts := TStringList.Create;
  Entry := TStringList.Create;
  try
    Parts.Delimiter := ';';
    Parts.StrictDelimiter := True;
    Parts.DelimitedText := ASpec;
    for I := 0 to Parts.Count - 1 do
    begin
      Entry.Delimiter := ':';
      Entry.StrictDelimiter := True;
      Entry.DelimitedText := Parts[I];
      if Entry.Count = 3 then
        FEntries.Add(Entry[0] + '=' + Entry[1] + '|' + Entry[2]);
    end;
  finally
    Entry.Free;
    Parts.Free;
  end;
end;

destructor TFileSelector.Destroy;
begin
  FEntries.Free;
  inherited Destroy;
end;

function TFileSelector.Select(const AHost: string;
  const APort: Word): IClientIdentity;
var
  Value: string;
  P: Integer;
begin
  // no entry for the port: present nothing
  Result := nil;
  Value := FEntries.Values[IntToStr(APort)];
  P := Pos('|', Value);
  if P = 0 then
    Exit;
  // read from disk now, so a file replaced since the last dial is picked up
  Result := TClientIdentity.FromPemFiles(Copy(Value, 1, P - 1),
    Copy(Value, P + 1, MaxInt));
end;

constructor TFixedHttpsProxy.Create(const AKind: TProxyKind; const APort: Word);
begin
  inherited Create;
  FProxy := TProxy.Create(AKind, 'localhost', APort);
end;

function TFixedHttpsProxy.SelectProxy(const AUri: string): IProxy;
begin
  Result := FProxy;
end;

var
  Factory: THttpClientFactory;
  Urls: TStringList;
  UrlIndex: Integer;
  SelectSpec, ProxyPort, ProxyCert, ProxyKey, ReqCert, ReqKey: string;
  ReqId: IClientIdentity;
  Client: IHttpClient;
  Response: IHttpResponse;
  Listener: TFirstText;
  ListenerRef: IWebSocketListener;
  Socket: IWebSocket;
  CaFile, Passphrase: string;
begin
  if ParamCount < 3 then
  begin
    WriteLn(StdErr,
      'usage: example_mtls_get <url> <cert.pem|-> <key.pem> [ca.pem [passphrase]]');
    Halt(2);
  end;
  CaFile := '';
  Passphrase := '';
  if ParamCount >= 4 then
    CaFile := ParamStr(4);
  if ParamCount >= 5 then
    Passphrase := ParamStr(5);

  // HTTP/1.1 is accepted as well as HTTP/2, so any server will do
  Factory := THttpClientFactory.Create.WithHttp1Fallback(True);
  SelectSpec := GetEnvironmentVariable('MTLS_SELECT');
  ProxyPort := GetEnvironmentVariable('MTLS_PROXY');
  ProxyCert := GetEnvironmentVariable('MTLS_PROXY_CERT');
  ProxyKey := GetEnvironmentVariable('MTLS_PROXY_KEY');
  ReqCert := GetEnvironmentVariable('MTLS_REQUEST_CERT');
  ReqKey := GetEnvironmentVariable('MTLS_REQUEST_KEY');
  ReqId := nil;
  if SelectSpec <> '' then
    Factory := Factory.WithClientIdentitySelector(TFileSelector.Create(SelectSpec))
  else if ParamStr(2) <> '-' then
    Factory := Factory.WithClientCertificateFiles(ParamStr(2), ParamStr(3),
      Passphrase);
  if ProxyPort <> '' then
    if GetEnvironmentVariable('MTLS_PROXY_KIND') = 'http' then
      Factory := Factory.WithProxySelector(
        TFixedHttpsProxy.Create(pkHttp, Word(StrToInt(ProxyPort))))
    else
      Factory := Factory.WithProxySelector(
        TFixedHttpsProxy.Create(pkHttps, Word(StrToInt(ProxyPort))));
  if CaFile <> '' then
    Factory := Factory.WithCACertFile(CaFile);
  try
    if ProxyCert <> '' then
      Factory := Factory.WithProxyClientIdentity(
        TClientIdentity.FromPemFiles(ProxyCert, ProxyKey));
    if ReqCert <> '' then
      ReqId := TClientIdentity.FromPemFiles(ReqCert, ReqKey);
    // an unreadable file, a wrong passphrase, a key that does not match the
    // certificate and an expired certificate all fail here, not on the request
    Client := Factory.Build;
  except
    on E: EHttpTlsConfigError do
    begin
      WriteLn(StdErr, 'client identity rejected: ', E.Message);
      Halt(1);
    end;
  end;
  Urls := TStringList.Create;
  Urls.Delimiter := ',';
  Urls.StrictDelimiter := True;
  Urls.DelimitedText := ParamStr(1);
  try
    try
      for UrlIndex := 0 to Urls.Count - 1 do
        if Pos('wss://', Urls[UrlIndex]) = 1 then
        begin
          Listener := TFirstText.Create;
          ListenerRef := Listener;
          Socket := Client.Send(TWebSocketRequest.Create(Urls[UrlIndex],
            ListenerRef).WithAutoRequest.WithClientIdentity(ReqId));
          if Listener.Done.WaitFor(5000) = wrSignaled then
            WriteLn('message: ', Listener.Text)
          else
            WriteLn(StdErr, 'no message arrived');
          Socket.Close;
        end
        else
        begin
          Response := Client.Send(THttpRequest.Create(hmGet, Urls[UrlIndex])
            .WithClientIdentity(ReqId));
          WriteLn('status: ', Response.StatusCode);
          WriteLn('body bytes: ', Length(ReadText(Response)));
        end;
    except
      on E: EHttpTlsClientAuthError do
      begin
        // the server refused our certificate; retrying cannot change that
        WriteLn(StdErr, 'server rejected the client certificate: ', E.Alert);
        Halt(3);
      end;
      on E: EHttpError do
      begin
        WriteLn(StdErr, 'request failed: ', E.ClassName, ': ', E.Message);
        Halt(1);
      end;
    end;
  finally
    Client.Close;
    Urls.Free;
  end;
end.
