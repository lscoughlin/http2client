/// http2client example: one GET, or a wss session, with a client certificate.
// - build: `make examples`
// - run:   bin/mtls_get https://localhost:8443/ client.crt client.key [ca.crt [passphrase]]
//          bin/mtls_get wss://localhost:8443/ws client.crt client.key ca.crt
//          a certificate of `-` presents no identity
// - shows: WithClientCertificateFiles, a bad identity failing at Build, and the
//   distinct EHttpTlsClientAuthError when the server rejects the certificate.
program example_mtls_get;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, SyncObjs, Http2.Errors, Http2.Stream, Http2.Messages,
  Http2.Client, Http2.WebSocket;

type
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

var
  Factory: THttpClientFactory;
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
  if ParamStr(2) <> '-' then
    Factory := Factory.WithClientCertificateFiles(ParamStr(2), ParamStr(3),
      Passphrase);
  if CaFile <> '' then
    Factory := Factory.WithCACertFile(CaFile);
  try
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
  try
    try
      if Pos('wss://', ParamStr(1)) = 1 then
      begin
        Listener := TFirstText.Create;
        ListenerRef := Listener;
        Socket := Client.Send(TWebSocketRequest.Create(ParamStr(1), ListenerRef)
          .WithAutoRequest);
        if Listener.Done.WaitFor(5000) = wrSignaled then
          WriteLn('message: ', Listener.Text)
        else
          WriteLn(StdErr, 'no message arrived');
        Socket.Close;
      end
      else
      begin
        Response := Client.Send(THttpRequest.Create(hmGet, ParamStr(1)));
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
  end;
end.
