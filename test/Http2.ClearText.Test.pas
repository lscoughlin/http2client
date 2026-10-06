/// cleartext h2c and HTTP/1.1 fallback tests (plan S13)
// - Covers the factory surface (task 13.1) and the policy/limit behaviour.
//   The wire paths (prior knowledge, upgrade, HTTP/1.1 codec) land in 13.2-13.6.
unit Http2.ClearText.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry,
  Http2.Errors, Http2.Tls, Http2.Stream, Http2.Messages, Http2.Client;

type
  /// a factory that must never be dialled: the strict default rejects the
  /// request before the transport is reached
  TNeverDialFactory = class(TInterfacedObject, IHttp2SocketFactory)
  public
    function Dial(const AHost: string; const APort: Word;
      const ATimeoutMs: Integer): IHttp2Socket;
  end;

  TClearTextTest = class(TTestCase)
  published
    procedure TestDefaultsAreStrict;
    procedure TestWithClearTextChangesThePolicy;
    procedure TestWithHttp1FallbackIsOffByDefault;
    procedure TestFluentChainStaysCopyOnWrite;
    procedure TestStrictModeRejectsCleartextUrl;
    procedure TestHttpsUrlIsNotAffectedByThePolicy;
  end;

implementation

function TNeverDialFactory.Dial(const AHost: string; const APort: Word;
  const ATimeoutMs: Integer): IHttp2Socket;
begin
  raise Exception.Create('the transport must not be dialled');
end;

procedure TClearTextTest.TestDefaultsAreStrict;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create;
  AssertEquals('Http1Fallback defaults off', False, F.Http1Fallback);
  AssertTrue('ClearTextPolicy defaults to ctReject',
    F.ClearTextPolicy = ctReject);
end;

procedure TClearTextTest.TestWithClearTextChangesThePolicy;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create.WithClearText(ctPriorKnowledge);
  AssertTrue('policy is ctPriorKnowledge', F.ClearTextPolicy = ctPriorKnowledge);
  F := THttpClientFactory.Create.WithClearText(ctUpgrade);
  AssertTrue('policy is ctUpgrade', F.ClearTextPolicy = ctUpgrade);
end;

procedure TClearTextTest.TestWithHttp1FallbackIsOffByDefault;
var
  F: THttpClientFactory;
begin
  F := THttpClientFactory.Create.WithHttp1Fallback;
  AssertEquals('WithHttp1Fallback turns it on', True, F.Http1Fallback);
  F := THttpClientFactory.Create.WithHttp1Fallback(False);
  AssertEquals('explicit False keeps it off', False, F.Http1Fallback);
end;

procedure TClearTextTest.TestFluentChainStaysCopyOnWrite;
var
  A, B: THttpClientFactory;
begin
  A := THttpClientFactory.Create;
  B := A.WithClearText(ctUpgrade).WithMaxConnections(9);
  // the original factory must be untouched: WithX returns a new record
  AssertTrue('the original policy is still strict', A.ClearTextPolicy = ctReject);
  AssertEquals('the original MaxConnections is unchanged', 4, A.MaxConnections);
  AssertTrue('the fork carries the new policy', B.ClearTextPolicy = ctUpgrade);
  AssertEquals('the fork carries the new cap', 9, B.MaxConnections);
end;

procedure TClearTextTest.TestStrictModeRejectsCleartextUrl;
var
  Client: IHttpClient;
  Raised: Boolean;
  Code: Integer;
begin
  Client := THttpClientFactory.Create
    .WithSocketFactory(TNeverDialFactory.Create)
    .Build;
  Raised := False;
  Code := -1;
  try
    Client.Send(THttpRequest.Create(hmGet, 'http://plain.example/x'));
  except
    on E: EHttpError do
    begin
      Raised := True;
      Code := Ord(E.ErrorCode);
    end;
  end;
  AssertTrue('a cleartext request raises by default', Raised);
  AssertEquals('the error code is PROTOCOL_ERROR', Ord(ecProtocolError), Code);
  Client.Close;
end;

procedure TClearTextTest.TestHttpsUrlIsNotAffectedByThePolicy;
var
  Client: IHttpClient;
  Raised: Boolean;
  Msg: string;
begin
  // an https origin must pass the cleartext guard and reach the transport,
  // which proves the guard keys on the scheme and not on the policy alone
  Client := THttpClientFactory.Create
    .WithSocketFactory(TNeverDialFactory.Create)
    .Build;
  Raised := False;
  Msg := '';
  try
    Client.Send(THttpRequest.Create(hmGet, 'https://secure.example/x'));
  except
    on E: Exception do
    begin
      Raised := True;
      Msg := E.Message;
    end;
  end;
  AssertTrue('the transport was reached', Raised);
  AssertTrue('and it was the dial stub, not the cleartext guard',
    Pos('transport must not be dialled', Msg) > 0);
  Client.Close;
end;

initialization
  RegisterTest(TClearTextTest);
end.
