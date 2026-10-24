/// Unit tests for Http2.ClientCert and the identity factory methods
// (doc/design/mtls.md "Testing")
// - no network: every case loads the fixtures under test/certs/mtls, which
//   tools/validate/make-mtls-certs.sh regenerates.
unit Http2.ClientCert.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, DateUtils, fpcunit, testregistry,
  mormot.lib.openssl11, Http2.Errors, Http2.ClientCert, Http2.Tls, Http2.Client;

type
  TClientCertTest = class(TTestCase)
  protected
    procedure SetUp; override;
    function FailureMessage(const AKind: Integer): string;
  published
    // PEM
    procedure TestPemFilesLoadAndReportSubjectFingerprintAndExpiry;
    procedure TestChainFileKeepsTheIntermediate;
    procedure TestFromPemLoadsFromMemory;
    procedure TestEncryptedKeyWithTheRightPassphrase;
    procedure TestEncryptedKeyWithTheWrongPassphraseRaises;
    procedure TestEncryptedKeyWithoutAPassphraseRaisesInsteadOfPrompting;
    procedure TestMismatchedKeyRaises;
    procedure TestTruncatedCertificatePemRaises;
    procedure TestTruncatedKeyPemRaises;
    procedure TestEmptyChainRaises;
    procedure TestTextWithNoPemBlockRaises;
    procedure TestUnreadableFileNamesTheFile;
    procedure TestExpiredLeafLoadsAndReportsThePast;
    // PKCS#12
    procedure TestPkcs12WithoutAChain;
    procedure TestPkcs12WithAChain;
    procedure TestPkcs12WrongPassphraseRaises;
    procedure TestPkcs12GarbageRaises;
    procedure TestPkcs12FromMemory;
    // secrets
    procedure TestNoLoaderMessageContainsThePassphrase;
    // factory surface
    procedure TestBuildAcceptsAGoodIdentity;
    procedure TestBuildRaisesForAnExpiredIdentity;
    procedure TestBuildRaisesForUnreadableCertificateFiles;
    procedure TestBadFilesFailAtBuildNotAtTheWithCall;
    procedure TestBuildMessageNeverContainsThePassphrase;
    procedure TestBuildWithoutAnIdentityIsUnchanged;
    procedure TestClientAuthAlertNames;
  end;

implementation

const
  cPass = 'mtls-test-pass';
  cSecret = 'S3cr3t-Wr0ng-Pass-Phrase';

function Fixture(const AName: string): string;
begin
  Result := ExtractFilePath(ParamStr(0)) + '../test/certs/mtls/' + AName;
  if FileExists(Result) then
    Exit;
  Result := 'test/certs/mtls/' + AName;
end;

function ReadBytes(const AName: string): TBytes;
var
  S: TFileStream;
begin
  S := TFileStream.Create(Fixture(AName), fmOpenRead or fmShareDenyNone);
  try
    SetLength(Result, S.Size);
    if Length(Result) > 0 then
      S.ReadBuffer(Result[0], Length(Result));
  finally
    S.Free;
  end;
end;

function Utf8Bytes(const AText: string): TBytes;
var
  U: UTF8String;
begin
  U := UTF8String(AText);
  SetLength(Result, Length(U));
  if Length(U) > 0 then
    Move(U[1], Result[0], Length(U));
end;

function Truncated(const ABytes: TBytes; const ACount: Integer): TBytes;
begin
  Result := Copy(ABytes, 0, ACount);
end;

procedure TClientCertTest.SetUp;
begin
  // load OpenSSL on the main thread before anything else uses it
  if not OpenSslIsAvailable then
    Fail('OpenSSL is not available: set OPENSSL_LIBPATH');
end;

procedure TClientCertTest.TestPemFilesLoadAndReportSubjectFingerprintAndExpiry;
var
  Id: IClientIdentity;
  I: Integer;
begin
  Id := TClientIdentity.FromPemFiles(Fixture('client.crt'), Fixture('client.key'));
  AssertTrue('subject names the client', Pos('mtls client', Id.Subject) > 0);
  AssertEquals('SHA-256 as hex', 64, Length(Id.Fingerprint));
  for I := 1 to Length(Id.Fingerprint) do
    AssertTrue('lowercase hex', Id.Fingerprint[I] in ['0'..'9', 'a'..'f']);
  AssertTrue('expires in the future', Id.NotAfter > LocalTimeToUniversal(Now));
  AssertTrue('valid for at least ten years more',
    Id.NotAfter > IncYear(LocalTimeToUniversal(Now), 10));
end;

procedure TClientCertTest.TestChainFileKeepsTheIntermediate;
var
  Id: IClientIdentity;
  Alone: IClientIdentity;
begin
  Id := TClientIdentity.FromPemFiles(Fixture('client-chain.pem'),
    Fixture('client.key'));
  Alone := TClientIdentity.FromPemFiles(Fixture('client.crt'), Fixture('client.key'));
  AssertEquals('leaf then one intermediate', 1, Id.GetChainCount);
  AssertEquals('a lone leaf has no chain', 0, Alone.GetChainCount);
  AssertEquals('the leaf is the first certificate', Alone.Fingerprint,
    Id.Fingerprint);
end;

procedure TClientCertTest.TestFromPemLoadsFromMemory;
var
  Id: IClientIdentity;
begin
  Id := TClientIdentity.FromPem(ReadBytes('client-chain.pem'),
    ReadBytes('client.key'));
  AssertEquals('chain', 1, Id.GetChainCount);
  AssertTrue('subject', Pos('mtls client', Id.Subject) > 0);
end;

procedure TClientCertTest.TestEncryptedKeyWithTheRightPassphrase;
var
  Id: IClientIdentity;
begin
  Id := TClientIdentity.FromPemFiles(Fixture('client.crt'),
    Fixture('client-encrypted.key'), cPass);
  AssertTrue('loaded', Id <> nil);
end;

procedure TClientCertTest.TestEncryptedKeyWithTheWrongPassphraseRaises;
begin
  try
    TClientIdentity.FromPemFiles(Fixture('client.crt'),
      Fixture('client-encrypted.key'), cSecret);
    Fail('a wrong passphrase must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('the message names the key file',
        Pos('client-encrypted.key', E.Message) > 0);
  end;
end;

procedure TClientCertTest.TestEncryptedKeyWithoutAPassphraseRaisesInsteadOfPrompting;
begin
  // OpenSSL would read a passphrase from the terminal if no callback answered
  try
    TClientIdentity.FromPemFiles(Fixture('client.crt'),
      Fixture('client-encrypted.key'));
    Fail('a missing passphrase must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('raised', E.Message <> '');
  end;
end;

procedure TClientCertTest.TestMismatchedKeyRaises;
begin
  try
    TClientIdentity.FromPemFiles(Fixture('client.crt'),
      Fixture('other-client.key'));
    Fail('a key that does not match the leaf must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('says so', Pos('does not match', E.Message) > 0);
  end;
end;

procedure TClientCertTest.TestTruncatedCertificatePemRaises;
var
  Cert: TBytes;
begin
  Cert := ReadBytes('client.crt');
  try
    TClientIdentity.FromPem(Truncated(Cert, Length(Cert) div 2),
      ReadBytes('client.key'));
    Fail('a truncated certificate must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('raised', E.Message <> '');
  end;
end;

procedure TClientCertTest.TestTruncatedKeyPemRaises;
var
  Key: TBytes;
begin
  Key := ReadBytes('client.key');
  try
    TClientIdentity.FromPem(ReadBytes('client.crt'),
      Truncated(Key, Length(Key) div 2));
    Fail('a truncated key must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('raised', E.Message <> '');
  end;
end;

procedure TClientCertTest.TestEmptyChainRaises;
begin
  try
    TClientIdentity.FromPem(nil, ReadBytes('client.key'));
    Fail('an empty chain must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('says empty', Pos('empty', E.Message) > 0);
  end;
end;

procedure TClientCertTest.TestTextWithNoPemBlockRaises;
begin
  try
    TClientIdentity.FromPem(Utf8Bytes('not a certificate'),
      ReadBytes('client.key'));
    Fail('text without a PEM block must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('raised', E.Message <> '');
  end;
end;

procedure TClientCertTest.TestUnreadableFileNamesTheFile;
begin
  try
    TClientIdentity.FromPemFiles(Fixture('no-such.crt'), Fixture('client.key'));
    Fail('a missing file must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('names the file', Pos('no-such.crt', E.Message) > 0);
  end;
end;

procedure TClientCertTest.TestExpiredLeafLoadsAndReportsThePast;
var
  Id: IClientIdentity;
begin
  // the loader parses; refusing an expired identity is Build's job
  Id := TClientIdentity.FromPemFiles(Fixture('expired.crt'), Fixture('expired.key'));
  AssertTrue('expired in the past', Id.NotAfter < LocalTimeToUniversal(Now));
end;

procedure TClientCertTest.TestPkcs12WithoutAChain;
var
  Id: IClientIdentity;
begin
  Id := TClientIdentity.FromPkcs12File(Fixture('client.p12'), cPass);
  AssertEquals('no chain', 0, Id.GetChainCount);
  AssertTrue('subject', Pos('mtls client', Id.Subject) > 0);
end;

procedure TClientCertTest.TestPkcs12WithAChain;
var
  Id: IClientIdentity;
begin
  Id := TClientIdentity.FromPkcs12File(Fixture('client-chain.p12'), cPass);
  AssertEquals('the intermediate travels with the bundle', 1, Id.GetChainCount);
  AssertEquals('same leaf as the PEM',
    TClientIdentity.FromPemFiles(Fixture('client.crt'),
      Fixture('client.key')).Fingerprint, Id.Fingerprint);
end;

procedure TClientCertTest.TestPkcs12WrongPassphraseRaises;
begin
  try
    TClientIdentity.FromPkcs12File(Fixture('client.p12'), cSecret);
    Fail('a wrong passphrase must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('names the bundle', Pos('client.p12', E.Message) > 0);
  end;
end;

procedure TClientCertTest.TestPkcs12GarbageRaises;
begin
  try
    TClientIdentity.FromPkcs12(Utf8Bytes('definitely not a pkcs12 bundle'), cPass);
    Fail('garbage must raise');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('raised', E.Message <> '');
  end;
end;

procedure TClientCertTest.TestPkcs12FromMemory;
var
  Id: IClientIdentity;
begin
  Id := TClientIdentity.FromPkcs12(ReadBytes('client-chain.p12'), cPass);
  AssertEquals('chain', 1, Id.GetChainCount);
end;

function TClientCertTest.FailureMessage(const AKind: Integer): string;
begin
  Result := '';
  try
    case AKind of
      0: TClientIdentity.FromPemFiles(Fixture('client.crt'),
           Fixture('client-encrypted.key'), cSecret);
      1: TClientIdentity.FromPkcs12File(Fixture('client.p12'), cSecret);
      2: TClientIdentity.FromPkcs12(Utf8Bytes('garbage'), cSecret);
      3: TClientIdentity.FromPemFiles(Fixture('missing.crt'),
           Fixture('client-encrypted.key'), cSecret);
      4: TClientIdentity.FromPemFiles(Fixture('client.crt'),
           Fixture('other-client.key'), cSecret);
    end;
  except
    on E: EHttpTlsConfigError do
      Result := E.Message;
  end;
end;

procedure TClientCertTest.TestNoLoaderMessageContainsThePassphrase;
var
  I: Integer;
  Msg: string;
begin
  // a wrong passphrase on PEM and PKCS#12, on garbage, on a missing file and
  // beside a mismatched key
  for I := 0 to 4 do
  begin
    Msg := FailureMessage(I);
    AssertTrue('attempt ' + IntToStr(I) + ' raised', Msg <> '');
    AssertEquals('attempt ' + IntToStr(I) + ' has no passphrase', 0,
      Pos(cSecret, Msg));
  end;
end;

procedure TClientCertTest.TestBuildAcceptsAGoodIdentity;
var
  Client: IHttpClient;
begin
  Client := THttpClientFactory.Create
    .WithClientIdentity(TClientIdentity.FromPemFiles(Fixture('client.crt'),
      Fixture('client.key')))
    .Build;
  AssertTrue('built', Client <> nil);
  Client.Close;
end;

procedure TClientCertTest.TestBuildRaisesForAnExpiredIdentity;
begin
  try
    THttpClientFactory.Create
      .WithClientIdentity(TClientIdentity.FromPemFiles(Fixture('expired.crt'),
        Fixture('expired.key')))
      .Build;
    Fail('an expired identity must fail at Build');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('says expired', Pos('expired', E.Message) > 0);
  end;
end;

procedure TClientCertTest.TestBuildRaisesForUnreadableCertificateFiles;
begin
  try
    THttpClientFactory.Create
      .WithClientCertificateFiles(Fixture('missing.crt'), Fixture('client.key'))
      .Build;
    Fail('unreadable files must fail at Build');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('names the file', Pos('missing.crt', E.Message) > 0);
  end;
end;

procedure TClientCertTest.TestBadFilesFailAtBuildNotAtTheWithCall;
var
  F: THttpClientFactory;
begin
  // the factory is a value builder: configuring does not raise
  F := THttpClientFactory.Create.WithClientCertificateFiles(
    Fixture('client.crt'), Fixture('other-client.key'));
  AssertTrue('no identity was kept', F.ClientIdentity = nil);
  try
    F.Build;
    Fail('a mismatched key must fail at Build');
  except
    on E: EHttpTlsConfigError do
      AssertTrue('says so', Pos('does not match', E.Message) > 0);
  end;
end;

procedure TClientCertTest.TestBuildMessageNeverContainsThePassphrase;
begin
  try
    THttpClientFactory.Create
      .WithClientCertificateFiles(Fixture('client.crt'),
        Fixture('client-encrypted.key'), cSecret)
      .Build;
    Fail('a wrong passphrase must fail at Build');
  except
    on E: EHttpTlsConfigError do
      AssertEquals('no passphrase in the message', 0, Pos(cSecret, E.Message));
  end;
end;

procedure TClientCertTest.TestBuildWithoutAnIdentityIsUnchanged;
var
  Client: IHttpClient;
begin
  Client := THttpClientFactory.Create.Build;
  AssertTrue('built', Client <> nil);
  Client.Close;
end;

procedure TClientCertTest.TestClientAuthAlertNames;
begin
  // reason = 1000 + the TLS alert number (openssl/sslerr.h)
  AssertEquals('certificate required', ClientAuthAlertName(1116));
  AssertEquals('bad certificate', ClientAuthAlertName(1042));
  AssertEquals('unknown ca', ClientAuthAlertName(1048));
  AssertEquals('certificate expired', ClientAuthAlertName(1045));
  AssertEquals('certificate revoked', ClientAuthAlertName(1044));
  AssertEquals('access denied', ClientAuthAlertName(1049));
  AssertEquals('unsupported certificate', ClientAuthAlertName(1043));
  AssertEquals('unknown certificate', ClientAuthAlertName(1046));
  AssertEquals('anything else is not a client-auth alert', '',
    ClientAuthAlertName(1040));
end;

initialization
  RegisterTest(TClientCertTest);
end.
