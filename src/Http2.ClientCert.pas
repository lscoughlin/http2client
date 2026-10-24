/// Client identity (certificate chain and private key) for mutual TLS
// - this unit is part of the http2client project (see doc/design/mtls.md): it
//   loads a PEM or PKCS#12 identity into OpenSSL objects once, checks the key
//   against the leaf, and hands the objects to the TLS layer on each dial.  It
//   does not depend on the client, so an identity can be loaded to test it.
// - the passphrase is copied into a buffer that is wiped as soon as loading
//   ends; nothing here logs, and no message carries key or passphrase bytes.
unit Http2.ClientCert;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, DateUtils,
  mormot.core.base, mormot.lib.openssl11,
  Http2.Errors;

type
  /// a loaded identity; immutable once built, safe to share between threads
  IClientIdentity = interface
    function GetSubject: string;
    function GetFingerprint: string;
    function GetNotAfter: TDateTime;
    /// the leaf certificate; borrowed, valid while this identity is referenced
    function GetCertificate: PX509;
    /// the private key matching the leaf; borrowed like GetCertificate
    function GetPrivateKey: PEVP_PKEY;
    /// the certificates after the leaf (intermediates), in file order
    function GetChainCount: Integer;
    function GetChainCertificate(const AIndex: Integer): PX509;
    /// leaf subject, for diagnostics only
    property Subject: string read GetSubject;
    /// lowercase hex SHA-256 of the leaf's DER encoding
    property Fingerprint: string read GetFingerprint;
    /// UTC expiry of the leaf
    property NotAfter: TDateTime read GetNotAfter;
  end;

  /// loaders for IClientIdentity; each raises EHttpTlsConfigError for an
  /// unreadable file, malformed PEM or PKCS#12, a wrong passphrase or a key
  /// that does not match the leaf.  An expired leaf still loads (NotAfter
  /// tells), and THttpClientFactory.Build refuses it.
  TClientIdentity = class
  public
    /// PEM chain file (leaf first) and PEM key file
    class function FromPemFiles(const ACertFile, AKeyFile: string;
      const APassphrase: string = ''): IClientIdentity; static;
    /// the same from memory
    class function FromPem(const ACertPem, AKeyPem: TBytes;
      const APassphrase: string = ''): IClientIdentity; static;
    /// a PKCS#12 file
    class function FromPkcs12File(const AFile: string;
      const APassphrase: string = ''): IClientIdentity; static;
    /// a PKCS#12 bundle held in memory
    class function FromPkcs12(const AData: TBytes;
      const APassphrase: string = ''): IClientIdentity; static;
  end;

implementation

const
  cErrLibShift = 23;       // ERR_LIB_OFFSET
  cErrLibMask = $FF;
  cErrReasonMask = $7FFFFF;
  cErrLibPem = 9;          // ERR_LIB_PEM
  cPemNoStartLine = 108;   // PEM_R_NO_START_LINE: the normal end of a PEM file

type
  /// the passphrase handed to OpenSSL's PEM callback
  TPassphrase = record
    Data: UTF8String;
  end;
  PPassphrase = ^TPassphrase;
  TX509Array = array of PX509;

  TClientIdentityImpl = class(TInterfacedObject, IClientIdentity)
  private
    FLeaf: PX509;
    FKey: PEVP_PKEY;
    FChain: array of PX509;
    FSubject: string;
    FFingerprint: string;
    FNotAfter: TDateTime;
  public
    /// takes ownership of ALeaf, AKey and every certificate in AChain
    constructor Create(const ALeaf: PX509; const AKey: PEVP_PKEY;
      const AChain: array of PX509);
    destructor Destroy; override;
    function GetSubject: string;
    function GetFingerprint: string;
    function GetNotAfter: TDateTime;
    function GetCertificate: PX509;
    function GetPrivateKey: PEVP_PKEY;
    function GetChainCount: Integer;
    function GetChainCertificate(const AIndex: Integer): PX509;
  end;

{ OpenSSL error queue }

/// drain the error queue and return the reason of its last entry as text
// ('bad decrypt'); AReasonCode receives the numeric reason of the LAST entry
// and AFirstCode the whole first code, '' when the queue was empty
function DrainOpenSslErrors(out AFirstCode, ALastCode: Cardinal): string;
var
  Code, First, Last: Cardinal;
  Buf: array[0..255] of AnsiChar;
  Text: string;
  P: Integer;
begin
  First := 0;
  Last := 0;
  repeat
    Code := ERR_get_error;
    if Code = 0 then
      Break;
    if First = 0 then
      First := Code;
    Last := Code;
  until False;
  AFirstCode := First;
  ALastCode := Last;
  Result := '';
  if Last = 0 then
    Exit;
  FillChar(Buf, SizeOf(Buf), 0);
  ERR_error_string_n(Last, @Buf[0], SizeOf(Buf) - 1);
  Text := string(PAnsiChar(@Buf[0]));
  // 'error:1C800064:Provider routines::bad decrypt': keep the reason only
  P := Length(Text);
  while (P > 0) and (Text[P] <> ':') do
    Dec(P);
  Result := Copy(Text, P + 1, MaxInt);
end;

function OpenSslReasonText: string;
var
  First, Last: Cardinal;
begin
  Result := DrainOpenSslErrors(First, Last);
  if Result = '' then
    Result := 'unknown OpenSSL error';
end;

procedure RequireOpenSsl;
begin
  if not OpenSslIsAvailable then
    raise EHttpTlsConfigError.Create(
      'OpenSSL is not available: set OPENSSL_LIBPATH to the OpenSSL library ' +
      'directory (e.g. /opt/homebrew/opt/openssl@3/lib)');
  ERR_clear_error;
end;

/// OpenSSL's PEM password callback: copies the passphrase; an empty one
// returns 0 so OpenSSL fails instead of prompting on the terminal
function PassphraseCallback(buf: PUtf8Char; size, rwflag: Integer;
  userdata: Pointer): Integer; cdecl;
var
  Pass: PPassphrase;
  N: Integer;
begin
  Result := 0;
  Pass := PPassphrase(userdata);
  if (Pass = nil) or (Pass^.Data = '') then
    Exit;
  N := Length(Pass^.Data);
  if N > size then
    N := size;
  Move(Pass^.Data[1], buf^, N);
  Result := N;
end;

procedure WipePassphrase(var APass: TPassphrase);
begin
  if APass.Data <> '' then
  begin
    UniqueString(APass.Data);
    FillChar(APass.Data[1], Length(APass.Data), 0);
  end;
  APass.Data := '';
end;

procedure SetPassphrase(var APass: TPassphrase; const AText: string);
begin
  APass.Data := UTF8String(AText);
  if APass.Data <> '' then
    UniqueString(APass.Data);    // never share the caller's buffer: it is wiped
end;

function ReadFileBytes(const AFile, AWhat: string): TBytes;
var
  S: TFileStream;
begin
  Result := nil;
  try
    S := TFileStream.Create(AFile, fmOpenRead or fmShareDenyNone);
    try
      SetLength(Result, S.Size);
      if Length(Result) > 0 then
        S.ReadBuffer(Result[0], Length(Result));
    finally
      S.Free;
    end;
  except
    on E: EHttpError do
      raise;
    on E: Exception do
      raise EHttpTlsConfigError.CreateFmt('cannot read %s "%s"', [AWhat, AFile]);
  end;
end;

/// the one place that checks a leaf and key against each other
procedure CheckKeyMatchesLeaf(const ALeaf: PX509; const AKey: PEVP_PKEY;
  const AWhat: string);
var
  Ctx: PSSL_CTX;
begin
  Ctx := SSL_CTX_new(TLS_client_method());
  if Ctx = nil then
    raise EHttpTlsConfigError.Create('SSL_CTX_new failed');
  try
    ERR_clear_error;
    // a scratch context, so the real per-dial contexts only ever receive an
    // identity that is already known to be consistent
    if (SSL_CTX_use_certificate(Ctx, ALeaf) <> 1) or
       (SSL_CTX_use_PrivateKey(Ctx, AKey) <> 1) or
       (SSL_CTX_check_private_key(Ctx) <> 1) then
      raise EHttpTlsConfigError.CreateFmt(
        '%s: the private key does not match the certificate (%s)',
        [AWhat, OpenSslReasonText]);
  finally
    SSL_CTX_free(Ctx);
  end;
end;

{ TClientIdentityImpl }

constructor TClientIdentityImpl.Create(const ALeaf: PX509;
  const AKey: PEVP_PKEY; const AChain: array of PX509);
var
  I: Integer;
begin
  inherited Create;
  FLeaf := ALeaf;
  FKey := AKey;
  SetLength(FChain, Length(AChain));
  for I := 0 to High(AChain) do
    FChain[I] := AChain[I];
  FSubject := string(FLeaf^.SubjectName);
  FFingerprint := LowerCase(string(FLeaf^.FingerPrint(EVP_sha256)));
  FNotAfter := FLeaf^.NotAfter;
end;

destructor TClientIdentityImpl.Destroy;
var
  I: Integer;
begin
  for I := 0 to High(FChain) do
    X509_free(FChain[I]);
  if FLeaf <> nil then
    X509_free(FLeaf);
  if FKey <> nil then
    EVP_PKEY_free(FKey);
  inherited Destroy;
end;

function TClientIdentityImpl.GetSubject: string;
begin
  Result := FSubject;
end;

function TClientIdentityImpl.GetFingerprint: string;
begin
  Result := FFingerprint;
end;

function TClientIdentityImpl.GetNotAfter: TDateTime;
begin
  Result := FNotAfter;
end;

function TClientIdentityImpl.GetCertificate: PX509;
begin
  Result := FLeaf;
end;

function TClientIdentityImpl.GetPrivateKey: PEVP_PKEY;
begin
  Result := FKey;
end;

function TClientIdentityImpl.GetChainCount: Integer;
begin
  Result := Length(FChain);
end;

function TClientIdentityImpl.GetChainCertificate(
  const AIndex: Integer): PX509;
begin
  Result := FChain[AIndex];
end;

{ loading }

/// build the identity from the parsed objects, taking ownership of them
function Assemble(var ALeaf: PX509; var AKey: PEVP_PKEY;
  const AChain: array of PX509; const AWhat: string): IClientIdentity;
var
  Impl: TClientIdentityImpl;
  I: Integer;
begin
  try
    CheckKeyMatchesLeaf(ALeaf, AKey, AWhat);
  except
    for I := 0 to High(AChain) do
      X509_free(AChain[I]);
    X509_free(ALeaf);
    EVP_PKEY_free(AKey);
    ALeaf := nil;
    AKey := nil;
    raise;
  end;
  Impl := TClientIdentityImpl.Create(ALeaf, AKey, AChain);
  ALeaf := nil;
  AKey := nil;
  Result := Impl;
end;

procedure FreeCertList(const AList: array of PX509);
var
  I: Integer;
begin
  for I := 0 to High(AList) do
    X509_free(AList[I]);
end;

/// parse every certificate in a PEM buffer, leaf first; raises on a malformed
// block and when there is none
procedure ReadCertificates(const APem: TBytes; const AWhat: string;
  out ALeaf: PX509; out AChain: TX509Array);
var
  Bio: PBIO;
  X: PX509;
  First, Last: Cardinal;
  Reason: string;
begin
  ALeaf := nil;
  AChain := nil;
  if Length(APem) = 0 then
    raise EHttpTlsConfigError.CreateFmt('%s is empty', [AWhat]);
  Bio := BIO_new_mem_buf(@APem[0], Length(APem));
  if Bio = nil then
    raise EHttpTlsConfigError.Create('BIO_new_mem_buf failed');
  try
    ERR_clear_error;
    while True do
    begin
      X := PEM_read_bio_X509(Bio, nil, nil, nil);
      if X = nil then
        Break;
      if ALeaf = nil then
        ALeaf := X
      else
      begin
        SetLength(AChain, Length(AChain) + 1);
        AChain[High(AChain)] := X;
      end;
    end;
    Reason := DrainOpenSslErrors(First, Last);
    // running out of PEM blocks is the normal end; anything else is damage
    if (ALeaf = nil) or
       not (((Last shr cErrLibShift) and cErrLibMask = cErrLibPem) and
            (Last and cErrReasonMask = cPemNoStartLine)) then
    begin
      FreeCertList(AChain);
      X509_free(ALeaf);
      ALeaf := nil;
      AChain := nil;
      if Reason = '' then
        Reason := 'no certificate found';
      raise EHttpTlsConfigError.CreateFmt('%s: %s', [AWhat, Reason]);
    end;
  finally
    BIO_free(Bio);
  end;
end;

function LoadPem(const ACertPem, AKeyPem: TBytes; const APassphrase,
  ACertWhat, AKeyWhat: string): IClientIdentity;
var
  Leaf: PX509;
  Chain: TX509Array;
  Key: PEVP_PKEY;
  Bio: PBIO;
  Pass: TPassphrase;
begin
  RequireOpenSsl;
  ReadCertificates(ACertPem, ACertWhat, Leaf, Chain);
  Key := nil;
  try
    if Length(AKeyPem) = 0 then
      raise EHttpTlsConfigError.CreateFmt('%s is empty', [AKeyWhat]);
    Bio := BIO_new_mem_buf(@AKeyPem[0], Length(AKeyPem));
    if Bio = nil then
      raise EHttpTlsConfigError.Create('BIO_new_mem_buf failed');
    SetPassphrase(Pass, APassphrase);
    try
      Key := PEM_read_bio_PrivateKey(Bio, nil, @PassphraseCallback, @Pass);
    finally
      WipePassphrase(Pass);
      BIO_free(Bio);
    end;
    if Key = nil then
      raise EHttpTlsConfigError.CreateFmt(
        '%s: cannot read the private key (%s)', [AKeyWhat, OpenSslReasonText]);
  except
    FreeCertList(Chain);
    X509_free(Leaf);
    raise;
  end;
  Result := Assemble(Leaf, Key, Chain, ACertWhat);
end;

function LoadPkcs12(const AData: TBytes; const APassphrase,
  AWhat: string): IClientIdentity;
var
  Bio: PBIO;
  P12: PPKCS12;
  Leaf: PX509;
  Key: PEVP_PKEY;
  Stack: Pstack_st_X509;
  Chain: TX509Array;
  Pass: TPassphrase;
  I, N, Ok: Integer;
begin
  RequireOpenSsl;
  if Length(AData) = 0 then
    raise EHttpTlsConfigError.CreateFmt('%s is empty', [AWhat]);
  Bio := BIO_new_mem_buf(@AData[0], Length(AData));
  if Bio = nil then
    raise EHttpTlsConfigError.Create('BIO_new_mem_buf failed');
  try
    P12 := d2i_PKCS12_bio(Bio, nil);
  finally
    BIO_free(Bio);
  end;
  if P12 = nil then
    raise EHttpTlsConfigError.CreateFmt('%s: not a PKCS#12 bundle (%s)',
      [AWhat, OpenSslReasonText]);
  Leaf := nil;
  Key := nil;
  Stack := nil;
  Chain := nil;
  SetPassphrase(Pass, APassphrase);
  try
    Ok := PKCS12_parse(P12, PUtf8Char(Pass.Data), @Key, @Leaf, @Stack);
  finally
    WipePassphrase(Pass);
    PKCS12_free(P12);
  end;
  if Ok <> 1 then
    raise EHttpTlsConfigError.CreateFmt(
      '%s: cannot open the PKCS#12 bundle, wrong passphrase or damaged (%s)',
      [AWhat, OpenSslReasonText]);
  // the parsed stack owns its certificates; move them into the identity
  if Stack <> nil then
  begin
    N := OPENSSL_sk_num(Stack);
    SetLength(Chain, N);
    for I := 0 to N - 1 do
      Chain[I] := OPENSSL_sk_value(Stack, I);
    OPENSSL_sk_free(Stack);
  end;
  if (Leaf = nil) or (Key = nil) then
  begin
    FreeCertList(Chain);
    X509_free(Leaf);
    EVP_PKEY_free(Key);
    raise EHttpTlsConfigError.CreateFmt(
      '%s: the bundle holds no certificate and private key pair', [AWhat]);
  end;
  Result := Assemble(Leaf, Key, Chain, AWhat);
end;

class function TClientIdentity.FromPem(const ACertPem, AKeyPem: TBytes;
  const APassphrase: string): IClientIdentity;
begin
  // from memory, so the messages name the kind of input rather than a file
  Result := LoadPem(ACertPem, AKeyPem, APassphrase, 'client certificate PEM',
    'client key PEM');
end;

class function TClientIdentity.FromPemFiles(const ACertFile, AKeyFile: string;
  const APassphrase: string): IClientIdentity;
var
  CertWhat, KeyWhat: string;
begin
  CertWhat := Format('client certificate "%s"', [ACertFile]);
  KeyWhat := Format('client key "%s"', [AKeyFile]);
  Result := LoadPem(ReadFileBytes(ACertFile, 'client certificate file'),
    ReadFileBytes(AKeyFile, 'client key file'), APassphrase, CertWhat, KeyWhat);
end;

class function TClientIdentity.FromPkcs12File(const AFile: string;
  const APassphrase: string): IClientIdentity;
begin
  Result := LoadPkcs12(ReadFileBytes(AFile, 'PKCS#12 file'), APassphrase,
    Format('PKCS#12 bundle "%s"', [AFile]));
end;

class function TClientIdentity.FromPkcs12(const AData: TBytes;
  const APassphrase: string): IClientIdentity;
begin
  Result := LoadPkcs12(AData, APassphrase, 'PKCS#12 bundle');
end;

end.
