/// Public-API request tests (plan story S09, task 09.4 / 09.9)
// - covers method-token validation + uppercasing, the body/body-writer
//   exclusivity rule, default-port omission in :authority, '/' path default,
//   and the exact pseudo-header block a THttpRequest emits at encode time.
// - non-vacuous by construction: the encoded-block test DECODES the emitted
//   HEADERS frame and asserts each pseudo-header value, so removing the
//   uppercasing or the port omission fails it.
unit Http2.Request.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpcunit, testregistry,
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.Connection, Http2.Stream, Http2.Client, Http2.ConnectionThread.Test;

type
  /// an IBodyWriter that never yields a chunk (single-use, empty)
  TNullWriter = class(TInterfacedObject, IBodyWriter)
  public
    function NextChunk(out ABuffer: TBytes): Boolean;
  end;

  TRequestTest = class(TTestCase)
  published
    procedure TestMethodTokenFromEnum;
    procedure TestMethodTokenIsUppercased;
    procedure TestInvalidMethodTokenRaises;
    procedure TestBodyAndBodyWriterAreMutuallyExclusive;
    procedure TestDefaultPortOmittedFromAuthority;
    procedure TestNonDefaultPortKeptInAuthority;
    procedure TestEmptyPathBecomesSlash;
    procedure TestEncodedPseudoHeadersMatchRequest;
  end;

implementation

function TNullWriter.NextChunk(out ABuffer: TBytes): Boolean;
begin
  ABuffer := nil;
  Result := False;
end;

function StrOf(const A: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(A) do
    Result := Result + Chr(A[I]);
end;

function FieldValue(const ABlock: THeaderBlock; const AName: string): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(ABlock) do
    if ABlock[I].Name = AName then
      Exit(ABlock[I].Value);
end;

{ TRequestTest }

procedure TRequestTest.TestMethodTokenFromEnum;
begin
  AssertEquals('GET', 'GET',
    THttpRequest.Create(hmGet, 'https://a.example/').MethodToken);
  AssertEquals('POST', 'POST',
    THttpRequest.Create(hmPost, 'https://a.example/').MethodToken);
  AssertEquals('DELETE', 'DELETE',
    THttpRequest.Create(hmDelete, 'https://a.example/').MethodToken);
end;

procedure TRequestTest.TestMethodTokenIsUppercased;
var
  R: THttpRequest;
begin
  R := THttpRequest.Create(hmGet, 'https://a.example/')
    .WithMethodToken('pUrGe');
  AssertEquals('extension verb is uppercased', 'PURGE', R.MethodToken);
  R := THttpRequest.Create(hmGet, 'https://a.example/')
    .WithMethodToken('get');
  AssertEquals('lowercase is uppercased', 'GET', R.MethodToken);
  // WithMethod resets the override
  R := R.WithMethod(hmPut);
  AssertEquals('WithMethod clears the override', 'PUT', R.MethodToken);
end;

procedure TRequestTest.TestInvalidMethodTokenRaises;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    THttpRequest.Create(hmGet, 'https://a.example/').WithMethodToken('bad token');
  except
    on E: EHttpProtocolError do Raised := True;
  end;
  AssertTrue('a token with whitespace raises', Raised);

  Raised := False;
  try
    THttpRequest.Create(hmGet, 'https://a.example/').WithMethodToken('');
  except
    on E: EHttpProtocolError do Raised := True;
  end;
  AssertTrue('an empty token raises', Raised);
end;

procedure TRequestTest.TestBodyAndBodyWriterAreMutuallyExclusive;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    THttpRequest.Create(hmPost, 'https://a.example/')
      .WithBodyWriter(TNullWriter.Create)
      .WithBody(THttpBody.FromString('x'));
  except
    on E: EHttpError do Raised := True;
  end;
  AssertTrue('body after body-writer raises', Raised);

  Raised := False;
  try
    THttpRequest.Create(hmPost, 'https://a.example/')
      .WithBody(THttpBody.FromString('x'))
      .WithBodyWriter(TNullWriter.Create);
  except
    on E: EHttpError do Raised := True;
  end;
  AssertTrue('body-writer after body raises', Raised);
end;

procedure TRequestTest.TestDefaultPortOmittedFromAuthority;
var
  R: THttpRequest;
begin
  R := THttpRequest.Create(hmGet, 'https://api.example/v1/things');
  AssertEquals('443 is omitted from :authority', 'api.example', R.Authority);
  R := THttpRequest.Create(hmGet, 'https://api.example:443/v1');
  AssertEquals('explicit 443 is still omitted', 'api.example', R.Authority);
end;

procedure TRequestTest.TestNonDefaultPortKeptInAuthority;
var
  R: THttpRequest;
begin
  R := THttpRequest.Create(hmGet, 'https://api.example:8443/v1');
  AssertEquals('non-default port is kept', 'api.example:8443', R.Authority);
end;

procedure TRequestTest.TestEmptyPathBecomesSlash;
var
  R: THttpRequest;
begin
  R := THttpRequest.Create(hmGet, 'https://api.example');
  AssertEquals('empty path defaults to /', '/', R.Path);
  R := THttpRequest.Create(hmGet, 'https://api.example?x=1');
  AssertEquals('query-only URL keeps the query', '?x=1', R.Path);
  R := THttpRequest.Create(hmGet, 'https://api.example/search?q=2');
  AssertEquals('path + query preserved', '/search?q=2', R.Path);
end;

procedure TRequestTest.TestEncodedPseudoHeadersMatchRequest;
var
  Sock: TMockSocket;
  Conn: TConnection;
  Alloc: TStreamIdAllocator;
  Lease: TStreamLease;
  Enc, Dec: THpackCodec;
  H: TFrame;
  Block: THeaderBlock;
  Req: TStreamRequest;
begin
  Sock := TMockSocket.Create;
  Conn := TConnection.Create(Sock);
  Alloc := TStreamIdAllocator.Create;
  Enc := THpackCodec.Create;
  Dec := THpackCodec.Create;
  try
    Req := THttpRequest.Create(hmGet, 'https://api.example/search?q=2')
      .ToStreamRequest;
    Lease := TStreamLease.Create(Conn, Alloc, Req, Enc, Dec);
    try
      Lease.Start;
      AssertTrue('a HEADERS frame was enqueued', Conn.Outbound.Pop(H));
      AssertEquals('request HEADERS frame', Ord(ftHeaders),
        Ord(H.Header.FrameType));
      Block := Dec.Decode(ExtractHeaderBlock(H));
      AssertEquals(':method', 'GET', FieldValue(Block, ':method'));
      AssertEquals(':scheme', 'https', FieldValue(Block, ':scheme'));
      AssertEquals(':path', '/search?q=2', FieldValue(Block, ':path'));
      AssertEquals(':authority', 'api.example',
        FieldValue(Block, ':authority'));
    finally
      Lease.ReleaseLease;
    end;
  finally
    Dec.Free;
    Enc.Free;
    Alloc.Free;
    Conn.Free;
  end;
end;

initialization
  RegisterTest(TRequestTest);
end.
