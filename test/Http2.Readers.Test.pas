/// Structured-format reader/sender tests (src/Http2.Readers.pas).
// - JSON and XML live in Http2.Readers, OUTSIDE the 13-unit core, so this unit
//   is the gate that the optional unit still compiles and works.
// - non-vacuous: every Read helper is shown to actually parse (a member value
//   is asserted), and every error path is shown to raise EHttpProtocolError.
//   The send helpers assert both the body bytes and the content-type header.
unit Http2.Readers.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, fpjson, DOM, fpcunit, testregistry,
  Http2.Errors, Http2.Headers, Http2.Stream, Http2.Messages,
  Http2.Client, Http2.Readers;

type
  /// a body stream over a fixed byte array (mirrors Http2.Client.Test's fake)
  TReaderFakeBody = class(TInterfacedObject, IHttpBodyStream)
  private
    FData: TBytes;
    FPos: Integer;
  public
    constructor Create(const AData: TBytes);
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
  end;

  /// a response carrying a fake body
  TReaderFakeResponse = class(TInterfacedObject, IHttpResponse)
  private
    FStatus: LongInt;
    FHeaders: IHttpHeaders;
    FBody: IHttpBodyStream;
  public
    constructor Create(const AStatus: LongInt; const ABody: IHttpBodyStream);
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
  end;

  TReadersTest = class(TTestCase)
  published
    procedure TestJsonObjectReaderParsesMembers;
    procedure TestJsonDataReaderDecodesArray;
    procedure TestJsonObjectReaderRejectsNonObject;
    procedure TestJsonObjectReaderRejectsInvalidJson;
    procedure TestJsonReaderRejectsWrongType;
    procedure TestXmlDocumentReaderParsesDocument;
    procedure TestXmlDocumentReaderAcceptsUsAsciiDeclaration;
    procedure TestXmlDocumentReaderAcceptsUsAsciiCaseInsensitive;
    procedure TestXmlDocumentReaderAcceptsUsAsciiWithBom;
    procedure TestXmlDocumentReaderKeepsIso88591Bytes;
    procedure TestXmlDocumentReaderRejectsMalformed;
    procedure TestWithJsonBodySerializesAndSetsContentType;
    procedure TestWithJsonTextKeepsExplicitContentType;
    procedure TestWithXmlBodySerializesAndSetsContentType;
  end;

implementation

{ TReaderFakeBody }

constructor TReaderFakeBody.Create(const AData: TBytes);
begin
  inherited Create;
  FData := AData;
  FPos := 0;
end;

function TReaderFakeBody.Read(var ABuffer; const ACount: LongInt): LongInt;
var
  Available: Integer;
begin
  Available := Length(FData) - FPos;
  if Available <= 0 then
    Exit(0);
  if ACount < Available then
    Available := ACount;
  Move(FData[FPos], ABuffer, Available);
  Inc(FPos, Available);
  Result := Available;
end;

function TReaderFakeBody.Eof: Boolean;
begin
  Result := FPos >= Length(FData);
end;

{ TReaderFakeResponse }

constructor TReaderFakeResponse.Create(const AStatus: LongInt;
  const ABody: IHttpBodyStream);
begin
  inherited Create;
  FStatus := AStatus;
  FHeaders := NewHttpHeaders;
  FBody := ABody;
end;

function TReaderFakeResponse.GetStatusCode: LongInt;
begin
  Result := FStatus;
end;

function TReaderFakeResponse.GetHeaders: IHttpHeaders;
begin
  Result := FHeaders;
end;

function TReaderFakeResponse.GetBody: IHttpBodyStream;
begin
  Result := FBody;
end;

function RespOf(const AText: string): IHttpResponse;
var
  Raw: TBytes;
  I: Integer;
begin
  // Ord-based byte extraction, matching the rest of the suite: a hard cast
  // TBytes(AnsiString(...)) misreads the length prefix, and a `string(...)`
  // cast on a TBytes truncates. See BytesToStr for the reverse direction.
  SetLength(Raw, Length(AText));
  for I := 1 to Length(AText) do
    Raw[I - 1] := Byte(AText[I]);
  Result := TReaderFakeResponse.Create(200, TReaderFakeBody.Create(Raw));
end;

function BytesToStr(const A: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(A) do
    Result := Result + Chr(A[I]);
end;

{ tests }

procedure TReadersTest.TestJsonObjectReaderParsesMembers;
var
  Obj: TJSONObject;
  Arr: TJSONArray;
begin
  Obj := ReadJsonObject(RespOf(
    '{"name":"widget","count":3,"ok":true,"tags":["a","b"]}'));
  try
    AssertEquals('string member', 'widget', Obj.Get('name', ''));
    AssertEquals('integer member', 3, Obj.Get('count', -1));
    AssertTrue('boolean member', Obj.Get('ok', False));
    Arr := Obj.Get('tags', TJSONArray(nil));
    AssertNotNull('array member present', Arr);
    AssertEquals('array length', 2, Arr.Count);
    AssertEquals('array element', 'b', Arr.Items[1].AsString);
  finally
    Obj.Free;
  end;
end;

procedure TReadersTest.TestJsonDataReaderDecodesArray;
var
  Data: TJSONData;
begin
  Data := ReadJsonData(RespOf('[10,20,30]'));
  try
    AssertEquals('top-level type', 'TJSONArray', Data.ClassName);
    AssertEquals('element count', 3, TJSONArray(Data).Count);
    AssertEquals('element 1', 20, TJSONArray(Data).Items[1].AsInteger);
  finally
    Data.Free;
  end;
end;

procedure TReadersTest.TestJsonObjectReaderRejectsNonObject;
var
  Raised: Boolean;
  Obj: TJSONObject;
begin
  Raised := False;
  Obj := nil;
  try
    Obj := ReadJsonObject(RespOf('123'));
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('non-object JSON raises EHttpProtocolError', Raised);
  AssertTrue('no object leaks out', Obj = nil);
end;

procedure TReadersTest.TestJsonObjectReaderRejectsInvalidJson;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    TJsonObjectReader.Parse('this is not json');
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('invalid JSON raises EHttpProtocolError', Raised);
end;

procedure TReadersTest.TestJsonReaderRejectsWrongType;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    // the body is an object, but T requires an array
    TJsonReader<TJSONArray>.Parse('{"a":1}');
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('wrong JSON type raises EHttpProtocolError', Raised);
end;

procedure TReadersTest.TestXmlDocumentReaderParsesDocument;
var
  Doc: TXMLDocument;
  Root, Child: TDOMNode;
begin
  Doc := ReadXmlDocument(RespOf('<catalog><book id="b1">Dune</book></catalog>'));
  try
    Root := Doc.DocumentElement;
    AssertEquals('root element', 'catalog', Root.NodeName);
    Child := Root.FirstChild;
    AssertEquals('child element', 'book', Child.NodeName);
    AssertEquals('child text', 'Dune', Child.TextContent);
    AssertEquals('attribute', 'b1', Child.Attributes.GetNamedItem('id').NodeValue);
  finally
    Doc.Free;
  end;
end;

procedure TReadersTest.TestXmlDocumentReaderAcceptsUsAsciiDeclaration;
var
  Doc: TXMLDocument;
begin
  // fcl-xml rejects us-ascii; the reader rewrites it to utf-8 (byte-safe,
  // because US-ASCII is a strict subset of UTF-8).
  Doc := TXmlDocumentReader.Parse(
    '<?xml version="1.0" encoding="us-ascii"?><slides><slide>hi</slide></slides>');
  try
    AssertEquals('root element', 'slides', Doc.DocumentElement.NodeName);
    AssertEquals('child text', 'hi',
      Doc.DocumentElement.FirstChild.TextContent);
  finally
    Doc.Free;
  end;
end;

procedure TReadersTest.TestXmlDocumentReaderAcceptsUsAsciiCaseInsensitive;
var
  Doc: TXMLDocument;
begin
  Doc := TXmlDocumentReader.Parse(
    '<?xml version="1.0" encoding="US-ASCII"?><a>x</a>');
  try
    AssertEquals('root element', 'a', Doc.DocumentElement.NodeName);
  finally
    Doc.Free;
  end;
  Doc := TXmlDocumentReader.Parse(
    '<?xml version=''1.0'' encoding=''Ascii''?><a>x</a>');
  try
    AssertEquals('single-quoted ascii root', 'a', Doc.DocumentElement.NodeName);
  finally
    Doc.Free;
  end;
end;

procedure TReadersTest.TestXmlDocumentReaderAcceptsUsAsciiWithBom;
var
  Doc: TXMLDocument;
begin
  // a UTF-8 BOM does not rescue the declaration on its own: the rewrite must
  Doc := TXmlDocumentReader.Parse(
    #$EF#$BB#$BF + '<?xml version="1.0" encoding="us-ascii"?><a>x</a>');
  try
    AssertEquals('BOM + us-ascii root', 'a', Doc.DocumentElement.NodeName);
  finally
    Doc.Free;
  end;
end;

procedure TReadersTest.TestXmlDocumentReaderKeepsIso88591Bytes;
var
  Doc: TXMLDocument;
begin
  // iso-8859-1 is supported by fcl-xml and must NOT be rewritten: the raw
  // high byte (0xE9 = e-acute) must survive as one byte.
  Doc := TXmlDocumentReader.Parse(
    '<?xml version="1.0" encoding="iso-8859-1"?><a>caf' + #$E9 + '</a>');
  try
    AssertEquals('root element', 'a', Doc.DocumentElement.NodeName);
    AssertEquals('latin-1 text preserved', 'caf' + #$E9,
      Doc.DocumentElement.TextContent);
  finally
    Doc.Free;
  end;
end;

procedure TReadersTest.TestXmlDocumentReaderRejectsMalformed;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    TXmlDocumentReader.Parse('<root><a></root>');
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('malformed XML raises EHttpProtocolError', Raised);
end;

procedure TReadersTest.TestWithJsonBodySerializesAndSetsContentType;
var
  Src: TJSONObject;
  Req: THttpRequest;
begin
  Src := TJSONObject(GetJSON('{"a":1,"b":"two"}'));
  try
    Req := WithJsonBody(
      THttpRequest.Create(hmPost, 'https://api.example/echo'), Src);
    AssertTrue('body is set', Req.Body.IsSet);
    AssertEquals('serialized body', string(Src.AsJSON), BytesToStr(Req.Body.Data));
    AssertEquals('content-type defaulted', 'application/json',
      Req.Headers.GetFirst('content-type'));
  finally
    Src.Free;
  end;
end;

procedure TReadersTest.TestWithJsonTextKeepsExplicitContentType;
var
  Req: THttpRequest;
begin
  Req := WithJsonText(
    THttpRequest.Create(hmPost, 'https://api.example/echo')
      .WithHeader('content-type', 'application/vnd.api+json'),
    '{"a":1}');
  AssertEquals('explicit content-type preserved', 'application/vnd.api+json',
    Req.Headers.GetFirst('content-type'));
  AssertEquals('body verbatim', '{"a":1}', BytesToStr(Req.Body.Data));
end;

procedure TReadersTest.TestWithXmlBodySerializesAndSetsContentType;
var
  Doc: TXMLDocument;
  Req: THttpRequest;
  Body: string;
begin
  Doc := TXmlDocumentReader.Parse('<note><to>you</to></note>');
  try
    Req := WithXmlBody(
      THttpRequest.Create(hmPost, 'https://api.example/echo'), Doc);
    AssertEquals('content-type defaulted', 'application/xml',
      Req.Headers.GetFirst('content-type'));
    Body := BytesToStr(Req.Body.Data);
    AssertTrue('serialized XML carries the root', Pos('<note>', Body) > 0);
    AssertTrue('serialized XML carries the child text', Pos('you', Body) > 0);
  finally
    Doc.Free;
  end;
end;

initialization
  RegisterTest(TReadersTest);

end.
