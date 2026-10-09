/// Structured-format readers and senders for http2client: JSON and XML.
// - this unit is part of the http2client project (see doc/design/messages.md).
// - the 14-unit core library deliberately keeps no fpjson/fcl-xml dependency.
//   The structured formats therefore live here, in one optional unit. Add
//   `Http2.Readers` to your uses clause only when you need JSON or XML.
// - fcl-json (fpjson/jsonparser) and fcl-xml (DOM/XMLRead/XMLWrite) are pure
//   Object Pascal units shipped with FPC, so linking this unit adds no C
//   dependency either.
// - Read helpers parse the whole response body. Send helpers attach a body and
//   the matching content-type, and are pure request builders: they never touch
//   the network. The returned object of every Read helper is CALLER-OWNED and
//   must be freed.
unit Http2.Readers;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, TypInfo, DOM,
  fpjson, jsonparser,
  Http2.Errors, Http2.Headers, Http2.Stream, Http2.Messages,
  Http2.Client;

type
  /// reads a JSON body into a TJSONObject. The CALLER OWNS the returned object
  /// and must Free it. A body that does not parse as JSON, or that parses to a
  /// non-object value (an array, a number, a bare string), raises
  /// EHttpProtocolError with ecProtocolError.
  TJsonObjectReader = class(TInterfacedObject, IResponseReader<TJSONObject>)
  public
    /// parse AText as a JSON object; the caller owns the result
    class function Parse(const AText: string): TJSONObject; overload; static;
    /// read a response body to EOF and parse it as a JSON object
    function Read(const AResponse: IHttpResponse): TJSONObject; overload;
  end;

  /// reads a JSON body into any TJSONData descendant (TJSONObject, TJSONArray,
  /// TJSONString, TJSONNumber ...). The CALLER OWNS the result and must Free
  /// it. A body that does not parse as JSON raises EHttpProtocolError.
  TJsonReader<T: TJSONData> = class(TInterfacedObject, IResponseReader<T>)
  public
    /// parse AText as JSON and cast to T; the caller owns the result
    class function Parse(const AText: string): T; overload; static;
    /// read a response body to EOF and parse it as T
    function Read(const AResponse: IHttpResponse): T; overload;
  end;

  /// reads an XML body into a TXMLDocument. The CALLER OWNS the returned
  /// document and must Free it. A body that is not well-formed XML raises
  /// EHttpProtocolError (the fcl-xml EXMLReadError is not leaked).
  /// An `encoding="us-ascii"` (or `ascii`) declaration is rewritten to
  /// utf-8 before parsing, since fcl-xml rejects us-ascii but US-ASCII is a
  /// subset of UTF-8; every other declared encoding is passed through as-is.
  TXmlDocumentReader = class(TInterfacedObject, IResponseReader<TXMLDocument>)
  public
    /// parse AText as XML; the caller owns the result
    class function Parse(const AText: string): TXMLDocument; overload; static;
    /// read a response body to EOF and parse it as XML
    function Read(const AResponse: IHttpResponse): TXMLDocument; overload;
  end;

/// read a whole response body to EOF and parse it as a JSON object; the caller
/// owns the result (Free it)
function ReadJsonObject(const AResponse: IHttpResponse): TJSONObject;

/// read a whole response body to EOF and parse it as JSON; the caller owns the
/// result (Free it)
function ReadJsonData(const AResponse: IHttpResponse): TJSONData;

/// read a whole response body to EOF and parse it as XML; the caller owns the
/// result (Free it)
function ReadXmlDocument(const AResponse: IHttpResponse): TXMLDocument;

/// serialize AData and attach it as the request body, defaulting
/// `content-type: application/json` when none is set
function WithJsonBody(const ARequest: THttpRequest;
  const AData: TJSONData): THttpRequest;

/// attach AJson verbatim as the request body, defaulting
/// `content-type: application/json` when none is set
function WithJsonText(const ARequest: THttpRequest;
  const AJson: string): THttpRequest;

/// serialize ADoc and attach it as the request body, defaulting
/// `content-type: application/xml` when none is set
function WithXmlBody(const ARequest: THttpRequest;
  const ADoc: TXMLDocument): THttpRequest;

implementation

uses
  XMLRead, XMLWrite;

{ TJsonObjectReader }

class function TJsonObjectReader.Parse(const AText: string): TJSONObject;
var
  D: TJSONData;
begin
  try
    D := GetJSON(AText);
  except
    on E: EJSONParser do
      raise EHttpProtocolError.Create(
        'response body is not valid JSON', ecProtocolError);
  end;
  if not (D is TJSONObject) then
  begin
    D.Free;
    raise EHttpProtocolError.Create(
      'response body is not a JSON object', ecProtocolError);
  end;
  Result := TJSONObject(D);
end;

function TJsonObjectReader.Read(const AResponse: IHttpResponse): TJSONObject;
begin
  if AResponse = nil then
    raise EHttpProtocolError.Create('response is nil', ecInternalError);
  Result := Parse(ReadText(AResponse));
end;

{ TJsonReader<T> }

class function TJsonReader<T>.Parse(const AText: string): T;
var
  D: TJSONData;
begin
  try
    D := GetJSON(AText);
  except
    on E: EJSONParser do
      raise EHttpProtocolError.Create(
        'response body is not valid JSON', ecProtocolError);
  end;
  if not (D is T) then
  begin
    D.Free;
    raise EHttpProtocolError.CreateFmt(
      'response body is not a %s', [PTypeInfo(TypeInfo(T))^.Name]);
  end;
  Result := T(D);
end;

function TJsonReader<T>.Read(const AResponse: IHttpResponse): T;
begin
  if AResponse = nil then
    raise EHttpProtocolError.Create('response is nil', ecInternalError);
  Result := Parse(ReadText(AResponse));
end;

{ TXmlDocumentReader }

/// case-insensitive index of ASub in S, searching from AStart (1-based);
/// 0 when not found
function IndexOfCI(const S: string; const AStart: Integer;
  const ASub: string): Integer;
var
  I, J: Integer;
begin
  Result := 0;
  if ASub = '' then
    Exit;
  for I := AStart to Length(S) - Length(ASub) + 1 do
  begin
    J := 1;
    while (J <= Length(ASub)) and
          (UpCase(S[I + J - 1]) = UpCase(ASub[J])) do
      Inc(J);
    if J > Length(ASub) then
    begin
      Result := I;
      Exit;
    end;
  end;
end;

/// fcl-xml's XMLRead accepts utf-8 and iso-8859-1 but rejects `us-ascii` (and
/// windows-1252/utf-16) as an unsupported encoding. US-ASCII is a strict
/// subset of UTF-8, so rewriting an `us-ascii`/`ascii` declaration to `utf-8`
/// is byte-safe and lets us parse the many documents that declare us-ascii
/// (httpbin's /xml among them). The rewrite is deliberately bounded to that
/// one case: a blind rewrite of windows-1252 or utf-16 (which carry high
/// bytes or a BOM) would corrupt the input, so those still raise.
function NormalizeXmlDeclarationEncoding(const AText: string): string;
var
  P, DeclEnd, EncPos, ValStart, ValEnd: Integer;
  Quote: Char;
  Value: string;
begin
  Result := AText;
  P := 1;
  // a UTF-8 BOM may precede the declaration
  if (Length(AText) >= 3) and (AText[1] = #$EF) and (AText[2] = #$BB) and
     (AText[3] = #$BF) then
    P := 4;
  if Copy(AText, P, 5) <> '<?xml' then
    Exit;
  DeclEnd := Pos('?>', AText);
  if DeclEnd = 0 then
    Exit;
  EncPos := IndexOfCI(AText, P, 'encoding');
  if (EncPos = 0) or (EncPos > DeclEnd) then
    Exit;
  Inc(EncPos, Length('encoding'));
  while (EncPos <= DeclEnd) and (AText[EncPos] <= ' ') do
    Inc(EncPos);
  if (EncPos > DeclEnd) or (AText[EncPos] <> '=') then
    Exit;
  Inc(EncPos);
  while (EncPos <= DeclEnd) and (AText[EncPos] <= ' ') do
    Inc(EncPos);
  if (EncPos > DeclEnd) or not (AText[EncPos] in ['''', '"']) then
    Exit;
  Quote := AText[EncPos];
  ValStart := EncPos + 1;
  ValEnd := ValStart;
  while (ValEnd <= DeclEnd) and (AText[ValEnd] <> Quote) do
    Inc(ValEnd);
  if ValEnd > DeclEnd then
    Exit;
  Value := LowerCase(Copy(AText, ValStart, ValEnd - ValStart));
  if (Value = 'us-ascii') or (Value = 'ascii') then
    Result := Copy(AText, 1, ValStart - 1) + 'utf-8' +
      Copy(AText, ValEnd, Length(AText) - ValEnd + 1);
end;

class function TXmlDocumentReader.Parse(const AText: string): TXMLDocument;
var
  S: TStringStream;
  Doc: TXMLDocument;
begin
  S := TStringStream.Create(NormalizeXmlDeclarationEncoding(AText));
  try
    try
      ReadXMLFile(Doc, S);
    except
      on E: Exception do
        raise EHttpProtocolError.CreateFmt(
          'response body is not well-formed XML: %s', [E.Message]);
    end;
  finally
    S.Free;
  end;
  Result := Doc;
end;

function TXmlDocumentReader.Read(const AResponse: IHttpResponse): TXMLDocument;
begin
  if AResponse = nil then
    raise EHttpProtocolError.Create('response is nil', ecInternalError);
  Result := Parse(ReadText(AResponse));
end;

{ module helpers }

function ReadJsonObject(const AResponse: IHttpResponse): TJSONObject;
var
  R: IResponseReader<TJSONObject>;
begin
  R := TJsonObjectReader.Create;
  Result := R.Read(AResponse);
end;

function ReadJsonData(const AResponse: IHttpResponse): TJSONData;
var
  R: IResponseReader<TJSONData>;
begin
  R := TJsonReader<TJSONData>.Create;
  Result := R.Read(AResponse);
end;

function ReadXmlDocument(const AResponse: IHttpResponse): TXMLDocument;
var
  R: IResponseReader<TXMLDocument>;
begin
  R := TXmlDocumentReader.Create;
  Result := R.Read(AResponse);
end;

function WithJsonBody(const ARequest: THttpRequest;
  const AData: TJSONData): THttpRequest;
begin
  if AData = nil then
    raise EHttpProtocolError.Create('JSON body is nil', ecInternalError);
  Result := WithJsonText(ARequest, AData.AsJSON);
end;

function WithJsonText(const ARequest: THttpRequest;
  const AJson: string): THttpRequest;
begin
  if (ARequest.Headers = nil) or
     (not ARequest.Headers.Contains(HeaderContentType)) then
    Result := ARequest.WithHeader(HeaderContentType, 'application/json')
  else
    Result := ARequest;
  Result := WithTextBody(Result, AJson);
end;

function WithXmlBody(const ARequest: THttpRequest;
  const ADoc: TXMLDocument): THttpRequest;
var
  OutS: TStringStream;
begin
  if ADoc = nil then
    raise EHttpProtocolError.Create('XML document is nil', ecInternalError);
  OutS := TStringStream.Create('');
  try
    WriteXML(ADoc, OutS);
    if (ARequest.Headers = nil) or
       (not ARequest.Headers.Contains(HeaderContentType)) then
      Result := ARequest.WithHeader(HeaderContentType, 'application/xml')
    else
      Result := ARequest;
    Result := WithTextBody(Result, OutS.DataString);
  finally
    OutS.Free;
  end;
end;

end.
