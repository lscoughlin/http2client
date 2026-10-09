/// HTTP/2 header map and header-name constants (plan S02)
// - this unit is part of the http2client project (see doc/design/messages.md)
// - a plain case-insensitive multi-valued map: no HPACK/TLS/socket/thread
unit Http2.Headers;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, Classes, Generics.Collections, Http2.Errors;

const
  // Pseudo-headers (never mixed into the regular map).
  HeaderMethod    = ':method';
  HeaderPath      = ':path';
  HeaderScheme    = ':scheme';
  HeaderAuthority = ':authority';
  HeaderStatus    = ':status';

  // Regular headers, lowercase (HTTP/2 wire form).
  HeaderContentType   = 'content-type';
  HeaderContentLength = 'content-length';
  HeaderContentEncoding = 'content-encoding';
  HeaderAccept        = 'accept';
  HeaderAcceptEncoding = 'accept-encoding';
  HeaderUserAgent     = 'user-agent';
  HeaderAuthorization = 'authorization';
  HeaderCookie        = 'cookie';
  HeaderSetCookie     = 'set-cookie';
  HeaderCacheControl  = 'cache-control';
  HeaderLocation      = 'location';
  HeaderHost          = 'host';
  HeaderTe            = 'te';
  /// Server-Sent Events resume header (WHATWG "last event ID string")
  HeaderLastEventId   = 'last-event-id';

type
  /// case-insensitive, multi-valued HTTP/2 header map
  IHttpHeaders = interface
    /// append AValue under AName; a repeated name grows the value list
    procedure Add(const AName, AValue: string);
    /// replace every value for AName with the single AValue
    procedure SetValue(const AName, AValue: string);
    /// all values for AName in insertion order (empty when absent)
    function GetValues(const AName: string): TArray<string>;
    /// the first value for AName, or '' when absent
    function GetFirst(const AName: string): string;
    function Contains(const AName: string): Boolean;
    procedure Remove(const AName: string);
    /// the regular header names present (pseudo-headers are excluded)
    function Names: TArray<string>;
    /// carry a pseudo-header (name starts with ':') without entering the map
    procedure AddPseudo(const AName, AValue: string);
    /// read a pseudo-header set via AddPseudo, or '' when absent
    function GetPseudo(const AName: string): string;
  end;

/// construct a fresh empty header map
function NewHttpHeaders: IHttpHeaders;

implementation

type
  THttpHeaders = class(TInterfacedObject, IHttpHeaders)
  private
    FMap: TDictionary<string, TStringList>;
    FPseudo: TDictionary<string, string>;
    function Normalize(const AName: string): string;
    procedure RejectForbidden(const ALowerName: string);
    procedure RejectPseudo(const AName, ALowerName: string);
    function ListFor(const ALowerName: string): TStringList;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const AName, AValue: string);
    procedure SetValue(const AName, AValue: string);
    function GetValues(const AName: string): TArray<string>;
    function GetFirst(const AName: string): string;
    function Contains(const AName: string): Boolean;
    procedure Remove(const AName: string);
    function Names: TArray<string>;
    procedure AddPseudo(const AName, AValue: string);
    function GetPseudo(const AName: string): string;
  end;

const
  /// HTTP/1.1 connection-specific headers, forbidden on the HTTP/2 wire
  ForbiddenHeaders: array[0..4] of string = (
    'connection', 'keep-alive', 'transfer-encoding', 'upgrade',
    'proxy-connection');

function NewHttpHeaders: IHttpHeaders;
begin
  Result := THttpHeaders.Create;
end;

constructor THttpHeaders.Create;
begin
  inherited Create;
  FMap := TDictionary<string, TStringList>.Create;
  FPseudo := TDictionary<string, string>.Create;
end;

destructor THttpHeaders.Destroy;
var
  L: TStringList;
begin
  for L in FMap.Values do
    L.Free;
  FMap.Free;
  FPseudo.Free;
  inherited Destroy;
end;

function THttpHeaders.Normalize(const AName: string): string;
begin
  Result := LowerCase(AName);
end;

procedure THttpHeaders.RejectForbidden(const ALowerName: string);
var
  I: Integer;
begin
  for I := Low(ForbiddenHeaders) to High(ForbiddenHeaders) do
    if ALowerName = ForbiddenHeaders[I] then
      raise EHttpProtocolError.Create(
        'connection-specific header forbidden in HTTP/2: ' + ALowerName,
        ecProtocolError);
end;

procedure THttpHeaders.RejectPseudo(const AName, ALowerName: string);
begin
  if (ALowerName <> '') and (ALowerName[1] = ':') then
    raise EHttpProtocolError.Create(
      'pseudo-header not allowed in the regular map: ' + AName,
      ecProtocolError);
end;

function THttpHeaders.ListFor(const ALowerName: string): TStringList;
begin
  if not FMap.TryGetValue(ALowerName, Result) then
  begin
    Result := TStringList.Create;
    FMap.Add(ALowerName, Result);
  end;
end;

procedure THttpHeaders.Add(const AName, AValue: string);
var
  LName: string;
begin
  LName := Normalize(AName);
  RejectForbidden(LName);
  RejectPseudo(AName, LName);
  ListFor(LName).Add(AValue);
end;

procedure THttpHeaders.SetValue(const AName, AValue: string);
var
  LName: string;
  L: TStringList;
begin
  LName := Normalize(AName);
  RejectForbidden(LName);
  RejectPseudo(AName, LName);
  L := ListFor(LName);
  L.Clear;
  L.Add(AValue);
end;

function THttpHeaders.GetValues(const AName: string): TArray<string>;
var
  L: TStringList;
  I: Integer;
begin
  Result := nil;
  L := nil;
  if FMap.TryGetValue(Normalize(AName), L) then
  begin
    SetLength(Result, L.Count);
    for I := 0 to L.Count - 1 do
      Result[I] := L[I];
  end;
end;

function THttpHeaders.GetFirst(const AName: string): string;
var
  L: TStringList;
begin
  L := nil;
  if FMap.TryGetValue(Normalize(AName), L) and (L.Count > 0) then
    Result := L[0]
  else
    Result := '';
end;

function THttpHeaders.Contains(const AName: string): Boolean;
begin
  Result := FMap.ContainsKey(Normalize(AName));
end;

procedure THttpHeaders.Remove(const AName: string);
var
  L: TStringList;
  LName: string;
begin
  LName := Normalize(AName);
  if FMap.TryGetValue(LName, L) then
  begin
    // FPC 3.2.4 TStringList has no Remove; the dictionary owns the list
    FMap.Remove(LName);
    L.Free;
  end;
end;

function THttpHeaders.Names: TArray<string>;
var
  LName: string;
  I: Integer;
begin
  Result := nil;
  SetLength(Result, FMap.Count);
  I := 0;
  for LName in FMap.Keys do
  begin
    Result[I] := LName;
    Inc(I);
  end;
end;

procedure THttpHeaders.AddPseudo(const AName, AValue: string);
begin
  FPseudo.AddOrSetValue(Normalize(AName), AValue);
end;

function THttpHeaders.GetPseudo(const AName: string): string;
begin
  Result := '';
  FPseudo.TryGetValue(Normalize(AName), Result);
end;

end.
