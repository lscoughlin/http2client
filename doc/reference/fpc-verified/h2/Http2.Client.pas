{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}
unit Http2.Client;

interface

uses SysUtils, Generics.Collections;

type
  THttpMethod = (hmGet, hmHead, hmPost, hmPut, hmDelete, hmConnect,
    hmOptions, hmTrace, hmPatch);

  IHttpHeaders = interface
    procedure Add(const AName, AValue: string);
    function GetFirst(const AName: string): string;
    function Contains(const AName: string): Boolean;
    function Names: TArray<string>;
  end;

  IHttpBodyStream = interface
    function Read(var ABuffer; const ACount: LongInt): LongInt;
    function Eof: Boolean;
  end;

  IHttpResponse = interface
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
    property StatusCode: LongInt read GetStatusCode;
    property Headers: IHttpHeaders read GetHeaders;
    property Body: IHttpBodyStream read GetBody;
  end;

  IBodyWriter = interface
    function NextChunk(out ABuffer: TBytes): Boolean;
  end;

  THttpBody = record
  private
    FData: TBytes;
    FIsSet: Boolean;
  public
    class function FromBytes(const AData: TBytes): THttpBody; static;
    class function FromString(const AData: string): THttpBody; static;
    function IsSet: Boolean;
    function Data: TBytes;
  end;

  THttpRequest = record
  private
    FMethod: THttpMethod;
    FMethodOverride: string;
    FUrl: string;
    FHeaders: IHttpHeaders;
    FBody: THttpBody;
    FBodyWriter: IBodyWriter;
  public
    class function Create(const AMethod: THttpMethod;
      const AUrl: string): THttpRequest; static;
    function WithMethod(const AMethod: THttpMethod): THttpRequest;
    function WithMethodToken(const AToken: string): THttpRequest;
    function WithHeader(const AName, AValue: string): THttpRequest;
    function WithBody(const ABody: THttpBody): THttpRequest;
    function WithBodyWriter(const AWriter: IBodyWriter): THttpRequest;
    function Url: string;
    function Method: THttpMethod;
    function Headers: IHttpHeaders;
    function Body: THttpBody;
    function BodyWriter: IBodyWriter;
  end;

  IHttpClient = interface
    function Send(const ARequest: THttpRequest): IHttpResponse;
    procedure Close;
    function GetMaxConnections: LongInt;
    function GetActiveConnections: LongInt;
    property MaxConnections: LongInt read GetMaxConnections;
    property ActiveConnections: LongInt read GetActiveConnections;
  end;

  TClientConfig = record
  private
    FMaxConnections: LongInt;
    FMaxStreamsPerConnection: LongInt;
    FFollowRedirects: Boolean;
    FMaxRedirects: LongInt;
  public
    class function Create: TClientConfig; static;
    function WithMaxConnections(const AValue: LongInt): TClientConfig;
    function WithMaxStreamsPerConnection(const AValue: LongInt): TClientConfig;
    function WithFollowRedirects(const AValue: Boolean): TClientConfig;
  end;

  THttpClientFactory = record
  private
    FConfig: TClientConfig;
  public
    class function Create: THttpClientFactory; static;
    function WithMaxConnections(const AValue: LongInt): THttpClientFactory;
    function WithMaxStreamsPerConnection(const AValue: LongInt): THttpClientFactory;
    function WithFollowRedirects(const AValue: Boolean = True): THttpClientFactory;
    function Build: IHttpClient;
  end;

  THeaders = class(TInterfacedObject, IHttpHeaders)
  private
    FMap: TDictionary<string, TList<string>>;
  public
    constructor Create;
    destructor Destroy; override;
    procedure Add(const AName, AValue: string);
    function GetFirst(const AName: string): string;
    function Contains(const AName: string): Boolean;
    function Names: TArray<string>;
  end;

  THttpClient = class(TInterfacedObject, IHttpClient)
  private
    FConfig: TClientConfig;
  public
    constructor Create(const AConfig: TClientConfig);
    function Send(const ARequest: THttpRequest): IHttpResponse;
    procedure Close;
    function GetMaxConnections: LongInt;
    function GetActiveConnections: LongInt;
  end;

implementation

{ THttpBody }

class function THttpBody.FromBytes(const AData: TBytes): THttpBody;
begin
  Result.FData := AData;
  Result.FIsSet := True;
end;

class function THttpBody.FromString(const AData: string): THttpBody;
var
  Raw: RawByteString;
begin
  Raw := UTF8Encode(AData);
  SetLength(Result.FData, Length(Raw));
  if Length(Raw) > 0 then
    Move(Raw[1], Result.FData[0], Length(Raw));
  Result.FIsSet := True;
end;

function THttpBody.IsSet: Boolean;
begin
  Result := FIsSet;
end;

function THttpBody.Data: TBytes;
begin
  Result := FData;
end;

{ THttpRequest }

class function THttpRequest.Create(const AMethod: THttpMethod;
  const AUrl: string): THttpRequest;
begin
  Result.FMethod := AMethod;
  Result.FUrl := AUrl;
  Result.FHeaders := THeaders.Create;
  Result.FBody := Default(THttpBody);
  Result.FBodyWriter := nil;
end;

function THttpRequest.WithMethod(const AMethod: THttpMethod): THttpRequest;
begin
  Result := Self;
  Result.FMethod := AMethod;
  Result.FMethodOverride := '';
end;

function THttpRequest.WithMethodToken(const AToken: string): THttpRequest;
begin
  Result := Self;
  Result.FMethodOverride := UpperCase(AToken);
end;

function THttpRequest.WithHeader(const AName, AValue: string): THttpRequest;
begin
  Result := Self;
  Result.FHeaders.Add(AName, AValue);
end;

function THttpRequest.WithBody(const ABody: THttpBody): THttpRequest;
begin
  Result := Self;
  if Assigned(Result.FBodyWriter) then
    raise Exception.Create('body and bodywriter are mutually exclusive');
  Result.FBody := ABody;
end;

function THttpRequest.WithBodyWriter(const AWriter: IBodyWriter): THttpRequest;
begin
  Result := Self;
  if Result.FBody.IsSet then
    raise Exception.Create('body and bodywriter are mutually exclusive');
  Result.FBodyWriter := AWriter;
end;

function THttpRequest.Url: string; begin Result := FUrl; end;
function THttpRequest.Method: THttpMethod; begin Result := FMethod; end;
function THttpRequest.Headers: IHttpHeaders; begin Result := FHeaders; end;
function THttpRequest.Body: THttpBody; begin Result := FBody; end;
function THttpRequest.BodyWriter: IBodyWriter; begin Result := FBodyWriter; end;

{ TClientConfig }

class function TClientConfig.Create: TClientConfig;
begin
  Result.FMaxConnections := 4;
  Result.FMaxStreamsPerConnection := 100;
  Result.FFollowRedirects := True;
  Result.FMaxRedirects := 10;
end;

function TClientConfig.WithMaxConnections(const AValue: LongInt): TClientConfig;
begin
  Result := Self; Result.FMaxConnections := AValue;
end;

function TClientConfig.WithMaxStreamsPerConnection(
  const AValue: LongInt): TClientConfig;
begin
  Result := Self; Result.FMaxStreamsPerConnection := AValue;
end;

function TClientConfig.WithFollowRedirects(const AValue: Boolean): TClientConfig;
begin
  Result := Self; Result.FFollowRedirects := AValue;
end;

{ THttpClientFactory }

class function THttpClientFactory.Create: THttpClientFactory;
begin
  Result.FConfig := TClientConfig.Create;
end;

function THttpClientFactory.WithMaxConnections(
  const AValue: LongInt): THttpClientFactory;
begin
  Result := Self;
  Result.FConfig := Result.FConfig.WithMaxConnections(AValue);
end;

function THttpClientFactory.WithMaxStreamsPerConnection(
  const AValue: LongInt): THttpClientFactory;
begin
  Result := Self;
  Result.FConfig := Result.FConfig.WithMaxStreamsPerConnection(AValue);
end;

function THttpClientFactory.WithFollowRedirects(
  const AValue: Boolean): THttpClientFactory;
begin
  Result := Self;
  Result.FConfig := Result.FConfig.WithFollowRedirects(AValue);
end;

function THttpClientFactory.Build: IHttpClient;
begin
  Result := THttpClient.Create(FConfig);
end;

{ THeaders }

constructor THeaders.Create;
begin
  inherited Create;
  FMap := TDictionary<string, TList<string>>.Create;
end;

destructor THeaders.Destroy;
var
  L: TList<string>;
begin
  for L in FMap.Values do
    L.Free;
  FMap.Free;
  inherited;
end;

procedure THeaders.Add(const AName, AValue: string);
var
  Key: string;
  L: TList<string>;
begin
  Key := LowerCase(AName);
  if not FMap.TryGetValue(Key, L) then
  begin
    L := TList<string>.Create;
    FMap.Add(Key, L);
  end;
  L.Add(AValue);
end;

function THeaders.GetFirst(const AName: string): string;
var
  L: TList<string>;
begin
  if FMap.TryGetValue(LowerCase(AName), L) and (L.Count > 0) then
    Result := L[0]
  else
    Result := '';
end;

function THeaders.Contains(const AName: string): Boolean;
begin
  Result := FMap.ContainsKey(LowerCase(AName));
end;

function THeaders.Names: TArray<string>;
var
  I: Integer;
  E: TPair<string, TList<string>>;
begin
  SetLength(Result, FMap.Count);
  I := 0;
  for E in FMap do
  begin
    Result[I] := E.Key;
    Inc(I);
  end;
end;

{ THttpClient }

constructor THttpClient.Create(const AConfig: TClientConfig);
begin
  inherited Create;
  FConfig := AConfig;
end;

function THttpClient.Send(const ARequest: THttpRequest): IHttpResponse;
begin
  Result := nil;   // stub
end;

procedure THttpClient.Close;
begin
end;

function THttpClient.GetMaxConnections: LongInt;
begin
  Result := FConfig.FMaxConnections;
end;

function THttpClient.GetActiveConnections: LongInt;
begin
  Result := 0;
end;

end.
