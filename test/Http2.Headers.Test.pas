/// Unit tests for Http2.Headers (plan story S02, tasks 02.1 - 02.5)
// - covers multi-value maps, case-insensitivity, ordering, pseudo split and
//   forbidden-header rejection
unit Http2.Headers.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils, fpcunit, testregistry, Http2.Errors, Http2.Headers;

type
  THeadersTest = class(TTestCase)
  private
    function IndexOfName(const ANames: TArray<string>;
      const AName: string): Integer;
    procedure AssertAddRaisesForbidden(const AName: string);
    procedure AssertSetValueRaisesForbidden(const AName: string);
  published
    // 02.1 the basic map
    procedure TestAddAndContainsAreCaseInsensitive;
    procedure TestGetFirstReturnsFirstValue;
    procedure TestMultiValueSetCookie;
    procedure TestValueOrderPreserved;
    procedure TestSetValueReplacesAllValues;
    procedure TestGetValuesOfAbsentNameIsEmpty;
    procedure TestRemoveWorksThenContainsFalse;
    procedure TestRemoveAbsentNameIsNoop;
    // 02.3 header-name constants
    procedure TestPseudoHeaderConstants;
    procedure TestRegularHeaderConstants;
    // 02.4 forbidden-header guard
    procedure TestForbiddenHeadersRaiseOnAdd;
    procedure TestForbiddenHeadersRaiseOnSetValue;
    procedure TestForbiddenErrorCodeIsProtocolError;
    // 02.5 pseudo vs regular split
    procedure TestPseudoHeadersRejectedInRegularMap;
    procedure TestPseudoRoundTripAndAbsentFromNames;
    procedure TestNamesExcludesPseudoHeaders;
  end;

implementation

{ helpers }

function THeadersTest.IndexOfName(const ANames: TArray<string>;
  const AName: string): Integer;
var
  I: Integer;
begin
  Result := -1;
  for I := 0 to High(ANames) do
    if ANames[I] = AName then
      Exit(I);
end;

procedure THeadersTest.AssertAddRaisesForbidden(const AName: string);
var
  H: IHttpHeaders;
  Raised: Boolean;
begin
  H := NewHttpHeaders;
  Raised := False;
  try
    H.Add(AName, 'x');
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('Add(' + AName + ') must raise EHttpProtocolError', Raised);
end;

procedure THeadersTest.AssertSetValueRaisesForbidden(const AName: string);
var
  H: IHttpHeaders;
  Raised: Boolean;
begin
  H := NewHttpHeaders;
  Raised := False;
  try
    H.SetValue(AName, 'x');
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('SetValue(' + AName + ') must raise EHttpProtocolError', Raised);
end;

{ 02.1 }

procedure THeadersTest.TestAddAndContainsAreCaseInsensitive;
var
  H: IHttpHeaders;
begin
  H := NewHttpHeaders;
  H.Add('Content-Type', 'text/plain');
  AssertTrue('lowercase lookup after mixed-case add',
    H.Contains('content-type'));
  AssertTrue('uppercase lookup after mixed-case add',
    H.Contains('CONTENT-TYPE'));
  AssertEquals('value reachable by any case',
    'text/plain', H.GetFirst('CoNtEnT-tYpE'));
end;

procedure THeadersTest.TestGetFirstReturnsFirstValue;
var
  H: IHttpHeaders;
begin
  H := NewHttpHeaders;
  H.Add('x-test', 'one');
  H.Add('x-test', 'two');
  AssertEquals('first value', 'one', H.GetFirst('x-test'));
end;

procedure THeadersTest.TestMultiValueSetCookie;
var
  H: IHttpHeaders;
  V: TArray<string>;
begin
  H := NewHttpHeaders;
  H.Add(HeaderSetCookie, 'a=1; Path=/');
  H.Add(HeaderSetCookie, 'b=2; HttpOnly');
  V := H.GetValues('set-cookie');
  AssertEquals('two set-cookie values', 2, Length(V));
  AssertEquals('first cookie', 'a=1; Path=/', V[0]);
  AssertEquals('second cookie', 'b=2; HttpOnly', V[1]);
end;

procedure THeadersTest.TestValueOrderPreserved;
var
  H: IHttpHeaders;
  V: TArray<string>;
begin
  H := NewHttpHeaders;
  H.Add('x-order', 'alpha');
  H.Add('x-order', 'beta');
  H.Add('x-order', 'gamma');
  V := H.GetValues('x-order');
  AssertEquals('count', 3, Length(V));
  AssertEquals('v0', 'alpha', V[0]);
  AssertEquals('v1', 'beta', V[1]);
  AssertEquals('v2', 'gamma', V[2]);
end;

procedure THeadersTest.TestSetValueReplacesAllValues;
var
  H: IHttpHeaders;
  V: TArray<string>;
begin
  H := NewHttpHeaders;
  H.Add('x-multi', 'one');
  H.Add('x-multi', 'two');
  H.SetValue('X-MULTI', 'only');
  V := H.GetValues('x-multi');
  AssertEquals('replaced to one value', 1, Length(V));
  AssertEquals('replacement value', 'only', V[0]);
end;

procedure THeadersTest.TestGetValuesOfAbsentNameIsEmpty;
var
  H: IHttpHeaders;
begin
  H := NewHttpHeaders;
  AssertEquals('absent name count', 0, Length(H.GetValues('x-missing')));
  AssertEquals('absent GetFirst', '', H.GetFirst('x-missing'));
  AssertFalse('absent Contains', H.Contains('x-missing'));
end;

procedure THeadersTest.TestRemoveWorksThenContainsFalse;
var
  H: IHttpHeaders;
begin
  H := NewHttpHeaders;
  H.Add('x-remove', 'one');
  H.Add('x-remove', 'two');
  AssertTrue('present before remove', H.Contains('x-remove'));
  H.Remove('X-REMOVE');
  AssertFalse('absent after remove', H.Contains('x-remove'));
  AssertEquals('values cleared', 0, Length(H.GetValues('x-remove')));
end;

procedure THeadersTest.TestRemoveAbsentNameIsNoop;
var
  H: IHttpHeaders;
begin
  H := NewHttpHeaders;
  H.Add('other', 'kept');
  H.Remove('x-not-there');
  AssertTrue('other survives', H.Contains('other'));
  AssertEquals('other value intact', 'kept', H.GetFirst('other'));
end;

{ 02.3 }

procedure THeadersTest.TestPseudoHeaderConstants;
begin
  AssertEquals(':method', HeaderMethod);
  AssertEquals(':path', HeaderPath);
  AssertEquals(':scheme', HeaderScheme);
  AssertEquals(':authority', HeaderAuthority);
  AssertEquals(':status', HeaderStatus);
end;

procedure THeadersTest.TestRegularHeaderConstants;
begin
  AssertEquals('content-type', HeaderContentType);
  AssertEquals('content-length', HeaderContentLength);
  AssertEquals('content-encoding', HeaderContentEncoding);
  AssertEquals('accept', HeaderAccept);
  AssertEquals('accept-encoding', HeaderAcceptEncoding);
  AssertEquals('user-agent', HeaderUserAgent);
  AssertEquals('authorization', HeaderAuthorization);
  AssertEquals('cookie', HeaderCookie);
  AssertEquals('set-cookie', HeaderSetCookie);
  AssertEquals('cache-control', HeaderCacheControl);
  AssertEquals('location', HeaderLocation);
  AssertEquals('host', HeaderHost);
  AssertEquals('te', HeaderTe);
end;

{ 02.4 }

procedure THeadersTest.TestForbiddenHeadersRaiseOnAdd;
begin
  AssertAddRaisesForbidden('connection');
  AssertAddRaisesForbidden('keep-alive');
  AssertAddRaisesForbidden('transfer-encoding');
  AssertAddRaisesForbidden('upgrade');
  AssertAddRaisesForbidden('proxy-connection');
  AssertAddRaisesForbidden('Connection');
end;

procedure THeadersTest.TestForbiddenHeadersRaiseOnSetValue;
begin
  AssertSetValueRaisesForbidden('connection');
  AssertSetValueRaisesForbidden('keep-alive');
  AssertSetValueRaisesForbidden('transfer-encoding');
  AssertSetValueRaisesForbidden('upgrade');
  AssertSetValueRaisesForbidden('proxy-connection');
  AssertSetValueRaisesForbidden('UPGRADE');
end;

procedure THeadersTest.TestForbiddenErrorCodeIsProtocolError;
var
  H: IHttpHeaders;
  Code: Integer;
begin
  H := NewHttpHeaders;
  Code := -1;
  try
    H.Add('connection', 'close');
  except
    on E: EHttpProtocolError do
      Code := Ord(E.ErrorCode);
  end;
  AssertEquals('error code is PROTOCOL_ERROR', Ord(ecProtocolError), Code);
end;

{ 02.5 }

procedure THeadersTest.TestPseudoHeadersRejectedInRegularMap;
var
  H: IHttpHeaders;
  Raised: Boolean;
begin
  H := NewHttpHeaders;
  Raised := False;
  try
    H.Add(HeaderMethod, 'GET');
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('Add of :method raises', Raised);

  Raised := False;
  try
    H.SetValue(HeaderPath, '/');
  except
    on E: EHttpProtocolError do
      Raised := True;
  end;
  AssertTrue('SetValue of :path raises', Raised);
end;

procedure THeadersTest.TestPseudoRoundTripAndAbsentFromNames;
var
  H: IHttpHeaders;
begin
  H := NewHttpHeaders;
  H.AddPseudo(HeaderMethod, 'GET');
  H.AddPseudo(HeaderScheme, 'https');
  AssertEquals('pseudo method', 'GET', H.GetPseudo(HeaderMethod));
  AssertEquals('pseudo scheme', 'https', H.GetPseudo(HeaderScheme));
  AssertEquals('pseudo absent', '', H.GetPseudo(HeaderStatus));
  AssertFalse(':method not in regular map', H.Contains(HeaderMethod));
  AssertEquals('no names yet', 0, Length(H.Names));
end;

procedure THeadersTest.TestNamesExcludesPseudoHeaders;
var
  H: IHttpHeaders;
  N: TArray<string>;
begin
  H := NewHttpHeaders;
  H.AddPseudo(HeaderMethod, 'GET');
  H.AddPseudo(HeaderPath, '/x');
  H.Add(HeaderContentType, 'text/plain');
  H.Add(HeaderAccept, '*/*');
  N := H.Names;
  AssertEquals('two regular names', 2, Length(N));
  AssertTrue('content-type listed', IndexOfName(N, 'content-type') >= 0);
  AssertTrue('accept listed', IndexOfName(N, 'accept') >= 0);
  AssertTrue(':method not listed', IndexOfName(N, HeaderMethod) < 0);
  AssertTrue(':path not listed', IndexOfName(N, HeaderPath) < 0);
end;

initialization
  RegisterTest(THeadersTest);

end.
