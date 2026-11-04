/// HPACK wire-order dispatch regression tests
// - checks that connection-scoped decoder state advances before stream lookup
//   and that continuation blocks decode only after END_HEADERS.
unit Http2.HpackOrder.Test;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$interfaces com}

interface

uses SysUtils, fpcunit, testregistry, Http2.Errors, Http2.Frames,
  Http2.Hpack, Http2.Connection;

type
  THeaderCapture = class(TInterfacedObject, IConnectionStream)
  private
    FFrames: array of TFrame;
  public
    procedure OnConnectionFailed(const AMessage: string;
      const ACode: THttp2ErrorCode);
    procedure OnConnectionGoAway(const ALastStreamId: LongWord);
    procedure OnStreamFrame(const AFrame: TFrame);
    function FrameCount: Integer;
    function Frame(const Index: Integer): TFrame;
  end;

  THpackWireOrderTests = class(TTestCase)
  published
    procedure DynamicHeaderBlockDecodesInDispatchOrder;
    procedure UnregisteredStreamStillAdvancesDynamicTable;
    procedure ContinuationDecodesOnlyAfterEndHeaders;
  end;

implementation

procedure THeaderCapture.OnConnectionFailed(const AMessage: string;
  const ACode: THttp2ErrorCode);
begin
end;

procedure THeaderCapture.OnConnectionGoAway(const ALastStreamId: LongWord);
begin
end;

procedure THeaderCapture.OnStreamFrame(const AFrame: TFrame);
var N: Integer;
begin
  N := Length(FFrames);
  SetLength(FFrames, N + 1);
  FFrames[N] := AFrame;
end;

function THeaderCapture.FrameCount: Integer;
begin
  Result := Length(FFrames);
end;

function THeaderCapture.Frame(const Index: Integer): TFrame;
begin
  Result := FFrames[Index];
end;

function ResponseHeaders(const Name, Value: string): THeaderBlock;
begin
  Result := nil;
  SetLength(Result, 2);
  Result[0].Name := ':status';
  Result[0].Value := '200';
  Result[1].Name := Name;
  Result[1].Value := Value;
end;

function HeaderValue(const Headers: THeaderBlock; const Name: string): string;
var I: Integer;
begin
  for I := 0 to High(Headers) do
    if Headers[I].Name = Name then Exit(Headers[I].Value);
  Result := '';
end;

function NewConnection(const Decoder: THpackCodec): TConnection;
begin
  Result := TConnection.Create(nil);
  Result.HeaderDecoder := Decoder;
end;

procedure THpackWireOrderTests.DynamicHeaderBlockDecodesInDispatchOrder;
var Encoder, Decoder: THpackCodec; Conn: TConnection;
  FirstCapture, SecondCapture: THeaderCapture;
  FirstRef, SecondRef: IConnectionStream;
  FirstBlock, SecondBlock: TBytes; Fields: THeaderBlock; Routed: TFrame;
begin
  Encoder := THpackCodec.Create;
  Decoder := THpackCodec.Create;
  Conn := nil;
  try
    Conn := NewConnection(Decoder);
    FirstCapture := THeaderCapture.Create;
    SecondCapture := THeaderCapture.Create;
    FirstRef := FirstCapture;
    SecondRef := SecondCapture;
    Conn.RegisterStream(1, FirstRef);
    Conn.RegisterStream(3, SecondRef);

    FirstBlock := Encoder.Encode(ResponseHeaders('x-test-concurrent', 'dynamic-value'));
    SecondBlock := Encoder.Encode(ResponseHeaders('x-test-concurrent', 'dynamic-value'));
    AssertEquals('second block uses a compact dynamic reference', 2,
      Length(SecondBlock));
    AssertEquals(Ord($BE), SecondBlock[1]);

    AssertTrue(Conn.DispatchStreamFrame(BuildHeadersFrame(1, FirstBlock, True, False)));
    AssertTrue(Conn.DispatchStreamFrame(BuildHeadersFrame(3, SecondBlock, True, False)));

    AssertEquals(1, SecondCapture.FrameCount);
    Routed := SecondCapture.Frame(0);
    AssertTrue('second stream receives decoded metadata', Routed.HeadersDecoded);
    Fields := Routed.DecodedHeaders;
    AssertEquals('dynamic-value', HeaderValue(Fields, 'x-test-concurrent'));

    AssertEquals(1, FirstCapture.FrameCount);
    AssertTrue(FirstCapture.Frame(0).HeadersDecoded);
  finally
    Conn.Free;
    Decoder.Free;
    Encoder.Free;
  end;
end;

procedure THpackWireOrderTests.UnregisteredStreamStillAdvancesDynamicTable;
var Encoder, Decoder: THpackCodec; Conn: TConnection;
  Capture: THeaderCapture; CaptureRef: IConnectionStream;
  FirstBlock, SecondBlock: TBytes; Fields: THeaderBlock; Routed: TFrame;
begin
  Encoder := THpackCodec.Create;
  Decoder := THpackCodec.Create;
  Conn := nil;
  try
    Conn := NewConnection(Decoder);
    Capture := THeaderCapture.Create;
    CaptureRef := Capture;
    Conn.RegisterStream(3, CaptureRef);

    FirstBlock := Encoder.Encode(ResponseHeaders('x-test-concurrent', 'dynamic-value'));
    SecondBlock := Encoder.Encode(ResponseHeaders('x-test-concurrent', 'dynamic-value'));
    AssertFalse('first stream is no longer registered',
      Conn.DispatchStreamFrame(BuildHeadersFrame(1, FirstBlock, True, False)));
    AssertTrue(Conn.DispatchStreamFrame(BuildHeadersFrame(3, SecondBlock, True, False)));

    AssertEquals(1, Capture.FrameCount);
    Routed := Capture.Frame(0);
    AssertTrue('second block is decoded despite missing first lease',
      Routed.HeadersDecoded);
    Fields := Routed.DecodedHeaders;
    AssertEquals('dynamic-value', HeaderValue(Fields, 'x-test-concurrent'));
  finally
    Conn.Free;
    Decoder.Free;
    Encoder.Free;
  end;
end;

procedure THpackWireOrderTests.ContinuationDecodesOnlyAfterEndHeaders;
var Encoder, Decoder: THpackCodec; Conn: TConnection;
  Capture: THeaderCapture; CaptureRef: IConnectionStream;
  Block, FirstPart, LastPart: TBytes; SplitAt, I: Integer;
  First, Last: TFrame; Fields: THeaderBlock;
begin
  Encoder := THpackCodec.Create;
  Decoder := THpackCodec.Create;
  Conn := nil;
  try
    Conn := NewConnection(Decoder);
    Capture := THeaderCapture.Create;
    CaptureRef := Capture;
    Conn.RegisterStream(1, CaptureRef);

    Block := Encoder.Encode(ResponseHeaders('x-test-continuation', 'continued-value'));
    SplitAt := Length(Block) div 2;
    AssertTrue('fixture has bytes in both frames',
      (SplitAt > 0) and (SplitAt < Length(Block)));
    SetLength(FirstPart, SplitAt);
    for I := 0 to SplitAt - 1 do FirstPart[I] := Block[I];
    SetLength(LastPart, Length(Block) - SplitAt);
    for I := 0 to High(LastPart) do LastPart[I] := Block[SplitAt + I];

    AssertTrue(Conn.DispatchStreamFrame(
      BuildHeadersFrame(1, FirstPart, False, True)));
    AssertEquals(1, Capture.FrameCount);
    First := Capture.Frame(0);
    AssertFalse('partial block has no decoded metadata', First.HeadersDecoded);
    AssertTrue('END_STREAM from HEADERS is retained', First.IsEndStream);

    AssertTrue(Conn.DispatchStreamFrame(
      BuildContinuationFrame(1, LastPart, True)));
    AssertEquals(2, Capture.FrameCount);
    Last := Capture.Frame(1);
    AssertTrue('END_HEADERS produces decoded metadata', Last.HeadersDecoded);
    Fields := Last.DecodedHeaders;
    AssertEquals('continued-value', HeaderValue(Fields, 'x-test-continuation'));
  finally
    Conn.Free;
    Decoder.Free;
    Encoder.Free;
  end;
end;

initialization
  RegisterTest(THpackWireOrderTests);

end.
