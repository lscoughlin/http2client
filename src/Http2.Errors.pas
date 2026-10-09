/// HTTP/2 exception hierarchy and wire error codes (plan story S01)
// - this unit is part of the http2client project (see doc/design/errors-redirects.md)
unit Http2.Errors;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  SysUtils;

type
  /// RFC 7540 section 7 error codes; the low 32 bits of GOAWAY/RST_STREAM
  THttp2ErrorCode = (
    ecNoError            = $0,
    ecProtocolError      = $1,
    ecInternalError      = $2,
    ecFlowControlError   = $3,
    ecSettingsTimeout    = $4,
    ecStreamClosed       = $5,
    ecFrameSizeError     = $6,
    ecRefusedStream      = $7,
    ecCancel             = $8,
    ecCompressionError   = $9,
    ecConnectError       = $a,
    ecEnhanceYourCalm    = $b,
    ecInadequateSecurity = $c,
    ecHttp11Required     = $d);

  /// base class for every error this library raises
  EHttpError = class(Exception)
  private
    FErrorCode: THttp2ErrorCode;
  public
    constructor Create(const AMessage: string); overload;
    constructor Create(const AMessage: string;
      const AErrorCode: THttp2ErrorCode); overload;
    /// the HTTP/2 error code to place in RST_STREAM / GOAWAY
    property ErrorCode: THttp2ErrorCode read FErrorCode;
  end;

  /// a connection-scoped failure: every in-flight lease fails
  EHttpConnectionError = class(EHttpError);
  /// a protocol violation (framing, HPACK, illegal state)
  EHttpProtocolError = class(EHttpError);
  /// a single stream failed via RST_STREAM; the connection survives
  EHttpStreamError = class(EHttpError)
  private
    FStreamId: LongWord;
  public
    constructor Create(const AMessage: string; const AStreamId: LongWord;
      const AErrorCode: THttp2ErrorCode); overload;
    property StreamId: LongWord read FStreamId;
  end;
  /// a deadline (connect, header, idle) expired
  EHttpTimeout = class(EHttpError);
  /// the peer or transport closed the connection
  EHttpConnectionClosed = class(EHttpError);
  /// the redirect chain exceeded MaxRedirects
  EHttpTooManyRedirects = class(EHttpError);
  /// the SSE reconnect loop exceeded its retry bound
  EHttpTooManySseRetries = class(EHttpError);
  /// a non-replayable body cannot be re-sent on a 307/308 redirect
  EHttpNotReplayable = class(EHttpError);

/// stable, human-readable name for a wire error code
function Http2ErrorCodeName(const ACode: THttp2ErrorCode): string;

implementation

constructor EHttpError.Create(const AMessage: string);
begin
  inherited Create(AMessage);
  FErrorCode := ecInternalError;
end;

constructor EHttpError.Create(const AMessage: string;
  const AErrorCode: THttp2ErrorCode);
begin
  inherited Create(AMessage);
  FErrorCode := AErrorCode;
end;

constructor EHttpStreamError.Create(const AMessage: string;
  const AStreamId: LongWord; const AErrorCode: THttp2ErrorCode);
begin
  inherited Create(AMessage, AErrorCode);
  FStreamId := AStreamId;
end;

function Http2ErrorCodeName(const ACode: THttp2ErrorCode): string;
begin
  case ACode of
    ecNoError:            Result := 'NO_ERROR';
    ecProtocolError:      Result := 'PROTOCOL_ERROR';
    ecInternalError:      Result := 'INTERNAL_ERROR';
    ecFlowControlError:   Result := 'FLOW_CONTROL_ERROR';
    ecSettingsTimeout:    Result := 'SETTINGS_TIMEOUT';
    ecStreamClosed:       Result := 'STREAM_CLOSED';
    ecFrameSizeError:     Result := 'FRAME_SIZE_ERROR';
    ecRefusedStream:      Result := 'REFUSED_STREAM';
    ecCancel:             Result := 'CANCEL';
    ecCompressionError:   Result := 'COMPRESSION_ERROR';
    ecConnectError:       Result := 'CONNECT_ERROR';
    ecEnhanceYourCalm:    Result := 'ENHANCE_YOUR_CALM';
    ecInadequateSecurity: Result := 'INADEQUATE_SECURITY';
    ecHttp11Required:     Result := 'HTTP_1_1_REQUIRED';
  else
    Result := 'UNKNOWN_' + IntToStr(Ord(ACode));
  end;
end;

end.
