/// message-level interfaces shared by every client codec (plan S13)
// - doc/design/messages.md defines IHttpResponse, IHttpBodyStream and
//   IResponseReader<T>.  IHttpBodyStream lives in Http2.Stream.pas (it is
//   wired to the HTTP/2 lease), so this unit only carries the transport
//   neutral parts: the response interface and the typed body reader.
// - The unit exists so a second codec (the HTTP/1.1 fallback of plan S13,
//   src/Http2.Http1.pas) can implement IHttpResponse without depending on
//   Http2.Client.pas, which sits above it.  Without the split the dependency
//   would be circular: Http2.Client uses the codec to send, the codec would
//   use Http2.Client for the interface.
unit Http2.Messages;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}

interface

uses
  SysUtils,
  Http2.Errors, Http2.Headers, Http2.Tls, Http2.Stream;

type
  /// a response (doc/design/messages.md IHttpResponse). Pseudo-headers are
  /// surfaced through StatusCode, never through Headers.
  IHttpResponse = interface
    ['{8B1C2D3E-4F50-4A61-9C72-0123456789AB}']
    function GetStatusCode: LongInt;
    function GetHeaders: IHttpHeaders;
    function GetBody: IHttpBodyStream;
    property StatusCode: LongInt read GetStatusCode;
    property Headers: IHttpHeaders read GetHeaders;
    property Body: IHttpBodyStream read GetBody;
  end;

  /// bridges a response body into a value of T (doc/design/messages.md)
  IResponseReader<T> = interface
    function Read(const AResponse: IHttpResponse): T;
  end;

  /// how the client treats a cleartext ("http") origin (doc/design/
  /// fallback.md "Factory surface").  ctReject is the default: a cleartext
  /// request raises instead of silently sending bytes in the clear.  Defined
  /// here (not in Http2.Client) so the transport layer can act on it without
  /// depending on the client unit.
  TClearTextPolicy = (ctReject, ctPriorKnowledge, ctUpgrade);

  /// the transport selected for one origin (doc/design/fallback.md).  The
  /// client asks a socket factory for this first; the factory reports which
  /// wire protocol it can deliver for the scheme and the caller's policy.
  TNegotiatedProtocol = (npHttp2Tls, npHttp2Cleartext, npHttp1Tls,
    npHttp1Cleartext);

  /// implemented by a socket factory that also understands cleartext and the
  /// HTTP/1.1 fallback.  The base IHttp2SocketFactory (declared in
  /// Http2.Client) predates S13 and only knows "dial TLS, speak h2"; the
  /// client checks for this extended contract with Supports() so an injected
  /// test factory keeps working unchanged.
  ICleartextSocketFactory = interface
    ['{C13A0001-0000-4000-8000-000000000001}']
    /// dial AHost:APort for AScheme and return the socket plus the protocol
    /// the transport is committed to.  For TLS the protocol follows the ALPN
    /// result; for cleartext it follows APolicy and the peer's upgrade reply.
    function DialProtocol(const AHost: string; const APort: Word;
      const AScheme: string; const AHttp1Fallback: Boolean;
      const APolicy: TClearTextPolicy; const ATimeoutMs: Integer;
      out AProtocol: TNegotiatedProtocol): IHttp2Socket;
  end;

implementation

end.
