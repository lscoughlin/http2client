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
  Http2.Errors, Http2.Headers, Http2.Stream;

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

implementation

end.
