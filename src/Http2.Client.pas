/// Public HTTP/2 client API: factory, IHttpClient, requests (plan S09/S10)
// - this unit is part of the http2client project (see doc/design/)
unit Http2.Client;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.FlowControl, Http2.Tls, Http2.Connection, Http2.Stream, Http2.Observer;

implementation

end.
