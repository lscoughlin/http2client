/// Umbrella unit re-exporting the whole http2client surface
// - this unit is part of the http2client project (see doc/design/)
unit Http2;

{$mode delphi}{$H+}
{$modeswitch advancedrecords}
{$modeswitch typehelpers}
{$interfaces com}

interface

uses
  Http2.Errors, Http2.Frames, Http2.Headers, Http2.Hpack,
  Http2.FlowControl, Http2.Tls, Http2.Connection, Http2.Stream,
  Http2.Observer, Http2.Client;

implementation

end.
