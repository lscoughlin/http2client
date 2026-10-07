/// http2client example: send XML and read XML directly into a TXMLDocument.
// - build: `task examples`
// - run:   bin/xml_request https://nghttp2.org/httpbin/xml
// - shows: Http2.Readers.pas. WithXmlBody serializes a TXMLDocument request
//   body and defaults `content-type: application/xml`; ReadXmlDocument parses
//   an XML response straight into a TXMLDocument. The reader returns a
//   CALLER-OWNED document, freed in a `finally`.
// - note:   the reader also accepts documents that declare `encoding="us-ascii"`
//   (fcl-xml does not), which is why the endpoint above works.
program example_xml;

{$mode delphi}{$H+}

uses
  {$IFDEF UNIX}cthreads,{$ENDIF}
  SysUtils, DOM,
  Http2.Errors, Http2.Headers, Http2.Stream, Http2.Messages,
  Http2.Client, Http2.Readers;

/// render raw body bytes as text for the diagnostic print below
function BytesToText(const A: TBytes): string;
var
  I: Integer;
begin
  Result := '';
  for I := 0 to High(A) do
    Result := Result + Chr(A[I]);
end;

var
  Client: IHttpClient;
  Url: string;
  Response: IHttpResponse;
  Sent, Got: TXMLDocument;
  Note: TDOMNode;
  Request: THttpRequest;
begin
  if ParamCount < 1 then
  begin
    WriteLn(StdErr, 'usage: example_xml <url>');
    Halt(2);
  end;
  Url := ParamStr(1);

  // 1. build a document and attach it with WithXmlBody (no network here): the
  //    helper serializes the document and defaults content-type: application/xml
  Sent := TXMLDocument.Create;
  try
    Note := Sent.CreateElement('note');
    Sent.AppendChild(Note);
    Note.AppendChild(Sent.CreateElement('to')).TextContent := 'you';

    Request := WithXmlBody(
      THttpRequest.Create(hmPost, 'https://api.example/echo'), Sent);
    WriteLn('content-type: ', Request.Headers.GetFirst('content-type'));
    WriteLn('request xml: ', BytesToText(Request.Body.Data));
  finally
    Sent.Free;
  end;

  // 2. GET the URL and parse the response body directly into a TXMLDocument.
  Client := THttpClientFactory.Create.WithMaxConnectionsPerHost(1).Build;
  try
    Response := Client.Send(THttpRequest.Create(hmGet, Url));
    WriteLn('status: ', Response.StatusCode);

    Got := ReadXmlDocument(Response);
    try
      WriteLn('root element: ', Got.DocumentElement.NodeName);
    finally
      Got.Free;
    end;
  except
    on E: EHttpError do
    begin
      WriteLn(StdErr, 'request failed: ', E.ClassName, ': ', E.Message);
      Halt(1);
    end;
  end;
  Client.Close;
end.
