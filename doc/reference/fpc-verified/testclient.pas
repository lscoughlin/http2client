{$mode delphi}{$H+}
program testclient;
uses SysUtils, Http2.Client;
var
  Client: IHttpClient;
  Req: THttpRequest;
  Factory: THttpClientFactory;
begin
  Factory := THttpClientFactory.Create
    .WithMaxConnections(8)
    .WithMaxStreamsPerConnection(50)
    .WithFollowRedirects(False);
  Client := Factory.Build;
  WriteLn('max connections = ', Client.MaxConnections);
  Req := THttpRequest.Create(hmPost, 'https://example.com/api')
    .WithHeader('Content-Type', 'application/json')
    .WithHeader('Authorization', 'Bearer x')
    .WithBody(THttpBody.FromString('{"a":1}'));
  WriteLn('req url=', Req.Url, ' method=', Ord(Req.Method), ' ct=', Req.Headers.GetFirst('content-type'), ' body set=', Req.Body.IsSet);
  WriteLn('done');
end.
