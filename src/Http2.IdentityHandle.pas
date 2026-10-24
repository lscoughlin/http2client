/// the TLS-free handle a request carries for a client identity
// - Http2.WebSocket depends on the RTL only, so a request cannot name
//   IClientIdentity (which exposes OpenSSL types); it carries this base
//   interface instead, and IClientIdentity (Http2.ClientCert) descends from
//   it.  Callers pass an IClientIdentity; doc/design/mtls.md "Per-request
//   identity".
unit Http2.IdentityHandle;

{$mode delphi}{$H+}
{$interfaces com}

interface

type
  IClientIdentityHandle = interface
    ['{9937B7EF-26BF-44EF-B95B-99C6C7A9077D}']
  end;

implementation

end.
