#!/usr/bin/env bash
# Regenerate the mutual TLS fixtures under test/certs/mtls (doc/design/mtls.md,
# "Testing").  Everything is generated fresh on each run, so the script is safe
# to re-run; commit the result.
#
#   bash tools/validate/make-mtls-certs.sh
#
# What it writes (all keys are EC P-256, validity 25 years except expired.*):
#   ca.crt / ca.key               the private CA the test servers trust
#   other-ca.crt / other-ca.key   a second CA the servers do not trust
#   intermediate.crt / .key       an intermediate CA issued by ca
#   server.crt / server.key       a server certificate for localhost, from ca
#   client.crt / client.key       the accepted client, issued by intermediate
#   client-chain.pem              client.crt followed by intermediate.crt
#   client-encrypted.key          client.key under the passphrase below
#   expired.crt / expired.key     a client from ca whose validity ended in 2016
#   other-client.crt / .key       a client from other-ca
#   client.p12, client-chain.p12, expired.p12, other-client.p12
#                                 PKCS#12 bundles under the passphrase below
#                                 (client-chain.p12 also carries the intermediate)
#
# Env: OPENSSL (the openssl binary; default the Homebrew openssl@3 if present,
# else the one on PATH; the expired certificate needs -not_before, OpenSSL 3.4+).
set -eu

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/test/certs/mtls"
PASS="mtls-test-pass"
DAYS=9125

if [ -z "${OPENSSL:-}" ]; then
  if [ -x /opt/homebrew/opt/openssl@3/bin/openssl ]; then
    OPENSSL=/opt/homebrew/opt/openssl@3/bin/openssl
  else
    OPENSSL=openssl
  fi
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
rm -f "$OUT"/*

newkey() { # file
  "$OPENSSL" genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1" 2>/dev/null
}

# selfsigned_ca name subject
selfsigned_ca() {
  newkey "$OUT/$1.key"
  printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' >"$WORK/$1.ext"
  "$OPENSSL" req -new -key "$OUT/$1.key" -subj "$2" -out "$WORK/$1.csr"
  "$OPENSSL" x509 -req -in "$WORK/$1.csr" -signkey "$OUT/$1.key" -days "$DAYS" \
    -extfile "$WORK/$1.ext" -out "$OUT/$1.crt" 2>/dev/null
}

# issue name subject issuer extfile [extra x509 args...]
issue() {
  local name="$1" subject="$2" issuer="$3" ext="$4"
  shift 4
  newkey "$OUT/$name.key"
  "$OPENSSL" req -new -key "$OUT/$name.key" -subj "$subject" -out "$WORK/$name.csr"
  "$OPENSSL" x509 -req -in "$WORK/$name.csr" -CA "$OUT/$issuer.crt" \
    -CAkey "$OUT/$issuer.key" -CAcreateserial -CAserial "$WORK/serial" \
    -extfile "$ext" "$@" -out "$OUT/$name.crt" 2>/dev/null
}

printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n' >"$WORK/intermediate.ext"
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1\n' >"$WORK/server.ext"
printf 'basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n' >"$WORK/client.ext"

selfsigned_ca ca "/O=http2client mtls test/CN=mtls test CA"
selfsigned_ca other-ca "/O=http2client mtls test/CN=mtls other CA"
issue intermediate "/O=http2client mtls test/CN=mtls test intermediate" ca "$WORK/intermediate.ext" -days "$DAYS"
issue server "/O=http2client mtls test/CN=localhost" ca "$WORK/server.ext" -days "$DAYS"
issue client "/O=http2client mtls test/CN=mtls client" intermediate "$WORK/client.ext" -days "$DAYS"
issue expired "/O=http2client mtls test/CN=mtls expired client" ca "$WORK/client.ext" \
  -not_before 20150101000000Z -not_after 20160101000000Z
issue other-client "/O=http2client mtls test/CN=mtls other client" other-ca "$WORK/client.ext" -days "$DAYS"

cat "$OUT/client.crt" "$OUT/intermediate.crt" >"$OUT/client-chain.pem"
"$OPENSSL" pkcs8 -topk8 -v2 aes-256-cbc -in "$OUT/client.key" \
  -passout "pass:$PASS" -out "$OUT/client-encrypted.key"

p12() { # name [extra pkcs12 args...]
  local name="$1"
  shift
  "$OPENSSL" pkcs12 -export -inkey "$OUT/$name.key" -in "$OUT/$name.crt" \
    -passout "pass:$PASS" "$@" -out "$OUT/$name.p12"
}
p12 client
p12 expired
p12 other-client
"$OPENSSL" pkcs12 -export -inkey "$OUT/client.key" -in "$OUT/client.crt" \
  -certfile "$OUT/intermediate.crt" -passout "pass:$PASS" -out "$OUT/client-chain.p12"

# the fixtures are only useful if they behave as named
"$OPENSSL" verify -CAfile "$OUT/ca.crt" "$OUT/server.crt" >/dev/null
"$OPENSSL" verify -CAfile "$OUT/ca.crt" -untrusted "$OUT/intermediate.crt" \
  "$OUT/client.crt" >/dev/null
if "$OPENSSL" verify -CAfile "$OUT/ca.crt" "$OUT/client.crt" >/dev/null 2>&1; then
  echo "make-mtls-certs: client.crt verified without its intermediate" >&2
  exit 1
fi
for bad in expired other-client; do
  if "$OPENSSL" verify -CAfile "$OUT/ca.crt" -untrusted "$OUT/intermediate.crt" \
      "$OUT/$bad.crt" >/dev/null 2>&1; then
    echo "make-mtls-certs: $bad.crt was accepted" >&2
    exit 1
  fi
done
echo "make-mtls-certs: wrote $OUT"
