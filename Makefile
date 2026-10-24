# http2client - Free Pascal HTTP/2 client
# See doc/verification/validation.md for the validation record and
# doc/verification/toolchain.md for the locked toolchain facts.
#
#   make          build the library units
#   make test     build + run the fpcunit suite
#   make examples compile the example programs into bin/
#   make validate-sse  opt-in live SSE cases (resume, and event gaps against a
#                      server emitting at a known interval) against
#                      tools/validate/sse_server.py
#   make validate-proxy  opt-in live proxy gate against tools/validate/proxy_servers.py
#   make validate-websocket  opt-in live WebSocket gate against tools/validate/ws_servers.py
#   make validate-websocket-autobahn  Autobahn|Testsuite client run (needs Docker)
#   make validate-cleartext  opt-in live gate: cleartext requests are sent once
#   make validate-mtls  opt-in live mutual TLS gate against tools/validate/mtls_server.py and nghttpd
#   make validate-proxy-real  opt-in gate against REAL Apache httpd and Squid proxies (Docker host)
#   make measure-observer  opt-in observer overhead measurement on loopback
#   make clean    remove build outputs

FPC        ?= fpc
FPC_UNITS  ?= /usr/local/lib/fpc/3.2.4/units/aarch64-darwin
FPCFLAGS   ?= -O2 -vw -Mdelphi -Fu./src -Fu$(FPC_UNITS)/fcl-fpcunit
# mormot2 provides the TLS/ALPN layer (FPC's bundled opensslsockets has no
# ALPN). Unit dirs are on the search path; the runtime library path is passed
# via OPENSSL_LIBPATH because Darwin's system dylibs are unusable.
MORMOT      ?= third_party/mORMot2/src
OPENSSL_LIBPATH ?= /opt/homebrew/opt/openssl@3/lib
export OPENSSL_LIBPATH
FPCFLAGS   += -Fu$(MORMOT)/core -Fu$(MORMOT)/lib -Fu$(MORMOT)/net -Fu$(MORMOT)/crypt
SRC        = $(wildcard src/*.pas)
TESTSRC    = $(wildcard test/*.pas)
# the observer adapters are units shared by the examples and the tests, not programs
EXAMPLEUNITS = examples/observer_tracing.pas examples/observer_metrics.pas examples/observer_logging.pas
EXAMPLESRC = $(filter-out $(EXAMPLEUNITS),$(wildcard examples/*.pas))
BIN        = bin

.PHONY: all test examples measure-observer clean validate-interop validate-harness validate-sse validate-proxy validate-websocket validate-websocket-autobahn validate-cleartext validate-mtls validate-proxy-real validate

all: $(BIN)/libhttp2.a

$(BIN)/libhttp2.a: $(SRC) | $(BIN)
	$(FPC) $(FPCFLAGS) -Cn -FE$(BIN) src/Http2.pas

$(BIN):
	mkdir -p $(BIN)

test: all | $(BIN)
	$(FPC) $(FPCFLAGS) -Fu./test -Fu./examples -FE$(BIN) test/Http2.RunTests.pas
	$(BIN)/Http2.RunTests --all --format=plain --sparse

# Compile the example programs (smoke build; they are not executed here).  The
# adapter units in examples/ are compiled as part of the programs that use them.
examples: all | $(BIN)
	for f in $(EXAMPLESRC); do $(FPC) $(FPCFLAGS) -Fu./examples -FE$(BIN) $$f || exit 1; done
	for f in $(EXAMPLEUNITS); do $(FPC) $(FPCFLAGS) -Fu./examples -FE$(BIN) $$f || exit 1; done

# Opt-in observer overhead measurement (doc/verification/observer-overhead.md):
# a loopback request with no observer, with the tracing, metrics and logging
# adapters, and with the per-event gate on.  It starts its own loopback server;
# it is not part of `make test`.
measure-observer: all | $(BIN)
	$(FPC) $(FPCFLAGS) -Fu./examples -FE$(BIN) examples/observer_overhead.pas
	$(BIN)/observer_overhead

clean:
	rm -rf $(BIN) src/*.o src/*.ppu test/*.o test/*.ppu examples/*.o examples/*.ppu

# S12 gates. validate-interop is the mandatory nghttpd TLS+ALPN gate;
# validate-harness runs the 146-id h2-client-test-harness sweep (needs
# Docker/Rancher Desktop and takes ~30 minutes).
validate-interop:
	bash tools/validate/interop.sh

validate-harness:
	bash tools/validate/harness.sh

# Opt-in live SSE gate: tools/validate/sse-live.sh starts the reference
# event-stream server on a private port, runs the live cases (delivery and
# resume on /events, per-event gaps on /cadence), then stops the server again. The default suite skips that case (SSE_TEST_URL unset), so
# this target is the only way it executes.
validate-sse: all | $(BIN)
	bash tools/validate/sse-live.sh

# Opt-in live proxy gate: tools/validate/proxy-live.sh starts reference
# origins plus HTTP CONNECT, https and SOCKS5 proxies on loopback, runs
# TProxyLiveTest through the real client, and checks the servers' logs for the
# route each request took.
validate-proxy: all | $(BIN)
	bash tools/validate/proxy-live.sh

# Opt-in live WebSocket gate: tools/validate/websocket-live.sh starts a
# reference RFC 6455 server (ws and wss) and the proxy servers on loopback,
# runs TWebSocketLiveTest through the real client, and checks the servers' logs
# for what each connection did on the wire.
validate-websocket: all | $(BIN)
	bash tools/validate/websocket-live.sh

# The Autobahn|Testsuite fuzzing server (Docker) against the client.
validate-websocket-autobahn: all | $(BIN)
	bash tools/validate/websocket-live.sh autobahn

# Opt-in live cleartext gate: an HTTP/1.1-only server that logs each request
# proves a request is sent once under ctUpgrade (declined) and ctHttp1.
validate-cleartext: all | $(BIN)
	bash tools/validate/cleartext-live.sh

# Opt-in live mutual TLS gate: servers that require a client certificate (a
# Python ssl server pinned to TLS 1.2 and 1.3, and nghttpd --verify-client),
# driven by examples/mtls_get.pas.
validate-mtls: all | $(BIN)
	bash tools/validate/mtls-live.sh

validate: validate-interop validate-harness

# Opt-in real-proxy gate: Apache httpd (mod_proxy_connect) and Squid in stock
# containers on a Docker host (PROXY_REAL_HOST, default the remote box), the
# client driver tools/validate/proxy_real_client.pas built in the dev image;
# the proxies' access logs are read to prove the route.  Not part of `make test`.
validate-proxy-real:
	bash tools/validate/proxy-real.sh
