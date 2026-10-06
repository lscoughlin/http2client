# http2client - Free Pascal HTTP/2 client
# See doc/verification/validation.md for the validation record and
# doc/verification/toolchain.md for the locked toolchain facts.
#
#   make          build the library units
#   make test     build + run the fpcunit suite
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
BIN        = bin

.PHONY: all test clean validate-interop validate-harness validate

all: $(BIN)/libhttp2.a

$(BIN)/libhttp2.a: $(SRC) | $(BIN)
	$(FPC) $(FPCFLAGS) -Cn -FE$(BIN) src/Http2.pas

$(BIN):
	mkdir -p $(BIN)

test: all | $(BIN)
	$(FPC) $(FPCFLAGS) -Fu./test -FE$(BIN) test/Http2.RunTests.pas
	$(BIN)/Http2.RunTests --all --format=plain --sparse

clean:
	rm -rf $(BIN) src/*.o src/*.ppu test/*.o test/*.ppu

# S12 gates. validate-interop is the mandatory nghttpd TLS+ALPN gate;
# validate-harness runs the 146-id h2-client-test-harness sweep (needs
# Docker/Rancher Desktop and takes ~30 minutes).
validate-interop:
	bash tools/validate/interop.sh

validate-harness:
	bash tools/validate/harness.sh

validate: validate-interop validate-harness
