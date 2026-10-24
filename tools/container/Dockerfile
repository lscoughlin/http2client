# Dev container for http2client: Free Pascal, OpenSSL 3, nghttpd and Python.
#
# FPC 3.2.4 has no published Linux binary and no release tag; the compiler is
# built from the release_3_2_4_rc2 source tag with the distribution's FPC as
# the bootstrap.  Build:  docker build -t http2client-dev tools/container
# Run:  docker run --rm -v "$PWD:/src" -w /src http2client-dev make test
# The tree must include third_party/mORMot2 (the pinned checkout).
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl git make openssl libssl3 \
      fpc python3 nghttp2-server iproute2 procps \
    && rm -rf /var/lib/apt/lists/*
ARG FPC_TAG=release_3_2_4_rc2
RUN set -eux; \
    mkdir /tmp/fpcsrc; \
    curl -fsSL "https://gitlab.com/freepascal.org/fpc/source/-/archive/${FPC_TAG}/source-${FPC_TAG}.tar.gz" \
      | tar -xz -C /tmp/fpcsrc --strip-components=1; \
    cd /tmp/fpcsrc; \
    make -j"$(nproc)" all PP=/usr/bin/fpc >/tmp/fpc-build.log 2>&1 || (tail -40 /tmp/fpc-build.log; exit 1); \
    make install PREFIX=/usr/local >/tmp/fpc-install.log 2>&1 || (tail -40 /tmp/fpc-install.log; exit 1); \
    ln -sf "$(ls -d /usr/local/lib/fpc/3.* | head -1)" /usr/local/lib/fpc/current; \
    ln -sf /usr/local/lib/fpc/current/ppcx64 /usr/local/bin/ppcx64; \
    /usr/local/bin/fpcmkcfg -d basepath=/usr/local/lib/fpc/current -o /etc/fpc.cfg; \
    rm -rf /tmp/fpcsrc; \
    /usr/local/bin/fpc -iV
ENV PATH=/usr/local/bin:$PATH
ENV FPC=/usr/local/bin/fpc
ENV FPC_UNITS=/usr/local/lib/fpc/current/units/x86_64-linux
ENV OPENSSL_LIBPATH=/usr/lib/x86_64-linux-gnu
WORKDIR /src
