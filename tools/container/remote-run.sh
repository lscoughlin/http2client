#!/usr/bin/env bash
# tools/container/remote-run.sh — run a command in the dev container on a remote Docker host.
#
# Usage: tools/container/remote-run.sh HOST COMMAND...   (each checkout gets its own remote directory)
#   e.g. tools/container/remote-run.sh lscoughlin@liam-rzbox.local make test
#
# The image (tools/container/Dockerfile) is built once and reused: it is
# rebuilt only when it is missing or HTTP2_REBUILD_IMAGE=1.  The working tree
# (git HEAD plus uncommitted tracked changes, and third_party/mORMot2) is
# copied to the host and mounted into the container, so a code change never
# touches the image.  The container runs as the remote user, so files in the
# mounted tree stay deletable.
set -eu

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

HOST="${1:?usage: remote-run.sh HOST COMMAND...}"
shift
IMAGE="${HTTP2_IMAGE:-http2client-dev}"
# one remote directory per checkout, so concurrent runs from different
# worktrees never rebuild over each other
TAG="$(printf '%s' "$REPO_ROOT" | cksum | cut -d' ' -f1)"
DIR="${HTTP2_REMOTE_DIR:-http2client-ci/run-$TAG}"

# image: build only when absent (or forced)
if [ "${HTTP2_REBUILD_IMAGE:-0}" = 1 ] || \
   ! ssh "$HOST" "docker image inspect $IMAGE >/dev/null 2>&1"; then
  ssh "$HOST" "mkdir -p $DIR/ctx"
  scp -q tools/container/Dockerfile "$HOST:$DIR/ctx/"
  ssh "$HOST" "docker build -t $IMAGE $DIR/ctx"
fi

# tree: replace the tracked files, keep third_party and the build output
ssh "$HOST" "mkdir -p $DIR/src/third_party && cd $DIR/src && \
  find . -mindepth 1 -maxdepth 1 ! -name third_party ! -name bin -exec rm -rf {} +"
tar -c --no-xattrs $(git ls-files -c -m --exclude-standard | sort -u | \
  while read -r f; do [ -e "$f" ] && echo "$f"; done) 2>/dev/null | \
  ssh "$HOST" "tar -x -m -C $DIR/src"   # -m: stamp with the host clock, so a clock skew never hides a change
if ! ssh "$HOST" "[ -d $DIR/src/third_party/mORMot2/src ]"; then
  tar -c --no-xattrs -C third_party mORMot2 2>/dev/null | \
    ssh "$HOST" "tar -x -C $DIR/src/third_party"
fi

# %q keeps each argument intact through the remote shell, so
# `sh -c 'make test; make validate-proxy'` works as written
ARGS="$(printf '%q ' "$@")"
ssh "$HOST" "cd $DIR/src && docker run --rm --user \$(id -u):\$(id -g) \
  -e HOME=/tmp -v \"\$PWD:/src\" -w /src $IMAGE $ARGS"
