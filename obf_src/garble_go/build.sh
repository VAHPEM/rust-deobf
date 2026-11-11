#!/usr/bin/env bash
# Build the benign garble fixtures (VALIDATION §84) into $OUT (default ../../build): the same Go
# program plain (control) and with `garble -literals -tiny`, for linux/arm64, linux/amd64 and
# windows/amd64, with a FIXED garble seed so the output is reproducible (VALIDATION §77: an unseeded
# obfuscator's verdict follows its build). Needs Go (GO=/usr/lib/go-1.24/bin/go by default) and
# garble (`go install mvdan.cc/garble@$GARBLE_VERSION`, fetched from the Go module proxy).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${OUT:-$HERE/../../build}"; mkdir -p "$OUT"
GOROOT_BIN="${GOROOT_BIN:-/usr/lib/go-1.24/bin}"
export PATH="$GOROOT_BIN:$HOME/go/bin:$PATH" GOTOOLCHAIN=local CGO_ENABLED=0
GARBLE_VERSION="${GARBLE_VERSION:-v0.14.2}"
SEED="${SEED:-cnVzdC1kZW9iZi1nYXJibGU}"     # base64("rust-deobf-garble"): fixed, chosen up front
command -v garble >/dev/null || go install "mvdan.cc/garble@$GARBLE_VERSION"
cd "$HERE"
go version; garble version | head -1
for t in linux/arm64:elf-arm64: linux/amd64:elf: windows/amd64:pe:.exe; do
  IFS=: read -r osarch fmt ext <<<"$t"
  export GOOS="${osarch%/*}" GOARCH="${osarch#*/}"
  go build -trimpath -ldflags=-s -o "$OUT/garble_go__${fmt}__plain__strip$ext" .
  garble -literals -tiny -seed="$SEED" build -trimpath -ldflags=-s -o "$OUT/garble_go__${fmt}__garble__strip$ext" .
  echo "built garble_go $fmt"
done
