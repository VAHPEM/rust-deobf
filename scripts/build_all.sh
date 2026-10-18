#!/usr/bin/env bash
# Build every benchmark project across the config matrix: {ELF, PE} x {debug, release} x {strip, nostrip}
set -u
ROOT="$(cd "$(dirname "$0")/.."; pwd)"
SRC="$ROOT/bench_src"; OUT="$ROOT/build"; mkdir -p "$OUT"
MANIFEST="$ROOT/build/build_manifest.jsonl"; : > "$MANIFEST"

targets=( "x86_64-unknown-linux-gnu:elf" "x86_64-pc-windows-gnu:pe" )
for proj in plaintext xor_custom obfstr litcrypt cryptify muddy; do
  pdir="$SRC/$proj"; [ -d "$pdir" ] || continue
  # per-project build env (e.g. litcrypt/cryptify fixed key)
  env_line=$(python3 -c "import json;v=json.load(open('$SRC/manifest.json'))['variants']['$proj']['env'];print(f'{v[0]}={v[1]}' if v else '')")
  for t in "${targets[@]}"; do
    triple="${t%%:*}"; fmt="${t##*:}"
    for profile in debug release; do
      flags=""; [ "$profile" = release ] && flags="--release"
      ( cd "$pdir"
        env ${env_line:+$env_line} cargo build $flags --target "$triple" >/dev/null 2>&1
      )
      ext=""; [ "$fmt" = pe ] && ext=".exe"
      bin="$pdir/target/$triple/$profile/$proj$ext"
      [ -f "$bin" ] || { echo "MISS $proj $triple $profile"; continue; }
      for strip in nostrip strip; do
        name="${proj}__${fmt}__${profile}__${strip}$ext"
        dst="$OUT/$name"; cp "$bin" "$dst"
        if [ "$strip" = strip ]; then
          if [ "$fmt" = pe ]; then x86_64-w64-mingw32-strip "$dst" 2>/dev/null; else strip "$dst" 2>/dev/null; fi
        fi
        sz=$(stat -c%s "$dst")
        echo "{\"name\":\"$name\",\"proj\":\"$proj\",\"fmt\":\"$fmt\",\"profile\":\"$profile\",\"strip\":\"$strip\",\"bytes\":$sz}" >> "$MANIFEST"
        echo "OK  $name  ${sz}b"
      done
    done
  done
done
echo "built: $(wc -l < "$MANIFEST") binaries"
