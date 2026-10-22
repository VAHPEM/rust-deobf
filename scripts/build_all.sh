#!/usr/bin/env bash
# Build every benchmark project across the config matrix: {ELF, PE} x {debug, release} x {strip, nostrip}
set -u
ROOT="$(cd "$(dirname "$0")/.."; pwd)"
SRC="$ROOT/bench_src"; OUT="${BUILD_DIR:-$ROOT/build}"; mkdir -p "$OUT"
# BUILD_DIR=... builds elsewhere (e.g. with RUSTUP_TOOLCHAIN=1.99.1 next to the default build);
# the tests read RUST_DEOBF_BUILD
MANIFEST="$OUT/build_manifest.jsonl"; : > "$MANIFEST"

targets=( "x86_64-unknown-linux-gnu:elf" "x86_64-pc-windows-gnu:pe" )
# ARM64=1 also cross-builds AArch64 ELF (static musl, linked by rust-lld): no ARM machine or
# cross gcc needed, only `rustup target add aarch64-unknown-linux-musl`. rust-lld relaxes
# adrp+add pairs into `adr`, a codegen shape the static ARM64 recoverer has to handle.
if [ "${ARM64:-0}" = 1 ]; then
  targets+=( "aarch64-unknown-linux-musl:elf-arm64" )
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
fi
for proj in $(ls -d "$SRC"/*/ 2>/dev/null | xargs -n1 basename); do
  pdir="$SRC/$proj"; [ -d "$pdir" ] || continue
  # per-project build env (e.g. litcrypt/cryptify fixed key)
  env_line=$(python3 -c "import json;v=json.load(open('$SRC/manifest.json'))['variants'].get('$proj',{}).get('env');print(f'{v[0]}={v[1]}' if v else '')")
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
          if [ "$fmt" = pe ]; then x86_64-w64-mingw32-strip "$dst" 2>/dev/null
          elif [ "$fmt" = elf-arm64 ]; then llvm-strip "$dst" 2>/dev/null || aarch64-linux-gnu-strip "$dst" 2>/dev/null
          else strip "$dst" 2>/dev/null; fi
        fi
        sz=$(stat -c%s "$dst")
        echo "{\"name\":\"$name\",\"proj\":\"$proj\",\"fmt\":\"$fmt\",\"profile\":\"$profile\",\"strip\":\"$strip\",\"bytes\":$sz}" >> "$MANIFEST"
        echo "OK  $name  ${sz}b"
      done
    done
  done
done
echo "built: $(wc -l < "$MANIFEST") binaries"
