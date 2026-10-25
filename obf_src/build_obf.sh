#!/usr/bin/env bash
# Build the author-written obfuscation-crate test programs (benign) across formats and profiles,
# into build/. Ground truth is each crate's expected.json. Mirrors scripts/build_all.sh.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${BUILD_DIR:-$HERE/../build}"; mkdir -p "$OUT"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
targets=( "x86_64-unknown-linux-gnu:elf" "x86_64-pc-windows-gnu:pe" )
[ "${ARM64:-1}" = 1 ] && targets+=( "aarch64-unknown-linux-musl:elf-arm64" )
for proj in "$HERE"/*/; do
  name="$(basename "$proj")"; [ -f "$proj/Cargo.toml" ] || continue
  for t in "${targets[@]}"; do
    triple="${t%%:*}"; fmt="${t##*:}"; ext=""; [ "$fmt" = pe ] && ext=.exe
    for prof in release size-lto; do
      flags="--release"; [ "$prof" = size-lto ] && flags="--profile size-lto"
      ( cd "$proj" && timeout 240 cargo build $flags --target "$triple" >/dev/null 2>&1 )
      b="$proj/target/$triple/$prof/$name$ext"
      [ -f "$b" ] || { echo "MISS $name $fmt $prof"; continue; }
      for st in strip nostrip; do
        d="$OUT/${name}__${fmt}__${prof}__${st}$ext"; cp "$b" "$d"
        if [ "$st" = strip ]; then
          if [ "$fmt" = pe ]; then x86_64-w64-mingw32-strip "$d" 2>/dev/null
          elif [ "$fmt" = elf-arm64 ]; then llvm-strip "$d" 2>/dev/null || true
          else strip "$d" 2>/dev/null; fi
        fi
      done
      echo "built $name $fmt $prof"
    done
  done
done
