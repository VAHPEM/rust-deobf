#!/usr/bin/env bash
# Build the author-written obfuscation-crate test programs (benign) across formats and profiles,
# into build/. Ground truth is each crate's expected.json. Mirrors scripts/build_all.sh.
#
# FORMATS="elf pe elf-arm64" picks the output formats (default: elf pe, plus elf-arm64 unless
# ARM64=0). Exit status: 0 only when every requested binary was built and stripped; otherwise 1,
# after the whole matrix has been attempted. A failed build never ships a binary an earlier build
# left in target/; cargo's output is kept in $BUILD_DIR/build_logs/obf__<name>__<fmt>__<prof>.log
# and its tail printed on failure.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${BUILD_DIR:-$HERE/../build}"; mkdir -p "$OUT"
LOGS="$OUT/build_logs"; mkdir -p "$LOGS"
export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
all=( "x86_64-unknown-linux-gnu:elf" "x86_64-pc-windows-gnu:pe" "aarch64-unknown-linux-musl:elf-arm64" )
if [ -n "${FORMATS:-}" ]; then want=" $FORMATS "
else want=" elf pe "; [ "${ARM64:-1}" = 1 ] && want="$want elf-arm64 "; fi
targets=()
for t in "${all[@]}"; do case "$want" in *" ${t##*:} "*) targets+=( "$t" );; esac; done
if [ "${#targets[@]}" -eq 0 ]; then echo "build_obf: no known format in FORMATS='${FORMATS:-}'" >&2; exit 2; fi
# portable timeout: GNU coreutils `timeout`, Homebrew's `gtimeout`, or none
TO=""; command -v timeout >/dev/null 2>&1 && TO="timeout 240"
[ -z "$TO" ] && command -v gtimeout >/dev/null 2>&1 && TO="gtimeout 240"

failures=()
fail() { failures+=( "$1" ); echo "MISS $1" >&2; }
strip_one() {
  local fmt="$1" f="$2" tool cands
  case "$fmt" in
    pe) cands="x86_64-w64-mingw32-strip llvm-strip" ;;
    elf-arm64*) cands="llvm-strip aarch64-linux-gnu-strip strip" ;;
    *) cands="strip llvm-strip" ;;
  esac
  # macOS's own strip cannot process ELF/PE: use the LLVM / cross binutils ones there
  if [ "$(uname -s)" = Darwin ]; then
    case "$fmt" in pe) ;; elf-arm64*) cands="llvm-strip aarch64-linux-gnu-strip" ;; *) cands="llvm-strip x86_64-linux-gnu-strip" ;; esac
  fi
  for tool in $cands; do
    if command -v "$tool" >/dev/null 2>&1; then
      "$tool" "$f" && return 0
      echo "strip: $tool failed on $f" >&2
      return 1
    fi
  done
  echo "strip: none of [$cands] is installed (needed for $fmt)" >&2
  return 1
}

for proj in "$HERE"/*/; do
  name="$(basename "$proj")"; [ -f "$proj/Cargo.toml" ] || continue
  for t in "${targets[@]}"; do
    triple="${t%%:*}"; fmt="${t##*:}"; ext=""; [ "$fmt" = pe ] && ext=.exe
    for prof in release size-lto; do
      flags="--release"; [ "$prof" = size-lto ] && flags="--profile size-lto"
      b="$proj/target/$triple/$prof/$name$ext"
      log="$LOGS/obf__${name}__${fmt}__${prof}.log"
      if ! ( cd "$proj" && $TO cargo build $flags --target "$triple" ) >"$log" 2>&1; then
        echo "---- cargo build failed: $name $fmt $prof (last lines of $log) ----" >&2
        tail -n 25 "$log" >&2
        rm -f "$OUT/${name}__${fmt}__${prof}__strip$ext" "$OUT/${name}__${fmt}__${prof}__nostrip$ext"
        fail "$name $fmt $prof (cargo build failed)"
        continue
      fi
      [ -f "$b" ] || { fail "$name $fmt $prof (cargo succeeded but $b is missing)"; continue; }
      ok=1
      for st in strip nostrip; do
        d="$OUT/${name}__${fmt}__${prof}__${st}$ext"
        rm -f "$d"
        cp "$b" "$d" || { fail "$d (copy failed)"; ok=0; continue; }
        if [ "$st" = strip ] && ! strip_one "$fmt" "$d"; then
          rm -f "$d"; fail "${name}__${fmt}__${prof}__strip$ext (strip failed)"; ok=0
        fi
      done
      [ "$ok" = 1 ] && echo "built $name $fmt $prof"
    done
  done
done
if [ "${#failures[@]}" -gt 0 ]; then
  echo "FAILED: ${#failures[@]} build(s) missing:" >&2
  for f in "${failures[@]}"; do echo "  - $f" >&2; done
  exit 1
fi
