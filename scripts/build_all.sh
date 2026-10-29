#!/usr/bin/env bash
# Build every benchmark project across the config matrix:
#   {ELF, PE} x86-64 (+ AArch64 ELF with ARM64=1)  x  build profiles  x  {strip, nostrip}
#
# Profiles (defined in each bench_src/*/Cargo.toml by bench_src/gen_projects.py):
#   debug, release      the original benchmark profiles (opt-level 3, thin local LTO)
#   size-lto            opt-level="z", lto="fat", codegen-units=1, panic="abort"
#   speed-lto           opt-level=3,   lto="fat", codegen-units=1, panic="abort"
# The two LTO profiles are what shipped Rust malware typically uses; they move inlining and loop
# shape, which is exactly what the static recoverers key on, so the benchmark measures them too.
# The canary suite builds all four; the scatter suite builds release + the two LTO profiles.
# Override with PROFILES="release size-lto" (applies to every project), or ONLY="obfstr litcrypt".
# SKIP_EXISTING=1 keeps binaries that are already in the build directory.
#
# Exit status: 0 only when every requested binary was built (and stripped); otherwise 1, after the
# whole matrix has been attempted, with each failure listed. A failed `cargo build` never falls back
# to a binary left in target/ by an earlier build, and its output is kept in
# $BUILD_DIR/build_logs/<proj>__<fmt>__<profile>.log (the tail is printed on failure).
set -u
ROOT="$(cd "$(dirname "$0")/.."; pwd)"
SRC="$ROOT/bench_src"; OUT="${BUILD_DIR:-$ROOT/build}"; mkdir -p "$OUT"
LOGS="$OUT/build_logs"; mkdir -p "$LOGS"
failures=()
fail() { failures+=( "$1" ); echo "MISS $1" >&2; }

# strip_one FMT FILE: strip with the first tool that exists for that format, showing its errors
strip_one() {
  local fmt="$1" f="$2" tool cands
  case "$fmt" in
    pe) cands="x86_64-w64-mingw32-strip llvm-strip" ;;
    pe32) cands="i686-w64-mingw32-strip llvm-strip" ;;
    elf-arm64*) cands="llvm-strip aarch64-linux-gnu-strip strip" ;;
    *) cands="strip llvm-strip" ;;
  esac
  # macOS's own strip cannot process ELF/PE: use the LLVM / cross binutils ones there
  if [ "$(uname -s)" = Darwin ]; then
    case "$fmt" in pe|pe32) ;; elf-arm64*) cands="llvm-strip aarch64-linux-gnu-strip" ;; *) cands="llvm-strip x86_64-linux-gnu-strip" ;; esac
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
# BUILD_DIR=... builds elsewhere (e.g. with RUSTUP_TOOLCHAIN=1.99.1 next to the default build);
# the tests read RUST_DEOBF_BUILD
MANIFEST="$OUT/build_manifest.jsonl"; [ "${SKIP_EXISTING:-0}" = 1 ] || : > "$MANIFEST"

targets=( "x86_64-unknown-linux-gnu:elf" "x86_64-pc-windows-gnu:pe" )
# FORMATS="pe elf-arm64" builds only those output formats (CI runs one job per format);
# "pe32" (32-bit PE, i686-pc-windows-gnu + i686-w64-mingw32-gcc) is built only when named here
if [ -n "${FORMATS:-}" ]; then
  all=( "x86_64-unknown-linux-gnu:elf" "x86_64-pc-windows-gnu:pe" "aarch64-unknown-linux-musl:elf-arm64"
        "i686-pc-windows-gnu:pe32" )
  targets=()
  for t in "${all[@]}"; do case " $FORMATS " in *" ${t##*:} "*) targets+=( "$t" );; esac; done
  case " $FORMATS " in *" elf-arm64 "*) export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld;; esac
fi
# ARM64_GNU=1 also builds aarch64-unknown-linux-gnu: glibc, dynamic, imports through the PLT --
# the shape of an ARM64 Rust binary built on an ARM64 Linux machine. Natively on such a host, or
# cross with gcc-aarch64-linux-gnu (used automatically when present). NATIVE_ARM64=1 is an alias.
if [ "${ARM64_GNU:-${NATIVE_ARM64:-0}}" = 1 ]; then
  targets+=( "aarch64-unknown-linux-gnu:elf-arm64gnu" )
  if [ "$(uname -m)" != aarch64 ] && command -v aarch64-linux-gnu-gcc >/dev/null; then
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
  fi
fi
# ARM64=1 also cross-builds AArch64 ELF (static musl, linked by rust-lld): no ARM machine or
# cross gcc needed, only `rustup target add aarch64-unknown-linux-musl`. rust-lld relaxes
# adrp+add pairs into `adr`, a codegen shape the static ARM64 recoverer has to handle.
if [ "${ARM64:-0}" = 1 ]; then
  targets+=( "aarch64-unknown-linux-musl:elf-arm64" )
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
fi
projects="${ONLY:-$(ls -d "$SRC"/*/ 2>/dev/null | xargs -n1 basename)}"
for proj in $projects; do
  pdir="$SRC/$proj"; [ -f "$pdir/Cargo.toml" ] || continue
  # per-project build env (e.g. litcrypt/cryptify fixed key) and suite
  env_line=""; suite=""
  read -r env_line suite < <(python3 -c "
import json,sys;v=json.load(open(sys.argv[1]))['variants'].get(sys.argv[2],{})
e=v.get('env');print((f'{e[0]}={e[1]}' if e else '-'), v.get('suite','canary'))" "$SRC/manifest.json" "$proj")
  if [ -z "$suite" ]; then fail "$proj (cannot read bench_src/manifest.json)"; continue; fi
  [ "$env_line" = "-" ] && env_line=""
  if [ -n "${PROFILES:-}" ]; then profiles="$PROFILES"
  elif [ "$suite" = scatter ]; then profiles="release size-lto speed-lto"
  else profiles="debug release size-lto speed-lto"; fi
  for t in "${targets[@]}"; do
    triple="${t%%:*}"; fmt="${t##*:}"
    ext=""; case "$fmt" in pe|pe32) ext=".exe";; esac
    for profile in $profiles; do
      if [ "${SKIP_EXISTING:-0}" = 1 ] && [ -f "$OUT/${proj}__${fmt}__${profile}__strip$ext" ]; then
        continue
      fi
      case "$profile" in debug) flags="";; release) flags="--release";; *) flags="--profile $profile";; esac
      # a project without this profile (meta_probe has no LTO profiles): nothing to build
      case "$profile" in debug|release) ;; *) grep -q "^\[profile\.$profile\]" "$pdir/Cargo.toml" || continue;; esac
      bin="$pdir/target/$triple/$profile/$proj$ext"
      log="$LOGS/${proj}__${fmt}__${profile}.log"
      # a failed build must never ship the binary an earlier build left in target/
      if ! ( cd "$pdir" && env ${env_line:+"$env_line"} cargo build $flags --target "$triple" ) >"$log" 2>&1; then
        echo "---- cargo build failed: $proj $triple $profile (last lines of $log) ----" >&2
        tail -n 25 "$log" >&2
        # and the copies an earlier run put in the build directory are no longer this source's
        rm -f "$OUT/${proj}__${fmt}__${profile}__nostrip$ext" "$OUT/${proj}__${fmt}__${profile}__strip$ext"
        fail "$proj $triple $profile (cargo build failed)"
        continue
      fi
      [ -f "$bin" ] || { fail "$proj $triple $profile (cargo succeeded but $bin is missing)"; continue; }
      for strip in nostrip strip; do
        name="${proj}__${fmt}__${profile}__${strip}$ext"
        dst="$OUT/$name"
        rm -f "$dst"
        cp "$bin" "$dst" || { fail "$name (copy failed)"; continue; }
        if [ "$strip" = strip ] && ! strip_one "$fmt" "$dst"; then
          rm -f "$dst"; fail "$name (strip failed)"; continue
        fi
        sz=$(stat -c%s "$dst" 2>/dev/null || stat -f%z "$dst")
        echo "{\"name\":\"$name\",\"proj\":\"$proj\",\"suite\":\"$suite\",\"fmt\":\"$fmt\",\"profile\":\"$profile\",\"strip\":\"$strip\",\"bytes\":$sz}" >> "$MANIFEST"
        echo "OK  $name  ${sz}b"
      done
    done
  done
done
echo "built: $(wc -l < "$MANIFEST" | tr -d ' ') binaries"
if [ "${#failures[@]}" -gt 0 ]; then
  echo "FAILED: ${#failures[@]} build(s) missing:" >&2
  for f in "${failures[@]}"; do echo "  - $f" >&2; done
  exit 1
fi
