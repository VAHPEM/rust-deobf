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
set -u
ROOT="$(cd "$(dirname "$0")/.."; pwd)"
SRC="$ROOT/bench_src"; OUT="${BUILD_DIR:-$ROOT/build}"; mkdir -p "$OUT"
# BUILD_DIR=... builds elsewhere (e.g. with RUSTUP_TOOLCHAIN=1.99.1 next to the default build);
# the tests read RUST_DEOBF_BUILD
MANIFEST="$OUT/build_manifest.jsonl"; [ "${SKIP_EXISTING:-0}" = 1 ] || : > "$MANIFEST"

targets=( "x86_64-unknown-linux-gnu:elf" "x86_64-pc-windows-gnu:pe" )
# FORMATS="pe elf-arm64" builds only those output formats (CI runs one job per format)
if [ -n "${FORMATS:-}" ]; then
  all=( "x86_64-unknown-linux-gnu:elf" "x86_64-pc-windows-gnu:pe" "aarch64-unknown-linux-musl:elf-arm64" )
  targets=()
  for t in "${all[@]}"; do case " $FORMATS " in *" ${t##*:} "*) targets+=( "$t" );; esac; done
  case " $FORMATS " in *" elf-arm64 "*) export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld;; esac
fi
# NATIVE_ARM64=1 (on an AArch64 Linux host) also builds aarch64-unknown-linux-gnu: glibc, dynamic,
# imports through the PLT -- the shape of an ARM64 Rust binary built on the machine itself
if [ "${NATIVE_ARM64:-0}" = 1 ]; then targets+=( "aarch64-unknown-linux-gnu:elf-arm64gnu" ); fi
# ARM64=1 also cross-builds AArch64 ELF (static musl, linked by rust-lld): no ARM machine or
# cross gcc needed, only `rustup target add aarch64-unknown-linux-musl`. rust-lld relaxes
# adrp+add pairs into `adr`, a codegen shape the static ARM64 recoverer has to handle.
if [ "${ARM64:-0}" = 1 ]; then
  targets+=( "aarch64-unknown-linux-musl:elf-arm64" )
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
fi
projects="${ONLY:-$(ls -d "$SRC"/*/ 2>/dev/null | xargs -n1 basename)}"
for proj in $projects; do
  pdir="$SRC/$proj"; [ -d "$pdir" ] || continue
  # per-project build env (e.g. litcrypt/cryptify fixed key) and suite
  read -r env_line suite < <(python3 -c "
import json;v=json.load(open('$SRC/manifest.json'))['variants'].get('$proj',{})
e=v.get('env');print((f'{e[0]}={e[1]}' if e else '-'), v.get('suite','canary'))")
  [ "$env_line" = "-" ] && env_line=""
  if [ -n "${PROFILES:-}" ]; then profiles="$PROFILES"
  elif [ "$suite" = scatter ]; then profiles="release size-lto speed-lto"
  else profiles="debug release size-lto speed-lto"; fi
  for t in "${targets[@]}"; do
    triple="${t%%:*}"; fmt="${t##*:}"
    ext=""; [ "$fmt" = pe ] && ext=".exe"
    for profile in $profiles; do
      if [ "${SKIP_EXISTING:-0}" = 1 ] && [ -f "$OUT/${proj}__${fmt}__${profile}__strip$ext" ]; then
        continue
      fi
      case "$profile" in debug) flags="";; release) flags="--release";; *) flags="--profile $profile";; esac
      ( cd "$pdir"
        env ${env_line:+$env_line} cargo build $flags --target "$triple" >/dev/null 2>&1
      )
      bin="$pdir/target/$triple/$profile/$proj$ext"
      [ -f "$bin" ] || { echo "MISS $proj $triple $profile"; continue; }
      for strip in nostrip strip; do
        name="${proj}__${fmt}__${profile}__${strip}$ext"
        dst="$OUT/$name"; cp "$bin" "$dst"
        if [ "$strip" = strip ]; then
          if [ "$fmt" = pe ]; then x86_64-w64-mingw32-strip "$dst" 2>/dev/null
          elif [ "${fmt#elf-arm64}" != "$fmt" ]; then llvm-strip "$dst" 2>/dev/null || aarch64-linux-gnu-strip "$dst" 2>/dev/null || strip "$dst" 2>/dev/null
          else strip "$dst" 2>/dev/null; fi
        fi
        sz=$(stat -c%s "$dst" 2>/dev/null || stat -f%z "$dst")
        echo "{\"name\":\"$name\",\"proj\":\"$proj\",\"suite\":\"$suite\",\"fmt\":\"$fmt\",\"profile\":\"$profile\",\"strip\":\"$strip\",\"bytes\":$sz}" >> "$MANIFEST"
        echo "OK  $name  ${sz}b"
      done
    done
  done
done
echo "built: $(wc -l < "$MANIFEST") binaries"
