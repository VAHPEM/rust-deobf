#!/usr/bin/env bash
# Regenerate the PE import-binding fixtures (tests/test_imports.py). Tiny, benign, never run.
#   imp.c -> imp_x64.exe   x86-64: `call/jmp [rip+disp]` after an undecodable byte in .text
#            imp_x86.exe   x86:    `call/jmp [abs32]`
#            imp_arm64.exe ARM64:  `adrp; ldr; blr|br` (Windows on ARM)
# Needs clang + lld-link + llvm-dlltool (the import library comes from k.def; no Windows SDK).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
for spec in "x64 x86_64 i386:x86-64" "x86 i686 i386" "arm64 aarch64 arm64"; do
    set -- $spec
    clang --target="$2-pc-windows-msvc" -O1 -c "$here/imp.c" -o "$tmp/imp_$1.o"
    llvm-dlltool -m "$3" -d "$here/k.def" -l "$tmp/k_$1.lib"
    lld-link /nologo /entry:entry /subsystem:console /nodefaultlib "$tmp/imp_$1.o" "$tmp/k_$1.lib" \
        /out:"$here/imp_$1.exe"
done
