#!/usr/bin/env bash
# Regenerate the high-ImageBase PE fixtures of tests/test_ollvm_shapes.py (*_high_base tests): the
# OLLVM -bcf and Hikari string-encryption shapes from obf_src/, linked as MinGW-w64 x86-64 PEs at
# the default ImageBase 0x140000000 -- what windows-latest's host build produces -- so every host
# tests them. Benign programs; ANALYSED, never run.
#   bcf_O{1,2,s}_pe64.exe  obf_src/ollvm_bcf/bcf.c, no CRT (-nostdlib, entry = step, main renamed;
#                          msvcrt import library only), COFF symbols kept (_range reads `step`)
#   hikari_pe64.exe        obf_src/hikari_strenc/hikari_ctor.c with the full MinGW CRT,
#                          stripped (-s): the constructor table is found without symbols. GNU ld
#                          2.41 puts __CTOR_LIST__ inside .text ...
#   hikari_pe64_rdata.exe  ... and GNU ld 2.47 (what windows-latest's MSYS2 installs, Nov 2026)
#                          inside .rdata: the same source, built with that toolchain
#                          (HIKARI_OUT=hikari_pe64_rdata.exe ./build.sh; nothing else changes)
#
#   ./build.sh            rebuild in place (next to this script)
#   ./build.sh OUTDIR     build into OUTDIR instead
#
# Committed as built with Ubuntu 24.04's clang 18.1.3 + gcc-mingw-w64-x86-64 13.2.0 (GNU ld
# 2.41.90), e.g. in `docker run --platform linux/amd64 ubuntu:24.04` after
# `apt-get install clang gcc-mingw-w64-x86-64`; --no-insert-timestamp makes that byte for byte.
# hikari_pe64_rdata.exe: Arch Linux (archlinux:latest, 2026-11-20) clang 23.1.5 + mingw-w64-gcc
# 16.2.0 + mingw-w64-binutils 2.47 + mingw-w64-crt 14.0.0 (`pacman -S clang mingw-w64-gcc`).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
src="$here/../../../obf_src"
out="${1:-$here}"
mkdir -p "$out"
for tool in clang x86_64-w64-mingw32-ld; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "build.sh: '$tool' not found (needs clang + mingw-w64 x86-64)" >&2
    exit 1
  fi
done
CC=(clang --target=x86_64-w64-mingw32 -Wl,--image-base=0x140000000 -Wl,--no-insert-timestamp)
set -x
for o in 1 2 s; do
  "${CC[@]}" -O$o -Dmain=bcf_main -D__USE_MINGW_ANSI_STDIO=0 -nostdlib -Wl,-e,step \
    -Wl,--strip-debug -o "$out/bcf_O${o}_pe64.exe" "$src/ollvm_bcf/bcf.c" -lmsvcrt
done
"${CC[@]}" -O2 -s -o "$out/${HIKARI_OUT:-hikari_pe64.exe}" "$src/hikari_strenc/hikari_ctor.c"
