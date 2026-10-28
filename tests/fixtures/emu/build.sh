#!/usr/bin/env bash
# Regenerate the emulation-engine regression fixtures. All are tiny, benign programs that exercise
# one loader/runtime path each; they are ANALYSED (emulated function-by-function), never run.
#   null.c  -> null64     a call through a null pointer between two decodes (x86-64 PIE)
#   pe.c    -> pe64.exe   a PE .data whose VirtualSize >> SizeOfRawData (.bss merged in)
#   vt.c    -> vt32       an i386 PIE vtable whose size field a wide relocation patch would zero
#                         (linked with -z notext, as committed: it carries DT_TEXTREL)
#   ct.c    -> ct32/ct64  a global constructor, i386 PIE and x86-64 PIE
#   tls.c   -> tls.so     two initial-exec thread-locals (x86-64; R_X86_64_TPOFF64 relocations)
#   heap.c  -> heap.so    a constructor that malloc()s a block a global points at
#   mo.c    -> mo_chained/mo_classic   a Mach-O pointer table, chained fixups vs classic dyld
#   mo2.c   -> mo2_classic             a Mach-O __mod_init_func constructor
#
#   ./build.sh            rebuild the ELF fixtures in place (next to this script)
#   ./build.sh OUTDIR     build them into OUTDIR instead (to compare against the committed ones)
#
# Needs clang + ld.lld (i386 targets need nothing else: everything is -nostdlib). With Ubuntu
# clang/lld 18.1.3 (the version in each fixture's .comment) this reproduces the committed binaries
# byte for byte. pe64.exe and the Mach-O fixtures need lld-link / ld64 and are committed as built.
# Any failure aborts with a non-zero exit -- a fixture that silently failed to rebuild is worse
# than no rebuild.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:-$here}"
mkdir -p "$out"

for tool in clang ld.lld; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "build.sh: '$tool' not found (needs clang + lld)" >&2
    exit 1
  fi
done

CC=(clang -O1 -fuse-ld=lld)
set -x
"${CC[@]}"      -nostdlib -fpie -pie                 -o "$out/null64"  "$here/null.c"
"${CC[@]}" -m32 -nostdlib -fpie -pie -Wl,-z,notext   -o "$out/vt32"    "$here/vt.c"
"${CC[@]}"      -nostdlib -fpie -pie                 -o "$out/ct64"    "$here/ct.c"
"${CC[@]}" -m32 -nostdlib -fpie -pie                 -o "$out/ct32"    "$here/ct.c"
"${CC[@]}"      -nostdlib -shared -fpic -ftls-model=initial-exec -o "$out/tls.so" "$here/tls.c"
"${CC[@]}"      -nostdlib -shared -fpic              -o "$out/heap.so" "$here/heap.c"
{ set +x; } 2>/dev/null
echo "built null64 vt32 ct64 ct32 tls.so heap.so in $out"
echo "note: pe64.exe and the Mach-O fixtures are committed (need lld-link / ld64 to rebuild)"
