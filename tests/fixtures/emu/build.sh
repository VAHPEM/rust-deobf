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
#   tls2.c  -> tls2.so/tls2_32.so/tls2_a64.so  a 32-byte initial-exec TLS struct next to an 8-byte one
#   bigbss.c -> bigbss64  a constructor in an image whose .bss (32 MB) exceeds the emulator's _BSS_CAP
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

# explicit target triples: the fixtures are x86 / AArch64 whatever the build host is (on an ARM64
# host, `-m32` would mean 32-bit ARM, not i386 -- measured on ARM64 Kali)
X64=(clang -O1 -fuse-ld=lld --target=x86_64-linux-gnu)
X86=(clang -O1 -fuse-ld=lld --target=i386-linux-gnu)
set -x
"${X64[@]}" -nostdlib -fpie -pie                 -o "$out/null64"  "$here/null.c"
"${X86[@]}" -nostdlib -fpie -pie -Wl,-z,notext   -o "$out/vt32"    "$here/vt.c"
"${X64[@]}" -nostdlib -fpie -pie                 -o "$out/ct64"    "$here/ct.c"
"${X86[@]}" -nostdlib -fpie -pie                 -o "$out/ct32"    "$here/ct.c"
"${X64[@]}" -nostdlib -shared -fpic -ftls-model=initial-exec -o "$out/tls.so" "$here/tls.c"
"${X64[@]}" -nostdlib -shared -fpic              -o "$out/heap.so" "$here/heap.c"
clang -O1 --target=aarch64-linux-gnu -shared -fpic -nostdlib -fuse-ld=lld -o "$out/tls2_a64.so" "$here/tls2.c"
"${X64[@]}" -nostdlib -static                    -o "$out/bigbss64" "$here/bigbss.c"
{ set +x; } 2>/dev/null
# tls2.so / tls2_32.so need the x86 BFD linker: its GOT order puts T2 before T1, the order in which
# a fixed 8-byte stride overlapped the struct on x86 (lld orders them the other way). Only an x86
# host (or one with x86 binutils) has it; elsewhere they stay as committed.
if [ "$(uname -m)" = x86_64 ]; then
  small=(-Wl,-z,noseparate-code -Wl,-z,max-page-size=0x1000)
  set -x
  clang -O1 -shared -fpic -nostdlib "${small[@]}" -s       -o "$out/tls2.so"    "$here/tls2.c"
  clang -O1 -m32 -shared -fpic -nostdlib "${small[@]}"     -o "$out/tls2_32.so" "$here/tls2.c"
  { set +x; } 2>/dev/null
else
  echo "note: tls2.so / tls2_32.so not rebuilt (need the x86 BFD linker; host is $(uname -m))"
fi
echo "built null64 vt32 ct64 ct32 tls.so heap.so tls2.so tls2_32.so tls2_a64.so bigbss64 in $out"
echo "note: pe64.exe and the Mach-O fixtures are committed (need lld-link / ld64 to rebuild)"
