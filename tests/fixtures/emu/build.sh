#!/usr/bin/env bash
# Regenerate the emulation-engine regression fixtures. All are tiny, benign programs that exercise
# one loader/runtime path each; they are ANALYSED (emulated function-by-function), never run.
#   null.c  -> null64     a call through a null pointer between two decodes (x86-64)
#   pe.c    -> pe64.exe   a PE .data whose VirtualSize >> SizeOfRawData (.bss merged in)
#   vt.c    -> vt32       an i386 PIE vtable whose size field a wide relocation patch would zero
#   ct.c    -> ct32/ct64  a global constructor, i386 PIE and x86-64
#   tls.c   -> tls.so     two initial-exec thread-locals (x86-64)
#   heap.c  -> heap.so    a constructor that malloc()s a block a global points at
#   mo.c    -> mo_chained/mo_classic   a Mach-O pointer table, chained fixups vs classic dyld
#   mo2.c   -> mo2_classic             a Mach-O __mod_init_func constructor
# x86-64/i386 need clang + lld; the Mach-O fixtures need an ld64 toolchain (built elsewhere and
# committed). This script documents provenance; see each .c for the exact build flags used.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
clang -O1 -nostdlib -static -o "$here/null64"  "$here/null.c"   2>/dev/null || echo "null64: needs clang"
clang -m32 -O1 -fpie -pie -nostdlib -o "$here/vt32" "$here/vt.c" 2>/dev/null || echo "vt32: needs clang -m32"
clang -O1 -nostdlib -static -o "$here/ct64"    "$here/ct.c"     2>/dev/null || echo "ct64: needs clang"
clang -m32 -O1 -fpie -pie -nostdlib -o "$here/ct32" "$here/ct.c" 2>/dev/null || echo "ct32: needs clang -m32"
clang -shared -fpic -nostdlib -o "$here/tls.so"  "$here/tls.c"  2>/dev/null || echo "tls.so: needs clang"
clang -shared -fpic -o "$here/heap.so" "$here/heap.c"           2>/dev/null || echo "heap.so: needs clang"
echo "note: pe64.exe and the Mach-O fixtures are committed (need lld-link / ld64 to rebuild)"
