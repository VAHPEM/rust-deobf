#!/usr/bin/env bash
# Regenerate the static-recovery regression fixtures (benign: each decodes three canary strings).
# x86-64 needs `as`+`ld`; aarch64 needs a cross-assembler (clang --target, or aarch64 binutils).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
for m in shortkey slice_r9 slice_rcx; do
  python3 "$here/gen_x86.py" "$m" > "$here/$m.s"
  as "$here/$m.s" -o "$here/$m.o" && ld "$here/$m.o" -o "$here/$m" && rm -f "$here/$m.o"
done
for am in zerokey stack; do
  python3 "$here/gen_a64.py" "$am" > "$here/a64_$am.s"
done
for am in zerokey stack; do
  clang --target=aarch64-linux-gnu -nostdlib -static "$here/a64_$am.s" -o "$here/a64_$am" \
    || echo "aarch64 build needs clang with the aarch64 target; the committed binary stays"
  rm -f "$here/a64_$am.s"
done
echo "built: shortkey slice_r9 slice_rcx a64_zerokey a64_stack"

# i386 literal-recovery fixture (4-byte ptr/len &str table): needs a 32-bit assembler
as --32 "$here/i386_literals.s" -o "$here/i386_literals.o" 2>/dev/null \
  && ld -m elf_i386 "$here/i386_literals.o" -o "$here/i386_literals" && rm -f "$here/i386_literals.o" \
  || echo "i386 fixture needs a 32-bit as/ld; the committed binary stays"
# Mach-O chained-fixup vs classic dylibs: need an Apple/ld64 toolchain (built elsewhere, committed)
echo "note: macho_chained.dylib / macho_classic.dylib are committed (need ld64 -fixup_chains to rebuild)"
