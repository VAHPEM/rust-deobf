#!/usr/bin/env bash
# Regenerate the static-recovery regression fixtures (benign: each decodes three canary strings).
# x86-64 needs `as`+`ld`; aarch64 needs a cross-assembler (clang --target, or aarch64 binutils).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
for m in shortkey slice_r9 slice_rcx; do
  python3 "$here/gen_x86.py" "$m" > "$here/$m.s"
  as "$here/$m.s" -o "$here/$m.o" && ld "$here/$m.o" -o "$here/$m" && rm -f "$here/$m.o"
done
python3 "$here/gen_a64.py" zerokey > "$here/a64_zerokey.s"
clang --target=aarch64-linux-gnu -nostdlib -static "$here/a64_zerokey.s" -o "$here/a64_zerokey" \
  || echo "aarch64 build needs clang with the aarch64 target; the committed binary stays"
rm -f "$here/a64_zerokey.s"
echo "built: shortkey slice_r9 slice_rcx a64_zerokey"
