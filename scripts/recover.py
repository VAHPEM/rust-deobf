#!/usr/bin/env python3
"""recover.py - unified string-recovery front end for Rust binaries.

Detects the binary's architecture and format, then dispatches to the right recoverer:

  x86-64 (ELF or PE)  -> static call-site recovery   (recover_callsite.py)
  AArch64 (ELF)       -> static call-site recovery   (recover_arm64.py)
  anything, hard case -> run scripts/recover_dynamic.py in a sandbox (prints how)

Static recovery is fast and needs no execution, but only handles simple keyed decoders
(hand-rolled XOR/ADD/SUB and litcrypt). For optimised crate builds, inlined decoders
(obfstr) and AEAD (muddy), use the dynamic path. See VALIDATION.md.

    python scripts/recover.py <binary>
"""
from __future__ import annotations
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lief

CANARIES_HINT = "(pass a binary; recovered strings are printed, not matched against known values)"


def detect(path):
    b = lief.parse(str(path))
    if b is None:
        return None, None
    fmt = b.format.name if hasattr(b, "format") else "?"
    # architecture
    arch = "?"
    try:
        hdr = b.header
        m = (hdr.machine_type.name if hasattr(hdr, "machine_type") else str(hdr.machine)).upper()
        if "AARCH64" in m or "ARM64" in m:
            arch = "aarch64"
        elif "X86_64" in m or "AMD64" in m or "86_64" in m:
            arch = "x86_64"
        elif "ARM" in m:
            arch = "arm"
    except Exception:
        pass
    return fmt, arch


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path = Path(sys.argv[1])
    if not path.exists():
        sys.exit(f"no such file: {path}")

    fmt, arch = detect(path)
    print(f"binary: {path.name}   format={fmt}   arch={arch}")

    canaries = []  # print everything recovered; we are not scoring here
    if arch == "x86_64":
        import recover_callsite as R
        r = R.recover(path, canaries)
        engine = "static x86-64 (recover_callsite)"
    elif arch == "aarch64":
        import recover_arm64 as R
        r = R.recover(path, canaries)
        engine = "static aarch64 (recover_arm64)"
    else:
        print(f"no static engine for arch={arch}; use the dynamic path.")
        r = None
        engine = None

    if r is not None:
        strings = sorted(set(s for s in r.get("recovered_texts", []) if len(s) >= 6))
        print(f"\n== {engine} ==  decoder candidates: {r.get('decoders', 0)}")
        if strings:
            for s in strings:
                print(f"  {s}")
        else:
            print("  (no keyed decoder recovered statically)")

    print("\n== for optimised / inlined / AEAD builds, recover dynamically (sandbox only) ==")
    print(f"  python {Path(__file__).parent}/recover_dynamic.py {path}")


if __name__ == "__main__":
    main()
