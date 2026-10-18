#!/usr/bin/env python3
"""recover.py — recover obfuscated strings from a Rust (or other x86-64) binary.

A single entry point for analysts. Tries static call-site recovery first (fast, no
execution; handles hand-rolled XOR/ADD/SUB and litcrypt), then falls back to bounded
Unicorn emulation for inlined decoders (obfstr). Prints the decoded strings it finds.

    python scripts/recover.py <binary> [--min-len 6] [--no-emulate]

This is defensive tooling: it reads and statically/║emulated-decodes a binary to surface
hidden strings for malware triage. It does not run the sample's real code (external calls
are stubbed during emulation).
"""
from __future__ import annotations
import argparse, sys, string
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import recover_callsite as rcs

PRINT = set(bytes(string.printable, "ascii")) - set(b"\x0b\x0c")


def printable_strings(texts, min_len):
    out = []
    for t in texts:
        cur = []
        for ch in t:
            if ord(ch) < 128 and ch.encode()[0] in PRINT and ch not in "\r\n\t":
                cur.append(ch)
            else:
                if len(cur) >= min_len: out.append("".join(cur))
                cur = []
        if len(cur) >= min_len: out.append("".join(cur))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--min-len", type=int, default=6)
    ap.add_argument("--no-emulate", action="store_true", help="skip the emulation fallback")
    args = ap.parse_args()

    path = Path(args.binary)
    if not path.exists():
        sys.exit(f"no such file: {path}")

    # Pass an empty canary set: recover() still collects every decoded blob it produces.
    res = rcs.recover(path, canaries=[])
    static_strings = sorted(set(printable_strings(res.get("recovered_texts", []), args.min_len)))

    print(f"== static call-site recovery ==  ({res.get('decoders', 0)} decoder(s) found)")
    if static_strings:
        for s in static_strings:
            print(f"  {s}")
    else:
        print("  (no keyed decoder recovered statically)")

    if not args.no_emulate:
        try:
            import lief
            import recover_emulate as rem
            b = lief.parse(str(path))
            text = next((s for s in b.sections if s.name == ".text"), None)
            if text is not None:
                code = bytes(text.content); tva = text.virtual_address
                # emulate the largest handful of functions; collect decoded strings
                funcs = rem.function_ranges(b, code, tva)
                em = set()
                for (fva, _) in funcs[:60]:
                    rem.emulate_capture(b, code, tva, fva, [])
                    em |= getattr(rem.emulate_capture, "last_strings", set())
                em_strings = sorted(s for s in printable_strings(em, args.min_len)
                                    if s not in static_strings)
                print(f"\n== emulation fallback ==  ({len(funcs)} candidate function(s))")
                # show only strings that look like recovered plaintext, not emulation noise
                interesting = [s for s in em_strings if sum(c.isalnum() for c in s) >= len(s)*0.6]
                for s in interesting[:40]:
                    print(f"  {s}")
                if not interesting:
                    print("  (nothing additional recovered by emulation)")
        except Exception as e:
            print(f"\n== emulation fallback unavailable: {e} ==")


if __name__ == "__main__":
    main()
