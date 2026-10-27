#!/usr/bin/env python3
"""recover_lang.py - a per-function source-language map for a (possibly mixed-language) binary.

Real native binaries are rarely one language: every Rust binary statically links C (libc/musl, asm
crypto), FFI pulls in C/C++, and a dropper may bundle Go or Swift. rust-deobf's Rust-specific tiers
(metadata, demangling, vtables, crate idioms) should run on the Rust parts and not mislabel the
rest. This labels each function's language from its symbol mangling and the binary's language from
section fingerprints, so an analyst -- and the tool -- knows which lens applies where.

Signals:
  * symbol mangling per function: Rust v0 (`_R...`) / legacy (`_ZN...17h<hex>E`); C++ Itanium
    (`_Z...` without the Rust hash) or MSVC (`?...`); Swift (`$s...`); Objective-C (`-[... ...]`);
    Go (`pkg.Func`, `runtime.*`, import-path.symbol); otherwise C / unknown.
  * section fingerprints (binary-level, robust even when stripped): `.gopclntab`/`.go.buildinfo`
    (Go), `__swift5_*` (Swift), `__objc_*` (Objective-C), and the `.comment` producer string
    (rustc / GCC / clang).

    python3 scripts/recover_lang.py path/to/binary            # language summary + per-function counts
    python3 scripts/recover_lang.py path/to/binary --json
    python3 scripts/recover_lang.py --selftest

A first tier: attribution is exact where symbols survive, and section-level for the rest; idiom-based
attribution of fully-stripped functions (prologue/runtime fingerprints) is the next tier.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

_RUST_HASH = re.compile(r"17h[0-9a-f]{16}E")
# Go symbols, strictly: an import path with a slash (`host/pkg.Func`, unmistakable), or one of the
# curated Go stdlib/runtime package prefixes as `pkg.Func`. Deliberately NOT "any dotted name" --
# compiler-internal symbols like `DW.ref.*` and versioned ones are dotted too and must not match.
_GO_PKGS = ("runtime", "internal", "reflect", "sync", "syscall", "type", "go", "main", "os", "fmt",
            "net", "time", "strconv", "strings", "bytes", "io", "sort", "math", "errors", "bufio",
            "encoding", "unicode", "hash", "regexp", "context", "crypto", "bytealg", "cpu")
_GO_SYM = re.compile(r"^(?:" + "|".join(_GO_PKGS) + r")(?:/[\w.\-]+)*\.[A-Za-z_]"
                     r"|^[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-/]+\.[A-Za-z_]")
_OBJC = re.compile(r"^[-+]\[")


def classify_symbol(name: str) -> str | None:
    """The source language of a function symbol, or None if it carries no language signal."""
    n = name[1:] if name.startswith("__R") or name.startswith("__Z") else name  # Mach-O leading _
    if n.startswith("_R"):
        return "rust"
    if n.startswith("_ZN") or n.startswith("_Z"):
        return "rust" if _RUST_HASH.search(n) else "cpp"
    if n.startswith("?") and ("@@" in n or n.startswith("??")):
        return "cpp"            # MSVC mangling
    if n.startswith("$s") or n.startswith("$S") or n.startswith("_$s"):
        return "swift"
    if _OBJC.match(name):
        return "objc"
    if "." in n and "@" not in n and not n.startswith(("DW.", ".")) and _GO_SYM.match(n):
        return "go"
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", n):
        return "c"              # a plain, unmangled identifier: C (or asm)
    return None


# section name -> language it proves present
_SECTION_LANG = {
    ".gopclntab": "go", ".go.buildinfo": "go", ".note.go.buildid": "go",
    "__gopclntab": "go",
    "__swift5_types": "swift", "__swift5_proto": "swift", "__swift5_fieldmd": "swift",
    "__objc_classlist": "objc", "__objc_const": "objc", "__objc_data": "objc",
}


def recover(path) -> dict:
    import lief
    b = lief.parse(str(path))
    if b is None:
        return {"error": "unparseable"}
    sec_langs = set()
    for s in b.sections:
        nm = s.name
        for key, lang in _SECTION_LANG.items():
            if nm == key or (nm.startswith("__swift5_") and lang == "swift"):
                sec_langs.add(lang)
    # .comment producer string
    producer = ""
    for s in b.sections:
        if s.name == ".comment":
            try:
                producer = bytes(s.content).decode("latin-1", "ignore")
            except Exception:
                producer = ""
            break
    if "rustc" in producer:
        sec_langs.add("rust")
    if "GCC" in producer or "clang" in producer:
        sec_langs.add("c")

    per_fn = {}
    counts = {}
    present = set()            # languages proven present (defined OR imported mangled symbols)
    macho = b.format.name == "MACHO"
    for sym in b.symbols:
        name = sym.name
        if not name:
            continue
        lang = classify_symbol(name)
        if lang is None:
            continue
        # an imported (undefined, va 0) C++/Rust/Swift mangled symbol still proves that language is
        # linked in, even though it is not a function we can place -- a plain C name does not (every
        # binary imports libc), so only the distinctively-mangled ones count for presence.
        va = getattr(sym, "value", 0)
        is_fn = macho or getattr(sym, "is_function", False)
        if lang != "c":
            present.add(lang)
        if is_fn and va:
            per_fn[va] = lang
            counts[lang] = counts.get(lang, 0) + 1
            present.add(lang)

    # linked libraries: libstdc++/libc++ => C++; a C++ runtime dep is strong presence evidence
    try:
        for lib in b.libraries:
            ln = str(lib).lower()
            if "stdc++" in ln or "libc++" in ln or "c++abi" in ln:
                present.add("cpp")
            elif "libc." in ln or ln.startswith("libc"):
                present.add("c")
    except Exception:
        pass

    langs = set(counts) | sec_langs | present
    dominant = max(counts, key=counts.get) if counts else (sorted(sec_langs)[0] if sec_langs else None)
    return {
        "format": b.format.name, "languages_present": sorted(langs), "dominant": dominant,
        "mixed": len(langs) > 1, "symbol_language_counts": dict(sorted(counts.items())),
        "section_signals": sorted(sec_langs), "producer": producer.strip("\x00 ")[:80],
        "functions": {hex(va): lang for va, lang in sorted(per_fn.items())},
    }


def _print(res: dict) -> None:
    if "error" in res:
        print("recover_lang:", res["error"]); return
    print(f"format={res['format']}  languages: {', '.join(res['languages_present']) or 'unknown'}"
          f"  (dominant: {res['dominant']}, mixed: {res['mixed']})")
    if res["symbol_language_counts"]:
        print("  by symbol: " + ", ".join(f"{k}={v}" for k, v in res["symbol_language_counts"].items()))
    if res["section_signals"]:
        print("  section signals: " + ", ".join(res["section_signals"]))
    if res["producer"]:
        print("  producer: " + res["producer"])


def _selftest():
    c = classify_symbol
    # Rust v0 and legacy (with hash) vs C++ Itanium (no hash)
    assert c("_RNvCs123_4core3foo") == "rust"
    assert c("_ZN4core3foo17h0123456789abcdefE") == "rust"
    assert c("_ZN3std6vector4pushEv") == "cpp"            # Itanium, no Rust hash
    assert c("_ZSt4cout") == "cpp"
    assert c("?func@Class@@QEAAXXZ") == "cpp"             # MSVC
    assert c("$s4main3fooyyF") == "swift"
    assert c("-[AppDelegate applicationDidFinishLaunching:]") == "objc"
    assert c("runtime.main") == "go" and c("main.main") == "go"
    assert c("github.com/x/y.Handler") == "go"
    assert c("memcpy") == "c" and c("my_helper") == "c"
    assert c("") is None or c(".hidden") is None
    # Mach-O leading underscore stripped
    assert c("__RNvCs1_4core") == "rust" and c("__ZN3std3fooEv") == "cpp"
    print("selftest OK: symbol-language classification (rust v0/legacy, c++ Itanium/MSVC, swift, "
          "objc, go, c), Rust-hash disambiguation from C++")


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary:
        ap.error("give a binary, or --selftest")
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    res = recover(path)
    print(json.dumps(res, indent=2)) if a.json else _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
