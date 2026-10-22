#!/usr/bin/env python3
"""floss_export.py - write rust-deobf results as a FLOSS results document.

FLOSS (Mandiant) loads a saved results document as input: `floss results.json` renders it like
a fresh run, `floss --html results.json` produces a standalone report, and the FLOSS web viewer
opens it. Writing our findings in that schema lets analysts look at strings rust-deobf recovered
from Rust binaries (which FLOSS's own deobfuscation misses) with the tooling they already use,
next to the static strings of the same file.

Mapping onto FLOSS's string types:

  static call-site recovery  -> decoded_strings: address = ciphertext VA (GLOBAL),
                                decoded_at = call site, decoding_routine = decoder function
  emulation recovery         -> decoded_strings: address_type STACK (the plaintext is built in
                                the function's frame), decoded_at = decoding_routine = function
  static stack strings       -> stack_strings: function/program_counter = last immediate store,
                                frame_offset = slot offset from the frame register
  static strings             -> static_strings, extracted here (ASCII + UTF-16LE), so the
                                document is complete without running FLOSS

No FLOSS import is needed; the schema is plain JSON. Only `floss` >= 4 reads these documents.

    python floss_export.py --selftest
"""
from __future__ import annotations
import datetime
import hashlib
import json
import re
from pathlib import Path

ASCII_RE = re.compile(rb"[\x20-\x7e]{%d,}")
UTF16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}")


def static_strings(buf: bytes, min_length: int = 4):
    """ASCII and UTF-16LE strings with their file offsets, like FLOSS's static extraction."""
    out = []
    for m in re.finditer(ASCII_RE.pattern % min_length, buf):
        out.append({"string": m.group().decode("ascii"), "offset": m.start(), "encoding": "ASCII"})
    for m in re.finditer(UTF16_RE.pattern % min_length, buf):
        out.append({"string": m.group().decode("utf-16le"), "offset": m.start(), "encoding": "UTF-16LE"})
    out.sort(key=lambda s: s["offset"])
    return out


def _decoded(record: dict) -> dict:
    if record.get("method", "").startswith("static"):
        return {
            "address": int(record.get("blob") or 0),
            "address_type": "GLOBAL",
            "string": record["string"],
            "encoding": "ASCII",
            "decoded_at": int(record.get("call") or 0),
            "decoding_routine": int(record.get("decoder") or 0),
        }
    fn = int(record.get("function") or 0)
    return {
        "address": 0,
        "address_type": "STACK",
        "string": record["string"],
        "encoding": "ASCII",
        "decoded_at": fn,
        "decoding_routine": fn,
    }


def _stack(record: dict) -> dict:
    pc = int(record.get("pc") or 0)
    off = int(record.get("offset") or 0)
    return {
        "function": pc,
        "string": record["string"],
        "encoding": "ASCII",
        "program_counter": pc,
        "stack_pointer": 0,
        "original_stack_pointer": 0,
        "offset": 0,
        "frame_offset": abs(off),
    }


def build_document(path: Path, decoded: list, stack: list, min_length: int = 4,
                   imagebase: int = 0, language: str = "rust", tool_version: str = "rust-deobf") -> dict:
    """A FLOSS ResultDocument (as plain JSON) for `path` with the given recovery records."""
    buf = Path(path).read_bytes()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat("T").replace("+00:00", "Z")
    decoded_strings, seen = [], set()
    for r in decoded:
        d = _decoded(r)
        key = (d["string"], d["decoded_at"])
        if key not in seen:
            seen.add(key)
            decoded_strings.append(d)
    routines = sorted({d["decoding_routine"] for d in decoded_strings if d["decoding_routine"]})
    return {
        "metadata": {
            "file_path": str(path),
            "md5": hashlib.md5(buf).hexdigest(),
            "sha1": hashlib.sha1(buf).hexdigest(),
            "sha256": hashlib.sha256(buf).hexdigest(),
            "version": tool_version,
            "imagebase": imagebase,
            "min_length": min_length,
            "runtime": {"start_date": now},
            "language": language,
            "language_version": "",
            "language_selected": "",
        },
        "analysis": {
            "enable_static_strings": True,
            "enable_stack_strings": True,
            "enable_tight_strings": False,
            "enable_decoded_strings": True,
            "enable_language_strings": False,
            "enable_layout": False,
            "enable_tags": False,
            "functions": {
                "discovered": 0,
                "library": 0,
                "analyzed_stack_strings": 0,
                "analyzed_tight_strings": 0,
                "analyzed_decoded_strings": len(routines),
                # FLOSS ranks decoding routines by score; ours are confirmed decoders
                "decoding_function_scores": {str(a): {"score": 1.0, "xrefs_to": 0} for a in routines},
            },
        },
        "strings": {
            "static_strings": static_strings(buf, min_length),
            "stack_strings": [_stack(r) for r in stack if len(r["string"]) >= min_length],
            "tight_strings": [],
            "decoded_strings": [d for d in decoded_strings if len(d["string"]) >= min_length],
            "language_strings": [],
            "language_strings_missed": [],
        },
    }


def write(path_out: Path, document: dict) -> None:
    Path(path_out).write_text(json.dumps(document, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _selftest():
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        sample = Path(d) / "sample.bin"
        sample.write_bytes(b"\x00plain-static-string\x00\x00\x00" + "wide-one".encode("utf-16le") + b"\x00\x00")
        doc = build_document(
            sample,
            decoded=[{"string": "decoded-by-call-site", "decoder": 0x1000, "call": 0x1100, "blob": 0x2000,
                      "method": "static"},
                     {"string": "decoded-by-emulation", "function": 0x1500, "method": "emulation"}],
            stack=[{"string": "stack-built", "pc": 0x1600, "base": "rbp", "offset": -0x40}],
        )
        assert [s["string"] for s in doc["strings"]["static_strings"]] == ["plain-static-string", "wide-one"]
        d0, d1 = doc["strings"]["decoded_strings"]
        assert (d0["address"], d0["decoded_at"], d0["decoding_routine"], d0["address_type"]) == \
            (0x2000, 0x1100, 0x1000, "GLOBAL")
        assert (d1["decoded_at"], d1["address_type"]) == (0x1500, "STACK")
        assert doc["strings"]["stack_strings"][0]["frame_offset"] == 0x40
        assert set(doc) == {"metadata", "analysis", "strings"}
        json.dumps(doc)
    print("selftest OK: FLOSS document with static, decoded (call-site + emulation) and stack strings")


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        _selftest()
    else:
        sys.exit(__doc__)
