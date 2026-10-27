#!/usr/bin/env python3
"""recover_go.py - recover Go function names from the pclntab, the Go analog of the Rust metadata tier.

Go binaries carry a rich symbol table, the `pclntab`, that the runtime needs for panics and stack
traces -- and it survives `strip`, because stripping only removes the ELF/Mach-O symbol table, not
the pclntab the runtime reads at run time. So a "stripped" Go malware sample still names every one of
its functions (`main.beacon`, `main.(*Config).decrypt`, ...). This parses the pclntab back to
`{entry VA: function name}`, the Go counterpart of what recover_rust_meta does for Rust (metadata
that survives strip), and reports the Go toolchain version for provenance.

Supports the modern self-describing pclntab (Go 1.18+ magic 0xfffffff0, Go 1.20+ 0xfffffff1), the
common case today; older magics (1.16-1.17 0xfffffffa, 1.2-1.15 0xfffffffb) are detected and
reported but not fully parsed (next tier). Finds the table by section (`.gopclntab` / `__gopclntab`)
or by scanning for its magic (PE Go binaries carry it unnamed in `.rdata`).

    python3 scripts/recover_go.py path/to/go-binary            # summary + sample names
    python3 scripts/recover_go.py path/to/go-binary --json     # all {va: name}
    python3 scripts/recover_go.py --selftest
"""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

_MAGICS = {0xfffffffb: "go1.2-1.15", 0xfffffffa: "go1.16-1.17",
           0xfffffff0: "go1.18-1.19", 0xfffffff1: "go1.20+"}
_PARSEABLE = {0xfffffff0, 0xfffffff1}        # the header layout this tier parses
_GO_VER = re.compile(rb"go1\.\d{1,2}(?:\.\d{1,2})?")
_MAX_FUNCS = 2_000_000


def find_pclntab(b):
    """(virtual_address, raw_bytes, named) of the pclntab, or (None, None, False). `named` is True
    when it came from a `.gopclntab`/`__gopclntab` section (a strong Go signal) rather than a magic
    scan (which can match by chance in a non-Go binary)."""
    for name in (".gopclntab", "__gopclntab"):
        s = next((x for x in b.sections if x.name == name), None)
        if s is not None:
            return s.virtual_address, bytes(s.content), True
    # scan sections for a pclntab magic at an aligned offset (PE: unnamed in .rdata)
    for s in b.sections:
        try:
            raw = bytes(s.content)
        except Exception:
            continue
        for off in range(0, min(len(raw) - 8, 1 << 20), 8):
            if struct.unpack_from("<I", raw, off)[0] in _MAGICS \
                    and raw[off + 6] in (1, 2, 4) and raw[off + 7] in (4, 8):
                return s.virtual_address + off, raw[off:], False
    return None, None, False


def parse_pclntab(raw: bytes):
    """Return {"magic", "version_hint", "functions": {entry_va: name}} for a 1.18+/1.20+ pclntab."""
    if len(raw) < 72:
        return None
    magic = struct.unpack_from("<I", raw, 0)[0]
    if magic not in _MAGICS:
        return None
    info = {"magic": hex(magic), "version_hint": _MAGICS[magic], "functions": {}}
    if magic not in _PARSEABLE:
        return info
    ptr = raw[7]
    u = (lambda o: struct.unpack_from("<Q", raw, o)[0]) if ptr == 8 else \
        (lambda o: struct.unpack_from("<I", raw, o)[0])
    u32 = lambda o: struct.unpack_from("<I", raw, o)[0]
    i32 = lambda o: struct.unpack_from("<i", raw, o)[0]
    try:
        nfunc = u(8)
        text_start = u(24)
        funcname_off = u(32)
        pcln_off = u(64)
    except struct.error:
        return info
    if not (0 < nfunc <= _MAX_FUNCS) or pcln_off >= len(raw) or funcname_off >= len(raw):
        return info

    def cstr(o):
        if o < 0 or o >= len(raw):
            return ""
        end = raw.find(b"\x00", o)
        return raw[o:end if end != -1 else len(raw)].decode("utf-8", "replace")

    funcs = {}
    ft = pcln_off
    for i in range(nfunc):
        base = ft + i * 8
        if base + 8 > len(raw):
            break
        entryoff = u32(base)
        funcoff = u32(base + 4)
        fstruct = pcln_off + funcoff
        if fstruct + 8 > len(raw):
            continue
        name_off = i32(fstruct + 4)
        name = cstr(funcname_off + name_off)
        if name:
            funcs[text_start + entryoff] = name
    info["functions"] = funcs
    return info


def recover(path) -> dict:
    import lief
    b = lief.parse(str(path))
    if b is None:
        return {"is_go": False, "error": "unparseable"}
    data = Path(path).read_bytes()
    ver = _GO_VER.search(data)
    version = ver.group().decode() if ver else None
    try:
        va, raw, named = find_pclntab(b)
        parsed = parse_pclntab(raw) if raw is not None else None
    except Exception:
        va, raw, named, parsed = None, None, False, None
    funcs = parsed["functions"] if parsed else {}
    # Go only on strong evidence: a named pclntab section, a `go1.x` version string, or a scan-found
    # table that parsed into a substantial set of Go-shaped names -- so a chance magic match in a
    # non-Go binary is not reported as Go.
    go_shaped = sum(1 for n in funcs.values() if "." in n)
    is_go = bool(named or version or (len(funcs) >= 8 and go_shaped >= len(funcs) // 2))
    if not is_go:
        return {"is_go": False, "go_version": version, "function_count": 0, "functions": {},
                "note": "no Go pclntab found"}
    return {
        "is_go": True, "go_version": version,
        "pclntab_va": va, "pclntab_magic": parsed["magic"] if parsed else None,
        "pclntab_version_hint": parsed["version_hint"] if parsed else None,
        "function_count": len(funcs),
        "functions": {hex(k): v for k, v in sorted(funcs.items())},
    }


def _print(res: dict) -> None:
    if not res.get("is_go"):
        print("recover_go: not a Go binary" + (f" ({res.get('error')})" if res.get("error") else ""))
        return
    print(f"Go binary  version={res.get('go_version') or '?'}  "
          f"pclntab={res.get('pclntab_version_hint')}  functions={res['function_count']}")
    for va, name in list(res["functions"].items())[:20]:
        print(f"  {va}  {name}")
    if res["function_count"] > 20:
        print(f"  ... and {res['function_count'] - 20} more (--json for all)")


def _build_pclntab(funcs, text_start=0x401000):
    """Build a minimal valid 1.20+ pclntab holding `funcs` = [(entryoff, name)], for the selftest."""
    funcnametab = b"\x00"
    name_off = {}
    for _e, nm in funcs:
        name_off[nm] = len(funcnametab)
        funcnametab += nm.encode() + b"\x00"
    # layout: [72-byte header][functab: nfunc*(u32 entryoff,u32 funcoff)][func structs][funcnametab]
    header_len = 72
    functab_len = len(funcs) * 8
    funcstructs = b""
    funcoff_of = []
    for e, nm in funcs:
        funcoff_of.append(len(funcstructs))
        funcstructs += struct.pack("<Ii", e, name_off[nm]) + b"\x00" * 8   # entryoff u32, nameOff i32
    pcln_off = header_len                        # functab starts right after the header
    funcstruct_base = pcln_off + functab_len     # func structs follow the functab
    funcname_off = funcstruct_base + len(funcstructs)
    out = bytearray(b"\x00" * (header_len + functab_len))   # header + room for the functab
    struct.pack_into("<I", out, 0, 0xfffffff1)
    out[6] = 1  # minLC
    out[7] = 8  # ptrSize
    struct.pack_into("<Q", out, 8, len(funcs))      # nfunc
    struct.pack_into("<Q", out, 24, text_start)     # textStart
    struct.pack_into("<Q", out, 32, funcname_off)   # funcnameOffset
    struct.pack_into("<Q", out, 64, pcln_off)       # pclnOffset
    for i, (e, nm) in enumerate(funcs):
        # funcoff is relative to pcln_off; func structs begin functab_len after it
        struct.pack_into("<II", out, pcln_off + i * 8, e, functab_len + funcoff_of[i])
    out += funcstructs + funcnametab
    return bytes(out)


def _selftest():
    funcs = [(0x0, "main.main"), (0x40, "main.(*Config).decrypt"),
             (0x120, "runtime.main"), (0x300, "github.com/x/y.Beacon")]
    raw = _build_pclntab(funcs, text_start=0x401000)
    parsed = parse_pclntab(raw)
    assert parsed is not None and parsed["magic"] == "0xfffffff1"
    got = parsed["functions"]
    assert got.get(0x401000) == "main.main", got
    assert got.get(0x401040) == "main.(*Config).decrypt"
    assert got.get(0x401120) == "runtime.main"
    assert got.get(0x401300) == "github.com/x/y.Beacon"
    assert len(got) == 4
    # a truncated / non-Go buffer is handled without raising
    assert parse_pclntab(b"not a pclntab") is None
    assert parse_pclntab(struct.pack("<I", 0xdeadbeef) + b"\x00" * 100) is None
    # an older magic is detected but reports no functions (not parsed in this tier)
    old = bytearray(b"\x00" * 72); struct.pack_into("<I", old, 0, 0xfffffffa); old[7] = 8
    po = parse_pclntab(bytes(old))
    assert po["version_hint"] == "go1.16-1.17" and po["functions"] == {}
    print("selftest OK: 1.20+ pclntab parsed to {va: name} (main/runtime/import-path names), "
          "truncated/non-Go rejected, older magic detected-not-parsed")


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
