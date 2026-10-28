#!/usr/bin/env python3
"""recover_go.py - recover Go function names from the pclntab, the Go analog of the Rust metadata tier.

Go binaries carry a rich symbol table, the `pclntab`, that the runtime needs for panics and stack
traces -- and it survives `strip`, because stripping only removes the ELF/Mach-O symbol table, not
the pclntab the runtime reads at run time. So a "stripped" Go malware sample still names every one of
its functions (`main.beacon`, `main.(*Config).decrypt`, ...). This parses the pclntab back to
`{entry VA: function name}`, the Go counterpart of what recover_rust_meta does for Rust (metadata
that survives strip), and reports the Go toolchain version for provenance.

Parses every pclntab layout since Go 1.2 (magics 0xfffffffb 1.2-1.15, 0xfffffffa 1.16-1.17,
0xfffffff0 1.18-1.19, 0xfffffff1 1.20+) at either pointer size (GOARCH=386/arm use 4-byte header
fields). Finds the table by section (`.gopclntab` / `__gopclntab`) or by scanning whole sections for
its magic (PE Go binaries carry it unnamed in `.rdata`). Addresses are RVAs for PE, VAs otherwise.

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
_V12, _V116, _V118, _V120 = 0xfffffffb, 0xfffffffa, 0xfffffff0, 0xfffffff1
# A `go1.N[.M]` toolchain string, anchored on the left so `algo1.5`/`cargo1.2` do not count.
_GO_VER = re.compile(rb"(?<![A-Za-z0-9_.])go1\.\d{1,2}(?:\.\d{1,2})?(?![0-9])")
_MAX_FUNCS = 2_000_000
_MAX_NAME = 1024              # a function name is read at most this many bytes (crafted-table DoS)


def _header_ok(raw: bytes, off: int) -> bool:
    """Cheap structural check of a pclntab header at `raw[off:]` (any supported version)."""
    if off < 0 or off + 8 > len(raw):
        return False
    return (struct.unpack_from("<I", raw, off)[0] in _MAGICS and raw[off + 4:off + 6] == b"\0\0"
            and raw[off + 6] in (1, 2, 4) and raw[off + 7] in (4, 8))


def find_pclntab(b):
    """(virtual_address, raw_bytes, named) of the pclntab, or (None, None, False). `named` is True
    when it came from a `.gopclntab`/`__gopclntab` section (a strong Go signal) rather than a magic
    scan (which can match by chance in a non-Go binary). The address is lief's section address, i.e.
    an RVA for PE and a VA for ELF/Mach-O."""
    for name in (".gopclntab", "__gopclntab"):
        s = next((x for x in b.sections if x.name == name), None)
        if s is not None:
            return s.virtual_address, bytes(s.content), True
    # Scan every section, whole length, for a pclntab magic (PE: unnamed inside .rdata, which in a
    # large binary sits well past the first MB). A candidate must pass the header check AND parse
    # into at least one function; otherwise keep scanning past it.
    pats = [struct.pack("<I", m) + b"\0\0" for m in _MAGICS]
    for s in b.sections:
        try:
            raw = bytes(s.content)
        except Exception:
            continue
        cands = []
        for pat in pats:
            i = raw.find(pat)
            while i != -1:
                if i % 4 == 0 and _header_ok(raw, i):
                    cands.append(i)
                i = raw.find(pat, i + 1)
        for off in sorted(cands)[:64]:          # bound work on a crafted section full of magics
            parsed = parse_pclntab(raw[off:])
            if parsed and parsed["functions"]:
                return s.virtual_address + off, raw[off:], False
    return None, None, False


def _layout(magic: int, ptr: int):
    """Per-version pclntab layout: (header_len, fields) where `fields` maps name -> header offset.

    go1.2-1.15 : magic,pad,minLC,ptr | nfunc | functab[(entry uintptr, funcoff uintptr)] inline
    go1.16-1.17: ... | nfunc | nfiles | funcnameOff | cuOff | filetabOff | pctabOff | pclnOff
    go1.18+    : ... | nfunc | nfiles | textStart | funcnameOff | cuOff | filetabOff | pctabOff | pclnOff
    (each field after the 8-byte prefix is pointer-sized; GOARCH=386/arm put 4 there, not 8)."""
    if magic == _V12:
        return 8 + ptr, {"nfunc": 8}
    if magic == _V116:
        return 8 + 7 * ptr, {"nfunc": 8, "funcname": 8 + 2 * ptr, "pcln": 8 + 6 * ptr}
    return 8 + 8 * ptr, {"nfunc": 8, "text": 8 + 2 * ptr, "funcname": 8 + 3 * ptr,
                         "pcln": 8 + 7 * ptr}


def parse_pclntab(raw: bytes, text_start=None):
    """Return {"magic", "version_hint", "functions": {entry_va: name}} for a Go pclntab (1.2, 1.16,
    1.18, 1.20+ layouts, pointer size 4 or 8), or None if `raw` does not start with one. For 1.18+
    `text_start` overrides the header's textStart (a PIE whose field is 0 in the file, filled by a
    dynamic relocation). Bounded against crafted tables: nfunc must fit the table, a name is read
    at most _MAX_NAME bytes, repeated name offsets are decoded once, and the total decoded name
    bytes are capped relative to the table size."""
    if raw is None or len(raw) < 16 or not _header_ok(raw, 0):
        return None
    magic = struct.unpack_from("<I", raw, 0)[0]
    ptr = raw[7]
    info = {"magic": hex(magic), "version_hint": _MAGICS[magic], "ptr_size": ptr, "functions": {}}
    hlen, f = _layout(magic, ptr)
    if len(raw) < hlen:
        return info
    pfmt = "<Q" if ptr == 8 else "<I"
    up = lambda o: struct.unpack_from(pfmt, raw, o)[0]
    u32 = lambda o: struct.unpack_from("<I", raw, o)[0]
    i32 = lambda o: struct.unpack_from("<i", raw, o)[0]
    try:
        nfunc = up(f["nfunc"])
        if magic == _V12:
            functab, ent, names_base, fbase = 8 + ptr, 2 * ptr, 0, 0
        else:
            functab = fbase = up(f["pcln"])
            names_base = up(f["funcname"])
            ent = 8 if magic in (_V118, _V120) else 2 * ptr
        tstart = 0
        if magic in (_V118, _V120):
            tstart = up(f["text"]) if text_start is None else text_start
    except struct.error:
        return info
    # nfunc must be positive and its functab must lie inside the table (bounds a crafted count)
    if not (0 < nfunc <= _MAX_FUNCS) or functab < hlen or functab + nfunc * ent > len(raw) \
            or names_base >= len(raw):
        return info
    info["nfunc"] = nfunc

    memo = {}
    budget = [2 * len(raw) + (1 << 20)]       # total distinct name bytes; a real table is < len(raw)

    def cstr(o):
        if o in memo:
            return memo[o]
        if o < 0 or o >= len(raw) or budget[0] <= 0:
            return ""
        end = raw.find(b"\x00", o, o + _MAX_NAME)
        chunk = raw[o:end if end != -1 else min(len(raw), o + _MAX_NAME)]
        budget[0] -= len(chunk) + 1
        name = chunk.decode("utf-8", "replace")
        memo[o] = name
        return name

    funcs = {}
    for i in range(nfunc):
        base = functab + i * ent
        if magic in (_V118, _V120):
            entry = tstart + u32(base)
            fstruct = fbase + u32(base + 4)
            noff = fstruct + 4                       # _func{entryOff u32; nameOff i32}
        else:
            entry = up(base)
            fstruct = fbase + up(base + ptr)
            noff = fstruct + ptr                     # _func{entry uintptr; nameoff i32}
        if noff + 4 > len(raw):
            continue
        name = cstr(names_base + i32(noff))
        if budget[0] <= 0:
            info["truncated"] = True
            break
        if name:
            funcs[entry] = name
    info["functions"] = funcs
    # the functab ends with one extra entry: the end PC of the last function (= runtime.etext), so
    # a consumer can tell Go text from C code linked around it (cgo / external linking)
    endb = functab + nfunc * ent
    if endb + ent <= len(raw):
        info["text_end"] = tstart + u32(endb) if magic in (_V118, _V120) else up(endb)
    return info


def _text_start_reloc(b, va):
    """The textStart value a dynamic relocation writes at `va` (an external-linked PIE stores 0 in
    the file and relies on R_*_RELATIVE), or None."""
    try:
        for r in b.relocations:
            if getattr(r, "address", None) == va:
                ad = getattr(r, "addend", 0) or 0
                return ad or None
    except Exception:
        pass
    return None


def recover(path) -> dict:
    """{is_go, go_version, pclntab_va, function_count, functions{addr: name}, ...}. Addresses follow
    the toolkit convention: RVAs for PE (add `imagebase` to rebase), VAs for ELF / Mach-O."""
    import lief
    b = lief.parse(str(path))
    if b is None:
        return {"is_go": False, "error": "unparseable"}
    data = Path(path).read_bytes()
    ver = _GO_VER.search(data)
    version = ver.group().decode() if ver else None
    pe = b.format.name == "PE"
    imagebase = b.optional_header.imagebase if pe else 0
    try:
        va, raw, named = find_pclntab(b)
        parsed = parse_pclntab(raw) if raw is not None else None
        if parsed and not pe and parsed["magic"] in (hex(_V118), hex(_V120)):
            # an external-linked PIE stores textStart as 0 in the file (a RELATIVE relocation
            # fills it at load); take the relocation's addend so entries are real VAs
            ptr = parsed["ptr_size"]
            if struct.unpack_from("<Q" if ptr == 8 else "<I", raw, 8 + 2 * ptr)[0] == 0:
                ts = _text_start_reloc(b, va + 8 + 2 * ptr)
                if ts:
                    parsed = parse_pclntab(raw, text_start=ts)
    except Exception:
        va, raw, named, parsed = None, None, False, None
    funcs = parsed["functions"] if parsed else {}
    text_end = parsed.get("text_end") if parsed else None
    if pe and funcs:
        # the pclntab stores absolute VAs (textStart / entry); report RVAs like the rest of the
        # toolkit (lief section addresses, recover_imports, recover_cfg are RVA-based for PE)
        funcs = {k - imagebase if k >= imagebase else k: v for k, v in funcs.items()}
        if text_end is not None and text_end >= imagebase:
            text_end -= imagebase
    # Go only on strong evidence: a named pclntab section, a `go1.x` version string, or a scan-found
    # table that parsed into a substantial set of Go-shaped names -- so a chance magic match in a
    # non-Go binary is not reported as Go.
    go_shaped = sum(1 for n in funcs.values() if "." in n)
    is_go = bool(named or version or (len(funcs) >= 8 and go_shaped >= len(funcs) // 2))
    if not is_go:
        return {"is_go": False, "go_version": version, "function_count": 0, "functions": {},
                "note": "no Go pclntab found"}
    out = {
        "is_go": True, "go_version": version,
        "address_space": "rva" if pe else "va", "imagebase": imagebase,
        "pclntab_va": va, "pclntab_magic": parsed["magic"] if parsed else None,
        "pclntab_version_hint": parsed["version_hint"] if parsed else None,
        "function_count": len(funcs),
        "functions": {hex(k): v for k, v in sorted(funcs.items())},
    }
    if funcs and text_end is not None and text_end > min(funcs):
        out["text_end"] = hex(text_end)
    if parsed and parsed.get("truncated"):
        out["truncated"] = True
    return out


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


def _build_pclntab(funcs, text_start=0x401000, magic=_V120, ptr=8):
    """Build a minimal valid pclntab of version `magic` and pointer size `ptr` holding `funcs` =
    [(entryoff, name)], for the selftest / tests. Entries are text_start + entryoff."""
    pk = "<Q" if ptr == 8 else "<I"
    funcnametab = b"\x00"
    name_off = {}
    for _e, nm in funcs:
        name_off.setdefault(nm, len(funcnametab))
        if name_off[nm] == len(funcnametab):
            funcnametab += nm.encode() + b"\x00"
    hlen, f = _layout(magic, ptr)
    out = bytearray(hlen)
    struct.pack_into("<I", out, 0, magic)
    out[6], out[7] = 1, ptr
    struct.pack_into(pk, out, 8, len(funcs))
    if magic == _V12:
        # inline functab of (entry, funcoff) uintptr pairs + end pc; _func{entry; nameoff i32}
        # with nameoff relative to the table start, so the names go into the same buffer
        ftab_len = (2 * len(funcs) + 1) * ptr
        fs_base = hlen + ftab_len
        fsz = ptr + 4
        names_base = fs_base + fsz * len(funcs)
        out += b"\x00" * ftab_len
        for i, (e, nm) in enumerate(funcs):
            struct.pack_into(pk, out, hlen + 2 * i * ptr, text_start + e)
            struct.pack_into(pk, out, hlen + 2 * i * ptr + ptr, fs_base + fsz * i)
        struct.pack_into(pk, out, hlen + 2 * len(funcs) * ptr, text_start + funcs[-1][0] + 0x10)
        for e, nm in funcs:
            out += struct.pack(pk, text_start + e) + struct.pack("<i", names_base + name_off[nm])
        return bytes(out + funcnametab)
    new = magic in (_V118, _V120)
    ent = 8 if new else 2 * ptr
    pcln = hlen
    ftab_len = len(funcs) * ent + ent
    fsz = (8 if new else ptr + 4)
    fnames = pcln + ftab_len + fsz * len(funcs)
    struct.pack_into(pk, out, f["funcname"], fnames)
    struct.pack_into(pk, out, f["pcln"], pcln)
    if new:
        struct.pack_into(pk, out, f["text"], text_start)
    out += b"\x00" * ftab_len
    for i, (e, nm) in enumerate(funcs):
        foff = ftab_len + fsz * i                    # relative to pcln
        if new:
            struct.pack_into("<II", out, pcln + i * ent, e, foff)
        else:
            struct.pack_into(pk, out, pcln + i * ent, text_start + e)
            struct.pack_into(pk, out, pcln + i * ent + ptr, foff)
    end = funcs[-1][0] + 0x10                          # the functab's trailing end-PC entry
    if new:
        struct.pack_into("<I", out, pcln + len(funcs) * ent, end)
    else:
        struct.pack_into(pk, out, pcln + len(funcs) * ent, text_start + end)
    for e, nm in funcs:
        out += (struct.pack("<Ii", e, name_off[nm]) if new
                else struct.pack(pk, text_start + e) + struct.pack("<i", name_off[nm]))
    return bytes(out + funcnametab)


def _selftest():
    funcs = [(0x0, "main.main"), (0x40, "main.(*Config).decrypt"),
             (0x120, "runtime.main"), (0x300, "github.com/x/y.Beacon")]
    for magic in (_V12, _V116, _V118, _V120):
        for ptr, ts in ((8, 0x401000), (4, 0x8049000)):
            parsed = parse_pclntab(_build_pclntab(funcs, text_start=ts, magic=magic, ptr=ptr))
            assert parsed is not None and parsed["magic"] == hex(magic), (magic, ptr)
            got = parsed["functions"]
            want = {ts + e: n for e, n in funcs}
            assert got == want, (hex(magic), ptr, got)
            assert parsed["text_end"] == ts + funcs[-1][0] + 0x10, (hex(magic), ptr)
    # a truncated / non-Go buffer is handled without raising
    assert parse_pclntab(b"not a pclntab") is None
    assert parse_pclntab(struct.pack("<I", 0xdeadbeef) + b"\x00" * 100) is None
    # nfunc larger than the table can hold is rejected, not iterated
    big = bytearray(_build_pclntab(funcs)); struct.pack_into("<Q", big, 8, 1_000_000)
    assert parse_pclntab(bytes(big))["functions"] == {}
    # the version regex needs a left boundary
    assert _GO_VER.search(b"algo1.5") is None and _GO_VER.search(b"\x00go1.22.4\x00")
    print("selftest OK: pclntab 1.2/1.16/1.18/1.20+ x ptr 4/8 parsed to {va: name}, "
          "truncated/non-Go/oversized-nfunc rejected, go-version regex anchored")


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
