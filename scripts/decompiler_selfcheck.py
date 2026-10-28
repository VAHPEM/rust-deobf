#!/usr/bin/env python3
"""decompiler_selfcheck.py - check decompiler_bridge against a REAL running GhidraMCP / ida-pro-mcp.

Run it on the analysis VM with the binary already open in Ghidra (GhidraMCP plugin) or IDA
(ida-pro-mcp plugin / idalib-mcp). It opens nothing itself and never executes the binary; it reads
the binary locally (function starts, symbols, entry) and asks the decompiler about the same
functions, then prints a PASS/WARN/FAIL report:

  connect       the plugin answers; API version, program name, comment mode
  identity      the open program's sha256 equals the file's (WARN when the API reports none)
  mapping       decompiler_bridge.resolve_mapping verifies the image-base mapping on the entry
                point / function starts (the step every push depends on)
  functions     N function starts spread over .text map onto decompiler function starts (PASS at
                >= 90%); with symbols, how many names agree (informational, demangling differs)
  roundtrip     (--write-test only) write a "[rust-deobf] selfcheck <nonce>" line through the same
                merge path a push uses, read it back exactly, restore the original comment, read
                that back too. GhidraMCP: EOL comment; ida-pro-mcp: needs its py_eval tool.

    python3 scripts/decompiler_selfcheck.py sample.bin --backend ghidra-mcp
    python3 scripts/decompiler_selfcheck.py sample.bin --backend ida-mcp --write-test --json
    python3 scripts/decompiler_selfcheck.py --selftest

Exit codes: 0 no FAIL, 1 a check failed, 2 usage error, 5 decompiler unreachable / protocol error.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import decompiler_bridge as DB  # noqa: E402


def _check(name, status, detail):
    return {"check": name, "status": status, "detail": detail}


def local_functions(path: Path) -> tuple[dict, list]:
    """(layout header, [(address, symbol name or None)]) from the file, rust-deobf address space."""
    import lief
    import gen_runtime_sigs as G
    import recover
    hdr = DB.layout(path)
    b = recover._macho_slice(lief.parse(str(path)))
    names = {}
    try:
        if hdr["format"] == "PE":
            for e in b.exported_functions:
                if e.address and e.name:
                    names.setdefault(int(e.address), str(e.name))
        else:
            for s in b.symbols:                       # keep `b` alive while iterating (gotcha)
                nm = s.name if isinstance(s.name, str) else ""
                if s.value and nm and not nm.startswith("$"):
                    names.setdefault(int(s.value), nm)
    except Exception:
        pass
    starts = sorted(set(G.function_starts(b)))
    if hdr.get("entry") and hdr["entry"] not in starts:
        starts.insert(0, hdr["entry"])
    return hdr, [(a, names.get(a)) for a in starts]


def _sample(funcs: list, n: int) -> list:
    if len(funcs) <= n:
        return list(funcs)
    return [funcs[round(i * (len(funcs) - 1) / (n - 1))] for i in range(n)] if n > 1 else funcs[:1]


def _name_agrees(sym: str, dec: str | None) -> bool:
    if not dec:
        return False
    a, b = sym.lstrip("_"), dec.lstrip("_")
    return a == b or a in dec or b in sym


def _roundtrip(be, addr: int, nonce: str) -> list:
    """Write a selfcheck line via the bridge's merge path, read back, restore, read back."""
    line = f"{DB.PREFIX}selfcheck {nonce}"
    if isinstance(be, DB.GhidraMcpBackend):
        if be.comment_type != "eol":
            return [_check("roundtrip", "SKIP", "PRE comments cannot be read back through GhidraMCP")]
        orig = be._read_eol(addr)
        if orig is None:
            return [_check("roundtrip", "FAIL", f"cannot read the EOL comment at {DB._hex(addr)}")]
        merged = DB._merge_lines(orig, [line])
        st, why = be._post_comment("set_disassembly_comment", addr, merged)
        back = be._read_eol(addr)
        out = [_check("roundtrip write", "PASS" if st == "applied" and back == merged else "FAIL",
                      f"EOL at {DB._hex(addr)}: wrote {len(merged)} chars, read back "
                      f"{'identical' if back == merged else repr((back or '')[:80])} {why}".strip())]
        if orig == "" and be.api == "legacy":
            out.append(_check("roundtrip restore", "WARN", "GhidraMCP 1.x cannot clear a comment "
                              f"(empty values are dropped): remove the selfcheck line at "
                              f"{DB._hex(addr)} by hand"))
            return out
        st2, why2 = be._post_comment("set_disassembly_comment", addr, orig)
        back2 = be._read_eol(addr)
        ok = back2 == orig and (st2 == "applied" or (orig == "" and back2 == ""))
        out.append(_check("roundtrip restore", "PASS" if ok else "FAIL",
                          f"original comment {'restored' if ok else 'NOT restored: ' + repr(back2)}"))
        return out
    if not be.can_read:
        return [_check("roundtrip", "SKIP", "ida-pro-mcp offers no py_eval: comments cannot be "
                       "read back (enable it, or start idalib-mcp with --unsafe)")]
    state, _ = be.read_state([addr])
    orig = (state.get(addr) or {}).get("cmt", "")
    merged = DB._merge_lines(orig, [line])
    be._py(DB._IDA_WRITE, [[addr, "line", merged]])
    back = (be.read_state([addr])[0].get(addr) or {}).get("cmt")
    out = [_check("roundtrip write", "PASS" if back == merged else "FAIL",
                  f"line comment at {DB._hex(addr)} read back "
                  f"{'identical' if back == merged else repr((back or '')[:80])}")]
    be._py(DB._IDA_WRITE, [[addr, "line", orig]])
    back2 = (be.read_state([addr])[0].get(addr) or {}).get("cmt")
    out.append(_check("roundtrip restore", "PASS" if back2 == orig else "FAIL",
                      f"original comment {'restored' if back2 == orig else 'NOT restored'}"))
    return out


def run_checks(be, info: dict, hdr: dict, funcs: list, *, sha256=None, image_base=None, n=20,
               write_test=False) -> list:
    checks = [_check("connect", "PASS", f"{info.get('api')}, program {info.get('program')!r}"
                     + (f", comments: {info['comment_mode']}" if info.get("comment_mode") else ""))]
    dsha = info.get("sha256")
    if sha256 and dsha:
        same = sha256.lower() == str(dsha).lower()
        checks.append(_check("identity", "PASS" if same else "FAIL",
                             "sha256 matches" if same else f"open program sha256 {dsha} != file "
                             f"{sha256}: wrong program open"))
    else:
        checks.append(_check("identity", "WARN", "the decompiler reports no sha256: not checked"))
    sample = _sample(funcs, n)
    doc = {"address_space": hdr["address_space"], "address_base": DB._hex(hdr["address_base"]),
           "entry": DB._hex(hdr["entry"]) if hdr.get("entry") else None,
           "annotations": [{"address": DB._hex(a), "kind": "rename", "text": "x"} for a, _ in sample]}
    try:
        m = DB.resolve_mapping(doc, be, info, image_base=image_base)
    except DB.BridgeError as e:
        checks.append(_check("mapping", "FAIL", str(e)))
        return checks
    checks.append(_check("mapping", "PASS" if m["verified"] else "WARN",
                         f"{hdr['format']} {hdr['address_space']} + {DB._hex(m['delta'])} "
                         f"(decompiler image base {m['decompiler_image_base']}, file "
                         f"{DB._hex(hdr['file_image_base'])}); {m['how']}"))
    starts = named = agree = 0
    misses = []
    for a, sym in sample:
        fn = be.function_at(a + m["delta"])
        if fn is not None and fn[0] == a + m["delta"]:
            starts += 1
        else:
            misses.append(DB._hex(a + m["delta"]))
        if sym:
            named += 1
            agree += bool(fn and _name_agrees(sym, fn[1]))
    frac = starts / len(sample) if sample else 0.0
    st = "PASS" if frac >= 0.9 else ("WARN" if frac >= 0.5 else "FAIL")
    checks.append(_check("functions", st, f"{starts}/{len(sample)} sampled function starts are "
                         "decompiler function starts" + (f"; misses: {', '.join(misses[:5])}"
                                                         if misses else "")
                         + (f"; symbol names agree {agree}/{named}" if named else
                            "; no symbols to compare names")))
    if write_test:
        target = next((a + m["delta"] for a, _ in sample
                       if be.is_function_start(a + m["delta"])), None)
        if target is None:
            checks.append(_check("roundtrip", "FAIL", "no verified function start to write at"))
        else:
            checks.extend(_roundtrip(be, target, secrets.token_hex(4)))
    else:
        checks.append(_check("roundtrip", "SKIP", "read-only run (add --write-test)"))
    return checks


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--backend", choices=("ghidra-mcp", "ida-mcp"))
    ap.add_argument("--url")
    ap.add_argument("--image-base", type=DB._int, metavar="ADDR")
    ap.add_argument("--functions", type=int, default=20, help="function starts to sample (20)")
    ap.add_argument("--write-test", action="store_true",
                    help="also write/read back/restore one comment (changes the database briefly)")
    ap.add_argument("--ghidra-comment", choices=("eol", "pre"), default="eol")
    ap.add_argument("--ida-database", metavar="ID")
    ap.add_argument("--allow-remote", action="store_true")
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary or not a.backend:
        ap.error("a binary and --backend are required")
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    if a.functions < 1:
        ap.error("--functions must be >= 1")
    try:
        url = DB.check_url(a.url or DB.DEFAULT_URLS[a.backend], a.allow_remote)
        be = DB.make_backend(a.backend, url, rate=0, timeout=a.timeout,
                             ghidra_comment=a.ghidra_comment, ida_database=a.ida_database)
        info = be.connect()
        hdr, funcs = local_functions(path)
        checks = run_checks(be, info, hdr, funcs, sha256=DB._sha256(path),
                            image_base=a.image_base, n=a.functions, write_test=a.write_test)
    except DB.BridgeError as e:
        print(f"decompiler_selfcheck: {e}", file=sys.stderr)
        return e.code
    ok = not any(c["status"] == "FAIL" for c in checks)
    if a.json:
        print(json.dumps({"backend": a.backend, "url": url, "file": str(path), "ok": ok,
                          "checks": checks}, indent=2))
    else:
        for c in checks:
            print(f"{c['status']:4}  {c['check']:18} {c['detail']}")
        print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def _selftest():
    state = {"names": {0x140001010: "entry", 0x140002000: "FUN_140002000",
                       0x140003000: "real_name"},
             "insns": {0x140001010: [0x140001010], 0x140002000: [0x140002000, 0x140002004],
                       0x140003000: [0x140003000]},
             "eol": {0x140001010: "analyst text"}}
    srv, url = DB._selftest_ghidra_server(state)
    try:
        be = DB.make_backend("ghidra-mcp", url, rate=0)
        info = be.connect()
        hdr = {"format": "PE", "address_space": "rva", "address_base": 0,
               "file_image_base": 0x140000000, "entry": 0x1010}
        funcs = [(0x1010, None), (0x2000, None), (0x3000, "real_name")]
        checks = run_checks(be, info, hdr, funcs, write_test=True)
        got = {c["check"]: c["status"] for c in checks}
        assert got == {"connect": "PASS", "identity": "WARN", "mapping": "PASS",
                       "functions": "PASS", "roundtrip write": "PASS",
                       "roundtrip restore": "PASS"}, checks
        assert state["eol"] == {0x140001010: "analyst text"}       # restored exactly
        assert "names agree 1/1" in next(c for c in checks if c["check"] == "functions")["detail"]
        bad = run_checks(be, info, dict(hdr, entry=None), [(0x7000, None)], image_base=0x10000000)
        assert {c["check"]: c["status"] for c in bad}["mapping"] == "FAIL", bad
    finally:
        srv.shutdown()
        srv.server_close()
    print("selftest OK: connect/identity/mapping/functions checks, comment write -> read back -> "
          "restore round trip, a wrong image base reported as FAIL")


if __name__ == "__main__":
    sys.exit(main())
