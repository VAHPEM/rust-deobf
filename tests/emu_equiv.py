#!/usr/bin/env python3
"""Equivalence harness for the emulation tiers: a canonical, JSON-able dump of everything
recover_emulate / unpack_emulate (and, optionally, devirt_emulate) produce on the committed
fixtures, so a performance change can be checked to leave every output identical.

    python3 tests/emu_equiv.py dump OUT.json [--devirt]     # write the dump
    python3 tests/emu_equiv.py compare A.json B.json        # exit 1 and list the differences

What is dumped (benign_rust_std.x64, all 525 functions, one Emulator in address order, as the
pipeline reuses it): per function, a QUICK-budget run and a full-BUDGET run -- instruction count,
recovered strings, exact/used sets, branches seen, (branch, direction) pairs covered -- and the
path-exploring explore() of every decoder-scored function; then recover()'s records. For the pack
fixtures (+ the benign binary as a negative): unpack_emulate.recover() with and without --follow.
tests/test_emu_equivalence.py compares a fresh dump against the committed golden file.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "premium"))

BENIGN = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"
PACK = [ROOT / "tests" / "fixtures" / "pack" / n
        for n in ("upx_hello_pe64.exe", "upx_hello_pe32.exe", "packed_xor.elf64")]
DEVIRT = [ROOT / "tests" / "fixtures" / "vm" / n
          for n in ("rustcloak_vm.x64", "rustcloak_vm_call.x64", "rustcloak_vm_nested.x64",
                    "rustcloak_vm_obf.x64", "rustcloak_vm_rnd.x64", "rustcloak_vm_pe.exe",
                    "rustcloak_vm_arm64.so", "plain.x64")]


def _h(x) -> str:
    return hashlib.sha256(json.dumps(x, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _run_record(emu, strs):
    return {"count": emu.count, "strings": sorted(strs), "exact": sorted(emu.exact),
            "used": sorted(emu.used), "branches": len(emu.branches),
            "covered": _h(sorted(emu.covered))}


def dump_recover(path=BENIGN, explore=True):
    import recover_emulate as R
    img = R.Image(str(path))
    funcs = img.functions()
    scores = R._scores(img, funcs)
    emu = R.Emulator(img)
    try:
        emu.prime_constructors()
    except Exception:
        pass
    per = {}
    for fva, size in funcs:
        s, _, _ = emu.run(fva, size, budget=R.QUICK)
        q = _run_record(emu, s)
        s, _, _ = emu.run(fva, size)
        per[f"{fva:#x}"] = {"quick": q, "full": _run_record(emu, s)}
    if explore:
        for fva, size in funcs:
            if scores[fva] > 0:
                strs, n = emu.explore(fva, size)
                per[f"{fva:#x}"]["explore"] = {"runs": n, "strings": sorted(strs),
                                               "natural": sorted(emu.natural),
                                               "exact": sorted(emu.exact), "used": sorted(emu.used)}
    res = R.recover(str(path), [], workers=1)
    rec = {k: v for k, v in res.items() if k not in ("workers", "ram_note")}
    return {"functions": per, "recover": rec}


def dump_unpack(paths=None):
    import unpack_emulate as U
    out = {}
    for p in (paths or PACK + [BENIGN]):
        if not Path(p).is_file():
            continue
        for follow in (False, True):
            r = U.recover(str(p), follow=follow)
            r.pop("_regions", None)
            out[f"{Path(p).name} follow={follow}"] = r
    return out


def dump_devirt():
    import devirt_emulate as D
    out = {}
    for p in DEVIRT:
        if Path(p).is_file():
            r = D.recover_all(str(p))
            if isinstance(r, dict) and "file" in r:      # an absolute path: differs per checkout
                r = dict(r, file=Path(r["file"]).name)
            out[Path(p).name] = r
    return out


def dump(devirt=False, explore=True):
    import unicorn
    d = {"unicorn": unicorn.__version__, "recover_emulate": dump_recover(explore=explore),
         "unpack_emulate": dump_unpack()}
    if devirt:
        d["devirt_emulate"] = dump_devirt()
    # normalise through JSON (tuples -> lists, int keys -> str) so a dump compares equal to a load
    return json.loads(json.dumps(d, sort_keys=True, default=str))


def diff(a, b, path="", out=None, limit=40):
    """Paths at which two dumps differ (at most `limit`)."""
    out = [] if out is None else out
    if len(out) >= limit:
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b:
                out.append(f"{path}/{k}: only in {'B' if k not in a else 'A'}")
            else:
                diff(a[k], b[k], f"{path}/{k}", out, limit)
    elif a != b:
        out.append(f"{path}: {str(a)[:120]} != {str(b)[:120]}")
    return out


def load(p):
    p = Path(p)
    op = gzip.open if p.suffix == ".gz" else open
    with op(p, "rt") as f:
        return json.load(f)


def save(d, p):
    p = Path(p)
    op = gzip.open if p.suffix == ".gz" else open
    with op(p, "wt") as f:
        json.dump(d, f, sort_keys=True, separators=(",", ":"))


def main(argv=None):
    a = sys.argv[1:] if argv is None else argv
    if len(a) >= 2 and a[0] == "dump":
        save(dump(devirt="--devirt" in a), a[1])
        return 0
    if len(a) == 3 and a[0] == "compare":
        A, B = load(a[1]), load(a[2])
        A.pop("unicorn", None), B.pop("unicorn", None)
        d = diff(A, B)
        print("\n".join(d) if d else "identical")
        return 1 if d else 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
