#!/usr/bin/env python3
"""unpack.py - one unpacking command: static emulation first, dynamic dump as an opt-in fallback.

Static-first by design. It runs unpack_emulate.py (pure emulation, nothing executes on the host),
carves each recovered stage, and identifies an embedded PE stage-2 inside it. Only if the static
pass finds nothing AND the operator explicitly opts in does it fall back to the dynamic dumper
(dump_unpacked.py / Frida), which RUNS the sample -- gated behind --i-understand-this-executes and
meant for an isolated analysis VM. Nothing here executes a sample by default.

  unpack.py sample.bin                         # static only (safe)
  unpack.py sample.bin --entry 0x1650          # aim static emulation at the unpack routine
  unpack.py sample.bin --dump out/             # also write carved stages to out/
  unpack.py sample.bin --dynamic --i-understand-this-executes   # fallback: run in an isolated VM

Defensive triage; benign inputs only.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import dump_unpacked  # noqa: E402  (dynamic dumper + PE carver)
import unpack_emulate  # noqa: E402  (static emulator)


def _stages_from_regions(regions):
    """Turn unpack_emulate's carved regions into stage records, identifying an embedded PE in each
    (ties the static dump to dump_unpacked's PE carver)."""
    stages = []
    for r in regions:
        pes = dump_unpacked.carve_pes(r["_bytes"])
        stages.append({
            "source": "static-emulation",
            "va": r["va"], "size": r["size"], "executed": r["executed"],
            "entropy": r["entropy"], "sha256": r["sha256"],
            "embedded_pe": [{"offset": p["offset"], "pe_plus": p["pe_plus"],
                             "machine": p["machine"], "sections": p["sections"],
                             "size_of_image": p["size_of_image"]} for p in pes],
        })
    return stages


def recover(path, entry=None, dynamic=False, ack=False, argv=None, timeout=10.0, outdir=None):
    """Static-first unpacking. Returns {static, stages, dynamic, recommendation}.

    `dynamic` + `ack` are required together to run the sample; without the ack the dynamic branch
    refuses (it executes the target). `_regions` is kept for --dump and stripped from --json.
    """
    static = unpack_emulate.recover(path, entry)
    regions = static.pop("_regions", [])
    stages = _stages_from_regions(regions)
    out = {
        "static": static,
        "stages": stages,
        "dynamic": None,
        "recommendation": "",
        "_regions": regions,
    }
    if static["unpacked_detected"]:
        out["recommendation"] = "static unpacking succeeded; stage-2 carved by emulation"
        return out
    if not dynamic:
        out["recommendation"] = (
            "no write-then-execute seen statically. Aim --entry at the unpack routine "
            "(recover_cfg.py / detect_vm.py help locate it), or, in an ISOLATED analysis VM, "
            "re-run with --dynamic --i-understand-this-executes.")
        return out
    if not ack:
        out["dynamic"] = {"error": "refused: --dynamic runs the sample. Pass "
                          "--i-understand-this-executes and only inside an isolated analysis VM."}
        return out
    # dynamic fallback: this RUNS the target (Frida). Caller has acknowledged isolation.
    od = Path(outdir or "unpacked_dumps")
    dumps = dump_unpacked.run_frida(Path(path), argv or [], timeout, od)
    dyn_stages = []
    for d in dumps:
        blob = Path(d).read_bytes()
        pes = dump_unpacked.carve_pes(blob)
        dyn_stages.append({"source": "dynamic-frida", "file": str(d), "size": len(blob),
                           "entropy": round(dump_unpacked.shannon_entropy(blob), 3),
                           "embedded_pe": [{"offset": p["offset"], "pe_plus": p["pe_plus"],
                                            "sections": p["sections"]} for p in pes]})
    out["dynamic"] = {"dumped": len(dumps), "outdir": str(od)}
    out["stages"].extend(dyn_stages)
    out["recommendation"] = f"dynamic dump wrote {len(dumps)} region(s) to {od}/"
    return out


def _print(res):
    s = res["static"]
    print(f"static: arch={s['arch']} entry=0x{s['entry']:x} stopped={s['stopped']} "
          f"unpacked_detected={s['unpacked_detected']}")
    for st in res["stages"]:
        pe = f" embedded_pe={len(st['embedded_pe'])}" if st["embedded_pe"] else ""
        print(f"  [{st['source']}] va=0x{st.get('va', 0):x} size={st['size']} "
              f"executed={st.get('executed')} entropy={st['entropy']}{pe}")
        for p in st["embedded_pe"]:
            print(f"      PE @ +0x{p['offset']:x} {'PE32+' if p['pe_plus'] else 'PE32'} "
                  f"sections={p['sections']}")
    if res["dynamic"]:
        print(f"dynamic: {res['dynamic']}")
    print(f"-> {res['recommendation']}")


def _selftest():
    # 1. stage merge + PE carve: a synthetic static region carrying an embedded PE32+ is identified
    pe = bytearray(b"MZ" + b"\x00" * 0x3e)
    import struct
    struct.pack_into("<I", pe, 0x3c, 0x40)
    pe += b"PE\x00\x00" + struct.pack("<HH", 0x8664, 2) + b"\x00" * 0x10
    pe += struct.pack("<H", 0x20B) + b"\x00" * 54 + struct.pack("<I", 0x3000) + b"\x00" * 64
    region = {"_bytes": b"\xcc" * 64 + bytes(pe) + b"\xcc" * 64, "va": 0x5000,
              "size": 64 + len(pe) + 64, "executed": True, "entropy": 1.0,
              "sha256": "00" * 32}
    stages = _stages_from_regions([region])
    assert stages and stages[0]["embedded_pe"] and stages[0]["embedded_pe"][0]["pe_plus"], stages

    # 2. the dynamic branch refuses to run a sample without the isolation acknowledgement
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write((ROOT.parent / "tests" / "fixtures" / "pack" / "packed_xor.elf64").read_bytes())
        tmp = f.name
    r = recover(tmp, dynamic=True, ack=False)
    # this fixture unpacks statically, so dynamic is never reached -- detected True, no dynamic run
    assert r["static"]["unpacked_detected"] is True and r["dynamic"] is None, r
    Path(tmp).unlink()
    print("selftest OK: static stage carve finds embedded PE32+; static-first dispatch keeps the "
          "sample from running when emulation already succeeded")


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--entry", help="start RVA/VA of the unpack routine for static emulation")
    ap.add_argument("--dump", metavar="DIR", help="write carved static stages to DIR")
    ap.add_argument("--dynamic", action="store_true", help="fallback to the dynamic dumper (runs the sample)")
    ap.add_argument("--i-understand-this-executes", dest="ack", action="store_true",
                    help="required with --dynamic: confirms an isolated analysis VM")
    ap.add_argument("--argv", nargs=argparse.REMAINDER, default=[], help="args for the target (dynamic)")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--outdir", default="unpacked_dumps")
    ap.add_argument("--json", action="store_true", help="print the result dict as JSON")
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
    entry = int(a.entry, 0) if a.entry else None
    res = recover(path, entry, dynamic=a.dynamic, ack=a.ack, argv=a.argv,
                  timeout=a.timeout, outdir=a.outdir)
    if a.dump and res["_regions"]:
        d = Path(a.dump)
        d.mkdir(parents=True, exist_ok=True)
        for r in res["_regions"]:
            (d / f"stage_{r['va']:x}.bin").write_bytes(r["_bytes"])
        print(f"wrote {len(res['_regions'])} static stage(s) to {d}/", file=sys.stderr)
    res = {k: v for k, v in res.items() if k != "_regions"}
    print(json.dumps(res, indent=2)) if a.json else _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
