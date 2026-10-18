#!/usr/bin/env python3
"""Baseline evaluation: how many ground-truth canaries can strings(1) and FLOSS recover?

For each built binary we run:
  - strings(1)  : the naive floor
  - FLOSS       : static + stack + tight + decoded string recovery (Mandiant), with
                  --language rust so its Rust-aware plain-string pass is active

A canary counts as recovered if its exact text appears anywhere in the tool's output.
We report per-(obfuscator, format, profile, strip) canary recall. This is the number
that decides whether the "Rust is an open gap" claim holds up empirically.
"""
from __future__ import annotations
import json, subprocess, sys, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / "build"
MAN = json.loads((ROOT / "bench_src" / "manifest.json").read_text())
CANARIES = MAN["canaries"]
FLOSS = "/opt/flossenv/bin/floss"

# cryptify dropped: with a custom key it does not round-trip to the original string
# at runtime, so its canaries are not ground truth. (Its own README example silently
# drops a comma: encrypt_string!("Hello, World!") -> "Hello World!".)
SKIP = {"cryptify"}

def recovered(text: str) -> int:
    return sum(1 for c in CANARIES if c in text)

def run_strings(path: Path) -> str:
    out = []
    for enc in ("-n", "-el"):
        try:
            if enc == "-n":
                out.append(subprocess.run(["strings","-n","6",str(path)],capture_output=True,text=True,timeout=120).stdout)
            else:
                out.append(subprocess.run(["strings","-el","-n","6",str(path)],capture_output=True,text=True,timeout=120).stdout)
        except Exception as e:
            out.append("")
    return "\n".join(out)

def run_floss(path: Path, fmt: str) -> tuple[str,bool,str]:
    cmd = [FLOSS, "--language", "rust", "-j", str(path)]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
        if p.returncode != 0:
            # retry without rust language pass
            p2 = subprocess.run([FLOSS,"-j",str(path)],capture_output=True,text=True,timeout=1200)
            return p2.stdout, p2.returncode==0, (p.stderr[-300:] or p2.stderr[-300:])
        return p.stdout, True, ""
    except subprocess.TimeoutExpired:
        return "", False, "TIMEOUT(1200s)"
    except Exception as e:
        return "", False, str(e)[:300]

def main():
    rows = []
    bins = sorted(BUILD.glob("*"))
    bins = [b for b in bins if b.is_file() and not b.name.endswith(".jsonl") and b.name.split("__")[0] not in SKIP]
    for i, b in enumerate(bins, 1):
        proj, fmt, profile, striptail = b.name.split("__")
        strip = striptail.replace(".exe","")
        s_out = run_strings(b)
        s_rec = recovered(s_out)
        f_out, f_ok, f_err = run_floss(b, fmt)
        f_rec = recovered(f_out)
        rows.append({"proj":proj,"fmt":fmt,"profile":profile,"strip":strip,
                     "strings_recall":s_rec,"floss_recall":f_rec,"floss_ok":f_ok,
                     "floss_err":f_err,"n_canary":len(CANARIES)})
        print(f"[{i:2}/{len(bins)}] {b.name:<40} strings {s_rec}/5  floss {f_rec}/5" + (f"  ERR {f_err}" if not f_ok else ""), flush=True)
    (ROOT/"build"/"floss_results.jsonl").write_text("\n".join(json.dumps(r) for r in rows)+"\n")
    print("\nwrote build/floss_results.jsonl")

if __name__ == "__main__":
    main()
