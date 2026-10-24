#!/usr/bin/env python3
"""recover.py - unified string-recovery front end for Rust binaries.

Detects the binary's architecture and format, then runs the recoverers that apply:

  1. static call-site recovery  - keyed decoders (hand-rolled XOR/ADD/SUB, litcrypt, litcrypt2)
                                  x86-64 ELF/PE: recover_callsite.py   AArch64 ELF: recover_arm64.py
                                  cryptify: recover_cryptify.py (default key; a custom key is
                                  runtime-only and is reported as such)
  2. emulation                  - every decoder the static pass cannot read: recover_emulate.py
                                  (Unicorn; real calls, heap, relocations, path exploration).
                                  Runs by default (`--emulate always`), bounded by
                                  --time-budget; `--emulate auto` only when the static pass
                                  found nothing, `--emulate never` skips it.
  3. static stack strings       - immediates stored to the frame: recover_stackstrings.py
  4. Rust literals              - the plain, unobfuscated &str literals split out of the packed
                                  string section: recover_rust_strings.py (FLOSS's "language
                                  strings"); only those that look like indicators are printed
                                  unless --literals is given
  5. the hard cases (AEAD, runtime-only decoders) need recover_dynamic.py in a sandbox; the
     output says so when nothing else was found.

None of these execute the sample natively: the static passes only disassemble it and emulation
runs single functions inside Unicorn with external calls stubbed.

    python scripts/recover.py <binary>
    python scripts/recover.py <binary> --json                 # machine-readable records
    python scripts/recover.py <binary> --floss-json out.json  # a FLOSS results document:
                                                              #   floss out.json / floss --html out.json
    python scripts/recover.py <binary> --time-budget 300         # emulate longer (big binaries)
    python scripts/recover.py <binary> --emulate never           # static passes only, seconds
    python scripts/recover.py samples/ --jsonl triage.jsonl    # every binary under a directory
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lief


def _macho_slice(b):
    """A universal (fat) Mach-O parses to several slices; pick one (prefer x86-64, else the
    first). lief may already return a single Binary for a fat file, in which case pass through."""
    if hasattr(b, "sections") or not hasattr(b, "__iter__"):
        return b
    try:
        slices = list(b)
    except TypeError:
        return b
    if not slices:
        return b
    for s in slices:
        if "X86_64" in str(getattr(s.header, "cpu_type", "")).upper():
            return s
    return slices[0]


def detect(path):
    b = lief.parse(str(path))
    if b is None:
        return None, None, 0
    fmt = b.format.name if hasattr(b, "format") else "?"
    if fmt == "MACHO" or b.__class__.__name__ in ("FatBinary", "Binary") and not hasattr(b, "optional_header") and not hasattr(b, "sections"):
        b = _macho_slice(b)
        fmt = b.format.name if hasattr(b, "format") else fmt
    arch = "?"
    try:
        hdr = b.header
        # ELF/PE expose machine_type/machine; Mach-O exposes cpu_type
        cand = ""
        for attr in ("machine_type", "cpu_type", "machine"):
            if hasattr(hdr, attr):
                v = getattr(hdr, attr)
                cand = (v.name if hasattr(v, "name") else str(v)).upper()
                break
        if "AARCH64" in cand or "ARM64" in cand:
            arch = "aarch64"
        elif "X86_64" in cand or "AMD64" in cand or "86_64" in cand:
            arch = "x86_64"
        elif "I386" in cand or "80386" in cand or ("X86" in cand and "64" not in cand) or "INTEL" in cand:
            arch = "x86"                     # 32-bit x86
        elif "ARM" in cand:
            arch = "arm"
    except Exception:
        pass
    imagebase = 0
    if fmt == "PE":
        try:
            imagebase = b.optional_header.imagebase
        except Exception:
            pass
    return fmt, arch, imagebase


def _parse_size_mb(text: str) -> int:
    """Parse a RAM size to whole MB: '' -> 0 (no limit), '2048' -> 2048, '4G'/'4g' -> 4096,
    '512M' -> 512. Raises ValueError on anything else."""
    text = text.strip()
    if not text:
        return 0
    mult, num = 1, text
    if text[-1] in "gG":
        mult, num = 1024, text[:-1]
    elif text[-1] in "mM":
        mult, num = 1, text[:-1]
    try:
        val = float(num) * mult
    except ValueError:
        raise ValueError(f"--max-ram: cannot parse {text!r} (use e.g. 4G or 2048)")
    if val < 1:
        raise ValueError("--max-ram must be at least 1 MB")
    return int(val)


def run(path: Path, emulate: str = "always", stackstrings: bool = True, min_len: int = 6,
        time_budget: float = 120.0, max_funcs: int = 0, literals: bool = True,
        max_ram_mb: int = 0, libfuncs: bool = False) -> dict:
    """Run the applicable recoverers and return {"format", "arch", "decoded", "stack", ...}."""
    fmt, arch, imagebase = detect(path)
    result = {"file": str(path), "format": fmt, "arch": arch, "imagebase": imagebase,
              "decoded": [], "stack": [], "literals": [], "literals_missed": [],
              "libfuncs": [], "engines": [], "notes": []}
    # The emulation engine loads ELF, PE and Mach-O on x86-64, AArch64 and 32-bit x86. The static
    # call-site recoverers, cryptify, stack-strings and libfuncs are ELF/PE x86-64/AArch64 only;
    # elsewhere (32-bit x86, Mach-O) only emulation + literals run.
    emu_ok = fmt in ("ELF", "PE", "MACHO") and arch in ("x86_64", "aarch64", "x86")
    static_ok = fmt in ("ELF", "PE") and arch in ("x86_64", "aarch64")
    static_records = []
    if not emu_ok:
        result["notes"].append(
            f"the emulation engine supports ELF/PE/Mach-O on x86-64/aarch64/x86 (this is "
            f"{fmt}/{arch}): skipped. Literal recovery still runs; for strings also try "
            f"recover_rust_meta.py (crates, panic sites — works here) and, in a VM, "
            f"recover_dynamic.py.")
    elif not static_ok:
        result["notes"].append(
            f"{fmt}/{arch}: static call-site recovery is ELF/PE x86-64/aarch64 only; strings come "
            "from emulation and literal recovery here.")

    if static_ok:
        t0 = time.monotonic()
        if arch == "x86_64":
            import recover_callsite as R
            engine = "static x86-64 (recover_callsite)"
        else:
            import recover_arm64 as R
            engine = "static aarch64 (recover_arm64)"
        r = R.recover(path, [])
        static_records = [x for x in r.get("records", []) if len(x["string"]) >= min_len]
        result["decoded"].extend(static_records)
        result["engines"].append({"engine": engine, "decoders": r.get("decoders", 0),
                                  "strings": len(static_records), "seconds": round(time.monotonic() - t0, 1)})

        import recover_cryptify as C
        t0 = time.monotonic()
        c = C.recover(path)
        if c["cryptify"]:
            known = {x["string"] for x in result["decoded"]}
            crypt = [x for x in c["records"] if len(x["string"]) >= min_len and x["string"] not in known]
            result["decoded"].extend(crypt)
            static_records += crypt
            result["engines"].append({"engine": "cryptify (recover_cryptify)", "strings": len(crypt),
                                      "seconds": round(time.monotonic() - t0, 1)})
            if c["note"]:
                result["notes"].append(c["note"])

    if emu_ok and (emulate == "always" or (emulate == "auto" and not static_records)):
        import recover_emulate as E
        t0 = time.monotonic()
        e = E.recover(path, [], max_funcs=max_funcs, time_budget=time_budget, max_ram_mb=max_ram_mb)
        known = {x["string"] for x in result["decoded"]}
        emu = [x for x in e.get("records", []) if len(x["string"]) >= min_len and x["string"] not in known]
        result["decoded"].extend(emu)
        result["engines"].append({"engine": "emulation (recover_emulate)", "strings": len(emu),
                                  "functions": f'{e.get("functions_tried", 0)}/{e.get("functions_total", 0)}',
                                  "timed_out": e.get("timed_out", False),
                                  "workers": e.get("workers", 1),
                                  "seconds": round(time.monotonic() - t0, 1)})
        if e.get("timed_out"):
            result["notes"].append("emulation stopped at --time-budget; raise it to try more functions")
        if e.get("ram_note"):
            result["notes"].append(e["ram_note"])

    if stackstrings and static_ok:
        import recover_stackstrings as S
        t0 = time.monotonic()
        s = S.recover(path, min_len=min_len)
        result["stack"] = s.get("records", [])
        result["engines"].append({"engine": "static stack strings (recover_stackstrings)",
                                  "strings": len(result["stack"]), "seconds": round(time.monotonic() - t0, 1)})

    if literals:
        import recover_rust_strings as L
        t0 = time.monotonic()
        lit = L.recover(path, min_len=min_len)
        result["literals"] = lit["strings"]
        result["literals_missed"] = lit["missed"]
        result["engines"].append({"engine": "Rust literals (recover_rust_strings)",
                                  "strings": len(result["literals"]), "unexplained": len(lit["missed"]),
                                  "seconds": round(time.monotonic() - t0, 1)})

    if libfuncs and emu_ok:
        import recover_libfuncs as LF
        t0 = time.monotonic()
        db = LF.load_db()
        if db:
            lf = LF.match_binary(path, db)
            result["libfuncs"] = lf
            result["engines"].append({"engine": "library functions (recover_libfuncs)",
                                      "identified": len(lf),
                                      "seconds": round(time.monotonic() - t0, 1)})
        else:
            result["notes"].append("--libfuncs: no signature DB at scripts/data/libfunc_sigs.json; "
                                   "generate it with recover_libfuncs.py --gen <unstripped builds>")

    if not result["decoded"]:
        result["notes"].append("no decoded strings: for AEAD (e.g. muddy) or decoders that only run at "
                               "runtime, use recover_dynamic.py inside an isolated analysis VM")
    from recover_callsite import ioc_tags
    for x in result["decoded"] + result["stack"]:
        x["tags"] = ioc_tags(x["string"])
    for x in result["literals"]:
        # source paths of the toolchain and of crates.io dependencies are build metadata
        # (recover_rust_meta.py reports them), not indicators
        x["tags"] = [] if _TOOLCHAIN_PATH.search(x["string"]) else ioc_tags(x["string"])
    return result


_TOOLCHAIN_PATH = re.compile(r"^/rustc/[0-9a-f]{40}/|^/rust/deps/|[/\\]\.?cargo[/\\]registry[/\\]|"
                             r"^library[/\\]|[/\\]\.rustup[/\\]toolchains[/\\]")


def _hex(v):
    return f"0x{v:x}" if isinstance(v, int) else str(v)


def print_text(result: dict, all_literals: bool = False) -> None:
    print(f"binary: {Path(result['file']).name}   format={result['format']}   arch={result['arch']}")
    for e in result["engines"]:
        if "strings" in e:
            extra = "  ".join(f"{k}={v}" for k, v in e.items() if k not in ("engine", "strings"))
            print(f"  {e['engine']}: {e['strings']} strings  {extra}")
        else:
            extra = "  ".join(f"{k}={v}" for k, v in e.items() if k != "engine")
            print(f"  {e['engine']}: {extra}")
    if result["decoded"]:
        print("\n== decoded strings ==")
        for x in result["decoded"]:
            if x.get("method") == "static-cryptify":
                where = f"cryptify key {x['key']!r}  call {_hex(x['call'])}  data {_hex(x['blob'])}"
            elif x.get("method", "").startswith("static"):
                where = f"decoder {_hex(x['decoder'])}  call {_hex(x['call'])}  data {_hex(x['blob'])}"
            else:
                where = f"function {_hex(x['function'])}  (emulation)"
            print(f"  {x['string']}{_tags(x)}\n      {where}")
    if result["stack"]:
        print("\n== stack strings ==")
        for x in result["stack"]:
            print(f"  {x['string']}{_tags(x)}\n      store {_hex(x['pc'])}  [{x['base']}{x['offset']:+#x}]")
    lf = result.get("libfuncs", [])
    if lf:
        print(f"\n== library functions identified ({len(lf)}) ==")
        for x in lf[:40]:
            print(f"  {_hex(x['va'])}  {x['name']}")
        if len(lf) > 40:
            print(f"  ... and {len(lf) - 40} more (--json for all)")
    lits = result.get("literals", [])
    shown = lits if all_literals else [x for x in lits if x.get("tags")]
    if shown:
        title = "Rust literals" if all_literals else "Rust literals that look like indicators"
        print(f"\n== {title} ({len(shown)} of {len(lits)}; --literals prints all) ==" if not all_literals
              else f"\n== {title} ({len(lits)}) ==")
        for x in shown:
            print(f"  {x['string']!r}{_tags(x)}\n      0x{x['address']:x}  ({x['source']})")
    for n in result["notes"]:
        print(f"\nnote: {n}")
    if not result["decoded"]:
        print(f"  python {Path(__file__).parent}/recover_dynamic.py {result['file']}")


def _tags(x):
    return "   " + " ".join(f"[{t}]" for t in x.get("tags", [])) if x.get("tags") else ""


def run_dir(root: Path, out_jsonl: Path | None, **kw) -> None:
    """Triage every file under a directory: one JSON line per file, a summary table at the end."""
    files = sorted(p for p in root.rglob("*") if p.is_file())
    rows = []
    sink = out_jsonl.open("w", encoding="utf-8") if out_jsonl else None
    try:
        for p in files:
            fmt, arch, _ = detect(p)
            if arch not in ("x86_64", "aarch64"):
                continue
            try:
                res = run(p, **kw)
            except Exception as e:      # one malformed sample must not stop the batch
                res = {"file": str(p), "format": fmt, "arch": arch, "decoded": [], "stack": [],
                       "literals": [], "engines": [], "notes": [f"error: {e}"]}
            if sink:
                sink.write(json.dumps(res) + "\n")
            iocs = sorted({t for x in res["decoded"] + res["stack"] + res.get("literals", [])
                           for t in x.get("tags", [])})
            rows.append((p, res, iocs))
    finally:
        if sink:
            sink.close()
    width = max((len(str(p.relative_to(root))) for p, _, _ in rows), default=4)
    print(f"{'file':<{width}}  fmt  arch     decoded  stack  literals  indicators")
    for p, res, iocs in rows:
        print(f"{str(p.relative_to(root)):<{width}}  {str(res['format'])[:4]:<4} {res['arch']:<8} "
              f"{len(res['decoded']):>7}  {len(res['stack']):>5}  {len(res.get('literals', [])):>8}  "
              f"{', '.join(iocs)}")
    print(f"\n{len(rows)} binaries" + (f"; records: {out_jsonl}" if out_jsonl else ""))


def _rebase(records, imagebase, keys):
    """PE recoverers report RVAs; FLOSS documents use virtual addresses."""
    out = []
    for r in records:
        r = dict(r)
        for k in keys:
            if isinstance(r.get(k), int) and r[k]:
                r[k] += imagebase
        out.append(r)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", help="a binary, or a directory to triage every binary in it")
    ap.add_argument("--jsonl", metavar="OUT", help="directory mode: write one JSON record per file to OUT")
    ap.add_argument("--json", action="store_true", help="print the results as JSON")
    ap.add_argument("--floss-json", metavar="OUT", help="also write a FLOSS results document to OUT")
    ap.add_argument("--emulate", choices=("auto", "always", "never"), default="always",
                    help="run emulation always (default, bounded by --time-budget), only when the "
                         "static pass finds nothing (auto), or never")
    ap.add_argument("--no-stackstrings", action="store_true", help="skip static stack-string recovery")
    ap.add_argument("--no-literals", action="store_true", help="skip splitting the plain Rust literals")
    ap.add_argument("--literals", action="store_true", help="print every Rust literal, not only indicators")
    ap.add_argument("-n", "--min-length", type=int, default=6, help="minimum string length (default 6)")
    ap.add_argument("--time-budget", type=float, default=120.0, help="emulation time budget in seconds")
    ap.add_argument("--max-funcs", type=int, default=0,
                    help="maximum functions to emulate (default 0: no cap, the time budget decides)")
    ap.add_argument("--max-ram", metavar="SIZE", default="",
                    help="RAM budget for emulation, e.g. 4G or 2048 (MB); fewer worker processes "
                         "fit a smaller budget, trading speed for memory (also RUST_DEOBF_MAX_RAM_MB)")
    ap.add_argument("--libfuncs", action="store_true",
                    help="identify Rust std/crate functions by byte signature (needs a DB built with "
                         "recover_libfuncs.py --gen); surfaces library names so the decoders stand out")
    args = ap.parse_args(argv)

    path = Path(args.binary)
    if args.min_length < 1:
        ap.error("--min-length must be a positive integer")
    try:
        max_ram_mb = _parse_size_mb(args.max_ram)
    except ValueError as e:
        ap.error(str(e))
    if path.is_dir():
        run_dir(path, Path(args.jsonl) if args.jsonl else None, emulate=args.emulate,
                stackstrings=not args.no_stackstrings, min_len=args.min_length,
                time_budget=args.time_budget, max_funcs=args.max_funcs,
                literals=not args.no_literals, max_ram_mb=max_ram_mb, libfuncs=args.libfuncs)
        return
    if not path.is_file():
        ap.error(f"no such file: {path}")

    result = run(path, emulate=args.emulate, stackstrings=not args.no_stackstrings,
                 min_len=args.min_length, time_budget=args.time_budget, max_funcs=args.max_funcs,
                 literals=not args.no_literals, max_ram_mb=max_ram_mb, libfuncs=args.libfuncs)

    if args.floss_json:
        import floss_export
        ib = result["imagebase"]
        decoded = _rebase(result["decoded"], ib, ("decoder", "call", "blob", "function")) if ib else result["decoded"]
        doc = floss_export.build_document(path, decoded, result["stack"], min_length=args.min_length,
                                          imagebase=ib, literals=result["literals"],
                                          literals_missed=result["literals_missed"])
        floss_export.write(Path(args.floss_json), doc)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_text(result, all_literals=args.literals)
        if args.floss_json:
            print(f"\nFLOSS results document: {args.floss_json}  (open with `floss {args.floss_json}`)")


if __name__ == "__main__":
    main()
