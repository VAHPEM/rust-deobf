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
  5. the hard cases (AEAD, runtime-only decoders) need recover_dynamic.py, which EXECUTES the
     sample and so belongs in an isolated analysis VM; the output says so when nothing else was
     found.

None of these execute the sample natively: the static passes only disassemble it and emulation
runs single functions inside Unicorn with external calls stubbed.

    python scripts/recover.py <binary>
    python scripts/recover.py <binary> --json                 # machine-readable records
    python scripts/recover.py <binary> --floss-json out.json  # a FLOSS results document:
                                                              #   view it with `floss -l out.json`
    python scripts/recover.py <binary> --time-budget 300         # emulate longer (big binaries)
    python scripts/recover.py <binary> --emulate never           # static passes only, seconds
    python scripts/recover.py samples/ --jsonl triage.jsonl    # every binary under a directory

Each engine runs isolated: if one raises, the error is recorded in `notes` / the engine row and
the remaining engines (emulation in particular) still run.

Exit codes: 0 analysis ran (single file), or every parseable file in a directory ran; 2 usage error;
3 unsupported / unparseable input (single file: not an ELF/PE/Mach-O LIEF can read; directory: no
file in it could be parsed); 4 analysis error (an engine failed, or in directory mode at least one
file's run failed).
"""
from __future__ import annotations
import argparse
import json
import re
import shlex
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
    """(format, arch, imagebase); (None, None, 0) when LIEF cannot parse the file."""
    try:
        b = lief.parse(str(path))
    except Exception:                  # lief raises on some malformed headers
        return None, None, 0
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


EXIT_OK, EXIT_USAGE, EXIT_UNSUPPORTED, EXIT_ERROR = 0, 2, 3, 4


def _engine(result: dict, name: str, fn):
    """Run one engine; on an exception record it (engine row + note) and return None, so a failure
    in one recoverer never stops the others."""
    t0 = time.monotonic()
    try:
        return fn()
    except Exception as e:                         # noqa: BLE001 - isolate every engine
        msg = f"{type(e).__name__}: {e}"
        result["engines"].append({"engine": name, "error": msg,
                                  "seconds": round(time.monotonic() - t0, 1)})
        result["notes"].append(f"{name} failed ({msg}); the other engines still ran")
        result["errors"].append({"engine": name, "error": msg})
        return None


def run(path: Path, emulate: str = "always", stackstrings: bool = True, min_len: int = 6,
        time_budget: float = 120.0, max_funcs: int = 0, literals: bool = True,
        max_ram_mb: int = 0, libfuncs: bool = False, static: bool = True) -> dict:
    """Run the applicable recoverers and return {"format", "arch", "decoded", "stack", ...}.

    static=False skips the static call-site and cryptify passes (soc_triage --fast). Each engine is
    isolated: an exception in one is recorded in result["errors"] / ["notes"] and the rest run."""
    fmt, arch, imagebase = detect(path)
    result = {"file": str(path), "format": fmt, "arch": arch, "imagebase": imagebase,
              "decoded": [], "stack": [], "literals": [], "literals_missed": [],
              "libfuncs": [], "engines": [], "notes": [], "errors": []}
    if fmt is None:
        result["notes"].append("not an ELF/PE/Mach-O binary LIEF can parse: nothing to recover")
        return result
    # The emulation engine loads ELF, PE and Mach-O on x86-64, AArch64 and 32-bit x86. 32-bit PE
    # was routed to literals only until its Windows-std emulation was verified: stdcall imports
    # now pop their arguments, function starts come from .eh_frame (no .pdata on i386) and the
    # import trampolines cannot be overwritten, and the benchmark recovers every string on
    # i686-pc-windows-gnu builds. Library-function identification is still not verified there.
    # The static call-site recoverers, cryptify, stack-strings and libfuncs are ELF/PE
    # x86-64/AArch64 only; elsewhere (32-bit x86, Mach-O) only emulation + literals run.
    pe32 = fmt == "PE" and arch == "x86"
    emu_ok = fmt in ("ELF", "PE", "MACHO") and arch in ("x86_64", "aarch64", "x86")
    static_ok = fmt in ("ELF", "PE") and arch in ("x86_64", "aarch64")
    static_records = []
    if not emu_ok:
        result["notes"].append(
            f"the emulation engine supports ELF/PE/Mach-O on x86-64/aarch64 and 32-bit x86 "
            f"(this is {fmt}/{arch}): skipped. Literal recovery still runs; for strings "
            f"also try recover_rust_meta.py (crates, panic sites — works here) and, in a VM, "
            f"recover_dynamic.py.")
    elif not static_ok:
        result["notes"].append(
            f"{fmt}/{arch}: static call-site recovery is ELF/PE x86-64/aarch64 only; strings come "
            "from emulation and literal recovery here.")

    if static_ok and static:
        if arch == "x86_64":
            engine = "static x86-64 (recover_callsite)"
        else:
            engine = "static aarch64 (recover_arm64)"

        def _static():
            if arch == "x86_64":
                import recover_callsite as R
            else:
                import recover_arm64 as R
            return R.recover(path, [])
        t0 = time.monotonic()
        r = _engine(result, engine, _static)
        if r is not None:
            static_records = [x for x in r.get("records", []) if len(x["string"]) >= min_len]
            result["decoded"].extend(static_records)
            result["engines"].append({"engine": engine, "decoders": r.get("decoders", 0),
                                      "strings": len(static_records),
                                      "seconds": round(time.monotonic() - t0, 1)})

        def _cryptify():
            import recover_cryptify as C
            return C.recover(path)
        t0 = time.monotonic()
        c = _engine(result, "cryptify (recover_cryptify)", _cryptify)
        if c is not None and c.get("cryptify"):
            known = {x["string"] for x in result["decoded"]}
            crypt = [x for x in c["records"] if len(x["string"]) >= min_len and x["string"] not in known]
            result["decoded"].extend(crypt)
            static_records += crypt
            result["engines"].append({"engine": "cryptify (recover_cryptify)", "strings": len(crypt),
                                      "seconds": round(time.monotonic() - t0, 1)})
            if c.get("note"):
                result["notes"].append(c["note"])

    if emu_ok and (emulate == "always" or (emulate == "auto" and not static_records)):
        def _emulate():
            import recover_emulate as E
            return E.recover(path, [], max_funcs=max_funcs, time_budget=time_budget,
                             max_ram_mb=max_ram_mb)
        t0 = time.monotonic()
        e = _engine(result, "emulation (recover_emulate)", _emulate)
        if e is not None:
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
        def _stack():
            import recover_stackstrings as S
            return S.recover(path, min_len=min_len)
        t0 = time.monotonic()
        st = _engine(result, "static stack strings (recover_stackstrings)", _stack)
        if st is not None:
            result["stack"] = st.get("records", [])
            result["engines"].append({"engine": "static stack strings (recover_stackstrings)",
                                      "strings": len(result["stack"]),
                                      "seconds": round(time.monotonic() - t0, 1)})

    if literals:
        def _literals():
            import recover_rust_strings as L
            return L.recover(path, min_len=min_len)
        t0 = time.monotonic()
        lit = _engine(result, "Rust literals (recover_rust_strings)", _literals)
        if lit is not None:
            result["literals"] = lit.get("strings", [])
            result["literals_missed"] = lit.get("missed", [])
            result["engines"].append({"engine": "Rust literals (recover_rust_strings)",
                                      "strings": len(result["literals"]),
                                      "unexplained": len(result["literals_missed"]),
                                      "seconds": round(time.monotonic() - t0, 1)})

    if pe32 and libfuncs:
        result["notes"].append("32-bit PE: library-function identification is not verified here; "
                               "skipped.")
    if libfuncs and emu_ok and not pe32:
        def _libfuncs():
            import recover_libfuncs as LF
            db = LF.load_db()
            return (LF.match_binary(path, db) if db else None), bool(db)
        t0 = time.monotonic()
        out = _engine(result, "library functions (recover_libfuncs)", _libfuncs)
        if out is not None:
            lf, have_db = out
            if have_db:
                result["libfuncs"] = lf
                result["engines"].append({"engine": "library functions (recover_libfuncs)",
                                          "identified": len(lf),
                                          "seconds": round(time.monotonic() - t0, 1)})
            else:
                result["notes"].append("--libfuncs: no signature DB at scripts/data/libfunc_sigs.json; "
                                       "generate it with recover_libfuncs.py --gen <unstripped builds>")

    if not result["decoded"]:
        result["notes"].append("no decoded strings: for AEAD (e.g. muddy) or decoders that only run at "
                               "runtime, recover_dynamic.py can observe them -- it EXECUTES the sample, "
                               "so only inside an isolated analysis VM")
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
        if "error" in e:
            print(f"  {e['engine']}: FAILED  {e['error']}")
        elif "strings" in e:
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
    if not result["decoded"] and result.get("format") and not result.get("errors"):
        # a hint, not a ready-to-paste command: the dynamic tool runs the sample and refuses to
        # start without its explicit opt-in flag (and must only be used inside an isolated VM)
        print("  hint: see `recover_dynamic.py --help` (Frida; executes the sample -- isolated VM "
              f"only) for {shlex.quote(result['file'])}")


def _tags(x):
    return "   " + " ".join(f"[{t}]" for t in x.get("tags", [])) if x.get("tags") else ""


def run_dir(root: Path, out_jsonl: Path | None, **kw) -> int:
    """Triage every file under a directory: one JSON line per analysed file, a summary table at the
    end. Every binary the single-file mode supports is analysed (ELF/PE/Mach-O on x86-64, AArch64
    and 32-bit x86/ARM, with the same per-format routing); files LIEF cannot parse are counted as
    skipped, and a file whose run raised is listed with its error, never as a clean zero row.
    Returns an exit code (EXIT_OK / EXIT_UNSUPPORTED when nothing was parseable / EXIT_ERROR when
    any file failed)."""
    files = sorted(p for p in root.rglob("*") if p.is_file())
    rows, skipped, errored = [], [], 0
    sink = out_jsonl.open("w", encoding="utf-8") if out_jsonl else None
    try:
        for p in files:
            if out_jsonl is not None and p.resolve() == out_jsonl.resolve():
                continue                 # the JSONL we are writing may live inside the tree
            try:
                fmt, arch, _ = detect(p)
            except Exception as e:      # lief can raise on a malformed header
                skipped.append((p, f"detect failed: {type(e).__name__}: {e}"))
                continue
            if fmt is None:
                skipped.append((p, "not a binary LIEF can parse"))
                continue
            err = None
            try:
                res = run(p, **kw)
                if res.get("errors"):
                    err = "; ".join(f"{x['engine']}: {x['error']}" for x in res["errors"])
            except Exception as e:      # one malformed sample must not stop the batch
                err = f"{type(e).__name__}: {e}"
                res = {"file": str(p), "format": fmt, "arch": arch, "decoded": [], "stack": [],
                       "literals": [], "engines": [], "notes": [f"error: {err}"],
                       "errors": [{"engine": "run", "error": err}]}
            if err:
                errored += 1
            res["error"] = err
            if sink:
                sink.write(json.dumps(res) + "\n")
            iocs = sorted({t for x in res["decoded"] + res["stack"] + res.get("literals", [])
                           for t in x.get("tags", [])})
            rows.append((p, res, iocs, err))
    finally:
        if sink:
            sink.close()
    width = max((len(str(p.relative_to(root))) for p, *_ in rows), default=4)
    print(f"{'file':<{width}}  fmt  arch     decoded  stack  literals  indicators / error")
    for p, res, iocs, err in rows:
        tail = f"ERROR: {err[:100]}" if err else ", ".join(iocs)
        print(f"{str(p.relative_to(root)):<{width}}  {str(res['format'])[:4]:<4} {str(res['arch']):<8} "
              f"{len(res['decoded']):>7}  {len(res['stack']):>5}  {len(res.get('literals', [])):>8}  "
              f"{tail}")
    print(f"\n{len(rows)} binaries analysed, {errored} with errors, {len(skipped)} files skipped "
          "(not a parseable binary)" + (f"; records: {out_jsonl}" if out_jsonl else ""))
    if errored:
        return EXIT_ERROR
    if not rows and skipped:
        return EXIT_UNSUPPORTED
    return EXIT_OK


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
    args = ap.parse_args(argv)          # argparse exits 2 on a usage error

    path = Path(args.binary)
    if args.min_length < 1:
        ap.error("--min-length must be a positive integer")
    try:
        max_ram_mb = _parse_size_mb(args.max_ram)
    except ValueError as e:
        ap.error(str(e))
    kw = dict(emulate=args.emulate, stackstrings=not args.no_stackstrings, min_len=args.min_length,
              time_budget=args.time_budget, max_funcs=args.max_funcs,
              literals=not args.no_literals, max_ram_mb=max_ram_mb, libfuncs=args.libfuncs)
    if path.is_dir():
        # the single-file outputs have no meaning for a directory: refuse instead of ignoring them
        if args.json or args.floss_json or args.literals:
            ap.error("--json / --floss-json / --literals apply to a single binary; for a directory "
                     "use --jsonl OUT (one JSON record per file)")
        return run_dir(path, Path(args.jsonl) if args.jsonl else None, **kw)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    if args.jsonl:
        ap.error("--jsonl is the directory-mode output; for a single binary use --json")

    try:
        result = run(path, **kw)
    except Exception as e:
        print(f"recover: analysis error: {type(e).__name__}: {e}", file=sys.stderr)
        return EXIT_ERROR
    if result["format"] is None:
        print(f"recover: unsupported input: {path} is not an ELF/PE/Mach-O binary LIEF can parse",
              file=sys.stderr)
        return EXIT_UNSUPPORTED

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
            print(f"\nFLOSS results document: {args.floss_json}  "
                  f"(view it with `floss -l {shlex.quote(args.floss_json)}`)")
    return EXIT_ERROR if result.get("errors") else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
