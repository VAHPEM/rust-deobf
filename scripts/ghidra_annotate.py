# Ghidra post-script: annotate a program with rust-deobf's recovered strings.
#
# Reads the JSON that `recover.py --json` writes and, for each function that decoded strings,
# adds a plate comment listing them, a bookmark, and (when the function is still named with a
# default `FUN_`/`SUB_` name) renames it after the strongest indicator it revealed. Decoded
# strings are the triage headline; surfacing them in the decompiler is where an analyst reads
# them. Observational: it changes only comments, bookmarks and default names.
#
# Run headless. This is a PyGhidra (Python 3) script: since Ghidra 11.3 dropped Jython,
# plain `analyzeHeadless ... -postScript *.py` fails with "Ghidra was not started with
# PyGhidra. Python is not available". Launch it through PyGhidra instead (pip install the
# wheel bundled at Ghidra/Features/PyGhidra/pypkg/dist/ first):
#   recover.py sample --json > sample.rd.json
#   GHIDRA_INSTALL_DIR=/path/to/ghidra \
#     python3 -m pyghidra.ghidra_launch ghidra.app.util.headless.AnalyzeHeadless \
#       <proj_dir> <proj> -import sample \
#       -postScript ghidra_annotate.py sample.rd.json
# Easiest: scripts/ghidra_run.sh sample [sample.rd.json]  (does recover + import + annotate).
#
# @category Rust
# @runtime PyGhidra
import json
import re

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit


def _load():
    args = getScriptArgs()
    if not args:
        print("ghidra_annotate: no JSON path argument")
        return None
    with open(args[0]) as fh:
        return json.load(fh)


def _resolve(func_field):
    """recover.py reports the function as a hex virtual address in the binary's own terms.
    Ghidra may rebase (PIE, or a chosen image base), so try the raw address and the address
    shifted by the image base, and keep whichever lands in a real function or defined code."""
    if isinstance(func_field, int):
        va = func_field
    else:
        try:
            va = int(func_field, 16)
        except (TypeError, ValueError):
            return None
    base = currentProgram.getImageBase().getOffset()
    fm = currentProgram.getFunctionManager()
    seen = []
    for addr_val in (va, base + va):
        a = currentProgram.getImageBase().getNewAddress(addr_val)
        seen.append(a)
        f = fm.getFunctionContaining(a)
        if f is not None:
            return f.getEntryPoint(), f
    # no function yet (undiscovered): return the first address that is at least mapped
    for a in seen:
        if currentProgram.getMemory().contains(a):
            return a, fm.getFunctionContaining(a)
    return None


_SANE = re.compile(r"[^A-Za-z0-9]+")
_TAG_RANK = ["url", "ip", "domain", "mutex", "registry", "path", "email"]


def _rename_hint(strings, tags):
    for t in _TAG_RANK:
        if t in tags:
            for s in strings:
                token = _SANE.sub("_", s).strip("_")
                if token:
                    return "rd_%s_%s" % (t, token[:40])
    s = strings[0] if strings else ""
    token = _SANE.sub("_", s).strip("_")
    return "rd_str_%s" % token[:40] if token else None


def main():
    data = _load()
    if not data:
        return
    by_func = {}
    for rec in data.get("decoded", []):
        key = rec.get("function")
        if key is None:
            continue
        by_func.setdefault(key, {"strings": [], "tags": set()})
        by_func[key]["strings"].append(rec["string"])
        for t in rec.get("tags", []):
            by_func[key]["tags"].add(t)

    listing = currentProgram.getListing()
    btm = currentProgram.getBookmarkManager()
    annotated = renamed = 0
    for key, info in by_func.items():
        r = _resolve(key)
        if r is None:
            continue
        entry, func = r
        strings = sorted(set(info["strings"]))
        tags = info["tags"]
        plate = "rust-deobf: %d decoded string(s)\n" % len(strings)
        plate += "\n".join("  %s%s" % (s, "  [" + ",".join(sorted(t for t in tags)) + "]" if False else "")
                           for s in strings)
        listing.setComment(entry, CodeUnit.PLATE_COMMENT, plate)
        btm.setBookmark(entry, "Analysis", "rust-deobf",
                        "%d decoded: %s" % (len(strings), "; ".join(strings)[:160]))
        annotated += 1
        if func is not None:
            name = func.getName()
            if name.startswith("FUN_") or name.startswith("SUB_"):
                hint = _rename_hint(strings, tags)
                if hint:
                    try:
                        func.setName(hint, SourceType.ANALYSIS)
                        renamed += 1
                    except Exception as e:
                        print("rename failed at %s: %s" % (entry, e))
    print("ghidra_annotate: annotated %d function(s), renamed %d" % (annotated, renamed))


main()
