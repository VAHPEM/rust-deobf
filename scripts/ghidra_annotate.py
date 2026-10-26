# Ghidra post-script: annotate a program with rust-deobf's recovered strings.
#
# Reads the JSON that `recover.py --json` writes and, for each function that decoded strings,
# adds a plate comment listing them (with their indicator tags), a bookmark, and (when the function
# is still named with a default `FUN_`/`SUB_` name) renames it after the string carrying the
# strongest indicator tag. Emulation records name the function that built the string ("function");
# static call-site records name the decoder ("decoder") and the call site ("call"): those are
# grouped under the decoder function and each call site gets a pre-comment with its plaintext. Decoded
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


def _va(field):
    if isinstance(field, int):
        return field
    try:
        return int(field, 16)
    except (TypeError, ValueError):
        return None


def _new_address(value):
    """An Address in the program's default space, or None when the value does not fit it (e.g.
    raw + image base overflowing a 32-bit program's address space raises in Ghidra)."""
    try:
        return currentProgram.getImageBase().getNewAddress(value)
    except Exception:
        return None


def _resolve(func_field):
    """recover.py reports the function as a hex virtual address in the binary's own terms.
    Ghidra may rebase (PIE, or a chosen image base), so try the raw address and the address
    shifted by the image base, and keep whichever lands in a real function or defined code."""
    va = _va(func_field)
    if va is None:
        return None
    base = currentProgram.getImageBase().getOffset()
    fm = currentProgram.getFunctionManager()
    seen = []
    for addr_val in (va, base + va):
        a = _new_address(addr_val)
        if a is None:
            continue
        seen.append(a)
        f = fm.getFunctionContaining(a)
        if f is not None:
            return f.getEntryPoint(), f
    # no function yet (undiscovered): return the first address that is at least mapped
    for a in seen:
        if currentProgram.getMemory().contains(a):
            return a, fm.getFunctionContaining(a)
    return None


def _resolve_addr(field):
    """An instruction address (a call site), raw or image-base shifted, whichever is mapped."""
    va = _va(field)
    if va is None:
        return None
    base = currentProgram.getImageBase().getOffset()
    for addr_val in (va, base + va):
        a = _new_address(addr_val)
        if a is not None and currentProgram.getMemory().contains(a):
            return a
    return None


_SANE = re.compile(r"[^A-Za-z0-9]+")
_TAG_RANK = ["url", "ip", "domain", "mutex", "registry", "path", "email", "token", "guid"]


def _rename_hint(items):
    """items: [(string, set(tags))]. Name after the string that carries the strongest tag (by
    _TAG_RANK), not after whichever string sorts first; with no tags, the longest string."""
    for t in _TAG_RANK:
        for s, tags in items:
            if t in tags:
                token = _SANE.sub("_", s).strip("_")
                if token:
                    return "rd_%s_%s" % (t, token[:40])
    for s, _ in sorted(items, key=lambda it: (-len(it[0]), it[0])):
        token = _SANE.sub("_", s).strip("_")
        if token:
            return "rd_str_%s" % token[:40]
    return None


def _group(decoded):
    """{function key: {string: set(tags)}} and [(call site, string, tags)] from recover.py records.
    Emulation records carry "function"; static ones carry "decoder" (+ "call")."""
    by_func, calls = {}, []
    for rec in decoded:
        s = rec.get("string")
        if s is None:
            continue
        key = rec.get("function")
        if key is None:
            key = rec.get("decoder")
        tags = set(rec.get("tags") or [])
        if key is not None:
            by_func.setdefault(key, {}).setdefault(s, set()).update(tags)
        if rec.get("call") is not None:
            calls.append((rec["call"], s, tags))
    return by_func, calls


def _fmt(s, tags):
    return "  %s%s" % (s, ("  [" + ",".join(sorted(tags)) + "]") if tags else "")


def _build_vtable_type(ghidra_types, method_count):
    """A StructureDataType matching recover_types' RustVtable_<n>m spec, or None if unavailable."""
    try:
        from ghidra.program.model.data import (StructureDataType, PointerDataType,
                                               UnsignedLongDataType, CategoryPath)
    except Exception:
        return None
    spec = next((t for t in ghidra_types if t.get("name") == "RustVtable_%dm" % method_count), None)
    if spec is None:
        return None
    try:
        st = StructureDataType(CategoryPath("/rust-deobf"), spec["name"], spec["size"])
        ptr = PointerDataType()
        for f in spec["fields"]:
            dt = ptr if f["type"] == "pointer" else UnsignedLongDataType()
            st.replaceAtOffset(f["offset"], dt, dt.getLength(), f["name"], None)
        return currentProgram.getDataTypeManager().addDataType(st, None)
    except Exception as e:
        print("vtable type build failed (%s): %s" % (spec["name"], e))
        return None


def _apply_vtables(data):
    """Recovered trait-object vtables (recover_types): comment + bookmark each vtable, name its
    method functions (still-default FUN_/SUB_ only), and best-effort lay a RustVtable_<n>m struct on
    it. Observational like the rest; any step that cannot apply is skipped, never fatal."""
    vtables = data.get("vtables") or []
    if not vtables:
        return
    from ghidra.program.model.listing import CodeUnit
    listing = currentProgram.getListing()
    btm = currentProgram.getBookmarkManager()
    fm = currentProgram.getFunctionManager()
    ghidra_types = data.get("ghidra_types") or []
    applied = named = 0
    for vt in vtables:
        a = _resolve_addr(vt.get("va"))
        if a is None:
            continue
        mc = vt.get("method_count", len(vt.get("methods") or []))
        plate = ("rust-deobf: dyn Trait vtable\n  size=%s align=%s  %d method(s)"
                 % (vt.get("size"), vt.get("align"), mc))
        try:
            listing.setComment(a, CodeUnit.PLATE_COMMENT, plate)
            btm.setBookmark(a, "Analysis", "rust-deobf",
                            "vtable: size=%s align=%s %dm" % (vt.get("size"), vt.get("align"), mc))
            applied += 1
        except Exception as e:
            print("vtable comment failed at %s: %s" % (a, e))
        dt = _build_vtable_type(ghidra_types, mc)
        if dt is not None:
            try:
                end = a.add(dt.getLength() - 1)
                listing.clearCodeUnits(a, end, False)
                listing.createData(a, dt)
            except Exception:
                pass                    # undefined/conflicting bytes: keep the comment, skip the type
        # name the concrete type's methods behind the trait
        for idx, m in enumerate(vt.get("methods") or []):
            r = _resolve(m)
            if r is None:
                continue
            entry, func = r
            if func is None:
                continue
            nm = func.getName()
            if nm.startswith("FUN_") or nm.startswith("SUB_"):
                try:
                    func.setName("rd_vtmethod_%x_%d" % (_va(vt.get("va")) or 0, idx),
                                 SourceType.ANALYSIS)
                    named += 1
                except Exception:
                    pass
    print("ghidra_annotate: vtables annotated %d, vtable methods named %d" % (applied, named))


def main():
    data = _load()
    if not data:
        return
    by_func, calls = _group(data.get("decoded", []))

    listing = currentProgram.getListing()
    btm = currentProgram.getBookmarkManager()
    fm = currentProgram.getFunctionManager()

    # Library-function identifications (recover_libfuncs): rename still-default FUN_/SUB_
    # functions to their std/crate name so the decoders stand out from the library noise.
    lib_renamed = 0
    for rec in data.get("libfuncs", []):
        r = _resolve(rec.get("va"))
        if r is None:
            continue
        entry, func = r
        if func is None:
            continue
        name = func.getName()
        if not (name.startswith("FUN_") or name.startswith("SUB_")):
            continue
        sym = _SANE.sub("_", rec.get("name", "")).strip("_")
        if not sym:
            continue
        try:
            func.setName("lib_" + sym[:60], SourceType.ANALYSIS)
            btm.setBookmark(entry, "Analysis", "rust-deobf",
                            "library fn: %s" % rec.get("name", ""))
            lib_renamed += 1
        except Exception as e:
            print("libfunc rename failed at %s: %s" % (entry, e))

    annotated = renamed = 0
    # Merge by RESOLVED entry point: an emulation record ("function") and a static record
    # ("decoder") can name the same function in different spellings (int vs hex string, raw vs
    # image-base shifted); annotating them separately would let the second plate comment overwrite
    # the first.
    merged = {}
    for key, strmap in by_func.items():
        r = _resolve(key)
        if r is None:
            print("ghidra_annotate: %s not mapped in this program, skipped" % (key,))
            continue
        entry, func = r
        slot = merged.setdefault(str(entry), [entry, func, {}])
        if slot[1] is None:
            slot[1] = func
        for s, tags in strmap.items():
            slot[2].setdefault(s, set()).update(tags)

    for entry, func, strmap in merged.values():
        items = sorted(strmap.items())
        strings = [s for s, _ in items]
        plate = "rust-deobf: %d decoded string(s)\n" % len(items)
        plate += "\n".join(_fmt(s, t) for s, t in items)
        listing.setComment(entry, CodeUnit.PLATE_COMMENT, plate)
        btm.setBookmark(entry, "Analysis", "rust-deobf",
                        "%d decoded: %s" % (len(strings), "; ".join(strings)[:160]))
        annotated += 1
        if func is not None:
            name = func.getName()
            if name.startswith("FUN_") or name.startswith("SUB_"):
                hint = _rename_hint(items)
                if hint:
                    try:
                        func.setName(hint, SourceType.ANALYSIS)
                        renamed += 1
                    except Exception as e:
                        print("rename failed at %s: %s" % (entry, e))

    # static records: the call site that hands the ciphertext to the decoder gets its plaintext
    sites = {}
    for call, s, tags in calls:
        a = _resolve_addr(call)
        if a is None:
            continue
        sites.setdefault(str(a), [a, []])[1].append(_fmt(s, tags).strip())
    for a, lines in sites.values():
        listing.setComment(a, CodeUnit.PRE_COMMENT, "rust-deobf decodes: " + " | ".join(lines))
    print("ghidra_annotate: annotated %d function(s), %d call site(s), renamed %d, library fns named %d"
          % (annotated, len(sites), renamed, lib_renamed))

    # recovered trait-object vtables (recover_types, merged into the JSON by ghidra_run.sh)
    _apply_vtables(data)


main()
