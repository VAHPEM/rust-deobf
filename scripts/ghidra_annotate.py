# Ghidra post-script: annotate a program with rust-deobf's recovered strings.
#
# Reads the JSON that `recover.py --json` writes and, for each function that decoded strings,
# adds a plate comment listing them (with their indicator tags), a bookmark, and (when the function
# is still named with a default `FUN_`/`SUB_` name) renames it after the string carrying the
# strongest indicator tag. Emulation records name the function that built the string ("function");
# static call-site records name the decoder ("decoder") and the call site ("call"): those are
# grouped under the decoder function and each call site gets a pre-comment with its plaintext. Decoded
# strings are the triage headline; surfacing them in the decompiler is where an analyst reads
# them. With recover_idioms.py output merged in as "idioms" (ghidra_run.sh does this), it also
# marks Rust idioms: a pre comment with the recovered format string at every println!/format!/
# panic! site, "safety check (cold path)" pre comments at bounds/overflow/unwrap panic calls plus a
# bookmark (category "rust-deobf: safety-check") and an EOL note on the guarding branch, drop /
# dealloc EOL notes, default-name renames of identified panic / fmt / drop helpers (rd_panic_*,
# rd_fmt_*, rd_rust_dealloc, rd_drop_glue*), and a "returns Option/Result?" plate line on
# functions with enum-like returns. Observational: it changes only comments, bookmarks and
# default names (no code is modified or removed).
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


RD_CATEGORY = "/rust-deobf"

# recover_types field `type` -> width. "ulong" there means a pointer-sized usize (it emits "uint"
# for 4-byte-pointer targets), NOT Ghidra's C `ulong`, which is 4 bytes on Windows x64 (LLP64).
_PTR_SIZED = ("ulong", "usize", "size_t")
_INT_WIDTH = {"u8": 1, "uint8": 1, "byte": 1, "uchar": 1,
              "u16": 2, "uint16": 2, "ushort": 2,
              "u32": 4, "uint32": 4, "uint": 4,
              "u64": 8, "uint64": 8, "ulonglong": 8}
# unsigned integer Ghidra datatype class per byte width (fixed-width on every data organization)
_UINT_CLASS = {1: "ByteDataType", 2: "UnsignedShortDataType", 4: "UnsignedIntegerDataType",
               8: "UnsignedLongLongDataType"}


def _field_layout(spec, ptr_size):
    """Pure (no Ghidra): [(offset, name, kind, size)] for a recover_types struct spec in a program
    whose pointers are `ptr_size` bytes; kind is "pointer" or "uint". None when the spec does not
    describe a valid packed struct at this pointer size (unknown field type, field out of bounds,
    overlap, or gaps -- e.g. a spec built for 8-byte pointers in a 4-byte program)."""
    if ptr_size not in (2, 4, 8):
        return None
    size = spec.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        return None
    out = []
    for f in spec.get("fields") or []:
        off, ftype, name = f.get("offset"), f.get("type"), f.get("name")
        if not isinstance(off, int) or isinstance(off, bool) or off < 0:
            return None
        if ftype == "pointer":
            kind, width = "pointer", ptr_size
        elif ftype in _PTR_SIZED:
            kind, width = "uint", ptr_size
        elif ftype in _INT_WIDTH:
            kind, width = "uint", _INT_WIDTH[ftype]
        else:
            return None
        out.append((off, str(name) if name else "field_%x" % off, kind, width))
    if not out:
        return None
    out.sort()
    pos = 0
    for off, _, _, width in out:
        if off != pos:                  # overlap (off < pos) or gap (off > pos)
            return None
        pos = off + width
    return out if pos == size else None


def _range_action(units):
    """Pure: what to do with the bytes a vtable struct would cover, given the code units found
    there as [(kind, type_name, category_path)] (kind "instruction" | "data", defined units only).
    "create" -- nothing defined, lay the type; "replace" -- only our own rust-deobf type (a re-run):
    clear it and lay the new one; "skip" -- an instruction or someone else's data (Ghidra's analysis
    or the analyst's): leave it alone, this script is observational."""
    ours = False
    for kind, tname, cat in units:
        if kind != "data":
            return "skip"
        if cat == RD_CATEGORY:
            ours = True
        elif not re.match(r"undefined\d*$", tname or ""):
            return "skip"
    return "replace" if ours else "create"


def _program_ptr_size():
    try:
        return int(currentProgram.getDefaultPointerSize())
    except Exception:
        try:
            return int(currentProgram.getDataTypeManager().getDataOrganization().getPointerSize())
        except Exception:
            return None


def _build_vtable_type(ghidra_types, method_count):
    """A StructureDataType matching recover_types' RustVtable_<n>m spec, resolved against the
    program's DataTypeManager (so sizes follow the program's data organization), or None."""
    try:
        from ghidra.program.model.data import StructureDataType, PointerDataType, CategoryPath
        import ghidra.program.model.data as gdata
    except Exception:
        return None
    spec = next((t for t in ghidra_types if t.get("name") == "RustVtable_%dm" % method_count), None)
    if spec is None:
        return None
    ptr_size = _program_ptr_size()
    layout = _field_layout(spec, ptr_size)
    if layout is None:
        print("vtable type %s skipped: spec does not fit this program (pointer size %s)"
              % (spec.get("name"), ptr_size))
        return None
    try:
        dtm = currentProgram.getDataTypeManager()
        st = StructureDataType(CategoryPath(RD_CATEGORY), spec["name"], spec["size"], dtm)
        for off, name, kind, width in layout:
            if kind == "pointer":
                dt = PointerDataType(None, width, dtm)
            else:
                dt = getattr(gdata, _UINT_CLASS[width])(dtm)
            if dt.getLength() != width:
                print("vtable type %s skipped: %s field is %d bytes here, expected %d"
                      % (spec["name"], name, dt.getLength(), width))
                return None
            st.replaceAtOffset(off, dt, width, name, None)
        return dtm.addDataType(st, None)
    except Exception as e:
        print("vtable type build failed (%s): %s" % (spec["name"], e))
        return None


def _units_in(listing, start, end):
    """[(kind, type_name, category_path)] for the defined code units overlapping [start, end]."""
    from ghidra.program.model.address import AddressSet
    aset = AddressSet(start, end)
    units = []
    if listing.getInstructionContaining(start) is not None or \
            listing.getInstructions(aset, True).hasNext():
        units.append(("instruction", None, None))
    datas = []
    d = listing.getDefinedDataContaining(start)
    if d is not None:
        datas.append(d)
    it = listing.getDefinedData(aset, True)
    while it.hasNext():
        datas.append(it.next())
    for d in datas:
        dt = d.getDataType()
        units.append(("data", dt.getName(), dt.getCategoryPath().getPath()))
    return units


def _lay_vtable_type(listing, a, dt):
    """Lay `dt` at `a` unless that would destroy someone else's code units (see _range_action)."""
    try:
        end = a.add(dt.getLength() - 1)
        action = _range_action(_units_in(listing, a, end))
        if action == "skip":
            print("vtable type not applied at %s: existing code/data there (left as is)" % (a,))
            return False
        if action == "replace":
            listing.clearCodeUnits(a, end, False)
        listing.createData(a, dt)
        return True
    except Exception as e:
        print("vtable type not applied at %s: %s" % (a, e))
        return False


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
            _lay_vtable_type(listing, a, dt)    # keeps the comment either way
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


# ------------------------------------------------------------------------------------------------
# Rust idioms (recover_idioms.py): fmt macro sites, panic / safety-check paths, drop calls,
# identified helpers and enum-like returns. `_idiom_plan` is pure (no Ghidra) and unit-tested;
# `_apply_idioms` only executes its actions. Observational: comments, bookmarks, default names.
# ------------------------------------------------------------------------------------------------
IDIOM_BM_SAFETY = "rust-deobf: safety-check"
IDIOM_BM_FMT = "rust-deobf: fmt"
IDIOM_BM_RET = "rust-deobf: enum-return"
_HELPER_NAME = {"panic": "rd_panic_%s", "fmt_sink": "rd_fmt_%s", "dealloc": "rd_rust_dealloc",
                "drop_glue": "rd_drop_glue"}


def _idiom_plan(idioms):
    """Pure: the annotations for a recover_idioms result, as a list of actions
      ("pre", addr, text)            pre comment at an instruction (fmt / panic / drop call site)
      ("eol", addr, text)            end-of-line comment (the guard branch of a safety check)
      ("plate_add", addr, text)      a line appended to the function's plate comment
      ("bookmark", addr, category, text)
      ("rename", addr, name)         only applied when the function still has a default name
    Addresses are the binary's own (PE: RVAs), resolved later like every other record."""
    acts = []
    if not isinstance(idioms, dict):
        return acts
    for r in idioms.get("fmt_sites") or []:
        site = _va(r.get("site"))
        if site is None:
            continue
        text = '%s("%s")' % (r.get("macro") or "format_args!", r.get("format", ""))
        if r.get("location"):
            text += "  @ " + r["location"]
        acts.append(("pre", site, "rust-deobf: " + text))
        acts.append(("bookmark", site, IDIOM_BM_FMT, text[:200]))
    for r in idioms.get("panic_sites") or []:
        site = _va(r.get("site"))
        if site is None:
            continue
        what = r.get("label") or r.get("kind") or "panic"
        loc = ("  @ " + r["location"]) if r.get("location") else ""
        msg = ('  "%s"' % r["message"][:120]) if r.get("message") else ""
        if r.get("safety_check"):
            acts.append(("pre", site, "rust-deobf: safety check (cold path): %s%s%s" % (what, loc, msg)))
        else:
            acts.append(("pre", site, "rust-deobf: panic path (cold): %s%s%s" % (what, loc, msg)))
        guard = _va(r.get("guard"))
        anchor = guard if guard is not None else site
        if guard is not None:
            acts.append(("eol", guard, "rust-deobf: cold branch -> %s (%s)" % (what, hex(site))))
        acts.append(("bookmark", anchor, IDIOM_BM_SAFETY, "%s%s" % (what, loc)))
    for r in idioms.get("drop_sites") or []:
        site = _va(r.get("site"))
        if site is None:
            continue
        acts.append(("eol", site, "rust-deobf: %s" % ("dealloc" if r.get("kind") == "dealloc" else "drop")))
    # helper renames: one name per (role, kind); a kind that occurs more than once gets its
    # address as a suffix so every name stays unique
    names = []
    for h in idioms.get("helpers") or []:
        va = _va(h.get("va"))
        tmpl = _HELPER_NAME.get(h.get("role"))
        if va is None or tmpl is None:
            continue
        kind = _SANE.sub("_", str(h.get("kind") or "unknown")).strip("_") or "unknown"
        names.append((va, tmpl % kind if "%s" in tmpl else tmpl, h))
    counts = {}
    for _va_, nm, _h in names:
        counts[nm] = counts.get(nm, 0) + 1
    for va, nm, h in names:
        if counts[nm] > 1:
            nm = "%s_%x" % (nm, va)
        acts.append(("rename", va, nm))
        acts.append(("plate_add", va, "rust-deobf: %s helper (%s, via %s)"
                     % (h.get("role"), h.get("kind"), h.get("via"))))
    for e in idioms.get("enum_returns") or []:
        va = _va(e.get("va"))
        if va is None:
            continue
        line = "rust-deobf: %s [%s, confidence %s]" % (
            e.get("note") or "returns enum-like value (Option/Result?)", e.get("shape"), e.get("confidence"))
        ev = e.get("evidence") or []
        if ev:
            line += "\n  " + "\n  ".join(str(x) for x in ev[:3])
        acts.append(("plate_add", va, line))
        acts.append(("bookmark", va, IDIOM_BM_RET, "%s (%s)" % (e.get("shape"), e.get("confidence"))))
    return acts


def _merge_plate(existing, line):
    """Pure: append `line` to a plate comment unless it is already there."""
    if not existing:
        return line
    if line in existing:
        return existing
    return existing + "\n" + line


def _apply_idioms(idioms):
    acts = _idiom_plan(idioms)
    if not acts:
        return
    listing = currentProgram.getListing()
    btm = currentProgram.getBookmarkManager()
    done = {"pre": 0, "eol": 0, "plate_add": 0, "bookmark": 0, "rename": 0}
    pre_text = {}
    for act in acts:
        kind = act[0]
        try:
            if kind in ("pre", "eol"):
                a = _resolve_addr(act[1])
                if a is None:
                    continue
                key = (str(a), kind)
                ctype = CodeUnit.PRE_COMMENT if kind == "pre" else CodeUnit.EOL_COMMENT
                if key not in pre_text:
                    # keep what is already there (e.g. a "rust-deobf decodes:" call-site comment)
                    try:
                        pre_text[key] = listing.getComment(ctype, a)
                    except Exception:
                        pre_text[key] = None
                # several facts at one address (a fmt site that is also a panic site): one comment
                pre_text[key] = _merge_plate(pre_text.get(key), act[2])
                listing.setComment(a, ctype, pre_text[key])
            elif kind == "bookmark":
                a = _resolve_addr(act[1])
                if a is None:
                    continue
                btm.setBookmark(a, "Analysis", act[2], act[3])
            elif kind in ("plate_add", "rename"):
                r = _resolve(act[1])
                if r is None:
                    continue
                entry, func = r
                if kind == "plate_add":
                    try:
                        old = listing.getComment(CodeUnit.PLATE_COMMENT, entry)
                    except Exception:
                        old = None
                    listing.setComment(entry, CodeUnit.PLATE_COMMENT, _merge_plate(old, act[2]))
                else:
                    if func is None:
                        continue
                    nm = func.getName()
                    if not (nm.startswith("FUN_") or nm.startswith("SUB_")):
                        continue
                    func.setName(act[2], SourceType.ANALYSIS)
            else:
                continue
            done[kind] += 1
        except Exception as e:
            print("idiom annotation failed (%s at %s): %s" % (kind, act[1], e))
    print("ghidra_annotate: idioms -> %d pre, %d eol, %d plate lines, %d bookmarks, %d renames"
          % (done["pre"], done["eol"], done["plate_add"], done["bookmark"], done["rename"]))


def main():
    data = _load()
    if not data:
        return
    if "fmt_sites" in data and "idioms" not in data:
        data = {"idioms": data}            # recover_idioms.py --json output passed directly
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
    # Rust idioms (recover_idioms, merged into the JSON by ghidra_run.sh as "idioms")
    _apply_idioms(data.get("idioms"))


main()
