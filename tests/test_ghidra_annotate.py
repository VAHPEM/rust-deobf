"""ghidra_annotate.py logic, run against a stubbed Ghidra API (no Ghidra needed)."""
import json
import sys
import types

from conftest import ROOT

SCRIPT = ROOT / "scripts" / "ghidra_annotate.py"


# the program's DataTypeManager: every datatype must be built against it (identity-checked)
DTM = types.SimpleNamespace(addDataType=lambda dt, handler: dt)


def _install_stubs(monkeypatch):
    for m in ("ghidra", "ghidra.program", "ghidra.program.model", "ghidra.program.model.symbol",
              "ghidra.program.model.listing", "ghidra.program.model.data",
              "ghidra.program.model.address"):
        monkeypatch.setitem(sys.modules, m, types.ModuleType(m))
    sys.modules["ghidra.program.model.symbol"].SourceType = types.SimpleNamespace(ANALYSIS="A")
    sys.modules["ghidra.program.model.listing"].CodeUnit = types.SimpleNamespace(
        PLATE_COMMENT=3, PRE_COMMENT=1, EOL_COMMENT=0)

    # minimal stubs for the vtable-datatype path. Widths mimic Ghidra on a Windows x64 (LLP64)
    # data organization: C `ulong` is 4 bytes there -- the bug was building the usize fields from it
    made = []

    def dtcls(cls_name, width):
        class _DT:
            def __init__(s, *a):
                assert a and a[-1] is DTM, "%s built without the program's DataTypeManager" % cls_name
                s._n = a[1] if cls_name == "PointerDataType" else width
                s.kind = cls_name
                made.append((cls_name, s._n))
            def getLength(s): return s._n
        return _DT

    class Struct:
        def __init__(s, cat, name, size, dtm=None):
            assert dtm is DTM, "struct built without the program's DataTypeManager"
            s.name = name; s._n = size; s.fields = []
        def replaceAtOffset(s, off, dt, ln, nm, cmt):
            assert ln == dt.getLength()
            s.fields.append((off, nm, dt.kind, ln))
        def getLength(s): return s._n
    dmod = sys.modules["ghidra.program.model.data"]
    dmod.StructureDataType = Struct
    dmod.PointerDataType = dtcls("PointerDataType", None)
    dmod.UnsignedLongDataType = dtcls("UnsignedLongDataType", 4)
    dmod.UnsignedLongLongDataType = dtcls("UnsignedLongLongDataType", 8)
    dmod.UnsignedIntegerDataType = dtcls("UnsignedIntegerDataType", 4)
    dmod.UnsignedShortDataType = dtcls("UnsignedShortDataType", 2)
    dmod.ByteDataType = dtcls("ByteDataType", 1)
    dmod.CategoryPath = lambda p: p
    sys.modules["ghidra.program.model.address"].AddressSet = lambda a, b: (a.v, b.v)
    return made


def _load_helpers(monkeypatch):
    """The script's module globals (helpers only: no JSON argument, so main() returns at once)."""
    _install_stubs(monkeypatch)
    g = {"getScriptArgs": lambda: [], "currentProgram": None, "__name__": "__main__"}
    exec(SCRIPT.read_text(), g)
    return g


def _run(tmp_path, monkeypatch, data, ptr_size=8, existing=()):
    """`existing`: defined code units already in the listing, [(start, end, kind, type, category)]."""
    made = _install_stubs(monkeypatch)
    comments, renames, created, cleared, bookmarks = {}, {}, [], [], []
    units = list(existing)

    class Addr:
        def __init__(s, v): s.v = v
        def getOffset(s): return s.v
        def getNewAddress(s, v): return Addr(v)
        def add(s, n): return Addr(s.v + n)
        def __str__(s): return hex(s.v)

    class Func:
        def __init__(s, e, n): s.e, s.n = e, n
        def getEntryPoint(s): return Addr(s.e)
        def getName(s): return s.n
        def setName(s, n, src): s.n = n; renames[s.e] = n

    funcs = [Func(0x401000, "FUN_00401000"), Func(0x402000, "FUN_00402000"), Func(0x403000, "FUN_00403000")]

    class Prog:
        def getImageBase(s): return Addr(0x400000)
        def getFunctionManager(s):
            return types.SimpleNamespace(getFunctionContaining=lambda a: next(
                (f for f in funcs if f.e <= a.v < f.e + 0x800), None))
        def getDefaultPointerSize(s): return ptr_size
        def getListing(s):
            def overlapping(lo, hi, kind):
                return [u for u in units if u[2] == kind and u[0] <= hi and u[1] >= lo]

            class _It:
                def __init__(s2, items): s2.items = list(items)
                def hasNext(s2): return bool(s2.items)
                def next(s2): return s2.items.pop(0)

            def data_obj(u):
                return types.SimpleNamespace(getDataType=lambda: types.SimpleNamespace(
                    getName=lambda: u[3],
                    getCategoryPath=lambda: types.SimpleNamespace(getPath=lambda: u[4])))

            def clear(a, b, c):
                cleared.append((a.v, b.v))
                units[:] = [u for u in units if not (u[0] <= b.v and u[1] >= a.v)]
            return types.SimpleNamespace(
                setComment=lambda a, k, t: comments.__setitem__((a.v, k), t),
                getComment=lambda k, a: comments.get((a.v, k)),
                getInstructionContaining=lambda a: next(iter(overlapping(a.v, a.v, "instruction")), None),
                getInstructions=lambda aset, fwd: _It(u for u in overlapping(*aset, "instruction")
                                                      if u[0] >= aset[0]),
                getDefinedDataContaining=lambda a: next(
                    (data_obj(u) for u in overlapping(a.v, a.v, "data")), None),
                getDefinedData=lambda aset, fwd: _It(data_obj(u) for u in overlapping(*aset, "data")
                                                     if u[0] > aset[0]),
                clearCodeUnits=clear,
                createData=lambda a, dt: created.append((a.v, dt.name, list(dt.fields))))
        def getBookmarkManager(s):
            return types.SimpleNamespace(setBookmark=lambda a, typ, cat, txt: bookmarks.append((a.v, cat, txt)))
        def getMemory(s): return types.SimpleNamespace(contains=lambda a: 0x400000 <= a.v < 0x410000)
        def getDataTypeManager(s):
            return DTM

    j = tmp_path / "rd.json"
    j.write_text(json.dumps(data))
    g = {"getScriptArgs": lambda: [str(j)], "currentProgram": Prog(), "__name__": "__main__"}
    exec(SCRIPT.read_text(), g)
    _run.created = created
    _run.cleared = cleared
    _run.bookmarks = bookmarks
    _run.made = made
    return comments, renames


def test_static_records_annotated_and_strongest_tag_names_function(tmp_path, monkeypatch):
    data = {"decoded": [
        # static call-site records: no "function", but decoder + call site
        {"string": "https://c2.example/gate", "decoder": 0x401000, "call": 0x401100, "blob": 0x405000,
         "method": "static", "tags": ["url"]},
        # emulation records: "function"; the url-free string sorts first but the mutex must name it
        {"string": "--skip-update-check", "function": 0x402000, "method": "emulation", "tags": []},
        {"string": "Global\\NW-5c1e9a", "function": 0x402000, "method": "emulation", "tags": ["mutex"]},
    ]}
    comments, renames = _run(tmp_path, monkeypatch, data)
    assert (0x401000, 3) in comments, "static records must be annotated on the decoder function"
    assert "https://c2.example/gate  [url]" in comments[(0x401000, 3)]          # tags are shown
    assert "https://c2.example/gate" in comments[(0x401100, 1)]                 # call-site comment
    assert renames[0x401000].startswith("rd_url_")
    assert renames[0x402000].startswith("rd_mutex_Global_NW"), renames
    assert "[mutex]" in comments[(0x402000, 3)]


def test_rva_records_resolve_through_image_base(tmp_path, monkeypatch):
    data = {"decoded": [{"string": "abcdefgh", "function": 0x3000, "method": "emulation", "tags": []}]}
    comments, renames = _run(tmp_path, monkeypatch, data)
    assert (0x403000, 3) in comments and renames[0x403000] == "rd_str_abcdefgh"


def test_vtables_annotated_and_methods_named(tmp_path, monkeypatch):
    # a recovered vtable at an RVA whose methods are two still-default functions: the vtable gets a
    # plate comment + a RustVtable struct, and both method functions are renamed behind the trait
    data = {"decoded": [], "vtables": [
        {"va": 0x5000, "drop_in_place": 0x1100, "size": 16, "align": 8,
         "methods": [0x2000, 0x3000], "method_count": 2}],
        "ghidra_types": [{"name": "RustVtable_2m", "size": 40, "fields": [
            {"offset": 0, "name": "drop_in_place", "type": "pointer"},
            {"offset": 8, "name": "size", "type": "ulong"},
            {"offset": 16, "name": "align", "type": "ulong"},
            {"offset": 24, "name": "method_0", "type": "pointer"},
            {"offset": 32, "name": "method_1", "type": "pointer"}]}]}
    comments, renames = _run(tmp_path, monkeypatch, data)
    # vtable VA resolves through the image base (0x400000 + 0x5000) and gets a plate comment
    assert (0x405000, 3) in comments and "dyn Trait vtable" in comments[(0x405000, 3)]
    assert "size=16 align=8" in comments[(0x405000, 3)]
    # the two method functions (0x402000, 0x403000 via image base) are renamed behind the trait
    assert renames.get(0x402000, "").startswith("rd_vtmethod_")
    assert renames.get(0x403000, "").startswith("rd_vtmethod_")
    # the struct datatype was laid on the vtable address
    assert [c[:2] for c in _run.created] == [(0x405000, "RustVtable_2m")]


def test_static_and_emulation_records_of_one_function_share_one_plate(tmp_path, monkeypatch):
    # the same function named two ways (static "decoder" int, emulation "function" hex string):
    # both strings must end up on ONE plate comment, not the second overwriting the first
    data = {"decoded": [
        {"string": "https://c2.example/gate", "decoder": 0x401000, "call": 0x401100,
         "method": "static", "tags": ["url"]},
        {"string": "Global\\NW-5c1e9a", "function": "0x401000", "method": "emulation",
         "tags": ["mutex"]},
    ]}
    comments, _ = _run(tmp_path, monkeypatch, data)
    plate = comments[(0x401000, 3)]
    assert "2 decoded string(s)" in plate
    assert "https://c2.example/gate" in plate and "Global\\NW-5c1e9a" in plate


# --------------------------------------------------------------------------------------------
# vtable struct: sizes from the program's pointer size (not Ghidra's C `ulong`), built against the
# program's DataTypeManager, and never laid over someone else's code units
# --------------------------------------------------------------------------------------------
def _vt_data(ptr, count=2, utype=None):
    utype = utype or ("uint" if ptr == 4 else "ulong")        # what recover_types emits
    fields = [{"offset": 0, "name": "drop_in_place", "type": "pointer"},
              {"offset": ptr, "name": "size", "type": utype},
              {"offset": 2 * ptr, "name": "align", "type": utype}]
    fields += [{"offset": (3 + m) * ptr, "name": "method_%d" % m, "type": "pointer"}
               for m in range(count)]
    return {"decoded": [], "vtables": [
        {"va": 0x5000, "size": 16, "align": 8, "methods": [0x2000, 0x3000][:count],
         "method_count": count}],
        "ghidra_types": [{"name": "RustVtable_%dm" % count, "size": (3 + count) * ptr,
                          "fields": fields}]}


def test_field_layout_pure_function(monkeypatch):
    g = _load_helpers(monkeypatch)
    lay = g["_field_layout"]
    spec64 = _vt_data(8)["ghidra_types"][0]
    assert lay(spec64, 8) == [(0, "drop_in_place", "pointer", 8), (8, "size", "uint", 8),
                              (16, "align", "uint", 8), (24, "method_0", "pointer", 8),
                              (32, "method_1", "pointer", 8)]
    spec32 = _vt_data(4)["ghidra_types"][0]
    assert [f[3] for f in lay(spec32, 4)] == [4] * 5
    # a spec built for 8-byte pointers does not fit a 4-byte program (gaps) -> refuse, don't guess
    assert lay(spec64, 4) is None and lay(spec32, 8) is None
    # explicit integer widths are honored
    spec = {"size": 12, "fields": [{"offset": 0, "type": "u64", "name": "a"},
                                   {"offset": 8, "type": "u32", "name": "b"}]}
    assert lay(spec, 4) == [(0, "a", "uint", 8), (8, "b", "uint", 4)]
    # unknown type / overlap / out of bounds / bad size -> None
    assert lay({"size": 8, "fields": [{"offset": 0, "type": "float", "name": "x"}]}, 8) is None
    assert lay({"size": 8, "fields": [{"offset": 0, "type": "pointer"},
                                      {"offset": 4, "type": "uint"}]}, 8) is None
    assert lay({"size": 8, "fields": [{"offset": 4, "type": "pointer"}]}, 8) is None
    assert lay({"size": 0, "fields": []}, 8) is None and lay(spec64, None) is None


def test_range_action_pure_function(monkeypatch):
    act = _load_helpers(monkeypatch)["_range_action"]
    assert act([]) == "create"
    assert act([("data", "undefined8", "/")]) == "create"
    assert act([("data", "RustVtable_2m", "/rust-deobf")]) == "replace"
    assert act([("instruction", None, None)]) == "skip"
    assert act([("data", "pointer", "/")]) == "skip"
    assert act([("data", "RustVtable_2m", "/rust-deobf"), ("data", "dword", "/")]) == "skip"


def test_vtable_struct_uses_pointer_sized_ints_on_llp64(tmp_path, monkeypatch):
    """PE x64: Ghidra's `ulong` is 4 bytes, so building size/align from UnsignedLongDataType made
    them too small. They must be 8-byte (UnsignedLongLong) fields, built with the program's DTM."""
    _run(tmp_path, monkeypatch, _vt_data(8), ptr_size=8)
    (va, name, fields), = _run.created
    assert (va, name) == (0x405000, "RustVtable_2m")
    assert fields == [(0, "drop_in_place", "PointerDataType", 8),
                      (8, "size", "UnsignedLongLongDataType", 8),
                      (16, "align", "UnsignedLongLongDataType", 8),
                      (24, "method_0", "PointerDataType", 8),
                      (32, "method_1", "PointerDataType", 8)]
    assert ("UnsignedLongDataType", 4) not in _run.made


def test_vtable_struct_32bit_program(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, _vt_data(4), ptr_size=4)
    (_, _, fields), = _run.created
    assert [(f[2], f[3]) for f in fields] == [("PointerDataType", 4), ("UnsignedIntegerDataType", 4),
                                              ("UnsignedIntegerDataType", 4), ("PointerDataType", 4),
                                              ("PointerDataType", 4)]


def test_vtable_spec_mismatching_pointer_size_is_skipped(tmp_path, monkeypatch, capsys):
    comments, _ = _run(tmp_path, monkeypatch, _vt_data(8), ptr_size=4)
    assert _run.created == []
    assert (0x405000, 3) in comments                     # the comment is still there
    assert "does not fit" in capsys.readouterr().out


def test_vtable_not_laid_over_existing_ghidra_data(tmp_path, monkeypatch, capsys):
    """Observational: Ghidra's own data (or an instruction) under the heuristic vtable stays put."""
    for unit in [(0x405008, 0x40500f, "data", "pointer", "/"),
                 (0x404ff8, 0x405007, "data", "qword", "/"),          # starts before, overlaps
                 (0x405010, 0x405013, "instruction", None, None)]:
        comments, _ = _run(tmp_path, monkeypatch, _vt_data(8), existing=[unit])
        assert _run.created == [] and _run.cleared == [], unit
        assert (0x405000, 3) in comments
        assert "existing code/data" in capsys.readouterr().out


def test_vtable_relaid_over_our_own_type_or_undefined(tmp_path, monkeypatch):
    _run(tmp_path, monkeypatch, _vt_data(8),
         existing=[(0x405000, 0x405027, "data", "RustVtable_2m", "/rust-deobf")])
    assert _run.cleared == [(0x405000, 0x405027)] and len(_run.created) == 1
    _run(tmp_path, monkeypatch, _vt_data(8),
         existing=[(0x405000, 0x405007, "data", "undefined8", "/")])
    assert _run.cleared == [] and len(_run.created) == 1


# --------------------------------------------------------------------------------------------
# ghidra_run.sh: a binary whose name starts with '-' must not be parsed as an option
# --------------------------------------------------------------------------------------------
def test_ghidra_run_handles_dash_leading_binary_name(tmp_path):
    """Drive the real wrapper with a fake Ghidra install and a fake `python3` that stands in only
    for the pyghidra import check and launcher (recover.py / recover_types.py run for real)."""
    import os
    import shutil
    import subprocess
    if shutil.which("bash") is None:
        import pytest
        pytest.skip("bash not available")
    ghidra = tmp_path / "ghidra"
    (ghidra / "Ghidra").mkdir(parents=True)
    fakebin = tmp_path / "bin"
    fakebin.mkdir()
    log, seen_json = tmp_path / "launch.args", tmp_path / "launch.json"
    fake = fakebin / "python3"
    fake.write_text(
        "#!/usr/bin/env bash\n"
        'if [ "$1" = "-c" ] && [ "$2" = "import pyghidra" ]; then exit 0; fi\n'
        'if [ "$1" = "-m" ] && [ "$2" = "pyghidra.ghidra_launch" ]; then\n'
        '  printf "%%s\\n" "$@" > "%s"; cp "${@: -1}" "%s"; exit 0\n'
        "fi\n"
        'exec "%s" "$@"\n' % (log, seen_json, sys.executable))
    fake.chmod(0o755)
    work = tmp_path / "work"
    work.mkdir()
    shutil.copy(ROOT / "tests" / "fixtures" / "emu" / "pe64.exe", work / "-sample.exe")
    env = dict(os.environ, PATH="%s:%s" % (fakebin, os.environ.get("PATH", "")),
               GHIDRA_INSTALL_DIR=str(ghidra), TMPDIR=str(tmp_path))
    p = subprocess.run(["bash", str(ROOT / "scripts" / "ghidra_run.sh"), "-sample.exe", "",
                        str(tmp_path / "proj")],
                       cwd=work, env=env, capture_output=True, text=True, timeout=300)
    assert p.returncode == 0, p.stdout + p.stderr
    rec = json.loads(seen_json.read_text())
    assert rec["format"] == "PE"                     # recover.py analyzed the '-' file
    assert "vtables" in rec and "ghidra_types" in rec   # recover_types.py ran and was merged
    assert "fmt_sites" in rec["idioms"]                 # recover_idioms.py ran and was merged
    args = log.read_text().splitlines()
    assert args[args.index("-import") + 1] == "./-sample.exe"


# --------------------------------------------------------------------------------------------
# Rust idioms (recover_idioms.py): pure plan + application through the stubbed API
# --------------------------------------------------------------------------------------------
IDIOMS = {
    "fmt_sites": [{"site": 0x1100, "macro": "println!", "format": "hello {} you are {}", "sink": "print"},
                  {"site": 0x2100, "macro": "panic!", "format": "too many: {}", "location": "src/main.rs:9:5"}],
    "panic_sites": [{"site": 0x2100, "kind": "panic", "label": "panic!", "safety_check": False,
                     "location": "src/main.rs:9:5"},
                    {"site": 0x1200, "kind": "bounds_check", "label": "index out of bounds",
                     "safety_check": True, "location": "src/main.rs:4:7", "guard": 0x11f0,
                     "guard_branch": "ja"}],
    "drop_sites": [{"site": 0x1300, "kind": "dealloc"}, {"site": 0x1310, "kind": "drop_glue"}],
    "helpers": [{"va": 0x3000, "role": "panic", "kind": "bounds_check", "via": "anchor"},
                {"va": 0x3100, "role": "dealloc", "kind": "dealloc", "via": "anchor"},
                {"va": 0x2000, "role": "drop_glue", "kind": "drop_glue", "via": "inferred"},
                {"va": 0x3300, "role": "drop_glue", "kind": "drop_glue", "via": "inferred"}],
    "enum_returns": [{"va": 0x1000, "shape": "tag+payload", "confidence": "high",
                      "note": "returns enum-like value (Option/Result?)",
                      "evidence": ["2/2 caller(s) test the returned tag (rax) then use the payload (rdx)"]}],
}


def test_idiom_plan_is_pure_and_complete(monkeypatch):
    plan = _load_helpers(monkeypatch)["_idiom_plan"](IDIOMS)
    pre = {a[1]: a[2] for a in plan if a[0] == "pre"}
    assert 'println!("hello {} you are {}")' in pre[0x1100]
    assert "safety check (cold path): index out of bounds  @ src/main.rs:4:7" in pre[0x1200]
    assert "panic path (cold): panic!" in [a[2] for a in plan if a[0] == "pre" and a[1] == 0x2100][1]
    eol = {a[1]: a[2] for a in plan if a[0] == "eol"}
    assert eol[0x11f0].startswith("rust-deobf: cold branch -> index out of bounds")
    assert eol[0x1300] == "rust-deobf: dealloc" and eol[0x1310] == "rust-deobf: drop"
    bms = [(a[1], a[2]) for a in plan if a[0] == "bookmark"]
    assert (0x11f0, "rust-deobf: safety-check") in bms          # on the guard, not the call
    assert (0x2100, "rust-deobf: safety-check") in bms          # no guard: on the call site
    renames = {a[1]: a[2] for a in plan if a[0] == "rename"}
    # unique names: a kind that occurs twice gets the address as a suffix
    assert renames == {0x3000: "rd_panic_bounds_check", 0x3100: "rd_rust_dealloc",
                       0x2000: "rd_drop_glue_2000", 0x3300: "rd_drop_glue_3300"}
    plate = [a[2] for a in plan if a[0] == "plate_add" and a[1] == 0x1000]
    assert plate and "returns enum-like value (Option/Result?) [tag+payload, confidence high]" in plate[0]
    # malformed input never raises
    g = _load_helpers(monkeypatch)
    assert g["_idiom_plan"](None) == [] and g["_idiom_plan"]({"fmt_sites": [{"site": "zz"}]}) == []
    assert g["_merge_plate"]("a", "b") == "a\nb" and g["_merge_plate"]("a\nb", "b") == "a\nb"


def test_idioms_applied_without_clobbering_string_plates(tmp_path, monkeypatch):
    """The decoded-strings plate on 0x401000 survives the idiom plate line appended to it; only
    default-named functions are renamed; addresses resolve through the image base (RVAs)."""
    data = {"decoded": [{"string": "https://c2.example/gate", "function": 0x401000,
                         "method": "emulation", "tags": ["url"]}],
            "idioms": IDIOMS}
    comments, renames = _run(tmp_path, monkeypatch, data)
    plate = comments[(0x401000, 3)]
    assert "1 decoded string(s)" in plate and "returns enum-like value" in plate
    assert 'println!("hello {} you are {}")' in comments[(0x401100, 1)]
    # one address with a fmt site AND a panic site: both lines in one pre comment
    both = comments[(0x402100, 1)]
    assert 'panic!("too many: {}")' in both and "panic path (cold)" in both
    assert comments[(0x4011f0, 0)].startswith("rust-deobf: cold branch")
    assert ("rust-deobf: safety-check") in {c for _a, c, _t in _run.bookmarks}
    # 0x401000 was renamed after its decoded string first; the helper rename only touches
    # still-default names (0x403000 -> rd_panic_bounds_check; 0x402000 drop glue)
    assert renames[0x401000].startswith("rd_url_")
    assert renames[0x403000] == "rd_panic_bounds_check" and renames[0x402000] == "rd_drop_glue_2000"


def test_idiom_comment_merges_with_decoder_call_site_comment(tmp_path, monkeypatch):
    """A call site that both decodes a string and is a fmt site keeps both lines."""
    data = {"decoded": [{"string": "abcdefgh", "decoder": 0x401000, "call": 0x401100,
                         "method": "static", "tags": []}],
            "idioms": {"fmt_sites": [{"site": 0x1100, "macro": "println!", "format": "x={}"}]}}
    comments, _ = _run(tmp_path, monkeypatch, data)
    pre = comments[(0x401100, 1)]
    assert "rust-deobf decodes: abcdefgh" in pre and 'println!("x={}")' in pre


def test_idioms_json_passed_directly(tmp_path, monkeypatch):
    """`ghidra_annotate.py idioms.json` with recover_idioms --json output (no recover.py keys)."""
    comments, _ = _run(tmp_path, monkeypatch, dict(IDIOMS))
    assert 'println!("hello {} you are {}")' in comments[(0x401100, 1)]
