"""ghidra_annotate.py logic, run against a stubbed Ghidra API (no Ghidra needed)."""
import json
import sys
import types

from conftest import ROOT

SCRIPT = ROOT / "scripts" / "ghidra_annotate.py"


def _run(tmp_path, monkeypatch, data):
    for m in ("ghidra", "ghidra.program", "ghidra.program.model", "ghidra.program.model.symbol",
              "ghidra.program.model.listing", "ghidra.program.model.data"):
        monkeypatch.setitem(sys.modules, m, types.ModuleType(m))
    sys.modules["ghidra.program.model.symbol"].SourceType = types.SimpleNamespace(ANALYSIS="A")
    sys.modules["ghidra.program.model.listing"].CodeUnit = types.SimpleNamespace(PLATE_COMMENT=3, PRE_COMMENT=1)

    # minimal stubs for the vtable-datatype path
    class _DT:
        def __init__(s, n=8): s._n = n
        def getLength(s): return s._n

    class Struct:
        def __init__(s, cat, name, size): s.name = name; s._n = size; s.fields = []
        def replaceAtOffset(s, off, dt, ln, nm, cmt): s.fields.append((off, nm))
        def getLength(s): return s._n
    dmod = sys.modules["ghidra.program.model.data"]
    dmod.StructureDataType = Struct
    dmod.PointerDataType = lambda: _DT(8)
    dmod.UnsignedLongDataType = lambda: _DT(8)
    dmod.CategoryPath = lambda p: p
    comments, renames, created = {}, {}, []

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
        def getListing(s):
            return types.SimpleNamespace(
                setComment=lambda a, k, t: comments.__setitem__((a.v, k), t),
                clearCodeUnits=lambda a, b, c: None,
                createData=lambda a, dt: created.append((a.v, dt.name)))
        def getBookmarkManager(s): return types.SimpleNamespace(setBookmark=lambda *a: None)
        def getMemory(s): return types.SimpleNamespace(contains=lambda a: 0x400000 <= a.v < 0x410000)
        def getDataTypeManager(s):
            return types.SimpleNamespace(addDataType=lambda dt, h: dt)

    j = tmp_path / "rd.json"
    j.write_text(json.dumps(data))
    g = {"getScriptArgs": lambda: [str(j)], "currentProgram": Prog(), "__name__": "__main__"}
    exec(SCRIPT.read_text(), g)
    _run.created = created
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
    assert (0x405000, "RustVtable_2m") in _run.created


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
