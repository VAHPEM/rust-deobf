"""decompiler_selfcheck.py against the plugin stand-ins (tests/decompiler_mocks.py), reading a real
fixture's function starts. The real-decompiler run is the maintainer's (VALIDATION.md)."""
import json
import subprocess
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import decompiler_bridge as DB  # noqa: E402
import decompiler_selfcheck as SC  # noqa: E402
from decompiler_mocks import GhidraLegacy, GhidraV2, Ida  # noqa: E402

VT = ROOT / "tests" / "fixtures" / "emu" / "vt32"
BASE = 0x10000                                    # Ghidra's usual base for a 32-bit PIE


def _ghidra_vt(**kw):
    hdr, funcs = SC.local_functions(VT)
    fs = {BASE + a: ("FUN_%08x" % (BASE + a), [BASE + a, BASE + a + 4]) for a, _ in funcs}
    return GhidraV2(BASE, fs, entry_points=[BASE + hdr["entry"]], fmt="ELF", **kw), hdr, funcs


def test_local_functions_from_the_fixture():
    hdr, funcs = SC.local_functions(VT)
    assert hdr["address_space"] == "va" and hdr["entry"] == 0x12e0
    assert [a for a, _ in funcs] == [0x12a0, 0x12b0, 0x12c0, 0x12e0]


def test_ghidra_v2_all_checks_pass_and_roundtrip_restores():
    g, hdr, funcs = _ghidra_vt(sha256=DB._sha256(VT))
    with g:
        g.comments[("EOL", BASE + 0x12a0)] = "analyst"
        be = DB.make_backend("ghidra-mcp", g.url, rate=0)
        info = be.connect()
        checks = SC.run_checks(be, info, hdr, funcs, sha256=DB._sha256(VT), write_test=True)
        st = {c["check"]: c["status"] for c in checks}
        assert st == {"connect": "PASS", "identity": "PASS", "mapping": "PASS",
                      "functions": "PASS", "roundtrip write": "PASS", "roundtrip restore": "PASS"}
        assert g.comments == {("EOL", BASE + 0x12a0): "analyst"}
        writes = [p["params"]["comment"] for p in g.posts()]
        assert writes[0].startswith("analyst\n" + DB.PREFIX + "selfcheck ") and writes[1] == "analyst"


def test_wrong_program_and_wrong_base_fail():
    g, hdr, funcs = _ghidra_vt(sha256="0" * 64)
    with g:
        be = DB.make_backend("ghidra-mcp", g.url, rate=0)
        info = be.connect()
        st = {c["check"]: c["status"] for c in
              SC.run_checks(be, info, hdr, funcs, sha256=DB._sha256(VT), image_base=0x400000)}
        assert st["identity"] == "FAIL" and st["mapping"] == "FAIL"
        assert not g.posts()


def test_ghidra_legacy_cannot_clear_is_a_warning():
    hdr, funcs = SC.local_functions(VT)
    with GhidraLegacy({BASE + a: ("FUN_%x" % a, [BASE + a]) for a, _ in funcs}) as g:
        be = DB.make_backend("ghidra-mcp", g.url, rate=0)
        info = be.connect()
        checks = SC.run_checks(be, info, hdr, funcs, image_base=BASE, write_test=True)
        st = {c["check"]: c["status"] for c in checks}
        assert st["mapping"] == "PASS" and st["roundtrip write"] == "PASS"
        assert st["roundtrip restore"] == "WARN"


def test_ida_roundtrip_via_py_eval_and_skip_without_it():
    hdr, funcs = SC.local_functions(VT)
    fs = {a: ("sub_%X" % a, a + 0x10) for a, _ in funcs}               # IDA keeps a PIE at 0
    with Ida(0, fs) as ida:
        ida.cmts[0x12a0] = "analyst"
        be = DB.make_backend("ida-mcp", ida.url, rate=0)
        info = be.connect()
        st = {c["check"]: c["status"] for c in SC.run_checks(be, info, hdr, funcs, write_test=True)}
        assert st["roundtrip write"] == "PASS" and st["roundtrip restore"] == "PASS"
        assert ida.cmts[0x12a0] == "analyst"
    with Ida(0, fs, py_eval=False) as ida:
        be = DB.make_backend("ida-mcp", ida.url, rate=0)
        info = be.connect()
        st = {c["check"]: c["status"] for c in SC.run_checks(be, info, hdr, funcs, write_test=True)}
        assert st["roundtrip"] == "SKIP" and st["mapping"] == "PASS"


def test_cli_json_and_exit_codes():
    g, _hdr, _funcs = _ghidra_vt()
    with g:
        p = subprocess.run([sys.executable, str(ROOT / "scripts" / "decompiler_selfcheck.py"),
                            str(VT), "--backend", "ghidra-mcp", "--url", g.url, "--json"],
                           capture_output=True, text=True, timeout=120)
        assert p.returncode == 0, p.stderr
        rep = json.loads(p.stdout)
        assert rep["ok"] and {c["check"] for c in rep["checks"]} >= {"mapping", "functions"}
        assert not g.posts()                                        # read-only without --write-test
        p = subprocess.run([sys.executable, str(ROOT / "scripts" / "decompiler_selfcheck.py"),
                            str(VT), "--backend", "ghidra-mcp", "--url", g.url,
                            "--image-base", "0x400000"], capture_output=True, text=True, timeout=120)
        assert p.returncode == 1 and "RESULT: FAIL" in p.stdout
    p = subprocess.run([sys.executable, str(ROOT / "scripts" / "decompiler_selfcheck.py"), str(VT),
                        "--backend", "ida-mcp", "--url", "http://127.0.0.1:9/mcp", "--timeout", "3"],
                       capture_output=True, text=True, timeout=120)
    assert p.returncode == DB.EXIT_BACKEND and "cannot reach" in p.stderr
