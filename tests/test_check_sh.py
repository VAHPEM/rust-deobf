"""scripts/check.sh regressions (Oct 2026 review): exit codes must mean something, and the
<name> mode must find the module's real test file. Commands run under CHECK_DRY_RUN=1 or with a
fake $PYTHON, so nothing heavy executes."""
import os
import shutil
import stat
import subprocess
import sys

import pytest
from conftest import ROOT

CHECK = ROOT / "scripts" / "check.sh"
pytestmark = pytest.mark.skipif(sys.platform == "win32" or shutil.which("bash") is None,
                                reason="check.sh is a bash script (POSIX hosts)")


def _run(*args, env=None):
    e = dict(os.environ, **(env or {}))
    return subprocess.run(["bash", str(CHECK), *args], capture_output=True, text=True, env=e,
                          cwd=ROOT, timeout=120)


def _fake_python(tmp_path, fail_on):
    """A $PYTHON stand-in that exits 1 when its argv contains `fail_on`, else 0."""
    p = tmp_path / "fakepy"
    p.write_text(f'#!/bin/sh\ncase "$*" in *{fail_on}*) exit 1;; esac\nexit 0\n')
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def test_unknown_module_is_a_usage_error():
    r = _run("recover_cryptoo")                          # a typo used to "pass" with exit 0
    assert r.returncode == 2 and "unknown module" in r.stderr


@pytest.mark.parametrize("name,testfile", [
    ("fuzz_recover", "tests/test_fuzz.py"),
    ("deobf_opaque", "tests/test_opaque.py"),
    ("deobf_deflatten", "tests/test_deflatten.py"),
    ("deobf_expr", "tests/test_expr_rustcloak.py"),
    ("unpack_emulate", "tests/test_unpack.py"),
    ("unpack", "tests/test_unpack_unified.py"),
    ("recover_emulate", "tests/test_emulate_regressions.py"),
    ("recover_crypto", "tests/test_crypto.py"),
    ("scripts/recover_enums.py", "tests/test_enums.py"),
])
def test_module_maps_to_its_real_test_file(name, testfile):
    assert (ROOT / testfile).is_file(), testfile
    r = _run(name, env={"CHECK_DRY_RUN": "1"})
    assert r.returncode == 0, r.stderr
    assert f"pytest {testfile} -q" in r.stdout, r.stdout


def test_premium_module_is_found():
    r = _run("deobf_opaque", env={"CHECK_DRY_RUN": "1"})
    assert r.returncode == 0 and "unknown module" not in r.stderr


def test_selftest_failure_is_not_swallowed(tmp_path):
    r = _run("fuzz_recover", env={"PYTHON": _fake_python(tmp_path, "--selftest")})
    assert r.returncode == 1, (r.stdout, r.stderr)


def test_test_failure_is_reported_even_when_selftest_passes(tmp_path):
    r = _run("fuzz_recover", env={"PYTHON": _fake_python(tmp_path, "pytest")})
    assert r.returncode == 1, (r.stdout, r.stderr)


def test_changed_with_missing_base_ref_is_an_error():
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    r = _run("changed", "no-such-ref-for-check-sh-test")
    assert r.returncode == 2 and "does not exist" in r.stderr


def test_changed_with_valid_base_runs(tmp_path):
    if not (ROOT / ".git").exists():
        pytest.skip("not a git checkout")
    r = _run("changed", "HEAD", env={"CHECK_DRY_RUN": "1", "TMPDIR": str(tmp_path),
                                     "PYTHON": _fake_python(tmp_path, "never-matches")})
    assert r.returncode == 0, r.stderr
    assert [p.name for p in tmp_path.iterdir()] == ["fakepy"]     # its temp list was removed
