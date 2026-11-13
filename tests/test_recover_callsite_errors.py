"""recover_callsite.py's error path, run as a process (what CI and callers see).

Pins the P5 fixes: an input that cannot be parsed (missing, unreadable, not a binary) is a clear
`ValueError: cannot parse ...` row and exit 1 -- it used to surface as an AttributeError -- and one
bad target does not lose the rest of a batch; an unknown `--flag` is a usage error (exit 2) and is
never taken for a target path; `--selftest` runs without a binary and writes nothing under build/.
Every analysis run here uses `--json`, which never writes build/recover_callsite_results.jsonl.
"""
import json
import os
import subprocess
import sys

import pytest
from conftest import ROOT

SCRIPT = ROOT / "scripts" / "recover_callsite.py"
RESULTS = ROOT / "build" / "recover_callsite_results.jsonl"


def _run(*args):
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                          capture_output=True, text=True, timeout=300)


def _results_state():
    """What the results file looks like now (None = absent), to show a run left it alone."""
    if not RESULTS.exists():
        return None
    st = RESULTS.stat()
    return RESULTS.read_bytes(), st.st_mtime_ns


def _rows(out):
    data = json.loads(out.stdout)
    return data if isinstance(data, list) else [data]


def _assert_cannot_parse(target):
    out = _run("--json", target)
    assert out.returncode == 1, out.stdout + out.stderr
    (row,) = _rows(out)
    assert row["target"] == str(target)
    assert row["error"].startswith("ValueError: cannot parse"), row
    assert "AttributeError" not in out.stdout + out.stderr


def test_missing_input(tmp_path):
    _assert_cannot_parse(tmp_path / "does_not_exist.bin")


def test_text_input(tmp_path):
    p = tmp_path / "notes.txt"
    p.write_text("not an executable\n")
    _assert_cannot_parse(p)


def test_directory_input(tmp_path):
    _assert_cannot_parse(tmp_path)


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="chmod 000 does not stop reads on Windows or as root")
def test_unreadable_input(tmp_path):
    import recover_callsite
    p = tmp_path / "locked.elf"
    p.write_bytes(recover_callsite._selftest_elf(b"k" * 8, [b"hello"]))
    p.chmod(0)
    try:
        _assert_cannot_parse(p)
    finally:
        p.chmod(0o600)


@pytest.mark.parametrize("bad_first", [False, True], ids=["good-bad", "bad-good"])
def test_mixed_batch_keeps_good_row(tmp_path, bad_first):
    import recover_callsite
    good = tmp_path / "good.elf"
    good.write_bytes(recover_callsite._selftest_elf(bytes.fromhex("5a13c72e914b08e6"),
                                                    [b"call-site string"]))
    bad = tmp_path / "missing.bin"
    targets = [bad, good] if bad_first else [good, bad]
    out = _run("--json", *targets)
    assert out.returncode == 1, out.stdout + out.stderr
    rows = {r["target"]: r for r in _rows(out)}
    assert set(rows) == {str(good), str(bad)}
    assert rows[str(bad)]["error"].startswith("ValueError: cannot parse")
    assert not rows[str(good)].get("error"), rows[str(good)]
    assert rows[str(good)]["decoders"] == 1


def test_unknown_flag_is_usage_error():
    before = _results_state()
    out = _run("--bogus")
    assert out.returncode == 2, out.stdout + out.stderr
    assert "unknown option" in out.stderr and "--bogus" in out.stderr
    assert out.stdout == ""
    assert _results_state() == before          # not taken for a target, nothing written


def test_selftest_writes_nothing_under_build():
    before = _results_state()
    out = _run("--selftest")
    assert out.returncode == 0, out.stdout + out.stderr
    assert "selftest OK" in out.stdout
    assert _results_state() == before
