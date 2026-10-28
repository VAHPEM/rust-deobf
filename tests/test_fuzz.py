"""Robustness regression: crafted/malformed binaries must not hang, OOM or crash the analyzer.

fuzz_recover.py found inputs that hung the emulation engine for effectively forever -- a section
whose size / VirtualSize field is enormous made two loops (`Emulator._fresh`'s page snapshot and
`_writable_sections`'s zero-padding) iterate over, or allocate, the whole bogus span before any
time budget applied. A hang/OOM on one sample would take down an analyst's batch run. The fixes cap
both at the same _seg_extent (_SEG_CAP) the mapper uses.

These committed reproducers are mutations of the repo's own benign canary fixtures (no malware, no
live indicators -- just corrupted benign binaries). Each one used to hang; each must now finish
cleanly. The harness's own --selftest (pinned-corpus + classifier) runs via test_selftests.py; this
pins the concrete reproducers end to end through the isolated runner.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import fuzz_recover  # noqa: E402

FUZZ_DIR = ROOT / "tests" / "fixtures" / "fuzz"
REPRODUCERS = sorted(FUZZ_DIR.glob("*.bin"))

# lief emits RuntimeWarnings while parsing these deliberately-malformed fixtures ("not a valid
# TYPE", "no content"); they are the expected noise of feeding a parser garbage, not test signal.
pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


@pytest.mark.parametrize("path", REPRODUCERS, ids=[p.name for p in REPRODUCERS])
def test_reproducer_does_not_hang_or_crash(path):
    """Each saved reproducer finishes inside the isolated runner (a hang would be a finding).

    A generous 60 s timeout: the fix brings each back to well under a second, so this is slack for
    a loaded CI runner, not a tight bound -- before the fix the same inputs ran past any timeout."""
    data = path.read_bytes()
    findings = fuzz_recover.run_isolated(data, time_budget=1.0, timeout=60.0,
                                         rlimit_mb=fuzz_recover.DEFAULT_RLIMIT_MB,
                                         active={"image", "emulate", "run", "triage"})
    assert findings == [], f"{path.name}: {findings}"


@pytest.mark.parametrize("path", REPRODUCERS, ids=[p.name for p in REPRODUCERS])
def test_reproducer_in_process_clean(path):
    """In-process, every target on each reproducer stays within the robustness contract (no
    uncontrolled exception, no hardened front end raising)."""
    findings = fuzz_recover.run_targets(path.read_bytes(), time_budget=1.0)
    assert findings == [], f"{path.name}: {findings}"


def test_harness_selftest_runs():
    """The harness's own pinned-corpus + classifier self-test passes in-process (also run as a CLI
    by test_selftests.py; here it guards against an import-time break)."""
    fuzz_recover._selftest()


def test_classifier_contract():
    # a controlled parse rejection is not a finding; an uncontrolled failure is
    assert fuzz_recover.classify("image", False, ValueError("no .text")) is None
    assert fuzz_recover.classify("emulate", False, MemoryError()) is not None
    assert fuzz_recover.classify("emulate", False, RecursionError()) is not None
    # a never-raise front end raising anything at all is a finding
    assert fuzz_recover.classify("run", True, ValueError("x")) is not None
    # triage's documented UnsupportedInput signal (by type name) is controlled
    class UnsupportedInput(Exception):
        pass
    assert fuzz_recover.classify("triage", False, UnsupportedInput("not a binary")) is None


# ------------------------------------------------------------------------------------------------
# harness regressions (Oct 2026 review): isolation, temp files, Ctrl-C, dedup, CLI validation
# ------------------------------------------------------------------------------------------------
import os  # noqa: E402
import random  # noqa: E402
import tempfile  # noqa: E402
import time  # noqa: E402

import fuzz_helpers  # noqa: E402


@pytest.fixture
def own_tmpdir(tmp_path, monkeypatch):
    """Point the OS temp dir at a private directory so leaked temp files are visible."""
    d = tmp_path / "osTemp"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
    return d


def test_isolated_large_result_is_read_not_misreported_as_hang():
    # a >64 KB result used to deadlock (join before reading the queue) and come back as a "hang"
    t = time.monotonic()
    r = fuzz_recover.run_isolated(b"\x7fELF", time_budget=0.5, timeout=20.0, rlimit_mb=0,
                                  targets_fn=fuzz_helpers.big_result)
    assert time.monotonic() - t < 15, "worker result was not read before join"
    assert len(r) == 1 and r[0]["exc_type"] == "MemoryError" and "hang" not in r[0]["reason"], r


def test_isolated_hang_is_attributed_and_leaks_no_temp_files(own_tmpdir):
    r = fuzz_recover.run_isolated(b"\x7fELF" + b"A" * 1000, time_budget=0.5, timeout=2.0,
                                  rlimit_mb=0, targets_fn=fuzz_helpers.hang)
    assert len(r) == 1 and r[0]["reason"].startswith("hang"), r
    assert r[0]["target"] == "meta", r                 # attributed from the worker's progress log
    assert any("stuck_in_parser" in f for f in r[0]["frames"]), r[0]   # watchdog stack dump
    # the killed worker could not clean up; the parent owns and removes both temp files
    assert sorted(os.listdir(own_tmpdir)) == []


def test_isolated_native_crash_is_attributed(own_tmpdir):
    r = fuzz_recover.run_isolated(b"\x7fELF", time_budget=0.5, timeout=20.0, rlimit_mb=0,
                                  targets_fn=fuzz_helpers.native_abort)
    assert len(r) == 1 and r[0]["target"] == "strings", r
    assert "signal" in r[0]["reason"] or "exited" in r[0]["reason"], r
    assert sorted(os.listdir(own_tmpdir)) == []


def test_isolated_clean_run_has_no_findings(own_tmpdir):
    assert fuzz_recover.run_isolated(b"x", 0.5, 20.0, 0, targets_fn=fuzz_helpers.clean) == []
    assert sorted(os.listdir(own_tmpdir)) == []


def test_temp_files_use_os_temp_dir_not_slash_tmp(own_tmpdir):
    # Windows has no /tmp: the old hard-coded fallback raised FileNotFoundError '\\tmp\\...'
    p = fuzz_recover._mktemp()
    try:
        assert p.parent == own_tmpdir and p.name.startswith(".fuzz_recover_")
    finally:
        p.unlink()
    fuzz_recover.run_targets(b"\x7fELF", targets_fn=fuzz_helpers.clean)
    assert sorted(os.listdir(own_tmpdir)) == []
    assert '"/tmp"' not in (ROOT / "scripts" / "fuzz_recover.py").read_text()


def test_isolation_falls_back_to_spawn_without_forkserver(monkeypatch):
    import multiprocessing as mp
    monkeypatch.setattr(mp, "get_all_start_methods", lambda: ["spawn"])     # e.g. Windows
    assert fuzz_recover._isolation_ctx().get_start_method() == "spawn"


def test_rlimit_is_skipped_without_resource_module(monkeypatch):
    monkeypatch.setitem(sys.modules, "resource", None)       # Windows: no `resource`
    fuzz_recover._apply_rlimit(64)                            # must not raise


def _interrupting(_tb, _active):
    def stop(_p):
        raise KeyboardInterrupt
    return [("image", stop, False)]


def test_ctrl_c_is_not_a_finding_and_stops_the_campaign(tmp_path):
    with pytest.raises(KeyboardInterrupt):
        fuzz_recover.run_targets(b"\x7fELF", targets_fn=_interrupting)
    with pytest.raises(KeyboardInterrupt):
        fuzz_recover.campaign([b"\x7fELF"], runs=10, deadline=None, rng=random.Random(1),
                              time_budget=0.1, isolate=False, timeout=5, rlimit_mb=0,
                              crash_dir=tmp_path / "c", verbose=False, targets_fn=_interrupting)
    assert not (tmp_path / "c").exists() or not list((tmp_path / "c").iterdir())
    assert KeyboardInterrupt not in fuzz_recover._UNCONTROLLED


def _two_bugs(_tb, _active):
    def by_first_byte(p):
        if p.read_bytes()[:1] in (b"A",):
            raise MemoryError
        raise RecursionError
    return [("image", by_first_byte, False)]


def test_findings_grouped_by_root_cause_not_input_hash(tmp_path):
    rng = random.Random(3)
    res = fuzz_recover.campaign([b"A" + bytes(600), b"B" + bytes(600)], runs=40, deadline=None,
                                rng=rng, time_budget=0.1, isolate=False, timeout=5, rlimit_mb=0,
                                crash_dir=tmp_path, verbose=False, meta={"seed": 3},
                                targets_fn=_two_bugs)
    kinds = sorted(g["exc_type"] for g in res)
    assert kinds == ["MemoryError", "RecursionError"], res     # 2 root causes, not ~40 inputs
    assert sum(g["count"] for g in res) == 40
    assert len(list(tmp_path.glob("*.bin"))) == 2
    notes = "".join(p.read_text(encoding="utf-8") for p in tmp_path.glob("*.txt"))
    assert "seed: 3" in notes and "hits:" in notes


def test_seed_is_chosen_printed_and_recorded(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(fuzz_recover, "_targets", _two_bugs)
    rc = fuzz_recover.main(["--runs", "3", "--no-fixture-seeds", "--no-isolate",
                            "--crash-dir", str(tmp_path)])
    assert rc == fuzz_recover.EXIT_FINDINGS
    out = capsys.readouterr().out
    import re
    m = re.search(r"seed=(\d+)", out)
    assert m, out
    note = next(tmp_path.glob("*.txt")).read_text(encoding="utf-8")
    assert f"seed: {m.group(1)}" in note and "isolate: False" in note and "time_budget:" in note
    assert "targets: image" in note


def test_unknown_target_name_is_a_usage_error(capsys):
    rc = fuzz_recover.main(["--targets", "imgae", "--runs", "1", "--no-fixture-seeds"])
    assert rc == fuzz_recover.EXIT_USAGE
    assert "imgae" in capsys.readouterr().err


def test_reproduce_honours_isolate_and_timeout(tmp_path, monkeypatch):
    seen = {}

    def fake_isolated(data, time_budget, timeout, rlimit_mb, active=None, targets_fn=None):
        seen.update(timeout=timeout, data=data)
        return [{"target": "meta", "reason": "hang (> 2s wall clock)", "traceback": ""}]
    monkeypatch.setattr(fuzz_recover, "run_isolated", fake_isolated)
    monkeypatch.setattr(fuzz_recover, "run_targets",
                        lambda *a, **k: pytest.fail("--isolate replay ran in-process"))
    f = tmp_path / "in.bin"
    f.write_bytes(b"\x7fELF")
    rc = fuzz_recover.main(["--reproduce", str(f), "--isolate", "--timeout", "2"])
    assert rc == fuzz_recover.EXIT_FINDINGS and seen == {"timeout": 2.0, "data": b"\x7fELF"}


def test_atheris_instruments_before_setup(monkeypatch):
    import contextlib
    import types
    calls = []

    @contextlib.contextmanager
    def instrument_imports():
        calls.append("instrument")
        yield
    fake = types.SimpleNamespace(instrument_imports=instrument_imports,
                                 Setup=lambda argv, fn: calls.append("Setup"),
                                 Fuzz=lambda: calls.append("Fuzz"))
    monkeypatch.setitem(sys.modules, "atheris", fake)
    assert fuzz_recover.atheris_main([], 0.1, {"detect"}) == fuzz_recover.EXIT_OK
    assert calls == ["instrument", "Setup", "Fuzz"]

    calls.clear()
    old = types.SimpleNamespace(instrument_all=lambda: calls.append("instrument_all"),
                                Setup=lambda argv, fn: calls.append("Setup"),
                                Fuzz=lambda: calls.append("Fuzz"))
    monkeypatch.setitem(sys.modules, "atheris", old)
    assert fuzz_recover.atheris_main([], 0.1, {"detect"}) == fuzz_recover.EXIT_OK
    assert calls == ["instrument_all", "Setup", "Fuzz"]
