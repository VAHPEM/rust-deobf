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
