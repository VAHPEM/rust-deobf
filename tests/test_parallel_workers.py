"""recover_emulate's parallel path: worker processes are never a bare fork (VALIDATION §86).

recover() used `mp.get_context("fork")` wherever fork existed. A bare fork copies the caller as it
is: on macOS a fork without exec from a process that loaded system frameworks or runs threads can
abort the child ("crashed on child side of fork pre-exec"); on Linux a fork after the caller created
a Unicorn engine fails with "Could not allocate dynamic translator buffer" (the CLAUDE.md gotcha).
A dead worker did not fail the run -- BrokenProcessPool was caught and the share re-run in the
parent -- so the cost was silent: a serial run after paying for the pool. Now both recover_emulate
and fuzz_recover take emu_backend.mp_context(): forkserver (engines preloaded), else spawn.

No committed fixture reaches PARALLEL_MIN (2000 functions; committing one would break the
no-large-binaries rule), so the parallel tests lower it: the choice to go parallel is made in the
parent, and the workers are real child processes that import recover_emulate afresh.
"""
import json
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("unicorn")
import emu_backend  # noqa: E402
import recover_emulate as R  # noqa: E402

ENCODINGS = ROOT / "tests" / "fixtures" / "strenc" / "encodings.arm64"     # 732 functions
CANARIES = json.loads((ROOT / "bench_src" / "manifest.json").read_text())["canaries"]


@pytest.mark.parametrize("methods,want", [
    (["fork", "spawn", "forkserver"], "forkserver"),     # Linux, macOS
    (["fork", "spawn"], "spawn"),                         # a fork-only POSIX: still not fork
    (["spawn"], "spawn"),                                 # Windows
])
def test_mp_context_is_forkserver_else_spawn_never_fork(methods, want):
    assert emu_backend.mp_context(methods).get_start_method() == want


def test_fuzz_recover_and_recover_emulate_share_the_choice(monkeypatch):
    import multiprocessing as mp
    import fuzz_recover
    monkeypatch.setattr(mp, "get_all_start_methods", lambda: ["fork", "spawn"])
    assert fuzz_recover._isolation_ctx().get_start_method() == "spawn"
    assert R.mp_context is emu_backend.mp_context


def _parallel(monkeypatch, workers):
    """recover() through the parallel path; returns (result, start methods used, parent reruns)."""
    used, reruns = [], []
    real_ctx, real_emulate = R.mp_context, R._emulate

    def ctx_spy(*a, **k):
        c = real_ctx(*a, **k)
        used.append(c.get_start_method())
        return c

    def emulate_spy(img, order, *a, **k):     # in the PARENT only: a share a dead worker left
        reruns.append(len(order))
        return real_emulate(img, order, *a, **k)
    monkeypatch.setattr(R, "PARALLEL_MIN", 100)
    monkeypatch.setattr(R, "mp_context", ctx_spy)
    monkeypatch.setattr(R, "_emulate", emulate_spy)
    res = R.recover(ENCODINGS, [], workers=workers, time_budget=300)
    return res, used, reruns


def test_parallel_recover_runs_in_safe_children_and_matches_one_process(monkeypatch):
    res, used, reruns = _parallel(monkeypatch, 2)
    assert res["workers"] == 2 and used and "fork" not in used, used
    assert reruns == [], f"a worker died and its share ran in the parent: {reruns}"
    monkeypatch.undo()
    one = R.recover(ENCODINGS, [], workers=1, time_budget=300)
    # the decoded strings do not depend on how the functions were shared out
    assert set(res["recovered_texts"]) == set(one["recovered_texts"]), (
        sorted(set(res["recovered_texts"]) ^ set(one["recovered_texts"])))
    assert res["functions_tried"] == one["functions_tried"] == one["functions_total"]
    # (canary 4 is the zlib stream: recover.run's compressed-strings engine, not emulation)
    assert set(CANARIES) - {"canary::echo::schema-version-4"} <= set(res["recovered_texts"])
