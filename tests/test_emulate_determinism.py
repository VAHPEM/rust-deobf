"""recover_emulate results must not depend on Python's memory allocation.

run() used to count a callee's faults in a dict keyed by id(frame). When a frame was abandoned and
freed, CPython handed its address to the NEXT frame dict, which then inherited the old frame's
fault count and was abandoned at its first fault -- so per-function results changed with anything
that shifted allocation (an extra object allocated in a hook, a different hook dispatch path).
Here every unwound/abandoned frame is followed by an allocation that grabs the freed address; the
per-function results (instruction count + recovered strings) must be identical with and without it.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("unicorn")
import recover_emulate as R  # noqa: E402

BENIGN = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def _results(img, funcs, perturb, monkeypatch):
    hold = []
    if perturb:
        orig_ab, orig_un = R.Emulator._abandon, R.Emulator._unwind

        def ab(self, *a):
            r = orig_ab(self, *a)
            hold.append({"ret": 0, "start": 0, "sp": 0, "regs": []})   # takes the freed slot
            return r

        def un(self, *a):
            r = orig_un(self, *a)
            hold.append({"ret": 0, "start": 0, "sp": 0, "regs": []})
            return r
        monkeypatch.setattr(R.Emulator, "_abandon", ab)
        monkeypatch.setattr(R.Emulator, "_unwind", un)
    emu = R.Emulator(img)
    out = {}
    for fva, size in funcs:
        s, _, _ = emu.run(fva, size, budget=R.QUICK)
        out[fva] = (emu.count, tuple(sorted(s)))
    monkeypatch.undo()
    return out, len(hold)


@pytest.mark.skipif(not BENIGN.is_file(), reason="benign fixture missing")
def test_results_independent_of_allocation(monkeypatch):
    img = R.Image(str(BENIGN))
    funcs = img.functions()
    plain, _ = _results(img, funcs, False, monkeypatch)
    perturbed, grabbed = _results(img, funcs, True, monkeypatch)
    assert grabbed > 100                     # the perturbation really ran
    diff = [hex(f) for f in plain if plain[f] != perturbed[f]]
    assert not diff, f"allocation-dependent results in {len(diff)} functions: {diff[:8]}"
