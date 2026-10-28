"""scripts/emu_backend.py: fast_hook_add must be a drop-in for Uc.hook_add.

The selftest (also run by test_selftests.py) covers the hand-assembled loop; here the same hooks are
put on REAL code -- functions of the committed benign Rust fixture, called the way recover_emulate
calls them -- and the event streams of the binding's hook_add and fast_hook_add must be identical.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("unicorn")
import emu_backend as EB  # noqa: E402
from unicorn import (UC_HOOK_BLOCK, UC_HOOK_CODE, UC_HOOK_INTR, UC_HOOK_MEM_READ,  # noqa: E402
                     UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE)

BENIGN = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_selftest():
    EB._selftest()


def test_hook_kinds():
    assert EB._kind(UC_HOOK_BLOCK) == "code" and EB._kind(UC_HOOK_CODE) == "code"
    assert EB._kind(UC_HOOK_MEM_WRITE) == "access"
    assert EB._kind(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE) == "access"
    assert EB._kind(UC_HOOK_MEM_READ_UNMAPPED) == "invalid"
    # mixed families and non-memory hooks go through the binding
    assert EB._kind(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_UNMAPPED) is None
    assert EB._kind(UC_HOOK_INTR) is None
    assert EB._kind(0) is None


@pytest.mark.skipif(not BENIGN.is_file(), reason="benign fixture missing")
def test_identical_events_on_real_functions():
    import bench_emu as B
    import recover_emulate as R
    img = R.Image(BENIGN)
    order = B._order(img, 24)
    streams = {}
    for mode in ("binding", "fast"):
        p = B._Plain("unicorn", img)
        ev = []
        add = p.uc.hook_add if mode == "binding" else (lambda *a: EB.fast_hook_add(p.uc, *a))
        add(UC_HOOK_BLOCK, lambda uc, a, s, d: ev.append(("b", a, s)))
        add(UC_HOOK_MEM_WRITE, lambda uc, ac, a, s, v, d: ev.append(("w", a, s, v)))
        add(UC_HOOK_MEM_READ, lambda uc, ac, a, s, v, d: ev.append(("r", a, s)))
        ends = []
        for fva, _size in order:
            p.reset()
            ev.append(("fn", fva))
            ends.append((p.run(fva, 4000)[1], p.regs()))
        streams[mode] = (ev, ends)
    ev_b, end_b = streams["binding"]
    ev_f, end_f = streams["fast"]
    assert len(ev_b) > 10000
    assert ev_f == ev_b
    assert end_f == end_b


def test_falls_back_without_binding_internals(monkeypatch):
    from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    monkeypatch.setattr(EB, "_ub", None)
    calls = []
    real = uc.hook_add
    uc.hook_add = lambda *a, **k: calls.append(a) or real(*a, **k)
    h = EB.fast_hook_add(uc, UC_HOOK_BLOCK, lambda *a: None)
    assert calls and calls[0][0] == UC_HOOK_BLOCK
    uc.hook_del(h)
