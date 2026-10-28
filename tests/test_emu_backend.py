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
    assert EB._kind(UC_HOOK_INTR) == "intr"
    from unicorn import UC_HOOK_INSN
    from unicorn.x86_const import UC_X86_INS_SYSCALL, UC_X86_INS_CPUID
    assert EB._kind(UC_HOOK_INSN, UC_X86_INS_SYSCALL) == "syscall"
    assert EB._kind(UC_HOOK_INSN, UC_X86_INS_CPUID) is None      # other insn hooks: the binding
    assert EB._kind(0) is None


def test_syscall_and_interrupt_hooks_match_the_binding():
    import struct
    from unicorn import UC_ARCH_X86, UC_MODE_64, UC_HOOK_INSN, Uc
    from unicorn.x86_const import UC_X86_INS_SYSCALL, UC_X86_REG_RAX, UC_X86_REG_RSP
    # mov eax,7 ; syscall ; int 0x80 ; syscall ; ret
    code = bytes.fromhex("b8070000000f05cd800f05c3")
    seen = {}
    for mode in ("binding", "fast"):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(0x1000, 0x1000)
        uc.mem_write(0x1000, code)
        uc.mem_map(0x8000, 0x1000)
        uc.mem_write(0x8800, struct.pack("<Q", 0x9000))
        uc.reg_write(UC_X86_REG_RSP, 0x8800)
        ev = seen[mode] = []

        def sysc(u, d):
            ev.append(("sys", u.reg_read(UC_X86_REG_RAX), d))
            u.reg_write(UC_X86_REG_RAX, u.reg_read(UC_X86_REG_RAX) + 1)

        def intr(u, n, d):
            ev.append(("int", n, d))
        if mode == "binding":
            uc.hook_add(UC_HOOK_INSN, sysc, "s", 1, 0, UC_X86_INS_SYSCALL)
            uc.hook_add(UC_HOOK_INTR, intr, "i")
        else:
            EB.fast_hook_add(uc, UC_HOOK_INSN, sysc, "s", 1, 0, UC_X86_INS_SYSCALL)
            EB.fast_hook_add(uc, UC_HOOK_INTR, intr, "i")
        uc.emu_start(0x1000, 0x9000, count=10)
    assert seen["fast"] == seen["binding"] and len(seen["fast"]) == 3, seen


def test_release_frees_the_emulator_without_gc():
    import gc
    import weakref
    from unicorn import UC_ARCH_X86, UC_MODE_64, Uc
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    EB.fast_hook_add(uc, UC_HOOK_BLOCK, lambda *a: None)
    EB.fast_hook_add(uc, UC_HOOK_MEM_WRITE, lambda *a: None)
    EB.fast_hook_add(uc, UC_HOOK_INTR, lambda *a: None)
    alive = weakref.ref(uc)
    gc.disable()
    try:
        EB.release(uc)
        del uc
        assert alive() is None            # freed by refcount: no cycle left through the hooks
    finally:
        gc.enable()


@pytest.mark.skipif(not BENIGN.is_file(), reason="benign fixture missing")
def test_recover_emulate_frees_old_emulators_without_gc(monkeypatch):
    import weakref
    import recover_emulate as R
    img = R.Image(BENIGN)
    emu = R.Emulator(img)
    for fva, size in img.functions()[:4]:
        emu.run(fva, size)
    alive = weakref.ref(emu.uc)
    calls = []
    monkeypatch.setattr(R.gc, "collect", lambda *a: calls.append(1))
    emu._fresh()
    assert alive() is None and not calls


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
