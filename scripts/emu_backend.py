#!/usr/bin/env python3
"""emu_backend.py - emulator-backend helpers shared by the emulation tiers.

Unicorn is the backend. Measured (bench_emu.py, VALIDATION.md): the emulation tiers spend almost
all of their time in Python hook callbacks, not in the engine -- recover_emulate's Emulator.run
~2% engine, unpack_emulate's UPX stub run ~4% engine -- so a faster engine buys little, while the
cost of getting each hook event into Python is large. This module cuts that cost:

* `fast_hook_add(uc, htype, callback, user_data=None, begin=1, end=0)` is a drop-in replacement for
  `uc.hook_add` for block / code / memory-access / invalid-memory hooks. It registers ONE ctypes
  callback straight with `uc_hook_add`, instead of the binding's ctypes callback -> `wrapper` ->
  `__hook_*_cb` -> your function chain (two extra Python frames per event). Semantics are the
  binding's: the callback gets the Uc object and the same arguments, an exception raised in it is
  recorded, stops emulation and is re-raised by `emu_start`, the handle works with `hook_del`, and
  an invalid-memory hook's return value decides whether emulation continues. Any other hook type
  (UC_HOOK_INSN, UC_HOOK_INTR, ...), or a Unicorn binding without the internals this relies on,
  goes through `uc.hook_add` unchanged.

icicle-emu (a JIT SLEIGH emulator, `pip install icicle-emu`) was evaluated as an alternative
backend and is deliberately NOT wired in: its Python API (0.0.11) has no hooks at all (only
breakpoints and stop-on-exception), it cannot resume correctly after self-modifying code, a new
instance costs ~0.1-0.3 s, and on real Rust functions its JIT is slower than Unicorn cold. Its raw
speed wins only on long hook-free loops, which no tier runs. `bench_emu.py` re-measures all of this.
"""
from __future__ import annotations

import ctypes
import sys

from unicorn import (UC_HOOK_BLOCK, UC_HOOK_CODE, UC_HOOK_MEM_FETCH, UC_HOOK_MEM_FETCH_PROT,
                     UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ, UC_HOOK_MEM_READ_AFTER,
                     UC_HOOK_MEM_READ_PROT, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE,
                     UC_HOOK_MEM_WRITE_PROT, UC_HOOK_MEM_WRITE_UNMAPPED, UcError)

try:                                          # binding internals (unicorn 2.1's unicorn_py3)
    from unicorn.unicorn_py3 import unicorn as _ub
    _CODE_CF = _ub.HOOK_CODE_CFUNC
    _ACCESS_CF = _ub.HOOK_MEM_ACCESS_CFUNC
    _INVALID_CF = _ub.HOOK_MEM_INVALID_CFUNC
    _hook_add = _ub.uclib.uc_hook_add
    _hook_h = _ub.uc_hook_h
except Exception:                             # another binding layout: always use uc.hook_add
    _ub = None

_CODE_TYPES = (UC_HOOK_BLOCK, UC_HOOK_CODE)
_ACCESS_MASK = UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE | UC_HOOK_MEM_FETCH | UC_HOOK_MEM_READ_AFTER
_INVALID_MASK = (UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED
                 | UC_HOOK_MEM_READ_PROT | UC_HOOK_MEM_WRITE_PROT | UC_HOOK_MEM_FETCH_PROT)


def _fail(uc, e):
    """What the binding's wrapper does with an exception raised in a hook."""
    if getattr(uc, "_hook_exception", None) is None:
        uc._hook_exception = e
    try:
        uc.emu_stop()
    except Exception:
        pass


def _kind(htype):
    if htype in _CODE_TYPES:
        return "code"
    if htype and not htype & ~_ACCESS_MASK:
        return "access"
    if htype and not htype & ~_INVALID_MASK:
        return "invalid"
    return None


def fast_hook_add(uc, htype, callback, user_data=None, begin=1, end=0):
    """`uc.hook_add(htype, callback, user_data, begin, end)` with one Python frame per event.
    Returns the hook handle (usable with uc.hook_del)."""
    kind = _kind(htype)
    if _ub is None or kind is None or not hasattr(uc, "_uch") or not hasattr(uc, "_callbacks"):
        return uc.hook_add(htype, callback, user_data, begin, end)
    if kind == "code":
        def cb(_h, address, size, _key):
            try:
                callback(uc, address, size, user_data)
            except BaseException as e:
                _fail(uc, e)
        fptr = _CODE_CF(cb)
    elif kind == "access":
        def cb(_h, access, address, size, value, _key):
            try:
                callback(uc, access, address, size, value, user_data)
            except BaseException as e:
                _fail(uc, e)
        fptr = _ACCESS_CF(cb)
    else:
        def cb(_h, access, address, size, value, _key):
            try:
                return bool(callback(uc, access, address, size, value, user_data))
            except BaseException as e:
                _fail(uc, e)
                return False
        fptr = _INVALID_CF(cb)
    handle = _hook_h()
    err = _hook_add(uc._uch, ctypes.byref(handle), htype, ctypes.cast(fptr, ctypes.c_void_p),
                    ctypes.c_void_p(0), ctypes.c_uint64(begin), ctypes.c_uint64(end))
    if err:
        raise UcError(err)
    uc._callbacks[handle.value] = fptr        # keeps the ctypes callback alive; hook_del drops it
    return handle.value


def _selftest():
    import struct
    from unicorn import UC_ARCH_X86, UC_MODE_64, Uc, UC_PROT_READ, UC_PROT_ALL
    from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSI, UC_X86_REG_RCX, UC_X86_REG_RSP
    # xor byte [rsi],0x5a ; add byte [rsi],3 ; inc rsi ; dec rcx ; jnz ; ret
    code = bytes.fromhex("80365a80060348ffc648ffc975f2c3")
    CODE, BUF, STK, SENT = 0x400000, 0x600000, 0x700000, 0x7fff0000

    def machine(n):
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        uc.mem_map(CODE, 0x1000)
        uc.mem_write(CODE, code)
        uc.mem_map(BUF, 0x2000)
        uc.mem_map(STK, 0x1000)
        uc.mem_write(STK + 0x800, struct.pack("<Q", SENT))
        uc.reg_write(UC_X86_REG_RSP, STK + 0x800)
        uc.reg_write(UC_X86_REG_RSI, BUF)
        uc.reg_write(UC_X86_REG_RCX, n)
        return uc

    # events and arguments match the binding's hook_add exactly
    seen = {}
    for add in ("binding", "fast"):
        uc = machine(40)
        ev = seen[add] = []
        f = uc.hook_add if add == "binding" else (lambda *a: fast_hook_add(uc, *a))
        f(UC_HOOK_BLOCK, lambda u, a, s, d: ev.append(("b", a, s, d, u is uc)), "ud")
        f(UC_HOOK_CODE, lambda u, a, s, d: ev.append(("c", a, s)), None, CODE + 3, CODE + 3)
        f(UC_HOOK_MEM_WRITE, lambda u, ac, a, s, v, d: ev.append(("w", ac, a, s, v & 0xff)))
        uc.emu_start(CODE, SENT)
    assert seen["fast"] == seen["binding"] and len(seen["fast"]) > 40, (seen["fast"][:4], seen["binding"][:4])
    assert all(e[4] for e in seen["fast"] if e[0] == "b")         # the callback got the Uc object

    # an exception in the callback stops emulation and is re-raised by emu_start
    uc = machine(40)
    calls = []

    def boom(u, a, s, d):
        calls.append(a)
        raise KeyError("x")
    fast_hook_add(uc, UC_HOOK_BLOCK, boom)
    try:
        uc.emu_start(CODE, SENT)
        raise AssertionError("no exception")
    except KeyError:
        pass
    assert len(calls) == 1

    # hook_del works on a fast handle
    uc = machine(10)
    n = []
    h = fast_hook_add(uc, UC_HOOK_BLOCK, lambda u, a, s, d: n.append(a))
    uc.hook_del(h)
    uc.emu_start(CODE, SENT)
    assert not n

    # invalid-memory hook: True continues (after mapping), False stops with UcError
    for ret in (True, False):
        uc = machine(8)
        uc.reg_write(UC_X86_REG_RSI, 0x900000)                   # unmapped buffer

        def unm(u, ac, a, s, v, d, ret=ret):
            if ret:
                u.mem_map(a & ~0xfff, 0x1000)
            return ret
        fast_hook_add(uc, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED, unm)
        try:
            uc.emu_start(CODE, SENT)
            ok = True
        except UcError:
            ok = False
        assert ok == ret, ret

    # write-protection fault: unprotect + return False, resume at the faulting store (returning
    # True after unprotecting drops that store on Unicorn 2.1 -- see bench_emu.py)
    uc = machine(0x1800)
    uc.mem_write(BUF, bytes(0x2000))
    uc.mem_protect(BUF, 0x2000, UC_PROT_READ)
    faults = []

    def wprot(u, ac, a, s, v, d):
        faults.append(a & ~0xfff)
        u.mem_protect(a & ~0xfff, 0x1000, UC_PROT_ALL)
        return False
    fast_hook_add(uc, UC_HOOK_MEM_WRITE_PROT, wprot)
    pc = CODE
    for _ in range(4):
        try:
            uc.emu_start(pc, SENT)
            break
        except UcError:
            pc = uc.reg_read(UC_X86_REG_RIP)
    assert faults == [BUF, BUF + 0x1000], faults
    assert bytes(uc.mem_read(BUF, 0x1800)) == bytes([0x5d]) * 0x1800

    # unsupported hook types fall through to the binding
    from unicorn import UC_HOOK_INTR
    uc = machine(1)
    h = fast_hook_add(uc, UC_HOOK_INTR, lambda u, i, d: None)
    uc.hook_del(h)
    print("selftest OK")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False,
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
