#!/usr/bin/env python3
"""bench_emu.py - measure emulation engines on rust-deobf's own workloads (a measurement tool).

Compares Unicorn (the engine every emulation tier uses) with icicle-emu (an optional, JIT-based
SLEIGH emulator: `pip install icicle-emu`) -- and Unicorn against itself under the hook layouts the
tiers use -- on equal work, so an engine or hook decision rests on numbers from the machine at hand:

* `loop`   - a tight byte decoder (xor/add over a buffer, the shape of the obfuscation crates'
             decryptors), no hooks, on x86-64 / i686 / AArch64. Raw engine speed, cold (first run,
             includes translation) and warm. Every engine's output buffer is checked against the
             decode computed in Python, so a fast wrong answer cannot win.
* `hooks`  - the same loop under the hooks the tiers install: Python block / memory-write / code
             hooks, a write hook narrowed to an address range the loop never touches, `count=`
             batching; and what icicle can offer instead (it has no hook API in Python):
             page-protection write tracking (store -> WritePerm fault -> mark page, unprotect,
             resume) and a Python `step(1)` loop standing in for a per-instruction hook. Dirty-page
             sets are cross-checked between engines.
* `funcs`  - real code: the highest-scoring functions of a binary (default: the committed
             tests/fixtures/vm/benign_rust_std.x64, byte-identical to the obfstr release build of
             the canary benchmark), each called the way recover_emulate calls a function (image +
             relocations + import trampolines mapped, fresh stack, scratch-pointer arguments,
             thread pointer set, instruction budget, sentinel return). Engines run with no hooks
             and must finish in the same register state (equal work, checked per function); then
             Unicorn with no-op Python block+write hooks (hook dispatch cost) and recover_emulate's
             real Emulator.run (dispatch + its analysis bodies) on the same functions, so the time
             can be split into engine / hook dispatch / hook bodies.

Usage:  bench_emu.py [--json] [--quick] [--workload loop|hooks|funcs|all] [--binary PATH]
                     [--funcs N] [--budget N] [--repeat N]
        bench_emu.py --selftest

Nothing here runs a sample on the host: everything is emulated. Inputs are benign fixtures.
"""
from __future__ import annotations

import json
import platform
import statistics
import struct
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from unicorn import (  # noqa: E402
    UC_ARCH_ARM64, UC_ARCH_X86, UC_HOOK_BLOCK, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_INTR,
    UC_HOOK_MEM_WRITE, UC_HOOK_MEM_WRITE_PROT, UC_MODE_32, UC_MODE_64, UC_MODE_ARM, UC_PROT_ALL,
    UC_PROT_READ, UC_PROT_WRITE, UC_ERR_EXCEPTION, Uc, UcError,
)
from unicorn import arm64_const as A  # noqa: E402
from unicorn import x86_const as X  # noqa: E402

try:                                    # optional engine
    import icicle as _icicle
except Exception:                       # not installed / no wheel for this platform
    _icicle = None

DEFAULT_BINARY = ROOT.parent / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"

# --------------------------------------------------------------------------------------------
# the decode loop, per architecture: buf[i] = ((buf[i] ^ 0x5a) + 3) & 0xff for i < n
# (pointer in rsi/esi/x0, count in rcx/ecx/x1; hand-assembled, checked by capstone in --selftest)
# --------------------------------------------------------------------------------------------
LOOP = {
    "x86_64": (bytes.fromhex("80365a" "800603" "48ffc6" "48ffc9" "75f2" "c3"), 5, 1),
    "i686": (bytes.fromhex("80365a" "800603" "46" "49" "75f6" "c3"), 5, 1),
    "aarch64": (b"".join(struct.pack("<I", w) for w in (
        0x52800B43,     # mov  w3, #0x5a
        0x39400002,     # ldrb w2, [x0]
        0x4A030042,     # eor  w2, w2, w3
        0x11000C42,     # add  w2, w2, #3
        0x38001402,     # strb w2, [x0], #1
        0xF1000421,     # subs x1, x1, #1
        0x54FFFF61,     # b.ne loop
        0xD65F03C0)),   # ret
        6, 2),
}
# (code, instructions per byte, fixed instructions outside the loop)

CODE, BUF, STK, STK_SIZE = 0x400000, 0x1000000, 0x7f00000, 0x100000
SENT = 0x7fff0000              # sentinel return address (recover_emulate's RET_SENTINEL)
_GPR = {
    "x86_64": ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
               "r12", "r13", "r14", "r15"],
    "aarch64": [f"x{i}" for i in range(31)] + ["sp"],
}


def _expect(data: bytes) -> bytes:
    return bytes(((b ^ 0x5a) + 3) & 0xff for b in data)


def _pattern(n: int) -> bytes:
    return bytes((i * 131 + 7) & 0xff for i in range(n))


def _uc_new(arch):
    if arch == "aarch64":
        return Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    return Uc(UC_ARCH_X86, UC_MODE_32 if arch == "i686" else UC_MODE_64)


def _uc_reg(arch, name):
    if arch == "aarch64":
        return getattr(A, "UC_ARM64_REG_" + name.upper())
    return getattr(X, "UC_X86_REG_" + name.upper())


def _ptr_regs(arch):
    return {"x86_64": ("rsi", "rcx", "rsp"), "i686": ("esi", "ecx", "esp"),
            "aarch64": ("x0", "x1", "sp")}[arch]


def icicle_available() -> bool:
    return _icicle is not None


def icicle_version() -> str | None:
    if _icicle is None:
        return None
    try:
        from importlib.metadata import version
        return version("icicle-emu")
    except Exception:
        return "unknown"


# --------------------------------------------------------------------------------------------
# loop / hooks workloads
# --------------------------------------------------------------------------------------------

class _UcLoop:
    """The decode loop on Unicorn, with a configurable hook layout. Hooks named `*_raw` are
    registered as bare ctypes callbacks through uc_hook_add, bypassing the binding's two Python
    wrapper frames per event (the same idea as recover_emulate._fast_access for register reads).
    `pages` tracks writes by page protection instead of a write hook (see run())."""

    def __init__(self, arch, n, hooks=(), count=False):
        self.arch, self.n, self.count = arch, n, count
        code = LOOP[arch][0]
        uc = self.uc = _uc_new(arch)
        uc.mem_map(CODE, 0x1000)
        uc.mem_write(CODE, code)
        self.buf_size = (n + 0xfff) & ~0xfff
        uc.mem_map(BUF, self.buf_size)
        uc.mem_map(STK, STK_SIZE)
        self.pages = set()
        self.calls = self.faults = 0
        self.track = "pages" in hooks
        self._keep = []                          # raw ctypes callbacks must outlive the hooks
        for h in hooks:
            if h == "block":
                uc.hook_add(UC_HOOK_BLOCK, self._on_block)
            elif h == "write":
                uc.hook_add(UC_HOOK_MEM_WRITE, self._on_write)
            elif h == "write_narrow":
                # narrowed to a range the loop never stores to (the stack): Unicorn filters in C
                uc.hook_add(UC_HOOK_MEM_WRITE, self._on_write, None, STK, STK + STK_SIZE - 1)
            elif h == "code":
                uc.hook_add(UC_HOOK_CODE, self._on_code)
            elif h == "block_raw":
                self._raw(UC_HOOK_BLOCK, "HOOK_CODE_CFUNC", lambda h_, a, s, u: self._on_block(None, a, s, u))
            elif h == "write_raw":
                self._raw(UC_HOOK_MEM_WRITE, "HOOK_MEM_ACCESS_CFUNC",
                          lambda h_, ac, a, s, v, u: self._on_write(None, ac, a, s, v, u))
            elif h == "pages":
                uc.hook_add(UC_HOOK_MEM_WRITE_PROT, self._on_wprot)

    def _raw(self, htype, cfunc_name, fn):
        import ctypes
        from unicorn.unicorn_py3 import unicorn as ub
        cb = getattr(ub, cfunc_name)(fn)
        hh = ub.uc_hook_h()
        err = ub.uclib.uc_hook_add(self.uc._uch, ctypes.byref(hh), htype, ctypes.cast(cb, ctypes.c_void_p),
                                   None, ctypes.c_uint64(1), ctypes.c_uint64(0))
        if err:
            raise UcError(err)
        self._keep.append(cb)

    def _on_block(self, uc, address, size, _):
        self.calls += 1

    def _on_code(self, uc, address, size, _):
        self.calls += 1

    def _on_write(self, uc, access, address, size, value, _):
        self.pages.add(address >> 12)

    def _on_wprot(self, uc, access, address, size, value, _):
        # unprotect and FAIL the access: emu_start raises, run() resumes at the faulting
        # instruction, which re-executes the store. (Returning True here instead silently DROPS
        # the faulting store on Unicorn 2.1 -- one wrong byte per page; measured.)
        pg = address & ~0xfff
        self.pages.add(pg >> 12)
        self.faults += 1
        uc.mem_protect(pg, 0x1000, UC_PROT_ALL)
        return False

    def prime(self, data):
        uc, arch = self.uc, self.arch
        self.pages, self.calls, self.faults = set(), 0, 0
        p, c, sp = _ptr_regs(arch)
        uc.mem_protect(BUF, self.buf_size, UC_PROT_ALL)
        uc.mem_write(BUF, data)
        if self.track:
            uc.mem_protect(BUF, self.buf_size, UC_PROT_READ)
        top = STK + STK_SIZE // 2
        if arch == "aarch64":
            uc.reg_write(_uc_reg(arch, "x30"), SENT)
        else:
            uc.mem_write(top, struct.pack("<I" if arch == "i686" else "<Q", SENT))
        uc.reg_write(_uc_reg(arch, sp), top)
        uc.reg_write(_uc_reg(arch, p), BUF)
        uc.reg_write(_uc_reg(arch, c), self.n)

    def run(self):
        per, fixed = LOOP[self.arch][1], LOOP[self.arch][2]
        insns = per * self.n + fixed
        pc_reg = _uc_reg(self.arch, {"x86_64": "rip", "i686": "eip", "aarch64": "pc"}[self.arch])
        pc = CODE
        while True:
            try:
                if self.count:
                    self.uc.emu_start(pc, SENT, count=insns + 16)
                else:
                    self.uc.emu_start(pc, SENT)
                return insns
            except UcError:
                if not self.track or self.faults > self.buf_size >> 12:
                    raise
                pc = self.uc.reg_read(pc_reg)       # the faulting store: run it again

    def output(self):
        return bytes(self.uc.mem_read(BUF, self.n))


class _IcLoop:
    """The decode loop on icicle. track='pages' makes the buffer read-only and records each page a
    store faults on (then unprotects it and resumes): icicle's substitute for a write hook."""

    def __init__(self, arch, n, track=None, jit=True):
        P = _icicle.MemoryProtection
        self.arch, self.n, self.track = arch, n, track
        vm = self.vm = _icicle.Icicle(arch, jit=jit)
        vm.mem_map(CODE, 0x1000, P.ExecuteRead)
        vm.mem_write(CODE, LOOP[arch][0])
        self.buf_size = (n + 0xfff) & ~0xfff
        vm.mem_map(BUF, self.buf_size, P.ReadWrite)
        vm.mem_map(STK, STK_SIZE, P.ReadWrite)
        vm.mem_map(SENT, 0x1000, P.ExecuteRead)      # a breakpoint needs a mapped, executable page
        self.pages = set()
        self.faults = 0

    def prime(self, data):
        P = _icicle.MemoryProtection
        vm, arch = self.vm, self.arch
        p, c, sp = _ptr_regs(arch)
        vm.mem_protect(BUF, self.buf_size, P.ReadWrite)
        vm.mem_write(BUF, data)
        if self.track == "pages":
            vm.mem_protect(BUF, self.buf_size, P.ReadOnly)
        top = STK + STK_SIZE // 2
        if arch == "aarch64":
            vm.reg_write("x30", SENT)
        else:
            vm.mem_write(top, struct.pack("<I" if arch == "i686" else "<Q", SENT))
        vm.reg_write(sp, top)
        vm.reg_write(p, BUF)
        vm.reg_write(c, self.n)
        vm.pc = CODE
        self.pages, self.faults = set(), 0

    def run(self):
        vm, E = self.vm, _icicle.ExceptionCode
        P = _icicle.MemoryProtection
        i0 = vm.icount
        vm.icount_limit = i0 + LOOP[self.arch][1] * self.n + LOOP[self.arch][2] + 16 + 2 * self.n
        while True:
            vm.run_until(SENT)
            if vm.pc == SENT:
                break
            if self.track == "pages" and vm.exception_code == E.WritePerm:
                pg = vm.exception_value & ~0xfff
                self.pages.add(pg >> 12)
                self.faults += 1
                vm.mem_protect(pg, 0x1000, P.ReadWrite)
                continue
            raise RuntimeError(f"icicle stopped at {vm.pc:#x}: {vm.exception_code}")
        # a store that faults is counted once more when it re-executes: report the loop's own count
        return vm.icount - i0 - self.faults

    def run_stepped(self):
        """A Python call per instruction (what a code hook costs when the engine has none)."""
        vm = self.vm
        i0 = vm.icount
        vm.icount_limit = 1 << 62
        n = 0
        while vm.pc != SENT:
            vm.step(1)
            n += 1
            if n > LOOP[self.arch][1] * self.n + 64:
                raise RuntimeError("step loop overran")
        return vm.icount - i0

    def output(self):
        return bytes(self.vm.mem_read(BUF, self.n))


def _time_runs(make, data, repeat):
    """(cold seconds, warm median seconds, instructions, output ok, the runner)."""
    r = make()
    exp = _expect(data)
    times, insns, ok = [], 0, True
    for _ in range(max(2, repeat + 1)):
        r.prime(data)
        t = time.perf_counter()
        insns = r.run()
        times.append(time.perf_counter() - t)
        ok &= r.output() == exp
    return times[0], statistics.median(times[1:]), insns, ok, r


def _row(arch, engine, cold, warm, insns, ok, **extra):
    row = {"arch": arch, "engine": engine, "insns": insns, "cold_s": round(cold, 5),
           "warm_s": round(warm, 5), "minsn_s": round(insns / warm / 1e6, 2) if warm else None,
           "ok": ok}
    row.update(extra)
    return row


def bench_loop(n=1 << 20, repeat=3, archs=("x86_64", "i686", "aarch64")):
    data = _pattern(n)
    rows = []
    for arch in archs:
        c, w, i, ok, _ = _time_runs(lambda: _UcLoop(arch, n), data, repeat)
        rows.append(_row(arch, "unicorn", c, w, i, ok))
        c, w, i, ok, _ = _time_runs(lambda: _UcLoop(arch, n, count=True), data, repeat)
        rows.append(_row(arch, "unicorn count=", c, w, i, ok))
        if _icicle is not None:
            c, w, i, ok, _ = _time_runs(lambda: _IcLoop(arch, n), data, repeat)
            rows.append(_row(arch, "icicle", c, w, i, ok))
            c, w, i, ok, _ = _time_runs(lambda: _IcLoop(arch, n, jit=False), data, repeat)
            rows.append(_row(arch, "icicle jit=False", c, w, i, ok))
    return rows


def bench_hooks(n=1 << 18, repeat=3, arch="x86_64", step_n=1 << 14):
    data = _pattern(n)
    want_pages = {(BUF >> 12) + k for k in range((n + 0xfff) >> 12)}
    rows = []
    for name, hooks, count in (("none", (), False), ("none, count=", (), True),
                               ("block", ("block",), False), ("block, count=", ("block",), True),
                               ("write", ("write",), False),
                               ("write narrowed to stack", ("write_narrow",), False),
                               ("block+write", ("block", "write"), False),
                               ("code", ("code",), False),
                               ("block, raw ctypes cb", ("block_raw",), False),
                               ("write, raw ctypes cb", ("write_raw",), False),
                               ("block+write, raw ctypes cb", ("block_raw", "write_raw"), False),
                               ("page-fault write tracking", ("pages",), False)):
        c, w, i, ok, r = _time_runs(lambda: _UcLoop(arch, n, hooks, count), data, repeat)
        if any(h.startswith("write") or h == "pages" for h in hooks) and "write_narrow" not in hooks:
            ok &= r.pages == want_pages
        extra = {"faults": r.faults} if r.track else {}
        rows.append(_row(arch, "unicorn", c, w, i, ok, hooks=name, py_calls=r.calls, **extra))
    if _icicle is not None:
        c, w, i, ok, _ = _time_runs(lambda: _IcLoop(arch, n), data, repeat)
        rows.append(_row(arch, "icicle", c, w, i, ok, hooks="none"))
        c, w, i, ok, r = _time_runs(lambda: _IcLoop(arch, n, track="pages"), data, repeat)
        rows.append(_row(arch, "icicle", c, w, i, ok and r.pages == want_pages,
                         hooks="page-fault write tracking", faults=r.faults))
        # step(1) per instruction, on a smaller buffer (it is slow by construction)
        sd = _pattern(step_n)
        r = _IcLoop(arch, step_n)
        times = []
        for _ in range(max(2, repeat + 1)):
            r.prime(sd)
            t = time.perf_counter()
            i = r.run_stepped()
            times.append(time.perf_counter() - t)
        rows.append(_row(arch, "icicle", times[0], statistics.median(times[1:]), i,
                         r.output() == _expect(sd), hooks="step(1) per instruction"))
    return rows


UPX_FIXTURE = ROOT.parent / "tests" / "fixtures" / "pack" / "upx_hello_pe64.exe"


def bench_unpack(path=UPX_FIXTURE, repeat=3):
    """unpack_emulate's real stub run (UPX) vs the same path with its Python block + write hooks
    removed (the trampoline/syscall/unmapped hooks kept, a C-filtered one-address code hook
    stopping at the OEP the full run found). The gap is what the hooks cost; the floor is the most
    ANY engine swap could remove -- and icicle cannot run this consumer without those hooks."""
    import unpack_emulate as U
    from recover_emulate import Image
    img = Image(path)
    entry = img.binary.entrypoint - img.imagebase

    def _NoBW(*args):
        # a real Uc whose hook_add ignores the block and memory-write hooks (an instance attribute
        # shadows the method; Uc dispatches to an arch subclass in __new__, so no subclassing)
        uc = Uc(*args)
        add = uc.hook_add

        def hook_add(htype, cb, *a, **k):
            if htype in (UC_HOOK_BLOCK, UC_HOOK_MEM_WRITE):
                return 0
            return add(htype, cb, *a, **k)
        uc.hook_add = hook_add
        return uc

    full, floor, oep, blocks = [], [], None, 0
    for _ in range(max(1, repeat)):
        up = U._Unpacker(img)
        t = time.perf_counter()
        up.run(entry)
        full.append(time.perf_counter() - t)
        oep, blocks, stopped = up.oep, up.blocks, up.stopped
    if oep is None:
        return {"binary": Path(path).name, "skipped": f"no OEP reached (stopped={stopped})"}
    real_uc = U.Uc
    # with emu_backend.fast_hook_add wired into unpack_emulate (INTEGRATION.patch), its hooks no
    # longer go through uc.hook_add: route them back so _NoBW can drop the block / write ones
    real_fast = getattr(U, "fast_hook_add", None)
    try:
        U.Uc = _NoBW
        if real_fast is not None:
            U.fast_hook_add = lambda uc, htype, cb, *a: uc.hook_add(htype, cb, *a)
        for _ in range(max(1, repeat)):
            up = U._Unpacker(img)
            up.uc.hook_add(UC_HOOK_CODE, lambda uc, a, s, u: uc.emu_stop(), None, oep, oep)
            t = time.perf_counter()
            up.run(entry)
            floor.append(time.perf_counter() - t)
            reached = up.uc.reg_read(up.PC) == oep
    finally:
        U.Uc = real_uc
        if real_fast is not None:
            U.fast_hook_add = real_fast
    f, fl = statistics.median(full), statistics.median(floor)
    return {"binary": Path(path).name, "blocks": blocks, "oep": oep - U.BASE,
            "full_s": round(f, 4), "no_block_write_hooks_s": round(fl, 4),
            "floor_reached_oep": reached, "hook_share": round(1 - fl / f, 3) if f else None}


def bench_setup(repeat=5):
    """Cost of a new engine instance (recover_emulate makes a fresh Unicorn every 64 runs)."""
    out = {}
    for arch in ("x86_64", "aarch64", "i686"):
        t = time.perf_counter()
        for _ in range(repeat):
            _uc_new(arch)
        out[f"unicorn {arch} ms"] = round((time.perf_counter() - t) / repeat * 1e3, 2)
        if _icicle is not None:
            t = time.perf_counter()
            for _ in range(repeat):
                _icicle.Icicle(arch)
            out[f"icicle {arch} ms"] = round((time.perf_counter() - t) / repeat * 1e3, 2)
    return out


# --------------------------------------------------------------------------------------------
# funcs workload: real functions, called the way recover_emulate calls them
# --------------------------------------------------------------------------------------------

class _MapShim:
    """Lets recover_emulate.map_image() map an image into icicle: its mem_map/mem_write, raising
    UcError (which map_image handles) where icicle raises its own MemoryException."""

    def __init__(self, vm, prot):
        self.vm, self.prot = vm, prot

    def mem_map(self, address, size, perms=None):
        try:
            self.vm.mem_map(address, size, self.prot)
        except Exception as e:
            raise UcError(11) from e                 # UC_ERR_MAP

    def mem_write(self, address, data):
        try:
            self.vm.mem_write(address, bytes(data))
        except Exception as e:
            raise UcError(7) from e                  # UC_ERR_WRITE_UNMAPPED


class _Plain:
    """One function call on one engine, no hooks: recover_emulate's memory layout and calling
    setup (image, relocations, import trampolines that just return, stack, scratch arguments, TLS
    thread pointer), an instruction budget and the sentinel return. A syscall, a trap (int3) or a
    fault ends the run on both engines."""

    HEAP_CLEAR = 0x100000

    def __init__(self, engine, img):
        import recover_emulate as R
        self.R, self.engine, self.img = R, engine, img
        self.arch = "aarch64" if img.arm else "x86_64"
        self.pmask = (1 << 64) - 1
        # data regions are mapped non-executable on BOTH engines: a jump into the stack / scratch
        # arguments then faults the same way on each (recover_emulate's block hook stops there
        # too). On icicle it also matters for another reason: once it has translated code on a
        # page, any later store to that page -- even the host's own mem_write -- raises
        # SelfModifyingCode and the instance cannot be reset (measured with icicle-emu 0.0.11).
        data = [(R.STACK, R.STACK_SIZE), (R.SCRATCH, R.SCRATCH_SIZE), (R.HEAP, R.HEAP_SIZE),
                (R.TLS, R.TLS_SIZE)]
        ret = b"\xc0\x03\x5f\xd6" if img.arm else b"\xc3"
        tramp = (ret + b"\x00" * (16 - len(ret))) * min(len(img.tramp) + 1, R.TRAMP_SIZE // 16)
        if engine == "unicorn":
            uc = self.uc = _uc_new(self.arch)
            if img.arm:
                try:
                    uc.ctl_set_cpu_model(A.UC_CPU_ARM64_MAX)
                except Exception:
                    pass
            R.map_image(uc, img.binary)
            for a, s in data:
                uc.mem_map(a, s, UC_PROT_READ | UC_PROT_WRITE)
            uc.mem_map(R.TRAMP, R.TRAMP_SIZE)
            uc.mem_map(SENT, 0x1000)
            self._w = uc.mem_write
            if img.arm:
                uc.hook_add(UC_HOOK_INTR, self._uc_stop)
            else:
                uc.hook_add(UC_HOOK_INSN, self._uc_stop, None, 1, 0, X.UC_X86_INS_SYSCALL)
        else:
            P = _icicle.MemoryProtection
            vm = self.vm = _icicle.Icicle(self.arch)
            # the image RWX, as recover_emulate's map_image leaves it on Unicorn
            R.map_image(_MapShim(vm, P.ExecuteReadWrite), img.binary)
            for a, s in data:
                vm.mem_map(a, s, P.ReadWrite)
            vm.mem_map(R.TRAMP, R.TRAMP_SIZE, P.ExecuteReadWrite)
            vm.mem_map(SENT, 0x1000, P.ExecuteRead)
            self._w = vm.mem_write
        self._w(R.TRAMP, tramp)
        for va, v in img.patches.items():
            try:
                self._w(R.BASE + va, struct.pack("<Q", v & self.pmask))
            except Exception:
                pass
        # The image's non-code pages (headers, .rodata, .data, .bss ...) are made non-executable on
        # both engines -- recover_emulate's block hook refuses to run them too -- and snapshotted
        # after relocation, then restored before every run, so no run's stores (a null-pointer
        # write lands in the header page at BASE 0) leak into the next one.
        pages = set()
        for sec in R._mappable_sections(img.binary):
            if not sec.virtual_address or not R._seg_extent(sec):
                continue
            lo = (R.BASE + sec.virtual_address) & ~0xfff
            hi = (R.BASE + sec.virtual_address + R._seg_extent(sec) + 0xfff) & ~0xfff
            pages.update(range(lo, hi, 0x1000))
        execr = [(img.text_va, img.text_end)] + list(img.exec_ranges)
        data_pages = sorted(pg for pg in pages
                            if not any(lo < pg + 0x1000 and pg < hi for lo, hi in execr))
        runs = []
        for pg in data_pages:
            if runs and runs[-1][1] == pg:
                runs[-1][1] = pg + 0x1000
            else:
                runs.append([pg, pg + 0x1000])
        self.restore = []
        for lo, hi in runs:
            try:
                if engine == "unicorn":
                    self.uc.mem_protect(lo, hi - lo, UC_PROT_READ | UC_PROT_WRITE)
                    blob = bytes(self.uc.mem_read(lo, hi - lo))
                else:
                    self.vm.mem_protect(lo, hi - lo, _icicle.MemoryProtection.ReadWrite)
                    blob = bytes(self.vm.mem_read(lo, hi - lo))
                self.restore.append((lo, blob))
            except Exception:
                continue                        # a page map_image could not map: nothing to keep
        self.stopped = None

    def _uc_stop(self, uc, *a):
        self.stopped = "trap"
        uc.emu_stop()

    def reset(self):
        """Same start state on both engines (not timed)."""
        R, w = self.R, self._w
        for va, blob in self.restore:
            try:
                w(va, blob)
            except Exception:
                pass
        w(R.STACK, b"\x00" * R.STACK_SIZE)
        w(R.SCRATCH, b"\x00" * 0x20000)
        w(R.HEAP, b"\x00" * self.HEAP_CLEAR)
        w(R.TLS, b"\x00" * R.TLS_SIZE)
        tp = R.TLS + R.TLS_SIZE // 2
        top = R.STACK + R.STACK_SIZE // 2
        regs = {r: 0 for r in _GPR[self.arch]}
        if self.arch == "aarch64":
            regs["x30"] = SENT
            for i in range(8):
                regs[f"x{i}"] = R.SCRATCH + 0x8000
            regs["sp"] = top
            regs["x29"] = 0
        else:
            w(tp, struct.pack("<Q", tp))
            w(top, struct.pack("<Q", SENT))
            regs.update(rsp=top, rbp=top)
            for r in ("rdi", "rsi", "rdx", "rcx", "r8", "r9"):
                regs[r] = R.SCRATCH + 0x8000
        if self.engine == "unicorn":
            for r, v in regs.items():
                self.uc.reg_write(_uc_reg(self.arch, r), v)
            if self.arch == "aarch64":
                self.uc.reg_write(A.UC_ARM64_REG_TPIDR_EL0, tp)
            else:
                self.uc.reg_write(X.UC_X86_REG_FS_BASE, tp)
        else:
            for r, v in regs.items():
                self.vm.reg_write(r, v)
            self.vm.reg_write("tpidr_el0" if self.arch == "aarch64" else "FS_OFFSET", tp)
        self.stopped = None

    def run(self, fva, budget):
        """Returns (seconds, stop reason). Only the engine call is timed."""
        pc = self.R.BASE + fva
        if self.engine == "unicorn":
            t = time.perf_counter()
            try:
                self.uc.emu_start(pc, SENT, count=budget)
                why = self.stopped or ("ret" if self.uc.reg_read(self._pc_reg()) == SENT else "budget")
            except UcError as e:
                # int3 / ud2-style CPU exceptions: "trap", as icicle reports them
                why = "trap" if e.errno == UC_ERR_EXCEPTION else "fault"
            return time.perf_counter() - t, why
        vm = self.vm
        vm.icount_limit = vm.icount + budget
        vm.pc = pc
        t = time.perf_counter()
        st = vm.run_until(SENT)
        dt = time.perf_counter() - t
        RS, E = _icicle.RunStatus, _icicle.ExceptionCode
        if vm.pc == SENT:
            why = "ret"
        elif st == RS.InstructionLimit:
            why = "budget"
        elif vm.exception_code == E.Syscall:
            why = "trap"                    # syscall / svc, and also int3 (icicle files it here)
        else:
            why = "fault"
        return dt, why

    def _pc_reg(self):
        return A.UC_ARM64_REG_PC if self.arch == "aarch64" else X.UC_X86_REG_RIP

    def regs(self):
        names = _GPR[self.arch]
        if self.engine == "unicorn":
            return tuple(self.uc.reg_read(_uc_reg(self.arch, r)) for r in names)
        return tuple(self.vm.reg_read(r) for r in names)

    def stack_hash(self):
        import hashlib
        R = self.R
        lo = R.STACK + R.STACK_SIZE // 2 - 0x4000
        rd = self.uc.mem_read if self.engine == "unicorn" else self.vm.mem_read
        return hashlib.sha256(bytes(rd(lo, 0x4000)) + bytes(rd(R.SCRATCH, 0x10000))).hexdigest()[:16]


def _order(img, k):
    import recover_emulate as R
    funcs = img.functions()
    try:
        scores = R._scores(img, funcs)
        order = sorted(funcs, key=lambda f: (-scores[f[0]], f[0]))
    except Exception:
        order = list(funcs)
    return order[:k] if k else order


def bench_funcs(path=DEFAULT_BINARY, k=60, budget=10000, passes=2):
    """Real functions on every engine; see the module docstring."""
    import recover_emulate as R
    img = R.Image(path)
    if img.x32:
        return {"binary": str(path), "skipped": "i686 is not covered by the function harness"}
    order = _order(img, k)
    out = {"binary": Path(path).name, "arch": "aarch64" if img.arm else "x86_64",
           "functions": len(order), "budget": budget, "passes": passes}

    engines = ["unicorn"] + (["icicle"] if _icicle is not None else [])
    plain, stops, finals = {}, {}, {}
    for eng in engines:
        t = time.perf_counter()
        p = _Plain(eng, img)
        setup = time.perf_counter() - t
        per_pass = []
        for ps in range(passes):
            tot = 0.0
            for fva, _size in order:
                p.reset()
                dt, why = p.run(fva, budget)
                tot += dt
                if ps == 0:
                    stops.setdefault(eng, []).append(why)
                    finals.setdefault(eng, []).append((p.regs(), p.stack_hash()))
            per_pass.append(tot)
        plain[eng] = {"setup_s": round(setup, 4), "pass_s": [round(x, 4) for x in per_pass]}

    # instructions per function: icicle counts them; Unicorn does not expose a count, so count the
    # unicorn run once more with a (slow, untimed) code hook -- the two must agree
    counts = []
    cp = _Plain("unicorn", img)
    n = [0]
    cp.uc.hook_add(UC_HOOK_CODE, lambda *a: n.__setitem__(0, n[0] + 1))
    for fva, _size in order:
        cp.reset()
        n[0] = 0
        cp.run(fva, budget)
        counts.append(n[0])
    insns = sum(counts)
    out["insns"] = insns
    out["stop_reasons"] = {e: {w: s.count(w) for w in sorted(set(s))} for e, s in stops.items()}
    if "icicle" in finals:
        same = sum(1 for a, b in zip(finals["unicorn"], finals["icicle"]) if a == b)
        out["equal_end_state"] = f"{same}/{len(order)}"
        out["mismatched"] = [f"{order[i][0]:#x}" for i, (a, b) in
                             enumerate(zip(finals["unicorn"], finals["icicle"])) if a != b][:16]
    for eng, d in plain.items():
        d["cold_minsn_s"] = round(insns / d["pass_s"][0] / 1e6, 2) if d["pass_s"][0] else None
        d["warm_minsn_s"] = round(insns / d["pass_s"][-1] / 1e6, 2) if d["pass_s"][-1] else None
    out["plain"] = plain

    # Unicorn with no-op Python hooks in recover_emulate's layout: the price of dispatch alone
    hp = _Plain("unicorn", img)
    hp.uc.hook_add(UC_HOOK_BLOCK, lambda uc, a, s, u: None)
    hp.uc.hook_add(UC_HOOK_MEM_WRITE, lambda uc, ac, a, s, v, u: None)
    tot = []
    for _ps in range(passes):
        x = 0.0
        for fva, _size in order:
            hp.reset()
            x += hp.run(fva, budget)[0]
        tot.append(x)
    out["unicorn_noop_hooks"] = {"pass_s": [round(x, 4) for x in tot],
                                 "warm_minsn_s": round(insns / tot[-1] / 1e6, 2) if tot[-1] else None}

    # recover_emulate's real Emulator.run on the same functions and budget (its own reset timed
    # separately and excluded, like the harness resets above)
    emu = R.Emulator(img)
    reset_t = [0.0]
    real_reset = emu._reset

    def timed_reset():
        t0 = time.perf_counter()
        real_reset()
        reset_t[0] += time.perf_counter() - t0
    emu._reset = timed_reset
    rec = []
    rec_insns = 0
    for ps in range(passes):
        reset_t[0] = 0.0
        t = time.perf_counter()
        n_ins = 0
        for fva, size in order:
            emu.run(fva, size, budget=budget)
            n_ins += emu.count
        rec.append(time.perf_counter() - t - reset_t[0])
        rec_insns = n_ins
    out["recover_emulate_run"] = {"pass_s": [round(x, 4) for x in rec], "insns": rec_insns,
                                  "warm_kinsn_s": round(rec_insns / rec[-1] / 1e3, 1) if rec[-1] else None}
    # where the time goes in recover_emulate's run, per instruction (warm)
    uc_ns = plain["unicorn"]["pass_s"][-1] / max(insns, 1) * 1e9
    hook_ns = out["unicorn_noop_hooks"]["pass_s"][-1] / max(insns, 1) * 1e9
    rec_ns = rec[-1] / max(rec_insns, 1) * 1e9
    split = {"engine_ns_per_insn": round(uc_ns, 1),
             "hook_dispatch_ns_per_insn": round(max(hook_ns - uc_ns, 0), 1),
             "hook_bodies_ns_per_insn": round(max(rec_ns - hook_ns, 0), 1),
             "recover_total_ns_per_insn": round(rec_ns, 1),
             "engine_share": round(uc_ns / rec_ns, 3) if rec_ns else None}
    if "icicle" in plain and plain["icicle"]["pass_s"][-1]:
        ic_ns = plain["icicle"]["pass_s"][-1] / max(insns, 1) * 1e9
        split["icicle_engine_ns_per_insn"] = round(ic_ns, 1)
        # Amdahl: recover_emulate with ONLY the engine swapped (if icicle had the hooks it needs)
        split["max_speedup_engine_swap"] = round(rec_ns / (rec_ns - uc_ns + ic_ns), 3) if rec_ns else None
    out["split"] = split
    return out


# --------------------------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------------------------

def host_info():
    import unicorn
    return {"machine": platform.machine(), "system": platform.system(),
            "python": platform.python_version(), "unicorn": unicorn.__version__,
            "icicle": icicle_version()}


def run_all(workload="all", quick=False, binary=None, nfuncs=None, budget=None, repeat=None):
    repeat = repeat or (1 if quick else 3)
    res = {"host": host_info()}
    if workload in ("loop", "all"):
        res["loop"] = bench_loop(n=(1 << 16) if quick else (1 << 20), repeat=repeat)
    if workload in ("hooks", "all"):
        res["hooks"] = bench_hooks(n=(1 << 14) if quick else (1 << 18), repeat=repeat,
                                   step_n=(1 << 10) if quick else (1 << 14))
    if workload in ("unpack", "all"):
        res["unpack"] = bench_unpack(repeat=1 if quick else 3)
    if workload in ("setup", "all"):
        res["setup"] = bench_setup(repeat=2 if quick else 5)
    if workload in ("funcs", "all"):
        res["funcs"] = bench_funcs(binary or DEFAULT_BINARY, k=nfuncs if nfuncs is not None else (12 if quick else 60),
                                   budget=budget or 10000)
    return res


def _print(res):
    h = res["host"]
    print(f"host: {h['system']} {h['machine']}, Python {h['python']}, unicorn {h['unicorn']}, "
          f"icicle {h['icicle'] or 'not installed'}")
    for key in ("loop", "hooks"):
        if key not in res:
            continue
        print(f"\n[{key}]")
        print(f"  {'arch':8} {'engine':18} {'hooks':28} {'insns':>9} {'cold s':>8} {'warm s':>8} "
              f"{'Minsn/s':>8}  ok")
        for r in res[key]:
            print(f"  {r['arch']:8} {r['engine']:18} {r.get('hooks', '-'):28} {r['insns']:>9} "
                  f"{r['cold_s']:>8.4f} {r['warm_s']:>8.4f} {r['minsn_s'] or 0:>8.2f}  {r['ok']}")
    if "unpack" in res:
        print(f"\n[unpack] {res['unpack']}")
    if "setup" in res:
        print("\n[setup] new instance: " + ", ".join(f"{k} {v}" for k, v in res["setup"].items()))
    if "funcs" in res:
        f = res["funcs"]
        print(f"\n[funcs] {f.get('binary')}")
        if "skipped" in f:
            print("  skipped:", f["skipped"])
            return
        print(f"  {f['functions']} functions, budget {f['budget']}, {f['insns']} instructions, "
              f"stops {f['stop_reasons']}, equal end state {f.get('equal_end_state', 'n/a')}")
        for eng, d in f["plain"].items():
            print(f"  {eng:8} no hooks: setup {d['setup_s']}s, passes {d['pass_s']} s, "
                  f"cold {d['cold_minsn_s']} / warm {d['warm_minsn_s']} Minsn/s")
        print(f"  unicorn + no-op py block/write hooks: {f['unicorn_noop_hooks']}")
        print(f"  recover_emulate Emulator.run: {f['recover_emulate_run']}")
        print(f"  split: {f['split']}")


def _selftest():
    import capstone
    # the hand-assembled loops decode to what the comments say
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    assert [i.mnemonic for i in md.disasm(LOOP["x86_64"][0], CODE)] == \
        ["xor", "add", "inc", "dec", "jne", "ret"]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    assert [i.mnemonic for i in md.disasm(LOOP["i686"][0], CODE)] == \
        ["xor", "add", "inc", "dec", "jne", "ret"]
    md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
    ins = list(md.disasm(LOOP["aarch64"][0], CODE))
    assert [i.mnemonic for i in ins] == ["mov", "ldrb", "eor", "add", "strb", "subs", "b.ne", "ret"]
    assert ins[6].op_str == f"#{CODE + 4:#x}", ins[6].op_str
    # every Unicorn layout decodes correctly (output checked against Python)
    rows = bench_loop(n=4096, repeat=1)
    assert rows and all(r["ok"] for r in rows), rows
    assert all(r["insns"] == LOOP[r["arch"]][1] * 4096 + LOOP[r["arch"]][2] for r in rows), rows
    hrows = bench_hooks(n=8192, repeat=1, step_n=256)
    assert all(r["ok"] for r in hrows), hrows
    by = {(r["engine"], r["hooks"]): r for r in hrows}
    assert by[("unicorn", "block")]["py_calls"] == 8192 + 1          # one block per iteration + ret
    assert by[("unicorn", "write narrowed to stack")]["py_calls"] == 0
    if _icicle is not None:
        assert by[("icicle", "page-fault write tracking")]["faults"] == 2
        assert by[("icicle", "step(1) per instruction")]["insns"] == 5 * 256 + 1
    print("selftest OK")


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False,
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("--workload", choices=("loop", "hooks", "unpack", "setup", "funcs", "all"), default="all")
    ap.add_argument("--binary", help=f"binary for the funcs workload (default {DEFAULT_BINARY.name})")
    ap.add_argument("--funcs", type=int, help="functions to run (top by decoder score; 0 = all)")
    ap.add_argument("--budget", type=int, help="instructions per function call (default 10000)")
    ap.add_argument("--repeat", type=int, help="timed repetitions for loop/hooks (median reported)")
    ap.add_argument("--quick", action="store_true", help="small sizes (seconds, for a smoke run)")
    ap.add_argument("--json", action="store_true", help="print the result dict as JSON")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    res = run_all(a.workload, a.quick, a.binary, a.funcs, a.budget, a.repeat)
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
