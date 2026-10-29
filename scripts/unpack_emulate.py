#!/usr/bin/env python3
"""unpack_emulate.py - static unpacking by emulation: run a self-unpacking stub under Unicorn
and recover the stage-2 it writes, without executing the sample on the host.

This is the *static* sibling of dump_unpacked.py (which runs the sample and dumps stage-2 from a
live process). Here nothing runs on the host: the stub is emulated, writes are tracked, and any
region that is both *written during the run* and *then executed* (a W^X / self-modifying step, the
signature of an in-place unpacker) is carved out and reported.

Scope (honest): this handles the common in-place / stub-at-entry unpacker that decodes a payload
into memory the image maps (or that it VirtualAllocs / mmaps) and jumps to it -- UPX and UPX-like
stubs, many Rust/crypter stubs -- on x86-64, x86-32 and AArch64, ELF (with or without a section
table) and PE. The image is mapped with its relocations, import slots and (PE) headers applied, and
the imports a stub relies on are answered (LoadLibrary/GetModuleHandle/GetProcAddress, VirtualAlloc/
VirtualProtect, a CRT start-up's usual calls; Linux mmap/mprotect/exit syscalls). Every pointer
GetProcAddress hands out that the stub stores to memory marks an IAT slot, so the result carries the
import table the stub REBUILT and the stage-2 call sites bound to it -- the packed program's imports,
recovered without running it.

Hand-offs are tracked by stage: every page records which stage last wrote it, and a JMP/RET into
code the CURRENT stage just produced is a hand-off. A hand-off into fresh memory (mmap/VirtualAlloc)
is an intermediate stage (UPX's ELF decompressor) and is followed; the first hand-off into the
file's own image is the original entry point (OEP). A CALL into produced code that returns (UPX runs
the program's TLS callbacks first) is reported as a callback, and a stub patching a byte or two of
itself is "self_patches", not stage-2. At an ELF entry point the stack is a real process stack
(argc/argv/envp/auxv), and the stub may re-open itself via /proc/self/exe -- only the sample itself
is ever served, every other path is ENOENT. Emulation stops at the
OEP unless --follow. It is NOT a universal unpacker: a stub that walks the PEB / export tables by
hand, needs real OS state, or uses an x86-32 stdcall import outside the known table stops early
(`stopped` says where); for those, point --entry at the unpacking routine (recover_cfg / detect_vm /
the string tiers help find it), or use the dynamic dump_unpacked.py in an isolated VM.

Safety: emulation is bounded (instruction count + wall clock) because a crafted stub can loop
forever; for batch use, run under forkserver isolation as recover_emulate.py does. Benign inputs
only.
"""
import hashlib
import math
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from recover_emulate import (  # noqa: E402  (shared, fuzz-hardened primitives)
    BASE, HEAP, HEAP_SIZE, RET_SENTINEL, STACK, STACK32, STACK_SIZE, TRAMP, TRAMP_SIZE, Image,
    map_image,
)
from emu_backend import fast_hook_add  # noqa: E402  (one Python frame per hook event)
from unicorn import (  # noqa: E402
    UC_ARCH_ARM64, UC_ARCH_X86, UC_HOOK_BLOCK, UC_HOOK_CODE, UC_HOOK_INSN, UC_HOOK_INTR,
    UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE,
    UC_HOOK_MEM_WRITE_UNMAPPED, UC_MODE_32, UC_MODE_64, UC_MODE_ARM, Uc, UcError,
)
from unicorn import x86_const as X  # noqa: E402
from unicorn import arm64_const as A  # noqa: E402

_MAX_INSNS = 20_000_000      # instruction budget: a crafted decode loop must not run forever
_WALL_S = 20.0               # wall-clock bound (slow hooks make instruction count a loose proxy)
_MIN_REGION = 16             # smallest written run worth reporting (bytes)
_MAX_REGIONS = 64            # cap carved regions so a scattered writer can't flood the report
_ENTROPY_HI = 7.2            # bits/byte above which a blob reads as packed/encrypted
_MAX_WRITE_PAGES = 1 << 15   # distinct pages a run may dirty (128 MB) before it is stopped
_DYN = TRAMP + TRAMP_SIZE // 2   # trampolines handed out by GetProcAddress / dlsym at run time
_DYN_MAX = (TRAMP_SIZE // 2) // 16
_MODULES = 0x6f000000        # fake HMODULE values returned by LoadLibrary / GetModuleHandle
_MAX_CALLSITES = 4096
_CALLSITE_SCAN = 16 << 20    # bytes of each executed stage disassembled for call-site binding
_MAX_STAGES = 16             # hand-offs followed before giving up (a staged packer, not a loop)

# Win32 imports an unpacking stub uses, with their stdcall argument counts (x86-32 callee pops them).
# Anything else returns 0; on x86-32 PE an unknown stdcall import cannot be returned from safely
# (unknown stack cleanup), so emulation stops there with stopped="import:<name>".
_WIN_ARGS = {
    "loadlibrarya": 1, "loadlibraryw": 1, "loadlibraryexa": 3, "loadlibraryexw": 3,
    "getmodulehandlea": 1, "getmodulehandlew": 1, "getprocaddress": 2, "virtualprotect": 4,
    "virtualalloc": 4, "virtualfree": 3, "flushinstructioncache": 3, "exitprocess": 1,
    "getcurrentprocess": 0, "isdebuggerpresent": 0, "getlasterror": 0, "sleep": 1,
    # what a CRT start-up / TLS callback typically calls before (or right after) the entry point
    "setlasterror": 1, "initializecriticalsection": 1, "entercriticalsection": 1,
    "leavecriticalsection": 1, "deletecriticalsection": 1, "tlsalloc": 0, "tlsgetvalue": 1,
    "tlssetvalue": 2, "tlsfree": 1, "getmodulefilenamea": 3, "getmodulefilenamew": 3,
    "getenvironmentvariablea": 3, "getenvironmentvariablew": 3, "gettickcount": 0,
    "createfilea": 7, "createfilew": 7, "getfilesize": 2, "closehandle": 1,
    "setunhandledexceptionfilter": 1, "virtualquery": 3, "getstartupinfoa": 1,
    "getstartupinfow": 1, "getcommandlinea": 0, "getcommandlinew": 0, "getcurrentthreadid": 0,
    "getcurrentprocessid": 0, "queryperformancecounter": 1, "getsystemtimeasfiletime": 1,
    "isdbcsleadbyteex": 2, "multibytetowidechar": 6, "widechartomultibyte": 8, "freelibrary": 1,
    "getprocessheap": 0, "heapalloc": 3, "heapfree": 3, "exitthread": 1,
}
# C runtime DLLs export cdecl functions: the caller cleans the stack, so any of them can be returned
# from on x86-32 without knowing its argument count
_CDECL_DLLS = ("msvcrt", "ucrtbase", "api-ms-win-crt", "vcruntime", "libc", "libgcc")
# Linux syscalls an unpacking stub uses: (x86-64, aarch64) numbers
_SYS = {"mmap": (9, 222), "mprotect": (10, 226), "munmap": (11, 215), "exit": (60, 93),
        "exit_group": (231, 94), "open": (2, None), "openat": (257, 56), "close": (3, 57),
        "read": (0, 63), "pread64": (17, 67), "lseek": (8, 62), "readlink": (89, None),
        "readlinkat": (267, 78), "write": (1, 64), "writev": (20, 66)}
_ENOENT, _EBADF = -2, -9
# A self-unpacking ELF stub re-opens its own file (UPX: openat + readlinkat("/proc/self/exe"), then
# mmap of that fd). Only the sample itself is ever served -- any other path is ENOENT.
_SELF_PATHS = ("/proc/self/exe",)
_SELF_FD = 3


def _entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    return sum(1 for x in b if 0x20 <= x < 0x7f or x in (9, 10, 13)) / len(b)


def _map_segments(uc, binary):
    """An ELF with no section table (UPX output, hand-stripped) maps nothing through map_image:
    map its PT_LOAD segments instead, with the same per-segment cap recover_emulate uses."""
    import lief
    from recover_emulate import _SEG_CAP, _MAX_MAP_VA
    for sg in binary.segments:
        try:
            if sg.type != lief.ELF.Segment.TYPE.LOAD:
                continue
            va, msz = sg.virtual_address, min(sg.virtual_size, _SEG_CAP)
            lo, hi = va & ~0xfff, (va + max(msz, 1) + 0xfff) & ~0xfff
            if not msz or BASE + hi > _MAX_MAP_VA:
                continue
            for pg in range(BASE + lo, BASE + hi, 0x1000):
                try:
                    uc.mem_map(pg, 0x1000)
                except UcError:
                    pass                       # already mapped by an overlapping segment
            c = bytes(sg.content)[:msz]
            if c:
                uc.mem_write(BASE + va, c)
        except (UcError, AttributeError, ValueError):
            continue


class _Unpacker:
    """A bounded emulator that watches for write-then-execute (self-unpacking).

    It maps the image with its relocations and import slots applied, answers the Win32 / libc
    imports and Linux syscalls an unpacking stub relies on (LoadLibrary/GetProcAddress/
    VirtualProtect/VirtualAlloc, mmap/mprotect), and records the import table the stub rebuilds:
    every pointer GetProcAddress hands out that is then stored to memory marks an IAT slot."""

    def __init__(self, img: Image, follow=False):
        self.img = img
        self.arm, self.x32, self.pe = img.arm, img.x32, img.pe
        self.ptr = 4 if self.x32 else 8
        self.follow = follow             # keep running past the first jump into unpacked code
        self.wpages = {}                 # page -> bytearray(4096) bitmap of bytes stored this run
        self.wx_hits = []                # block addresses executed from memory written this run
        self.self_patches = []           # blocks that ran over a few self-patched bytes (not stage-2)
        self.callbacks = []              # unpacked code the stub CALLed and got control back from
        self.first_unpacked = None       # first unpacked block executed (a callback or the OEP)
        self.prev_block = None           # (address, size, producing stage | None) of the last block
        self.epoch = 0                   # stage counter: 0 = the stub, +1 at every hand-off
        self.page_epoch = {}             # page -> stage that last wrote it
        self.handoffs = []               # [{va, in_image}] every jump into freshly produced code
        self.oep = None
        self.stopped = "ret"             # ret|oep|exit|budget|timeout|unmapped|write_cap|error|import:<n>
        self.blocks = 0
        self.modules = {}                # fake handle -> dll name
        self.dyn = []                    # GetProcAddress names; dyn i lives at _DYN + 16*i
        self.dyn_by_name = {}
        self.iat = {}                    # slot va -> "dll!api" for slots the stub filled in
        self.import_calls = []           # (name) of each emulated import call, capped
        self.heap_next = HEAP + 0x100000
        self._file = None                # the sample's bytes, read lazily if the stub re-opens itself
        self._fd_off = 0
        if self.arm:
            self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            self.SP, self.PC, self.RET = A.UC_ARM64_REG_SP, A.UC_ARM64_REG_PC, A.UC_ARM64_REG_X0
        elif self.x32:
            self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
            self.SP, self.PC, self.RET = X.UC_X86_REG_ESP, X.UC_X86_REG_EIP, X.UC_X86_REG_EAX
        else:
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
            self.SP, self.PC, self.RET = X.UC_X86_REG_RSP, X.UC_X86_REG_RIP, X.UC_X86_REG_RAX
        self.stack = STACK32 if self.x32 else STACK
        uc = self.uc
        map_image(uc, img.binary)
        if img.fmt == "ELF" and not len(img.binary.sections):
            _map_segments(uc, img.binary)
        if self.pe:
            # the PE headers live at the image base (RVA 0) in a real process, and unpacking stubs
            # touch them: UPX VirtualProtects the header page and clears section flags in place
            try:
                hdr = min(max(img.binary.optional_header.sizeof_headers, 0x200), 0x10000)
                uc.mem_map(BASE, (hdr + 0xfff) & ~0xfff)
                uc.mem_write(BASE, Path(img.path).read_bytes()[:hdr])
            except (UcError, OSError):
                pass                                   # overlaps a section: leave it as mapped
        uc.mem_map(self.stack, STACK_SIZE)
        uc.mem_map(HEAP, HEAP_SIZE)
        uc.mem_map(TRAMP, TRAMP_SIZE)
        uc.mem_write(TRAMP, b"\xc3" * TRAMP_SIZE)
        # relocations and import slots, as recover_emulate's emulator applies them
        fmt = "<I" if self.x32 else "<Q"
        mask = (1 << (8 * self.ptr)) - 1
        for va, v in img.patches.items():
            try:
                uc.mem_write(BASE + va, struct.pack(fmt, v & mask))
            except (UcError, struct.error):
                pass
        # the file's own image (sections, or PT_LOAD segments when there is no section table)
        self.image_ranges = []
        from recover_emulate import _seg_extent
        for sec in img.binary.sections:
            try:
                if sec.virtual_address and _seg_extent(sec):
                    self.image_ranges.append((BASE + sec.virtual_address,
                                              BASE + sec.virtual_address + _seg_extent(sec)))
            except Exception:
                continue
        if img.fmt == "ELF":
            for sg in img.binary.segments:
                try:
                    if int(sg.type) == 1 and sg.virtual_size:
                        self.image_ranges.append((BASE + sg.virtual_address,
                                                  BASE + sg.virtual_address + sg.virtual_size))
                except Exception:
                    continue
        fast_hook_add(uc, UC_HOOK_MEM_WRITE, self._on_write)
        fast_hook_add(uc, UC_HOOK_BLOCK, self._on_block)
        fast_hook_add(uc, UC_HOOK_CODE, self._on_tramp, None, TRAMP, TRAMP + TRAMP_SIZE - 1)
        fast_hook_add(
            uc, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
            self._on_unmapped)
        if self.arm:
            uc.hook_add(UC_HOOK_INTR, self._on_intr)
        elif not self.x32:
            uc.hook_add(UC_HOOK_INSN, self._on_syscall, None, 1, 0, X.UC_X86_INS_SYSCALL)

    # ---- memory bookkeeping ------------------------------------------------------------------
    def _written(self, a):
        bm = self.wpages.get(a & ~0xfff)
        return bool(bm and (bm[(a & 0xfff) >> 3] >> (a & 7)) & 1)

    def _on_write(self, uc, access, address, size, value, _):
        # per-page BIT maps (512 bytes per dirtied page): at the page cap that is 16 MB of
        # bookkeeping for 128 MB of tracked writes, bounded however much the stub stores
        if not (0 < size <= 64):
            return
        # page by page (a store spans at most two): one bitmap lookup per page, not per byte
        a, end = address, address + size
        wpages = self.wpages
        while a < end:
            pg = a & ~0xfff
            bm = wpages.get(pg)
            if bm is None:
                if len(wpages) >= _MAX_WRITE_PAGES:
                    self.stopped = "write_cap"
                    uc.emu_stop()
                    return
                bm = wpages[pg] = bytearray(512)
            stop = min(end, pg + 0x1000)
            for o in range(a & 0xfff, ((stop - 1) & 0xfff) + 1):
                bm[o >> 3] |= 1 << (o & 7)
            self.page_epoch[pg] = self.epoch
            a = stop
        # a pointer GetProcAddress returned, stored to memory = an IAT slot the stub rebuilt
        if size == self.ptr and _DYN <= value < _DYN + 16 * len(self.dyn):
            self.iat[address - BASE] = self.dyn[(value - _DYN) // 16]
        elif size == self.ptr and TRAMP <= value < TRAMP + 16 * len(self.img.tramp):
            self.iat[address - BASE] = self.img.tramp[(value - TRAMP) // 16]

    def _on_block(self, uc, address, size, _):
        self.blocks += 1
        if TRAMP <= address < TRAMP + TRAMP_SIZE:
            return              # an emulated import: transparent to stub/stage-2 hand-off tracking
        bm = self.wpages.get(address & ~0xfff)      # (self._written(address), inlined: hot)
        if not (bm and (bm[(address & 0xfff) >> 3] >> (address & 7)) & 1):
            self.prev_block = (address, size, None)        # original file code
            return
        n = max(1, min(size, 64))
        if sum(1 for a in range(address, address + n) if self._written(a)) * 2 < n:
            # a stub patching a byte or two of itself (UPX flips a TLS-callback `ret` to `cld`) is
            # self-modification, not an unpacked stage: note it, keep going
            if len(self.self_patches) < 64:
                self.self_patches.append(address)
            self.prev_block = (address, size, None)
            return
        # a block mostly made of bytes written during this run = unpacked code
        self.wx_hits.append(address)
        if self.first_unpacked is None:
            self.first_unpacked = address
        produced_by = self.page_epoch.get(address & ~0xfff)
        prev, self.prev_block = self.prev_block, (address, size, produced_by)
        if produced_by != self.epoch:
            return              # code an EARLIER stage produced: the current stage running its own code
        if prev is not None and prev[2] == self.epoch:
            return              # already inside the code the current stage produced (no transition)
        # control reached code the CURRENT stage just produced. A CALL that will come back (the
        # return address sits right after the previous block) is the stage invoking a callback --
        # UPX runs the program's TLS callbacks first; a JMP / RET into it is a hand-off.
        if prev is not None and self._called_from(prev[0] + prev[1]):
            if len(self.callbacks) < 64:
                self.callbacks.append(address)
            return
        in_image = any(lo <= address < hi for lo, hi in self.image_ranges)
        self.handoffs.append({"va": address - BASE, "in_image": in_image})
        self.epoch += 1
        if in_image:
            # unpacked code inside the file's own image: the original entry point. A hand-off into
            # fresh memory (mmap / VirtualAlloc) is an intermediate stage -- e.g. UPX's ELF
            # decompressor -- and emulation follows it to the next hand-off.
            if self.oep is None:
                self.oep = address
            if not self.follow:
                self.stopped = "oep"
                uc.emu_stop()
        elif len(self.handoffs) >= _MAX_STAGES:
            self.stopped = "stages"
            uc.emu_stop()

    def _on_unmapped(self, uc, access, address, size, value, _):
        self.stopped = "unmapped"
        self.fault = address
        uc.emu_stop()
        return False

    def _called_from(self, ret_site):
        """Was the current block entered by a call whose return address is `ret_site`?"""
        try:
            if self.arm:
                return self.uc.reg_read(A.UC_ARM64_REG_X30) == ret_site
            sp = self.uc.reg_read(self.SP)
            ra = struct.unpack("<I" if self.x32 else "<Q", self.uc.mem_read(sp, self.ptr))[0]
            return ra == ret_site
        except UcError:
            return False

    # ---- calling convention helpers ------------------------------------------------------------
    def _arg(self, i):
        uc = self.uc
        if self.arm:
            return uc.reg_read(A.UC_ARM64_REG_X0 + i) if i < 8 else 0
        if self.x32:
            sp = uc.reg_read(X.UC_X86_REG_ESP)
            return struct.unpack("<I", uc.mem_read(sp + 4 + 4 * i, 4))[0]
        regs = ([X.UC_X86_REG_RCX, X.UC_X86_REG_RDX, X.UC_X86_REG_R8, X.UC_X86_REG_R9] if self.pe
                else [X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX, X.UC_X86_REG_RCX,
                      X.UC_X86_REG_R8, X.UC_X86_REG_R9])
        if i < len(regs):
            return uc.reg_read(regs[i])
        sp = uc.reg_read(X.UC_X86_REG_RSP)          # Win64: 32-byte shadow space + return address
        return struct.unpack("<Q", uc.mem_read(sp + 8 + 8 * i, 8))[0]

    def _ret(self, value, nargs=0):
        """Return from an emulated import: set the result, pop the return address (and, for x86-32
        stdcall, the callee-cleaned arguments)."""
        uc = self.uc
        if self.arm:
            uc.reg_write(A.UC_ARM64_REG_X0, value & (2**64 - 1))
            uc.reg_write(A.UC_ARM64_REG_PC, uc.reg_read(A.UC_ARM64_REG_X30))
            return
        sp = uc.reg_read(self.SP)
        ret = struct.unpack("<I" if self.x32 else "<Q", uc.mem_read(sp, self.ptr))[0]
        uc.reg_write(self.RET, value & ((1 << (8 * self.ptr)) - 1))
        uc.reg_write(self.SP, sp + self.ptr + (4 * nargs if (self.x32 and self.pe) else 0))
        uc.reg_write(self.PC, ret)

    def _cstr(self, p, wide=False, limit=512):
        if not p:
            return ""
        try:
            raw = bytes(self.uc.mem_read(p, limit * (2 if wide else 1)))
        except UcError:
            return ""
        if wide:
            out = raw.decode("utf-16-le", "replace")
        else:
            out = raw.decode("latin-1")
        return out.split("\0", 1)[0]

    def _alloc(self, size):
        size = max(0x1000, (size + 0xfff) & ~0xfff)
        if self.heap_next + size > HEAP + HEAP_SIZE:
            return 0
        a, self.heap_next = self.heap_next, self.heap_next + size
        return a

    # ---- imports ---------------------------------------------------------------------------------
    def _on_tramp(self, uc, address, size, _):
        if address >= _DYN:
            i = (address - _DYN) // 16
            name = self.dyn[i] if i < len(self.dyn) else "?"
        else:
            i = (address - TRAMP) // 16
            name = self.img.tramp[i] if i < len(self.img.tramp) else "?"
        api = name.split("!")[-1].split("@")[0].lstrip("_").lower()
        if len(self.import_calls) < 4096:
            self.import_calls.append(name)
        try:
            self._import(api, name)
        except UcError:
            self.stopped = "error"
            uc.emu_stop()

    def _import(self, api, name):
        uc = self.uc
        nargs = _WIN_ARGS.get(api, 0)
        if api in ("loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw",
                   "getmodulehandlea", "getmodulehandlew", "dlopen"):
            dll = self._cstr(self._arg(0), wide=api.endswith("w")) or "<self>"
            h = next((k for k, v in self.modules.items() if v.lower() == dll.lower()), None)
            if h is None:
                h = _MODULES + 0x10000 * len(self.modules)
                self.modules[h] = dll
            return self._ret(h, nargs)
        if api in ("getprocaddress", "dlsym"):
            dll = self.modules.get(self._arg(0), "?")
            p = self._arg(1)
            sym = f"#{p}" if p < 0x10000 else self._cstr(p, limit=256)
            full = f"{dll}!{sym}"
            if full not in self.dyn_by_name:
                if len(self.dyn) >= _DYN_MAX:
                    return self._ret(0, nargs)
                self.dyn_by_name[full] = _DYN + 16 * len(self.dyn)
                self.dyn.append(full)
            return self._ret(self.dyn_by_name[full], nargs)
        if api == "virtualalloc":
            want, size = self._arg(0), self._arg(1)
            if want:
                try:
                    uc.mem_read(want, 1)
                    return self._ret(want, nargs)
                except UcError:
                    pass
            return self._ret(self._alloc(size), nargs)
        if api == "virtualprotect":
            old = self._arg(3)
            if old:
                try:
                    uc.mem_write(old, struct.pack("<I", 0x40))
                except UcError:
                    pass
            return self._ret(1, nargs)
        if api in ("virtualfree", "flushinstructioncache"):
            return self._ret(1, nargs)
        if api in ("exitprocess", "exit", "_exit"):
            self.stopped = "exit"
            uc.emu_stop()
            return
        if api in ("malloc", "calloc"):
            n = self._arg(0) * (self._arg(1) if api == "calloc" else 1)
            return self._ret(self._alloc(min(n, HEAP_SIZE)), nargs)
        dll = name.split("!")[0].lower() if "!" in name else ""
        if self.x32 and self.pe and api not in _WIN_ARGS and not dll.startswith(_CDECL_DLLS):
            # unknown stdcall cleanup: returning would corrupt the stack, so stop honestly here
            self.stopped = f"import:{name}"
            uc.emu_stop()
            return
        return self._ret(0, nargs)

    # ---- syscalls ----------------------------------------------------------------------------------
    def _is(self, nr, name):
        n = _SYS[name][1 if self.arm else 0]
        return n is not None and nr == n

    def _self_bytes(self):
        if self._file is None:
            try:
                self._file = Path(self.img.path).read_bytes()
            except OSError:
                self._file = b""
        return self._file

    def _syscall(self, nr, args):
        neg = lambda e: e & (2**64 - 1)                     # noqa: E731  (-errno, as the kernel returns)
        uc = self.uc
        if self._is(nr, "mmap"):
            addr, length, flags, fd, off = args[0], args[1], args[3], args[4], args[5]
            length = min(length, HEAP_SIZE)
            if addr and flags & 0x10:                       # MAP_FIXED: make sure it is mapped
                lo, hi = addr & ~0xfff, (addr + length + 0xfff) & ~0xfff
                for pg in range(lo, hi, 0x1000):
                    try:
                        uc.mem_map(pg, 0x1000)
                    except UcError:
                        pass
                if flags & 0x20:                            # MAP_ANONYMOUS replaces with zero pages
                    try:
                        uc.mem_write(lo, b"\0" * (hi - lo))
                    except UcError:
                        pass
                at = addr
            else:
                at = self._alloc(length)
                if not at:
                    return neg(-12)
            if not flags & 0x20 and fd == _SELF_FD:         # file-backed mapping of the sample itself
                data = self._self_bytes()[off:off + length]
                try:
                    uc.mem_write(at, data)
                except UcError:
                    pass
            return at
        if self._is(nr, "exit") or self._is(nr, "exit_group"):
            self.stopped = "exit"
            uc.emu_stop()
            return 0
        if self._is(nr, "open") or self._is(nr, "openat"):
            path = self._cstr(args[1] if self._is(nr, "openat") else args[0], limit=4096)
            if path in _SELF_PATHS or path == str(self.img.path):
                self._fd_off = 0
                return _SELF_FD
            return neg(_ENOENT)
        if self._is(nr, "readlink") or self._is(nr, "readlinkat"):
            path_p, buf, size = (args[1], args[2], args[3]) if self._is(nr, "readlinkat") \
                else (args[0], args[1], args[2])
            if self._cstr(path_p, limit=4096) not in _SELF_PATHS:
                return neg(_ENOENT)
            target = str(Path(self.img.path).resolve()).encode()[:max(0, size)]
            try:
                uc.mem_write(buf, target)
            except UcError:
                return neg(-14)                             # EFAULT
            return len(target)
        if self._is(nr, "read") or self._is(nr, "pread64"):
            fd, buf, size = args[0], args[1], min(args[2], HEAP_SIZE)
            if fd != _SELF_FD:
                return neg(_EBADF)
            off = args[3] if self._is(nr, "pread64") else self._fd_off
            data = self._self_bytes()[off:off + size]
            try:
                uc.mem_write(buf, data)
            except UcError:
                return neg(-14)
            if self._is(nr, "read"):
                self._fd_off = off + len(data)
            return len(data)
        if self._is(nr, "lseek"):
            if args[0] != _SELF_FD:
                return neg(_EBADF)
            whence, off = args[2], args[1]
            base = {0: 0, 1: self._fd_off, 2: len(self._self_bytes())}.get(whence)
            if base is None:
                return neg(-22)
            self._fd_off = max(0, base + (off - 2**64 if off >= 2**63 else off))
            return self._fd_off
        if self._is(nr, "write"):
            return min(args[2], 1 << 30)                    # swallowed, but report it as written
        if self._is(nr, "writev"):
            total = 0
            for i in range(min(args[2], 64)):
                try:
                    total += struct.unpack("<Q", bytes(uc.mem_read(args[1] + 16 * i + 8, 8)))[0]
                except UcError:
                    break
            return min(total, 1 << 30)
        return 0                                            # mprotect/munmap/close/...: success

    def _on_syscall(self, uc, _):
        nr = uc.reg_read(X.UC_X86_REG_RAX)
        args = [uc.reg_read(r) for r in (X.UC_X86_REG_RDI, X.UC_X86_REG_RSI, X.UC_X86_REG_RDX,
                                         X.UC_X86_REG_R10, X.UC_X86_REG_R8, X.UC_X86_REG_R9)]
        uc.reg_write(X.UC_X86_REG_RAX, self._syscall(nr, args))

    def _on_intr(self, uc, intno, _):
        if intno != 2:                                      # 2 = EXCP_SWI (svc)
            self.stopped = "error"
            uc.emu_stop()
            return
        nr = uc.reg_read(A.UC_ARM64_REG_X8)
        args = [uc.reg_read(A.UC_ARM64_REG_X0 + i) for i in range(6)]
        uc.reg_write(A.UC_ARM64_REG_X0, self._syscall(nr, args))

    # ---- run ---------------------------------------------------------------------------------------
    def _process_stack(self, entry_va):
        """The initial stack the kernel hands an ELF at its entry point: argc, argv, envp and the
        auxiliary vector (AT_PHDR/AT_PHNUM/AT_PAGESZ/AT_ENTRY/AT_RANDOM/AT_EXECFN ...). A self-
        unpacking stub (UPX) reads these to find its program headers and the real entry. Returns sp."""
        uc, w = self.uc, self.ptr
        fmt = "<I" if w == 4 else "<Q"
        top = self.stack + STACK_SIZE - 0x100
        name = str(Path(self.img.path).resolve()).encode()[:200] + b"\0"
        execfn = top - len(name)
        rnd = (execfn - 16) & ~0xf
        uc.mem_write(execfn, name)
        uc.mem_write(rnd, bytes(range(16)))
        b = self.img.binary
        try:
            phoff, phnum = b.header.program_header_offset, b.header.numberof_segments
            first = min((sg.virtual_address - sg.file_offset for sg in b.segments
                         if int(sg.type) == 1 and sg.file_offset <= phoff), default=0)
            phdr = first + phoff
        except Exception:
            phnum, phdr = 0, 0
        auxv = [(3, phdr), (4, 32 if w == 4 else 56), (5, phnum), (6, 0x1000), (7, 0), (8, 0),
                (9, entry_va), (11, 1000), (12, 1000), (13, 1000), (14, 1000), (16, 0), (17, 100),
                (23, 0), (25, rnd), (31, execfn), (0, 0)]
        words = [1, execfn, 0, 0] + [x for kv in auxv for x in kv]     # argc, argv[0], NULL, envp NULL
        sp = (rnd - 8 * len(words) - 0x40) & ~0xf
        uc.mem_write(sp, b"".join(struct.pack(fmt, x & ((1 << (8 * w)) - 1)) for x in words))
        return sp

    def run(self, entry_rva: int):
        import time
        uc = self.uc
        sp = self.stack + STACK_SIZE - 0x1000
        at_elf_entry = self.img.fmt == "ELF" and BASE + entry_rva == BASE + self.img.binary.entrypoint
        if at_elf_entry:
            # a process entry point: no return address, [sp] = argc (as the kernel sets it up)
            sp = self._process_stack(BASE + entry_rva)
            uc.reg_write(self.SP, sp)
            if self.arm:
                uc.reg_write(A.UC_ARM64_REG_X30, RET_SENTINEL)
        else:
            uc.reg_write(self.SP, sp)
            if self.arm:
                uc.reg_write(A.UC_ARM64_REG_X30, RET_SENTINEL)
            else:
                uc.mem_write(sp, struct.pack("<I" if self.x32 else "<Q", RET_SENTINEL))
        t0 = time.monotonic()
        try:
            uc.emu_start(BASE + entry_rva, RET_SENTINEL, timeout=int(_WALL_S * 1e6), count=_MAX_INSNS)
        except UcError:
            if self.stopped == "ret":
                self.stopped = "error"
        if self.stopped == "ret" and uc.reg_read(self.PC) != RET_SENTINEL:
            # emu_start returned without reaching the sentinel: a budget or wall-clock stop
            self.stopped = "timeout" if time.monotonic() - t0 >= _WALL_S * 0.98 else "budget"
        return self._regions()

    def _runs(self):
        """Contiguous written runs (gaps <= 8 bytes bridged), from the per-page bit maps."""
        runs, start, prev = [], None, None
        for pg in sorted(self.wpages):
            bm = self.wpages[pg]
            for byte_i, bits in enumerate(bm):
                if not bits:
                    continue
                for bit in range(8):
                    if not (bits >> bit) & 1:
                        continue
                    a = pg + (byte_i << 3) + bit
                    if start is None:
                        start = a
                    elif a - prev > 8:
                        runs.append((start, prev + 1))
                        start = a
                    prev = a
        if start is not None:
            runs.append((start, prev + 1))
        return runs

    def _regions(self):
        if not self.wpages:
            return []
        wx = sorted(set(self.wx_hits))
        text_lo = BASE + self.img.text_va
        text_hi = BASE + self.img.text_end
        out = []
        for lo, hi in self._runs():
            if hi - lo < _MIN_REGION:
                continue
            if self.stack <= lo < self.stack + STACK_SIZE:    # stack scribble, never a payload
                continue
            try:
                data = bytes(self.uc.mem_read(lo, hi - lo))
            except UcError:
                continue
            out.append({
                "va": lo - BASE,
                "size": hi - lo,
                "sha256": hashlib.sha256(data).hexdigest(),
                "entropy": round(_entropy(data), 2),
                "printable_ratio": round(_printable_ratio(data), 2),
                # executed means: a block ran from bytes that had been written this run (W -> X).
                # Code that ran first and was overwritten afterwards is not an unpacked stage.
                "executed": any(lo <= w < hi for w in wx),
                "in_text": text_lo <= lo < text_hi,
                "_bytes": data,
            })
        out.sort(key=lambda r: (not r["executed"], -r["size"]))
        return out[:_MAX_REGIONS]

    def callsites(self, regions):
        """Bind call/jmp [slot] sites in the executed stage-2 to the import the stub stored in that
        slot: the unpacked program's import table, reconstructed without running it."""
        if not self.iat or self.arm:
            return []
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        from capstone.x86 import X86_OP_MEM, X86_REG_RIP
        md = Cs(CS_ARCH_X86, CS_MODE_32 if self.x32 else CS_MODE_64)
        md.detail = True
        md.skipdata = True
        out = []
        for r in regions:
            if not r["executed"]:
                continue
            for insn in md.disasm(r["_bytes"][:_CALLSITE_SCAN], BASE + r["va"]):
                if insn.mnemonic not in ("call", "jmp") or not insn.operands:
                    continue
                op = insn.operands[0]
                if op.type != X86_OP_MEM or op.mem.index:
                    continue
                if op.mem.base == X86_REG_RIP:
                    slot = insn.address + insn.size + op.mem.disp
                elif op.mem.base == 0 and self.x32:
                    slot = op.mem.disp & 0xffffffff
                else:
                    continue
                api = self.iat.get(slot - BASE)
                if api:
                    out.append({"va": insn.address - BASE, "kind": insn.mnemonic,
                                "slot": slot - BASE, "api": api})
                    if len(out) >= _MAX_CALLSITES:
                        return out
        return out


def recover(path, entry=None, follow=False) -> dict:
    """Emulate `path` from its entry (or `entry`, an RVA -- a PE VA >= the image base is accepted
    and rebased) and report written-then-executed regions plus the import table the stub rebuilt.

    Returns {arch, entry, oep, instructions_blocks, stopped, unpacked:[{va,size,sha256,entropy,
    printable_ratio,executed,in_text}], unpacked_detected, rebuilt_imports, import_callsites,
    import_calls}; on an input it cannot load, {"error": ..., "unpacked_detected": False, ...}.
    """
    empty = {"unpacked_detected": False, "unpacked": [], "_regions": [], "rebuilt_imports": [],
             "import_callsites": [], "stopped": "error", "oep": None}
    try:
        img = Image(path)
    except Exception as e:                      # unparseable / no executable code: report, don't crash
        return {"error": f"cannot load: {e}", "arch": None, "entry": None,
                "instructions_blocks": 0, **empty}
    if entry is None:
        entry_rva = img.binary.entrypoint - img.imagebase
    else:
        entry_rva = entry - img.imagebase if (img.pe and entry >= img.imagebase) else entry
    arch = "aarch64" if img.arm else ("x86" if img.x32 else "x86_64")
    try:
        up = _Unpacker(img, follow=follow)
        regions = up.run(entry_rva)
    except (UcError, MemoryError, ValueError, OverflowError) as e:
        return {"error": f"emulator setup failed: {e}", "arch": arch, "entry": entry_rva,
                "instructions_blocks": 0, **empty}
    detected = any(r["executed"] and (not r["in_text"] or r["entropy"] < 7.9) for r in regions)
    if up.oep is None and up.handoffs:
        # every hand-off went to fresh memory (no in-image stage-2): the last one is the best OEP
        up.oep = BASE + up.handoffs[-1]["va"]
    elif up.oep is None and up.first_unpacked is not None:
        # never saw a JMP hand-off (the stub CALLed into stage-2 and the run ended inside it):
        # the first unpacked code is the best available OEP estimate
        up.oep = up.first_unpacked
    rebuilt = [{"slot": k, "api": v} for k, v in sorted(up.iat.items())]
    return {
        "arch": arch,
        "entry": entry_rva,
        "oep": (up.oep - BASE) if up.oep is not None else None,
        "instructions_blocks": up.blocks,
        "stopped": up.stopped,
        "unpacked_detected": detected,
        "unpacked": [{k: v for k, v in r.items() if k != "_bytes"} for r in regions],
        "rebuilt_imports": rebuilt,
        "import_callsites": up.callsites(regions),
        "import_calls": sorted(set(up.import_calls))[:200],
        "self_patches": [a - BASE for a in up.self_patches],
        "callbacks": [a - BASE for a in up.callbacks],
        "handoffs": up.handoffs,
        "_regions": regions,            # kept for --dump; stripped by --json
    }


def _print(res):
    if res.get("error"):
        print(f"error: {res['error']}")
        return
    oep = f" oep=0x{res['oep']:x}" if res.get("oep") is not None else ""
    print(f"arch={res['arch']} entry=0x{res['entry']:x} blocks={res['instructions_blocks']} "
          f"stopped={res['stopped']}{oep} unpacked_detected={res['unpacked_detected']}")
    if res.get("rebuilt_imports"):
        print(f"  import table rebuilt by the stub: {len(res['rebuilt_imports'])} entries, "
              f"{len(res.get('import_callsites', []))} call sites in stage-2 bound to them")
    if not res["unpacked"]:
        print("  no written-then-executed region observed from this entry.")
        print("  If the sample unpacks past libc _start or via mmap, pass --entry <unpack-routine>")
        print("  (recover_cfg.py / detect_vm.py help locate it), or use dynamic dump_unpacked.py.")
        return
    for r in res["unpacked"]:
        tag = "EXEC" if r["executed"] else "data"
        print(f"  [{tag}] va=0x{r['va']:x} size={r['size']} entropy={r['entropy']} "
              f"printable={r['printable_ratio']} sha256={r['sha256'][:16]} "
              f"{'(in .text)' if r['in_text'] else ''}")


def _selftest():
    # A synthetic in-place unpacker, assembled by hand (no binary, no toolchain): the stub stores a
    # `ret` byte into a writable target page, then jumps there and executes it. The emulator must see
    # the target region as written AND executed (a W^X unpack step) and carve it out.
    TGT = HEAP + 0x1000
    code = (
        b"\x48\xb8" + struct.pack("<Q", 0xC3) +            # mov rax, 0x00..00c3  (a `ret`)
        b"\x48\xa3" + struct.pack("<Q", TGT) +             # mov [TGT], rax        (the "unpack")
        b"\x48\xb8" + struct.pack("<Q", TGT) +             # mov rax, TGT
        b"\xff\xe0"                                        # jmp rax               (run stage-2)
    )
    CODE = 0x400000
    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(CODE, 0x1000)
    uc.mem_map(HEAP, HEAP_SIZE)
    uc.mem_map(STACK, STACK_SIZE)
    uc.mem_write(CODE, code)
    written, execd = set(), []

    def on_w(u, acc, addr, size, val, _):
        for a in range(addr, addr + size):
            written.add(a)

    def on_b(u, addr, size, _):
        execd.append(addr)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_w)
    uc.hook_add(UC_HOOK_BLOCK, on_b)
    sp = STACK + STACK_SIZE - 0x1000
    uc.reg_write(X.UC_X86_REG_RSP, sp)
    uc.mem_write(sp, struct.pack("<Q", RET_SENTINEL))
    uc.emu_start(CODE, RET_SENTINEL, count=100)
    assert TGT in written, "store to the unpack target not observed"
    assert any(TGT <= a < TGT + 8 for a in execd), "did not execute the unpacked bytes"

    # entropy + printable sanity
    assert _entropy(b"\x00" * 64) == 0.0
    assert _entropy(bytes(range(256))) > 7.9
    assert _printable_ratio(b"hello world") == 1.0 and _printable_ratio(b"\x00\x01") == 0.0
    print("selftest OK: synthetic in-place unpacker detected (write-then-execute carved); "
          "entropy/printable metrics sane")


def main(argv=None):
    import argparse
    import json
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False,
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--entry", help="start of the unpacking routine: an RVA, or a PE VA (>= the "
                    "image base, rebased automatically); hex ok, e.g. 0x1650")
    ap.add_argument("--follow", action="store_true",
                    help="keep emulating past the jump to the original entry point")
    ap.add_argument("--dump", metavar="DIR", help="write each carved region to DIR/unpacked_<va>.bin")
    ap.add_argument("--json", action="store_true", help="print the result dict as JSON")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary:
        ap.error("give a binary, or --selftest")
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    entry = int(a.entry, 0) if a.entry else None
    res = recover(path, entry, follow=a.follow)
    if a.dump and res["_regions"]:
        d = Path(a.dump)
        d.mkdir(parents=True, exist_ok=True)
        for r in res["_regions"]:
            (d / f"unpacked_{r['va']:x}.bin").write_bytes(r["_bytes"])
        print(f"wrote {len(res['_regions'])} region(s) to {d}/", file=sys.stderr)
    res = {k: v for k, v in res.items() if k != "_regions"}
    print(json.dumps(res, indent=2)) if a.json else _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
