"""Differential soundness test for premium/deobf_opaque.py against Unicorn emulation.

Random small straight-line blocks (x86-64, i386 and AArch64; mixed 8/16/32/64-bit widths, partial and
high-byte register writes, flag-setting arithmetic, over-wide and register-count shifts, every imul
form, cmn/adds/subs, sign/zero extensions, plus a sprinkle of instructions the lifter does NOT model)
end in a conditional branch. They are assembled with llvm-mc; whenever deobf_opaque claims the branch
always-/never-taken, the block is emulated from many random entry states (registers biased to edge
values, random flags) and every run must agree. The requirement is ZERO false claims: a false claim
would make a decompiler prune live code.

The default run is small and seeded (a few hundred blocks per arch, well under 20 s). For the full
sweep:

    python3 tests/test_opaque_differential.py --blocks 3000 [--seed N] [--arch x86_64,x86,aarch64]
    RUST_DEOBF_OPAQUE_DIFF_BLOCKS=3000 python3 -m pytest tests/test_opaque_differential.py -q

Skipped when llvm-mc, unicorn or z3 is unavailable.
"""
import os
import random
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "premium"))
sys.path.insert(0, str(ROOT / "scripts"))

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")

LLVM_MC = shutil.which("llvm-mc") or shutil.which("llvm-mc-18")
SPECIAL = [0, 1, 2, 3, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000,
           0xffffffff, 0x100000000, (1 << 63) - 1, 1 << 63, (1 << 64) - 1, (1 << 64) - 2, 31, 32, 63,
           64]

# ------------------------------------------------------------------------------ x86 generator --
_X86_GROUPS = {   # canonical -> names by width (8 = low byte); i386 uses only the first six
    "rax": {64: "rax", 32: "eax", 16: "ax", 8: "al"}, "rcx": {64: "rcx", 32: "ecx", 16: "cx", 8: "cl"},
    "rdx": {64: "rdx", 32: "edx", 16: "dx", 8: "dl"}, "rbx": {64: "rbx", 32: "ebx", 16: "bx", 8: "bl"},
    "rsi": {64: "rsi", 32: "esi", 16: "si", 8: "sil"}, "rdi": {64: "rdi", 32: "edi", 16: "di", 8: "dil"},
    "r8": {64: "r8", 32: "r8d", 16: "r8w", 8: "r8b"}, "r9": {64: "r9", 32: "r9d", 16: "r9w", 8: "r9b"},
}
_HIGH = ["ah", "ch", "dh", "bh"]
_LEGACY8 = ["al", "cl", "dl", "bl"] + _HIGH
_JCC = ["jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns", "jp", "jnp", "jl", "jge",
        "jle", "jg"]
_JCC_OP = {j: 0x70 + i for i, j in enumerate(_JCC)}


def _imm(rng, w):
    v = rng.choice(SPECIAL + [rng.getrandbits(w), -1, -2, -128, 5, 7, 0x55])
    lo, hi = -(1 << (w - 1)), (1 << w) - 1
    if w == 64:
        hi = (1 << 31) - 1                    # 64-bit ALU immediates are sign-extended imm32
        lo = -(1 << 31)
    return v if lo <= v <= hi else rng.choice([0, 1, -1, 7])


def _gen_x86(rng, m64):
    groups = list(_X86_GROUPS) if m64 else list(_X86_GROUPS)[:6]
    widths = [64, 32, 16, 8] if m64 else [32, 16, 8]

    def reg(w, legacy_only=False):
        if w == 8 and rng.random() < 0.25:
            return rng.choice(_HIGH)
        g = rng.choice(groups[:4] if (legacy_only or (w == 8 and not m64)) else groups)
        return _X86_GROUPS[g][w]

    def reg8_pair():
        a, b = reg(8), reg(8)
        if a in _HIGH and b not in _LEGACY8:      # ah..bh cannot share an insn with a REX reg
            b = rng.choice(_LEGACY8)
        elif b in _HIGH and a not in _LEGACY8:
            a = rng.choice(_LEGACY8)
        return a, b

    def two(w):
        if w == 8:
            return reg8_pair()
        return reg(w), reg(w)

    out = []
    # seed some constants so claims actually happen
    for _ in range(rng.randint(0, 2)):
        w = rng.choice(widths)
        r = reg(w)
        v = rng.choice(SPECIAL + [rng.getrandbits(w)]) & ((1 << w) - 1)
        out.append(f"mov {r}, {v}" if not (w == 64 and v >= 1 << 32) else f"movabs {r}, {v}")
    for _ in range(rng.randint(1, 5)):
        k = rng.random()
        w = rng.choice(widths)
        if k < 0.30:
            op = rng.choice(["add", "sub", "and", "or", "xor", "cmp", "test"])
            a, b = two(w)
            if rng.random() < 0.5:
                out.append(f"{op} {a}, {_imm(rng, w)}")
            else:
                out.append(f"{op} {a}, {b}")
        elif k < 0.40:
            out.append(f"{rng.choice(['inc', 'dec', 'neg', 'not'])} {reg(w)}")
        elif k < 0.52:
            cnt = rng.choice([0, 1, 1, 2, 7, 8, 15, 16, 31, 32, 33, 63, 64, 65, 127, 255])
            op = rng.choice(["shl", "shr", "sar", "sal"])
            if rng.random() < 0.3:
                r = reg(w) if w != 8 else rng.choice(["al", "dl", "bl", "ah", "dh", "bh"])
                if w != 8 and r.startswith(("ecx", "cx", "rcx")):
                    r = _X86_GROUPS["rdx"][w]
                out.append(f"mov cl, {cnt}" if rng.random() < 0.5 else "nop")
                out.append(f"{op} {r}, cl")
            else:
                out.append(f"{op} {reg(w)}, {cnt}")
        elif k < 0.62:
            ww = rng.choice([x for x in widths if x != 8])
            form = rng.randint(1, 3)
            if form == 1:
                out.append(f"imul {reg(ww)}")
            elif form == 2:
                out.append(f"imul {reg(ww)}, {reg(ww)}")
            else:
                out.append(f"imul {reg(ww)}, {reg(ww)}, {_imm(rng, ww)}")
        elif k < 0.74:
            src_w = rng.choice([8, 16] + ([32] if m64 else []))
            dst_w = rng.choice([x for x in widths if x > src_w] or [32])
            if src_w == 32:
                out.append(f"movsxd {reg(64)}, {reg(32)}")
            else:
                op = rng.choice(["movzx", "movsx"])
                if src_w == 8 and rng.random() < 0.3:
                    if dst_w == 64:
                        dst_w = 32
                    out.append(f"{op} {reg(dst_w, legacy_only=True)}, {rng.choice(_HIGH)}")
                else:
                    s = reg(src_w)
                    if s in _HIGH:
                        if dst_w == 64:
                            dst_w = 32
                        out.append(f"{op} {reg(dst_w, legacy_only=True)}, {s}")
                    else:
                        out.append(f"{op} {reg(dst_w)}, {s}")
        elif k < 0.80:
            aw = 64 if m64 else 32
            dw = rng.choice([aw, 32, 16])
            base, idx = reg(aw), reg(aw)
            out.append(f"lea {reg(dw)}, [{base} + {rng.choice([1, 2, 4, 8])}*{idx} + "
                       f"{rng.choice([0, 1, -1, 0x7fffffff, -0x80000000, 5])}]")
        elif k < 0.90:
            a, b = two(w)
            out.append(f"mov {a}, {b}")
        else:   # instructions the lifter must ABANDON on (or that otherwise disturb flags/regs)
            ww = rng.choice([x for x in widths if x != 8])
            out.append(rng.choice([f"adc {reg(ww)}, {reg(ww)}", f"sbb {reg(ww)}, 1",
                                   f"rol {reg(ww)}, 3", f"bt {reg(ww)}, 3", f"xchg {reg(ww)}, {reg(ww)}",
                                   "sete al", f"cmovne {reg(ww)}, {reg(ww)}", "cdq", "stc", "clc"]))
        if rng.random() < 0.35:     # often end on a compare, like real predicates do
            w = rng.choice(widths)
            a, b = two(w)
            out.append(f"{rng.choice(['cmp', 'test'])} {a}, " + (b if rng.random() < 0.4
                                                                  else str(_imm(rng, w))))
    return out


# -------------------------------------------------------------------------- AArch64 generator --
_A64_COND = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le"]
_BITMASK = {32: [0x1, 0xff, 0xff00, 0xffff, 0x80000000, 0x7fffffff, 0xfffffff0, 0x55555555, 0x3],
            64: [0x1, 0xff, 0xff00, 0xffffffff, 0x8000000000000000, 0x7fffffffffffffff,
                 0xfffffffffffffff0, 0x5555555555555555, 0xffffffff00000000, 0x3]}


def _gen_a64(rng):
    def r(w, zr=False):
        if zr and rng.random() < 0.15:
            return "xzr" if w == 64 else "wzr"
        return ("x" if w == 64 else "w") + str(rng.randint(0, 5))

    def shifted(w, ror=False):
        s = r(w, zr=True)
        if rng.random() < 0.5:
            kind = rng.choice(["lsl", "lsr", "asr"] + (["ror"] if ror else []))
            s += f", {kind} #{rng.choice([1, 2, 7, 15, 16, 31, w - 1])}"
        return s

    out = []
    for _ in range(rng.randint(0, 2)):
        w = rng.choice([32, 64])
        sh = rng.choice([0, 16] + ([32, 48] if w == 64 else []))
        out.append(f"{rng.choice(['movz', 'movn'])} {r(w)}, #{rng.choice([0, 1, 0x8000, 0xffff, 0x7fff, 5])}"
                   + (f", lsl #{sh}" if sh else ""))
    for _ in range(rng.randint(1, 5)):
        w = rng.choice([32, 64])
        k = rng.random()
        if k < 0.25:
            op = rng.choice(["add", "sub", "adds", "subs"])
            if rng.random() < 0.5:
                out.append(f"{op} {r(w)}, {r(w)}, #{rng.choice([0, 1, 4095, 7])}"
                           + (", lsl #12" if rng.random() < 0.2 else ""))
            else:
                out.append(f"{op} {r(w)}, {r(w, zr=True)}, {shifted(w)}")
        elif k < 0.42:
            op = rng.choice(["and", "orr", "eor", "ands", "orn", "eon", "bic", "bics"])
            if op in ("and", "orr", "eor", "ands") and rng.random() < 0.5:
                out.append(f"{op} {r(w)}, {r(w, zr=True)}, #{rng.choice(_BITMASK[w])}")
            else:
                out.append(f"{op} {r(w)}, {r(w, zr=True)}, {shifted(w, ror=True)}")
        elif k < 0.55:
            op = rng.choice(["lsl", "lsr", "asr", "ror"])
            if rng.random() < 0.5:
                out.append(f"{op} {r(w)}, {r(w)}, #{rng.choice([0, 1, 7, 31, w - 1])}")
            else:
                out.append(f"{op} {r(w)}, {r(w)}, {r(w)}")
        elif k < 0.63:
            out.append(rng.choice([f"mul {r(w)}, {r(w)}, {r(w)}", f"neg {r(w)}, {shifted(w)}",
                                   f"negs {r(w)}, {shifted(w)}", f"mvn {r(w)}, {shifted(w, True)}"]))
        elif k < 0.72:
            e = rng.choice(["sxtb", "sxth", "uxtb", "uxth", "sxtw"])
            if e == "sxtw":
                out.append(f"sxtw {r(64)}, {r(32)}")
            elif e[0] == "s":
                out.append(f"{e} {r(rng.choice([32, 64]))}, {r(32)}")
            else:
                out.append(f"{e} {r(32)}, {r(32)}")
        elif k < 0.80:
            out.append(f"movk {r(w)}, #{rng.choice([0, 1, 0xffff, 0x8000])}, lsl #"
                       f"{rng.choice([0, 16] + ([32, 48] if w == 64 else []))}")
        elif k < 0.88:
            out.append(f"mov {r(w)}, {r(w)}")
        else:   # unmodelled: must abandon
            out.append(rng.choice([f"csel {r(w)}, {r(w)}, {r(w)}, eq", f"madd {r(w)}, {r(w)}, {r(w)}, {r(w)}",
                                   f"ubfx {r(w)}, {r(w)}, #1, #3", f"adc {r(w)}, {r(w)}, {r(w)}",
                                   f"ccmp {r(w)}, #1, #4, ne", f"cset {r(w)}, hi",
                                   f"add {r(64)}, {r(64)}, {r(32)}, sxtw"]))
        if rng.random() < 0.35:
            w = rng.choice([32, 64])
            op = rng.choice(["cmp", "cmn", "tst"])
            if rng.random() < 0.5:
                imm = rng.choice(_BITMASK[w]) if op == "tst" else rng.choice([0, 1, 5, 4095])
                out.append(f"{op} {r(w)}, #{imm}")
            else:
                out.append(f"{op} {r(w)}, {shifted(w, ror=(op == 'tst'))}")
    t = rng.random()
    if t < 0.6:
        out.append(f"b.{rng.choice(_A64_COND)} #8")
    elif t < 0.8:
        out.append(f"{rng.choice(['cbz', 'cbnz'])} {r(rng.choice([32, 64]))}, #8")
    else:
        w = rng.choice([32, 64])
        out.append(f"{rng.choice(['tbz', 'tbnz'])} {r(w)}, #{rng.choice([0, 1, 7, 31, w - 1])}, #8")
    out.append("nop")
    return out


# --------------------------------------------------------------------------------- assembler --
def _assemble(arch, bodies):
    """Assemble many blocks in ONE llvm-mc run; blocks are separated by a marker instruction whose
    encoding the generators never produce (int3 / brk #0x7a7a)."""
    triple = {"x86_64": "x86_64", "x86": "i386", "aarch64": "aarch64"}[arch]
    marker = "int3" if arch != "aarch64" else "brk #0x7a7a"
    pre = ".intel_syntax noprefix\n" if arch != "aarch64" else ""
    src = pre + "".join("\n".join(b) + "\n" + marker + "\n" for b in bodies)
    args = [LLVM_MC, "-triple=" + triple, "-show-encoding"]
    if arch != "aarch64":
        args += ["-x86-asm-syntax=intel", "-output-asm-variant=1"]
    p = subprocess.run(args, input=src, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(p.stderr[:2000])
    mk = b"\xcc" if arch != "aarch64" else bytes.fromhex("404f2fd4")
    out, cur = [], b""
    for m in re.finditer(r"encoding: \[([^\]]*)\]", p.stdout):
        enc = bytes(int(x, 16) for x in m.group(1).split(","))
        if enc == mk:
            out.append(cur)
            cur = b""
        else:
            cur += enc
    assert len(out) == len(bodies), (len(out), len(bodies))
    return out


# --------------------------------------------------------------------------------- emulation --
class _Emu:
    SLOT = 0x100

    def __init__(self, arch, nblocks):
        from unicorn import UC_ARCH_ARM64, UC_ARCH_X86, UC_MODE_32, UC_MODE_64, UC_MODE_ARM, Uc
        from unicorn import arm64_const as A
        from unicorn import x86_const as X
        self.arch = arch
        if arch == "aarch64":
            self.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
            self.regs = [A.UC_ARM64_REG_X0 + i for i in range(29)]
            self.pc = A.UC_ARM64_REG_PC
            self.flagreg = A.UC_ARM64_REG_NZCV
        else:
            self.uc = Uc(UC_ARCH_X86, UC_MODE_64 if arch == "x86_64" else UC_MODE_32)
            names = ["RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "R8", "R9", "R10", "R11",
                     "R12", "R13", "R14", "R15"] if arch == "x86_64" else \
                ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP"]
            self.regs = [getattr(X, "UC_X86_REG_" + n) for n in names]
            self.pc = X.UC_X86_REG_RIP if arch == "x86_64" else X.UC_X86_REG_EIP
            self.flagreg = X.UC_X86_REG_EFLAGS
        self.base = 0x100000
        size = ((nblocks + 1) * self.SLOT + 0xfff) & ~0xfff
        self.uc.mem_map(self.base, size)
        self.next = self.base

    def place(self, code):
        at = self.next                  # every block gets its own address: no stale TB cache
        self.next += self.SLOT
        self.uc.mem_write(at, code)
        return at

    def run(self, at, ninsn, rng):
        width = 32 if self.arch == "x86" else 64
        pool = [v & ((1 << width) - 1) for v in SPECIAL]
        vals = []
        for r in self.regs:
            if vals and rng.random() < 0.15:
                v = rng.choice(vals)                     # equal registers: x == y corner cases
            elif rng.random() < 0.6:
                v = rng.choice(pool)
            else:
                v = rng.getrandbits(width)
            vals.append(v)
            self.uc.reg_write(r, v)
        if self.arch == "aarch64":
            self.uc.reg_write(self.flagreg, rng.getrandbits(4) << 28)
        else:
            bits = 0x2
            for b in (0, 2, 4, 6, 7, 11):
                bits |= rng.getrandbits(1) << b
            self.uc.reg_write(self.flagreg, bits)
        self.uc.emu_start(at, at + self.SLOT, count=ninsn)
        return self.uc.reg_read(self.pc)


def run_differential(n, seed, arches=("x86_64", "x86", "aarch64"), trials=40, verbose=False):
    import deobf_opaque as O
    from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, Cs
    stats = {}
    for arch in arches:
        rng = random.Random(f"{seed}:{arch}")
        if arch == "aarch64":
            bodies = [_gen_a64(rng) for _ in range(n)]
        else:
            bodies = [_gen_x86(rng, arch == "x86_64") for _ in range(n)]
        codes = _assemble(arch, bodies)
        jccs = []
        if arch != "aarch64":
            for i in range(n):
                j = rng.choice(_JCC)
                jccs.append(j)
                codes[i] = codes[i] + bytes([_JCC_OP[j], 0x02, 0x90, 0x90])
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if arch == "aarch64" else \
            Cs(CS_ARCH_X86, CS_MODE_64 if arch == "x86_64" else CS_MODE_32)
        emu = _Emu(arch, n)
        st = {"blocks": n, "claims": 0, "always": 0, "never": 0, "false": 0, "emu_errors": 0,
              "false_examples": []}
        for i, code in enumerate(codes):
            at = emu.place(code)
            r = O.classify_block(code, at, arch)
            if not r:
                continue
            st["claims"] += 1
            st["always" if r["result"] == "always-taken" else "never"] += 1
            insns = list(md.disasm(code, at))
            br = [x.address for x in insns].index(r["branch_va"])
            brins = insns[br]
            fall = brins.address + brins.size
            seen = set()
            try:
                for _ in range(trials):
                    pc = emu.run(at, br + 1, rng)
                    seen.add("fall" if pc == fall else "taken")
            except Exception as e:      # noqa: BLE001
                st["emu_errors"] += 1
                if verbose:
                    print("emu error", arch, bodies[i], e)
                continue
            want = "taken" if r["result"] == "always-taken" else "fall"
            if seen != {want}:
                st["false"] += 1
                if len(st["false_examples"]) < 10:
                    st["false_examples"].append((bodies[i], jccs[i] if jccs else "", r["result"],
                                                 sorted(seen)))
        stats[arch] = st
    return stats


@pytest.mark.skipif(not LLVM_MC, reason="llvm-mc not available")
def test_no_false_opaque_claims_vs_emulation():
    pytest.importorskip("z3")
    pytest.importorskip("unicorn")
    n = int(os.environ.get("RUST_DEOBF_OPAQUE_DIFF_BLOCKS", "250"))
    stats = run_differential(n, seed=20261029)
    for arch, st in stats.items():
        assert st["false"] == 0, (arch, st["false_examples"])
        assert st["emu_errors"] == 0, (arch, st)
        # the generator is tuned so the detector does make claims (else this test proves nothing)
        assert st["claims"] >= n // 20, (arch, st)
        assert st["always"] and st["never"], (arch, st)


def main(argv=None):
    import argparse
    import json
    import time
    ap = argparse.ArgumentParser(description="deobf_opaque differential soundness sweep")
    ap.add_argument("--blocks", type=int, default=3000)
    ap.add_argument("--seed", default="1")
    ap.add_argument("--arch", default="x86_64,x86,aarch64")
    ap.add_argument("--trials", type=int, default=64)
    a = ap.parse_args(argv)
    if not LLVM_MC:
        print("llvm-mc not available")
        return 2
    t = time.time()
    stats = run_differential(a.blocks, a.seed, tuple(a.arch.split(",")), trials=a.trials,
                             verbose=True)
    print(json.dumps(stats, indent=1, default=str))
    print(f"{time.time() - t:.1f}s")
    return 1 if any(s["false"] for s in stats.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
