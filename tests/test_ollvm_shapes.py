"""OLLVM / Hikari pass shapes beyond -fla (VALIDATION §82), hand-written in their post-pass form and
compiled at test time with the host C compiler (no obfuscating LLVM fork needed; benign programs):

- obf_src/ollvm_bcf/bcf.c: -bcf. Real blocks guarded by opaque predicates over two globals the
  program never writes (`y < 10 || x*(x-1) even`). deobf_opaque now reads a memory load as an
  unconstrained value (sound for always/never claims), models push/pop, rip-relative lea / adrp
  and AArch64 writeback, scans every block (not only function entries) and, where the function has
  no indirect jump, follows a block's single predecessor: clang -O2 computes the parity in one block
  and tests it in the next.
- obf_src/hikari_strenc/hikari_ctor.c: Hikari string encryption -- XOR'd constants in .data, all
  decrypted in place by one global constructor. Recovered already (measured before §82); locked here.
"""
import shutil
import subprocess
import sys

import pytest
from conftest import CLANG_TARGET, ROOT

sys.path.insert(0, str(ROOT / "premium"))
sys.path.insert(0, str(ROOT / "scripts"))
pytest.importorskip("z3")
pytest.importorskip("lief")
import deobf_opaque as O  # noqa: E402

BCF = ROOT / "obf_src" / "ollvm_bcf" / "bcf.c"
HIKARI = ROOT / "obf_src" / "hikari_strenc" / "hikari_ctor.c"
FIX = ROOT / "tests" / "fixtures" / "ollvm"
HIKARI_STRINGS = {"canary::hikari::config-path-a91f", "https://updates.example/channel/stable"}


def _targets():
    out = [("host", [*CLANG_TARGET])]
    if sys.platform == "darwin":
        out.append(("x86_64-macho", ["-arch", "x86_64"]))
    return out


def _build(tmp_path, src, opt, flags, name):
    if shutil.which("clang") is None:
        pytest.skip("clang not available")
    out = tmp_path / name
    r = subprocess.run(["clang", *flags, f"-O{opt}", "-o", str(out), str(src)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("build failed: " + r.stderr[-300:])
    return out if out.exists() else out.with_suffix(".exe")


def _range(path, name):
    """[start, next function start) of function `name`, in the toolkit's address space (PE: RVA).

    Through recover_emulate's own symbol reader: a COFF symbol's value is an offset into its
    section, not a VA -- reading it as one and subtracting the ImageBase gave a negative "range"
    (-0x13ffffb10 at MinGW x86-64's ImageBase 0x140000000), so every Windows claim fell outside."""
    import recover_emulate
    syms = sorted((v, n.lstrip("_")) for v, n in recover_emulate.Image(path).function_symbols())
    for i, (v, n) in enumerate(syms):
        if n == name:
            nxt = next((w for w, _ in syms[i + 1:] if w > v), v + 0x400)
            return v, nxt
    pytest.skip(f"symbol {name} not found")


def _check_bcf(exe, label, opt):
    res = O.recover(exe)
    lo, hi = _range(exe, "step")
    claims = res["opaque_branches"]
    # the guards are all in step(); measured: 3 claims at -O1, 2 at -O2/-Os (clang merges the
    # last two guards onto one parity test) on arm64 + x86-64 Mach-O
    assert len(claims) >= 2, (label, opt, claims, res["constant_branches"], res["implied_branches"])
    assert all(lo <= c["branch_va"] < hi for c in claims), (hex(lo), hex(hi), claims)


def _check_hikari(exe, label):
    import recover
    import recover_emulate
    # the decrypting constructor must be FOUND and replayed (Mach-O ld-prime: __init_offsets;
    # MinGW PE: __CTOR_LIST__, in .text or .rdata by GNU ld version); its strings are reported
    # from the replay, not only from a sweep run over ciphertext (§87)
    assert recover_emulate.Image(exe).constructor_vas(), label
    res = recover.run(exe, stackstrings=False, literals=False, time_budget=120)
    got = {x["string"] for x in res["decoded"]}
    assert HIKARI_STRINGS <= got, (label, sorted(got))


@pytest.mark.parametrize("opt", ["1", "2", "s"])
@pytest.mark.parametrize("label,flags", _targets())
def test_bcf_guards_are_opaque(tmp_path, label, flags, opt):
    _check_bcf(_build(tmp_path, BCF, opt, flags, f"bcf_{opt}"), label, opt)


@pytest.mark.parametrize("label,flags", _targets())
def test_hikari_constructor_strings(tmp_path, label, flags):
    _check_hikari(_build(tmp_path, HIKARI, "2", flags, "hikari"), label)


# The same two shapes as MinGW x86-64 PEs at its default ImageBase 0x140000000, committed
# (tests/fixtures/ollvm/build.sh), so every host checks what only windows-latest built before:
# there both tests above failed (COFF symbol values read as VAs; PE constructors not read).
def _high_base_pe(name):
    import lief
    exe = FIX / name
    b = lief.parse(str(exe))
    assert b.format == lief.Binary.FORMATS.PE and b.optional_header.imagebase == 0x140000000
    return exe


@pytest.mark.parametrize("opt", ["1", "2", "s"])
def test_bcf_guards_are_opaque_high_base(opt):
    _check_bcf(_high_base_pe(f"bcf_O{opt}_pe64.exe"), "pe64-high-base", opt)


# GNU ld 2.41 places __CTOR_LIST__ inside .text, 2.47 (windows-latest's MSYS2, Nov 2026) in .rdata
@pytest.mark.parametrize("name,table_sec", [("hikari_pe64.exe", ".text"),
                                            ("hikari_pe64_rdata.exe", ".rdata")])
def test_hikari_constructor_strings_high_base(name, table_sec):
    import recover_emulate
    exe = _high_base_pe(name)
    img = recover_emulate.Image(exe)
    # the fixture really has the layout it stands for (read via the unstripped section table)
    sec = next(s for s in img.binary.sections if s.name == table_sec)
    ones = b"\xff" * 8
    assert ones + ones not in bytes(sec.content) and ones in bytes(sec.content), table_sec
    # slots hold ImageBase + RVA: every constructor must come back as an RVA inside the code,
    # last-registered first (the CRT's order): MinGW's frame-registration ctor, then the decryptor
    vas = img.constructor_vas()
    assert len(vas) == 2 and all(img.text_va <= v < img.text_end for v in vas), [hex(v) for v in vas]
    _check_hikari(exe, "pe64-high-base")
