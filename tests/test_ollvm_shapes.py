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
    import lief
    b = lief.parse(str(path))
    syms = sorted((s.value, s.name.lstrip("_")) for s in b.symbols if s.value)
    for i, (v, n) in enumerate(syms):
        if n == name:
            base = b.optional_header.imagebase if b.format == lief.Binary.FORMATS.PE else 0
            nxt = next((w for w, _ in syms[i + 1:] if w > v), v + 0x400)
            return v - base, nxt - base
    pytest.skip(f"symbol {name} not found")


@pytest.mark.parametrize("opt", ["1", "2", "s"])
@pytest.mark.parametrize("label,flags", _targets())
def test_bcf_guards_are_opaque(tmp_path, label, flags, opt):
    exe = _build(tmp_path, BCF, opt, flags, f"bcf_{opt}")
    res = O.recover(exe)
    lo, hi = _range(exe, "step")
    claims = res["opaque_branches"]
    # the guards are all in step(); measured: 3 claims at -O1, 2 at -O2/-Os (clang merges the
    # last two guards onto one parity test) on arm64 + x86-64 Mach-O
    assert len(claims) >= 2, (label, opt, claims, res["constant_branches"], res["implied_branches"])
    assert all(lo <= c["branch_va"] < hi for c in claims), (hex(lo), hex(hi), claims)


@pytest.mark.parametrize("label,flags", _targets())
def test_hikari_constructor_strings(tmp_path, label, flags):
    import recover
    exe = _build(tmp_path, HIKARI, "2", flags, "hikari")
    res = recover.run(exe, stackstrings=False, literals=False, time_budget=120)
    got = {x["string"] for x in res["decoded"]}
    assert HIKARI_STRINGS <= got, (label, sorted(got))
