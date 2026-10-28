"""Optimization-reversal pass (premium/opt_reverse.py): jump-table un-switching + unrolled loops.

The --selftest (hand-assembled rel32 jump table + unrolled-loop detection) covers the recogniser
with no toolchain. This also compiles a real dense `match` with rustc and checks the switch is
recovered to an exact {index: target} map (skips if rustc is unavailable, like the other premium
build tests).
"""
import shutil
import struct
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "premium"))
sys.path.insert(0, str(ROOT / "scripts"))
import opt_reverse as O  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


def test_selftest_logic():
    O._selftest()


def test_canonical_subregisters():
    assert O._canon("edi") == "rdi" and O._canon("dil") == "rdi" and O._canon("di") == "rdi"
    assert O._canon("r8d") == "r8" and O._canon("r10w") == "r10"
    assert O._canon("rax") == "rax"


def _aarch64_target():
    try:
        out = subprocess.check_output(["rustup", "target", "list", "--installed"], text=True)
        return "aarch64-unknown-linux-musl" in out
    except Exception:
        return False


@pytest.mark.skipif(not (shutil.which("rustc") and _aarch64_target()),
                    reason="aarch64-unknown-linux-musl target not installed")
def test_real_arm64_jump_table(tmp_path):
    src = tmp_path / "a.rs"
    src.write_text(
        "use std::hint::black_box;\n"
        "#[inline(never)] pub fn d(n:u64)->u64{ match n {\n"
        + "".join(f"    {i} => black_box({10 + i}u64),\n" for i in range(20))
        + "    _ => black_box(999),\n} }\n"
        "fn main(){ println!(\"{}\", d(black_box(3))); }\n")
    binp = tmp_path / "a"
    r = subprocess.run(["rustc", "-O", "--target", "aarch64-unknown-linux-musl",
                        "-C", "linker=rust-lld", "-C", "link-self-contained=yes",
                        str(src), "-o", str(binp)], capture_output=True, text=True)
    if r.returncode != 0 or not binp.exists():
        pytest.skip("aarch64 build failed: " + r.stderr.strip()[-200:])
    res = O.analyze(binp)
    assert res["arch"] == "aarch64"
    twenty = [jt for jt in res["jump_tables"] if jt["count"] == 20]
    assert twenty, [jt["count"] for jt in res["jump_tables"]]
    import recover_emulate as E
    img = E.Image(str(binp))
    for jt in twenty:
        assert set(jt["cases"]) == set(range(20))
        for t in jt["cases"].values():
            assert img.text_va <= t < img.text_end


@pytest.mark.skipif(not shutil.which("rustc"), reason="rustc not available")
def test_real_match_jump_table(tmp_path):
    # host rustc builds for the host: x86-64 on an x86 host, AArch64 on an ARM64 host (e.g. Kali on
    # Apple silicon). LLVM's jump-table threshold differs per target: x86-64 tables an 8-arm match,
    # while AArch64 lowers 8 arms to a compare tree (nothing to un-switch) and only tables a wider
    # match -- so the arm count follows the host. Either way the table must be recovered exactly.
    import platform
    host = platform.machine().lower()
    arm = host in ("aarch64", "arm64")
    n = 20 if arm else 8
    src = tmp_path / "m.rs"
    src.write_text(
        "use std::hint::black_box;\n"
        "#[inline(never)] pub fn d(n:u64)->u64{ match n {\n"
        + "".join(f"    {i} => black_box({10 + i * 7}),\n" for i in range(n))
        + "    _ => black_box(999),\n} }\n"
        "fn main(){ println!(\"{}\", d(black_box(3))); }\n")
    binp = tmp_path / "m"
    r = subprocess.run(["rustc", "-O", str(src), "-o", str(binp)], capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("rustc failed: " + r.stderr.strip()[-200:])
    res = O.analyze(binp)
    assert res["arch"] == ("aarch64" if arm else "x86_64"), (res["arch"], host)
    # the n-arm match must appear as a recovered jump table with exactly n bounded cases whose
    # targets all land in .text (an exact un-switch, not a guessed length)
    import recover_emulate as E
    img = E.Image(str(binp))
    hits = [jt for jt in res["jump_tables"] if jt["count"] == n]
    assert hits, [jt["count"] for jt in res["jump_tables"]]
    for jt in hits:
        assert set(jt["cases"]) == set(range(n))
        for t in jt["cases"].values():
            assert img.text_va <= t < img.text_end


# --- regressions (review C): unrolled-loop decoding/selection, x86 jump-table recall -------------
def test_md_uses_arm64_decoder_for_aarch64():
    from capstone import CS_ARCH_ARM64, CS_ARCH_X86
    assert O._md("aarch64").arch == CS_ARCH_ARM64
    assert O._md("x86_64").arch == CS_ARCH_X86 and O._md("x86").arch == CS_ARCH_X86


def test_arm64_unrolled_loop_decoded_as_arm():
    # (add x0,x0,#1 ; add x1,x1,#4) x4 ; ret  -- was decoded with the x86 disassembler (wrong start)
    code = struct.pack("<9I", *([0x91000400, 0x91001021] * 4 + [0xd65f03c0]))
    loops = O.detect_unrolled_loops(code, 0x1000, "aarch64")
    assert loops == [{"start_va": 0x1000, "stride": 8, "count": 4, "span": 32, "block_insns": 2}]


def test_unrolled_loop_prefers_most_instructions_covered():
    # a 7-insn body x3 (add rax,imm32 x6 ; mov rbx,rcx) must be ONE run of 7-insn blocks, not three
    # 2-insn runs (the old selection compared reps*blen instructions against reps*stride bytes)
    body = bytes.fromhex("480544332211") * 6 + bytes.fromhex("4889cb")
    loops = O.detect_unrolled_loops(body * 3 + b"\xc3", 0x1000, "x86_64")
    assert len(loops) == 1, loops
    assert loops[0]["block_insns"] == 7 and loops[0]["count"] == 3 and loops[0]["stride"] == 39


def _x64_table(mid, ja=b"\x0f\x87", n=3):
    """cmp edi,2 ; j?? default ; <mid> ; lea rcx,[rip+T] ; movsxd rax,[rcx+rax*4] ; add rax,rcx ;
    jmp rax ; 4 bodies (mov eax,imm ; ret) ; table T of n rel32 entries -> (code, base, bodies, T)"""
    base = 0x1000
    pre = b"\x83\xff\x02" + ja + b"\x00\x00\x00\x00" + mid
    lea_at = len(pre)
    tail = b"\x48\x8d\x0d\x00\x00\x00\x00" + b"\x48\x63\x04\x81" + b"\x48\x01\xc8" + b"\xff\xe0"
    buf = bytearray(pre + tail)
    bodies = []
    for _ in range(4):
        bodies.append(base + len(buf))
        buf += b"\xb8\x11\x00\x00\x00\xc3"
    table = base + len(buf)
    for b in bodies[:n]:
        buf += struct.pack("<i", b - table)
    struct.pack_into("<i", buf, lea_at + 3, table - (base + lea_at + 7))
    return bytes(buf), base, bodies, table


def _rd(code, base):
    return lambda va: struct.unpack_from("<i", code, va - base)[0] \
        if 0 <= va - base <= len(code) - 4 else None


def test_x64_bound_followed_through_zero_extending_copy():
    # clang's u32 switch: cmp edi,K ; ja ; mov eax,edi ; ... [rcx + rax*4]  (0 tables before)
    code, base, bodies, table = _x64_table(b"\x89\xf8")              # mov eax, edi
    jts = O.recover_jump_tables(code, base, "x86_64", _rd(code, base), base, table)
    assert len(jts) == 1 and jts[0]["count"] == 3, jts
    assert jts[0]["cases"] == dict(enumerate(bodies[:3])) and jts[0]["table_va"] == table


def test_x64_no_table_when_index_redefined_or_unbounded():
    # the copy is then modified (add eax,5): the cmp no longer bounds the index -> no table
    code, base, _b, table = _x64_table(b"\x89\xf8\x83\xc0\x05")
    assert O.recover_jump_tables(code, base, "x86_64", _rd(code, base), base, table) == []
    # the index comes from an unrelated register (mov eax, esi): no bound -> no table
    code, base, _b, table = _x64_table(b"\x89\xf0")
    assert O.recover_jump_tables(code, base, "x86_64", _rd(code, base), base, table) == []
    # a compare not followed by an unsigned range jump (jb) is not a bound -> no table
    code, base, _b, table = _x64_table(b"\x89\xf8", ja=b"\x0f\x82")
    assert O.recover_jump_tables(code, base, "x86_64", _rd(code, base), base, table) == []


def test_x64_jae_bound_counts_k():
    # cmp edi,2 ; jae default -> valid indices 0..1 (2 cases), not 3
    code, base, bodies, table = _x64_table(b"\x89\xf8", ja=b"\x0f\x83", n=2)
    jts = O.recover_jump_tables(code, base, "x86_64", _rd(code, base), base, table)
    assert len(jts) == 1 and jts[0]["count"] == 2 and jts[0]["cases"] == dict(enumerate(bodies[:2]))


def _i386_pic(thunk):
    """i386 PIC switch: GOT in ebx (call/pop or __x86.get_pc_thunk.bx ; add ebx, GOT-PC), then
    cmp ecx,2 ; ja ; mov ecx,[ebx + ecx*4 + (T-GOT)] ; add ecx,ebx ; jmp ecx. Entries are T-relative
    to the GOT. Returns (code, base, bodies, table)."""
    base, got = 0x1000, 0x3000
    buf = bytearray(b"\xe8\x00\x00\x00\x00")                    # call next | call thunk (patched)
    pc = base + 5
    if not thunk:
        buf += b"\x5b"                                          # pop ebx (pc = its address)
    add_at = len(buf)
    buf += b"\x81\xc3\x00\x00\x00\x00"                          # add ebx, GOT - pc
    buf += b"\x83\xf9\x02" + b"\x0f\x87\x00\x00\x00\x00"        # cmp ecx,2 ; ja default
    load_at = len(buf)
    buf += b"\x8b\x8c\x8b\x00\x00\x00\x00" + b"\x01\xd9" + b"\xff\xe1"
    bodies = []
    for _ in range(4):
        bodies.append(base + len(buf))
        buf += b"\xb8\x11\x00\x00\x00\xc3"
    if thunk:
        th = base + len(buf)
        buf += b"\x8b\x1c\x24\xc3"                              # mov ebx,[esp] ; ret
        struct.pack_into("<i", buf, 1, th - (base + 5))
    table = base + len(buf)
    for b in bodies[:3]:
        buf += struct.pack("<i", b - got)
    struct.pack_into("<i", buf, add_at + 2, got - pc)
    struct.pack_into("<i", buf, load_at + 3, table - got)
    return bytes(buf), base, bodies, table


def test_i386_pic_got_relative_table():
    for thunk in (False, True):
        code, base, bodies, table = _i386_pic(thunk)
        jts = O.recover_jump_tables(code, base, "x86", _rd(code, base), base, bodies[3] + 6)
        assert len(jts) == 1, (thunk, jts)
        assert jts[0]["table_va"] == table and jts[0]["count"] == 3, jts[0]
        assert jts[0]["cases"] == dict(enumerate(bodies[:3])), (thunk, jts[0]["cases"])


def test_i386_no_table_without_pc_thunk():
    # `call` to an ordinary function (not a pc thunk) does not define ebx: no GOT, no table
    code, base, bodies, table = _i386_pic(True)
    code = bytearray(code)
    th = bodies[3] + 6                                          # the thunk's VA
    code[th - base:th - base + 4] = b"\x90\x90\x90\xc3"         # nop x3 ; ret (not mov ebx,[esp])
    code = bytes(code)
    assert O.recover_jump_tables(code, base, "x86", _rd(code, base), base, th) == []


_SW_C = ("".join(f"long f{i}(long);\n" for i in range(21))
         + "__attribute__((noinline)) long d(unsigned n, long x){ switch(n){\n"
         + "".join(f"case {i}: x=f{i}(x)+{3 + 7 * i}; break;\n" for i in range(20))
         + "default: x=f20(x); } return x+7; }\n"
         + "".join(f"__attribute__((noinline)) long f{i}(long x){{return x*{i + 2}+{i};}}\n"
                   for i in range(21))
         + "void _start(void){ volatile long r = d(3, 5); for(;;); }\n")


@pytest.mark.skipif(not shutil.which("clang"), reason="clang not available")
@pytest.mark.parametrize("target", ["x86_64-linux-gnu", "i386-linux-gnu", "aarch64-linux-gnu"])
def test_real_c_u32_switch_all_arches(tmp_path, target):
    # a u32 `switch` (clang zero-extends the bounded index via a copy; i386 PIC reads a GOT-relative
    # table): every case k must be recovered exactly and lead to the call of f<k>
    src = tmp_path / "sw.c"
    src.write_text(_SW_C)
    binp = tmp_path / ("sw_" + target)
    r = subprocess.run(["clang", "--target=" + target, "-O2", "-ffreestanding",
                        "-fno-stack-protector", "-nostdlib", "-static-pie", "-fPIE", "-fuse-ld=lld",
                        str(src), "-o", str(binp)], capture_output=True, text=True)
    if r.returncode != 0 or not binp.exists():
        pytest.skip("clang cross build failed: " + r.stderr.strip()[-200:])
    import lief
    from capstone import CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_MODE_ARM, Cs
    res = O.analyze(binp)
    arch = {"x86_64-linux-gnu": "x86_64", "i386-linux-gnu": "x86",
            "aarch64-linux-gnu": "aarch64"}[target]
    assert res["arch"] == arch
    hits = [jt for jt in res["jump_tables"] if jt["count"] == 20]
    assert len(hits) == 1, [jt["count"] for jt in res["jump_tables"]]
    b = lief.parse(str(binp))
    syms = {s.value: s.name for s in b.symbols if s.name}
    text = b.get_section(".text")
    code, tva = bytes(text.content), text.virtual_address
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM) if arch == "aarch64" else \
        Cs(CS_ARCH_X86, CS_MODE_32 if arch == "x86" else CS_MODE_64)
    md.detail = True
    for k, t in hits[0]["cases"].items():
        callee = next((syms.get(i.operands[0].imm) for i in md.disasm(code[t - tva:t - tva + 64], t)
                       if i.mnemonic in ("call", "bl")), None)
        assert callee == f"f{k}", (k, hex(t), callee)
