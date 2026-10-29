"""recover_idioms.py: fmt::Arguments / Location decoding, the per-function dataflow on
hand-assembled code (x86-64, i386, Win64, AArch64 shapes), and the committed benign fixtures."""
import struct

import pytest

from conftest import ROOT

import recover_idioms as R

STD_X64 = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"      # stripped, rustc 1.97
MACHO_A64 = ROOT / "tests" / "fixtures" / "macho" / "obfstr.arm64"        # symbols, rustc 1.91


class Mem:
    """A sparse little memory: put(va, bytes); read(va, n); ptr(va) (8-byte LE)."""

    def __init__(self, psize=8):
        self.blocks, self.psize = {}, psize

    def put(self, va, b):
        self.blocks[va] = bytes(b)

    def read(self, va, n):
        for base, b in self.blocks.items():
            if base <= va < base + len(b):
                return b[va - base:va - base + n]
        return b""

    def ptr(self, va):
        raw = self.read(va, self.psize)
        return int.from_bytes(raw, "little") if len(raw) == self.psize else None


# ------------------------------------------------------------------------------------------------
# pure decoders
# ------------------------------------------------------------------------------------------------
def test_template_literals_placeholders_and_escaping():
    m = Mem()
    m.put(0x1000, b"\x06hello \xc0\x05 {x}\n\xc0\x00")
    d = R.decode_template(m.read, 0x1000)
    assert d["text"] == "hello {} {{x}}\\n{}" and d["placeholders"] == 2 and d["nargs"] == 2
    assert d["literals"] == ["hello ", " {x}\n"]


def test_template_placeholder_options():
    m = Mem()
    # {:>8.3} : flags(align right, fill ' ') + width 8 + precision 3
    flags = (1 << 29) | (1 << 27) | (1 << 28) | 0x20
    m.put(0x1000, bytes([0xC7]) + struct.pack("<IHH", flags, 8, 3) + b"\x00")
    assert R.decode_template(m.read, 0x1000)["text"] == "{:>8.3}"
    # {:#x?} : alternate + debug-lower-hex ; {1} explicit index ; {:1$} indirect width
    flags = (3 << 29) | (1 << 23) | (1 << 25) | 0x20
    m.put(0x2000, bytes([0xC1]) + struct.pack("<I", flags) + bytes([0xC8]) + struct.pack("<H", 1)
          + bytes([0xD2]) + struct.pack("<H", 1) + b"\x00")
    d = R.decode_template(m.read, 0x2000)
    assert d["text"] == "{:#x?}{1}{:1$}" and d["nargs"] == 2, d
    # fill + center + zero pad + sign
    flags = (2 << 29) | (1 << 21) | (1 << 24) | ord("*")
    m.put(0x3000, bytes([0xC1]) + struct.pack("<I", flags) + b"\x00")
    assert R.decode_template(m.read, 0x3000)["text"] == "{:*^+0}"


@pytest.mark.parametrize("blob", [
    b"\x05ab\x00",                       # literal runs past the end marker
    b"\x90x\x00",                        # 0x81..0xBF is not a tag
    b"\x02\xff\xfe\x00",                 # literal is not UTF-8
    b"\x02a\x01\x00",                    # control character in a literal
    b"\xc1\x00\x00\x00\x80\x00",         # flags bit 31 must be zero
    b"\xd0\x00",                         # "width indirect" without a width
    b"\x80\x05\x00hello\x00",            # long form used for a short piece
    b"",                                 # nothing mapped
])
def test_template_rejects_malformed(blob):
    m = Mem()
    m.put(0x1000, blob)
    assert R.decode_template(m.read, 0x1000) is None


def test_template_unterminated_within_window_is_rejected():
    m = Mem()
    m.put(0x1000, (b"\x7f" + b"a" * 127) * 40)          # > TEMPLATE_MAX without an end byte
    assert R.decode_template(m.read, 0x1000) is None


def test_pieces_and_location_and_messages():
    m = Mem()
    m.put(0x6000, b"x= y=")
    m.put(0x6100, struct.pack("<QQQQ", 0x6000, 2, 0x6002, 3))
    assert R.decode_pieces(m.read, m.ptr, 0x6100, 2, 2, 8)["text"] == "x={} y={}"
    assert R.decode_pieces(m.read, m.ptr, 0x6100, 2, 5, 8) is None      # inconsistent counts
    m.put(0x4000, b"src/lib.rs")
    m.put(0x5000, struct.pack("<QQII", 0x4000, 10, 7, 9))
    assert R.read_location(m.read, m.ptr, 0x5000, 8) == ("src/lib.rs", 7, 9)
    m.put(0x5100, struct.pack("<QQII", 0x4000, 10, 0, 9))             # line 0: not a Location
    assert R.read_location(m.read, m.ptr, 0x5100, 8) is None
    m32 = Mem(4)
    m32.put(0x4000, b"src/a.rs")
    m32.put(0x5000, struct.pack("<IIII", 0x4000, 8, 3, 4))
    assert R.read_location(m32.read, m32.ptr, 0x5000, 4) == ("src/a.rs", 3, 4)
    assert R.message_kind("called `Option::unwrap()` on a `None` value") == "unwrap_none"
    assert R.message_kind("attempt to shift left with overflow") == "overflow"
    assert R.message_kind("attempt to calculate the remainder with a divisor of zero") == "div_by_zero"
    assert R.message_kind("end byte index 5 is out of bounds") == "str_index"
    assert R.message_kind("attempt to do something") is None


def test_v0_labels_keep_the_last_segment():
    assert R._readable("_RNvNtCscI6d9CVNmLh_4core9panicking18panic_bounds_check") == \
        "core::panicking::panic_bounds_check"
    assert R._readable("_RNvNtNtCsgczF5crJ4sT_3std2io5stdio6__print") == "std::io::stdio::_print"
    # the instantiating crate v0 appends is dropped
    assert R._readable("_RNvMs4_NtCs40k4W9msRzi_5alloc7raw_vecNtB5_11RawVecInner11finish_grow"
                       "Cs8FMd1QCh2cR_12goldberg_cff") == "alloc::raw_vec::RawVecInner::finish_grow"
    assert R._readable("_ZN4core9panicking9panic_fmt17h96de7a67cc512650E") == "core::panicking::panic_fmt"
    assert R._readable("__ZN4core6option13unwrap_failed17h5390b8bf3624dae4E") == "core::option::unwrap_failed"


# ------------------------------------------------------------------------------------------------
# dataflow on hand-assembled code
# ------------------------------------------------------------------------------------------------
def _rel(frm, size, to):
    return struct.pack("<i", to - (frm + size))


class Code:
    def __init__(self, base, size=0x400, fill=b"\xcc"):
        self.base, self.buf = base, bytearray(fill * size)

    def at(self, va, b):
        self.buf[va - self.base:va - self.base + len(b)] = b

    def prog(self, mem, funcs, arch="x86_64", abi="sysv", psize=8, **kw):
        code = bytes(self.buf)
        base = self.base

        def read(va, n):
            if base <= va < base + len(code):
                return code[va - base:va - base + n]
            return mem.read(va, n)

        def ptr(va):
            raw = read(va, psize)
            return int.from_bytes(raw, "little") if len(raw) == psize else None
        return R.Prog(arch, code, base, funcs, read, ptr, abi=abi, psize=psize, **kw)


def test_x86_64_fmt_site_and_stale_frame_slots_are_not_reused():
    """A second call that passes the same frame offset after the first consumer must not be decoded
    with the first call's words (regression: call records shared the live slot dict)."""
    m = Mem()
    m.put(0x1000, b"\x03ab \xc0\x00")
    c = Code(0x10000)
    seq = b"\x48\x83\xec\x28"                                         # sub rsp,0x28
    seq += b"\x48\x8d\x44\x24\x20\x48\x89\x44\x24\x10"                  # lea rax,[rsp+0x20]; mov [rsp+0x10],rax
    p = 0x10000 + len(seq)
    seq += b"\x48\x8d\x05" + _rel(p, 7, 0x10300)                       # lea rax,[fmtfn]
    seq += b"\x48\x89\x44\x24\x18"                                     # mov [rsp+0x18],rax
    p = 0x10000 + len(seq)
    seq += b"\x48\x8d\x3d" + _rel(p, 7, 0x1000)                        # lea rdi,[tmpl]
    seq += b"\x48\x8d\x74\x24\x10"                                     # lea rsi,[rsp+0x10]
    p = 0x10000 + len(seq)
    seq += b"\xe8" + _rel(p, 5, 0x10200)                               # call sink
    seq += b"\x48\x8d\x7c\x24\x10"                                     # lea rdi,[rsp+0x10]
    p = 0x10000 + len(seq)
    seq += b"\xe8" + _rel(p, 5, 0x10280)                               # call other(&frame)
    p = 0x10000 + len(seq)
    seq += b"\x48\x8d\x3d" + _rel(p, 7, 0x1000)                        # lea rdi,[tmpl] again
    seq += b"\x48\x8d\x74\x24\x10"                                     # lea rsi,[rsp+0x10]
    p = 0x10000 + len(seq)
    seq += b"\xe8" + _rel(p, 5, 0x10200)                               # call sink: args array gone?
    seq += b"\x48\x83\xc4\x28\xc3"
    c.at(0x10000, seq)
    c.at(0x10200, b"\xc3")
    c.at(0x10280, b"\xc3")
    c.at(0x10300, b"\xc3")
    res = R.run(c.prog(m, [0x10000, 0x10200, 0x10280, 0x10300]))
    sites = [f for f in res["fmt_sites"] if f["function"] == 0x10000]
    # the first call decodes; the second still sees the template + array pointer but the array
    # words were handed to `other` and forgotten, so it is not claimed as a validated site
    assert len(sites) == 1 and sites[0]["format"] == "ab {}", sites


def test_odd_length_str_is_not_from_str_for_a_non_sink():
    """`(ptr, 43)` to a panic helper is a plain &str; only an Arguments consumer reads `len<<1|1`."""
    m = Mem()
    msg = b"called `Option::unwrap()` on a `None` value"
    m.put(0x2000, msg)
    c = Code(0x10000)
    seq = b"\x48\x8d\x3d" + _rel(0x10000, 7, 0x2000)                   # lea rdi,[msg]
    seq += b"\xbe" + struct.pack("<I", len(msg))                        # mov esi,43
    seq += b"\xe8" + _rel(0x10000 + len(seq), 5, 0x10100)              # call helper (no ret)
    c.at(0x10000, seq)
    c.at(0x10100, b"\x0f\x0b")                                          # ud2: never returns
    res = R.run(c.prog(m, [0x10000, 0x10100]))
    assert not res["fmt_sites"], res["fmt_sites"]
    (p,) = [p for p in res["panic_sites"] if p["function"] == 0x10000]
    assert p["kind"] == "unwrap_none" and p["safety_check"]


def test_i386_pic_thunk_and_stack_args():
    """i386: `call next; pop ebx; add ebx,K` PIC base, template/args pushed on the stack."""
    m = Mem(4)
    m.put(0x9000, b"\x02v=\xc0\x00")
    c = Code(0x8000)
    a = 0x8000
    seq = b"\x55\x89\xe5\x53\x83\xec\x14"                               # push ebp; mov ebp,esp; push ebx; sub esp,0x14
    seq += b"\xe8\x00\x00\x00\x00"                                      # call next
    nxt = a + len(seq)
    seq += b"\x5b"                                                      # pop ebx  (= nxt)
    seq += b"\x81\xc3" + struct.pack("<i", 0x1000)                      # add ebx,0x1000
    seq += b"\x8d\x83" + struct.pack("<i", 0x8300 - nxt - 0x1000)      # lea eax,[ebx+fmtfn]
    seq += b"\x89\x45\xf4"                                              # mov [ebp-0xc],eax
    seq += b"\x8d\x45\xf0"                                              # lea eax,[ebp-0x10] (args)
    seq += b"\x8d\x8b" + struct.pack("<i", 0x9000 - nxt - 0x1000)      # lea ecx,[ebx+tmpl]
    seq += b"\x50\x51"                                                  # push eax; push ecx
    seq += b"\xe8" + _rel(a + len(seq), 5, 0x8200)                      # call sink
    seq += b"\x83\xc4\x1c\x5b\x5d\xc3"
    c.at(a, seq)
    c.at(0x8200, b"\xc3")
    c.at(0x8300, b"\xc3")
    res = R.run(c.prog(m, [a, 0x8200, 0x8300], arch="x86", abi="i386", psize=4))
    sites = [f for f in res["fmt_sites"] if f["function"] == a]
    assert sites and sites[0]["format"] == "v={}", res["fmt_sites"]


def test_win64_arguments_by_reference_and_location_on_stack():
    """Win64: a by-reference (template, args) pair; Location passed as the 5th (stack) argument."""
    m = Mem()
    m.put(0x1000, b"\x04oops\xc0\x00")
    m.put(0x4000, b"src\\main.rs")
    m.put(0x5000, struct.pack("<QQII", 0x4000, 11, 3, 5))
    c = Code(0x10000)
    seq = b"\x48\x83\xec\x58"                                           # sub rsp,0x58
    p = 0x10000 + len(seq)
    seq += b"\x48\x8d\x05" + _rel(p, 7, 0x10300)                        # lea rax,[fmtfn]
    seq += b"\x48\x89\x44\x24\x48"                                      # mov [rsp+0x48],rax  (args[0].fn)
    seq += b"\x48\x8d\x44\x24\x40\x48\x89\x44\x24\x38"                   # lea rax,[rsp+0x40]; mov [rsp+0x38],rax
    p = 0x10000 + len(seq)
    seq += b"\x48\x8d\x05" + _rel(p, 7, 0x1000)                         # lea rax,[tmpl]
    seq += b"\x48\x89\x44\x24\x30"                                      # mov [rsp+0x30],rax
    p = 0x10000 + len(seq)
    seq += b"\x48\x8d\x05" + _rel(p, 7, 0x5000)                         # lea rax,[loc]
    seq += b"\x48\x89\x44\x24\x20"                                      # mov [rsp+0x20],rax (5th arg)
    seq += b"\x48\x8d\x4c\x24\x30"                                      # lea rcx,[rsp+0x30] (&Arguments)
    seq += b"\xe8" + _rel(0x10000 + len(seq), 5, 0x10200)               # call panicky (no ret)
    c.at(0x10000, seq)
    c.at(0x10200, b"\x0f\x0b")
    c.at(0x10300, b"\xc3")
    res = R.run(c.prog(m, [0x10000, 0x10200, 0x10300], abi="win64", fmt="PE"))
    (f,) = [f for f in res["fmt_sites"] if f["function"] == 0x10000]
    assert f["format"] == "oops{}" and f["encoding"] == "template-ref"
    (p,) = [p for p in res["panic_sites"] if p["function"] == 0x10000]
    assert p["location"] == "src\\main.rs:3:5"


def test_sret_niche_store_is_enum_like_and_one_store_is_not():
    """`*out = None` as a Vec/String capacity niche on one path, a real value on the other."""
    c = Code(0x10000)
    seq = b"\x48\x85\xf6"                                               # test rsi,rsi
    seq += b"\x74\x08"                                                  # je +8
    seq += b"\x48\x89\x37"                                              # mov [rdi],rsi   (payload)
    seq += b"\x48\x89\x77\x08\xc3"                                      # mov [rdi+8],rsi; ret
    seq += b"\x48\xb8" + struct.pack("<Q", 1 << 63)                     # movabs rax,0x8000..
    seq += b"\x48\x89\x07\xc3"                                          # mov [rdi],rax; ret
    c.at(0x10000, seq)
    c.at(0x10100, b"\x48\xc7\x07\x05\x00\x00\x00\xc3")                  # mov qword [rdi],5; ret
    res = R.run(c.prog(Mem(), [0x10000, 0x10100]))
    er = {e["va"]: e for e in res["enum_returns"]}
    assert er.get(0x10000, {}).get("shape") == "sret-tag", res["enum_returns"]
    assert 0x10100 not in er


# ------------------------------------------------------------------------------------------------
# committed benign fixtures
# ------------------------------------------------------------------------------------------------
@pytest.fixture(scope="module")
def std_x64():
    if not STD_X64.exists():
        pytest.skip("fixture missing")
    return R.recover(STD_X64, use_libfuncs=False)


def test_stripped_std_fixture_helpers_by_anchor(std_x64):
    """Stripped 1.97 binary, no signatures: core's panic helpers and _print come back from their
    message / stream-name anchors alone."""
    kinds = {(h["role"], h["kind"]) for h in std_x64["helpers"] if h["via"] == "anchor"}
    for want in [("panic", "bounds_check"), ("panic", "slice_index"), ("panic", "unwrap_none"),
                 ("panic", "unwrap_err"), ("panic", "str_index"), ("panic", "capacity_overflow"),
                 ("fmt_sink", "print")]:
        assert want in kinds, (want, sorted(kinds))
    assert std_x64["fmt_encoding"] == "template"


def test_stripped_std_fixture_sites(std_x64):
    c = std_x64["counts"]
    assert c["panic_sites"] >= 300 and c["panic_with_location"] >= 150, c
    assert c["fmt_sites"] >= 50 and c["drop_sites"] >= 200, c
    texts = {f["format"] for f in std_x64["fmt_sites"]}
    assert "failed printing to {}: {}" in texts
    locs = [p["location"] for p in std_x64["panic_sites"] if "location" in p]
    assert all(l.split(":")[0].endswith(".rs") for l in locs)
    # every safety check names its kind and most have the guarding branch
    sc = [p for p in std_x64["panic_sites"] if p["safety_check"]]
    assert sc and sum(1 for p in sc if "guard" in p) * 2 >= len(sc)


def test_macho_pieces_era_fixture():
    """rustc 1.91 (pre-template): fmt::Arguments is a pieces/args struct passed by reference."""
    if not MACHO_A64.exists():
        pytest.skip("fixture missing")
    res = R.recover(MACHO_A64, use_libfuncs=False)
    assert res["fmt_encoding"] == "pieces"
    assert all(f["encoding"] == "pieces" for f in res["fmt_sites"])
    assert any(f["macro"] == "println!" and f["sink"] == "print" for f in res["fmt_sites"])
    roles = {(h["kind"], h["via"]) for h in res["helpers"] if h["role"] == "panic"}
    assert ("bounds_check", "symbol") in roles


def test_cli_json_and_error(tmp_path, capsys):
    bad = tmp_path / "x.bin"
    bad.write_bytes(b"not a binary")
    assert R.main([str(bad), "--json"]) == 1
    assert '"error"' in capsys.readouterr().out
    assert R.main([]) == 2


def test_conditional_tail_call_and_dealloc_call_shape_anchor():
    """No names at all: __rust_dealloc is the tiny forwarding thunk that many sites call with a
    constant power-of-two `align` (rdx) and never test the result; drop glue that reaches it
    through a conditional tail call (`jne thunk`) is inferred as drop glue."""
    c = Code(0x10000, size=0x1000)
    thunk, real = 0x10f00, 0x10f80
    c.at(thunk, b"\xe9" + _rel(thunk, 5, real))                         # jmp __rdl_dealloc
    c.at(real, b"\xc3")
    callers = []
    for k in range(12):                                                 # 12 drop-like callers
        a = 0x10000 + 0x40 * k
        seq = b"\xba\x08\x00\x00\x00"                                   # mov edx,8 (align)
        seq += b"\xbe\x10\x00\x00\x00"                                  # mov esi,16 (size)
        seq += b"\xe8" + _rel(a + len(seq), 5, thunk)                   # call __rust_dealloc
        seq += b"\xc3"
        c.at(a, seq)
        callers.append(a)
    glue = 0x10e00
    seq = b"\x48\x83\x3f\x00"                                           # cmp qword [rdi],0
    seq += b"\x0f\x85" + _rel(glue + 4, 6, callers[0])                  # jne drop_inner (tail)
    seq += b"\xc3"
    c.at(glue, seq)
    res = R.run(c.prog(Mem(), callers + [glue, thunk, real]))
    roles = {h["va"]: (h["role"], h["via"]) for h in res["helpers"]}
    assert roles[thunk] == ("dealloc", "shape") and roles[real][0] == "dealloc", roles
    assert roles[callers[0]][0] == "drop_glue" and roles[glue][0] == "drop_glue", roles
    assert sum(1 for d in res["drop_sites"] if d["kind"] == "dealloc" and d["function"] in callers) == 12
    assert any(d["function"] == glue for d in res["drop_sites"])        # the jne is a drop call


def test_formatter_fns_return_fmt_result_and_empty_vec_is_not_a_tag():
    """A fn whose address sits in an rt::Argument's formatter slot returns fmt::Result; an sret
    function writing {cap 0, ptr 8, len 0} on one path and cap 4 on another is an empty-vs-
    preallocated Vec, not a two-tag enum."""
    m = Mem()
    m.put(0x1000, b"\x02x=\xc0\x00")
    c = Code(0x10000)
    seq = b"\x48\x83\xec\x28"
    seq += b"\x48\x8d\x44\x24\x20\x48\x89\x44\x24\x10"                  # args[0].value
    p = 0x10000 + len(seq)
    seq += b"\x48\x8d\x05" + _rel(p, 7, 0x10300)                       # lea rax,[fmtfn]
    seq += b"\x48\x89\x44\x24\x18"                                     # args[0].formatter
    p = 0x10000 + len(seq)
    seq += b"\x48\x8d\x3d" + _rel(p, 7, 0x1000)
    seq += b"\x48\x8d\x74\x24\x10"
    seq += b"\xe8" + _rel(0x10000 + len(seq), 5, 0x10200)
    seq += b"\x48\x83\xc4\x28\xc3"
    c.at(0x10000, seq)
    c.at(0x10200, b"\xc3")
    c.at(0x10300, b"\x31\xc0\xc3")                                     # fmtfn: xor eax,eax; ret
    vec = 0x10100
    seq = b"\x48\x85\xf6\x74\x0c"                                      # test rsi,rsi; je empty
    seq += b"\x48\xc7\x07\x04\x00\x00\x00"                             # mov qword [rdi],4 (cap)
    seq += b"\x48\x89\x77\x08\xc3"                                     # mov [rdi+8],rsi; ret
    seq += b"\x48\xc7\x07\x00\x00\x00\x00"                             # cap 0
    seq += b"\x48\xc7\x47\x08\x08\x00\x00\x00"                         # ptr 8 (dangling)
    seq += b"\x48\xc7\x47\x10\x00\x00\x00\x00\xc3"                     # len 0
    c.at(vec, seq)
    res = R.run(c.prog(m, [0x10000, vec, 0x10200, 0x10300]))
    er = {e["va"]: e for e in res["enum_returns"]}
    assert er[0x10300]["shape"] == "fmt-result" and "fmt::Result" in er[0x10300]["note"]
    assert vec not in er, er.get(vec)
