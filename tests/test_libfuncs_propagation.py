"""Call-graph propagation in recover_libfuncs (thunks + drop glue), on hand-assembled code.

test_libfuncs.py needs a Rust build and is outside the fast CI subset; these are pure-bytes tests of
_call_graph / _propagate_from_graph for x86-64 and AArch64, pinning that a direct call to a target
that is not a known function start (a PLT / import stub) counts as other control flow, and that a
tail-jump is only a thunk when it is the function's only flow.
"""
import struct
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_libfuncs as LF  # noqa: E402

MATCHES = [{"va": 0x1000, "name": "std::foo", "sym": "F"},
           {"va": 0x1030, "name": "core::ptr::drop_in_place", "sym": "DP"},
           {"va": 0x1040, "name": "alloc::alloc::__rust_dealloc", "sym": "DA"}]


def _rel32(frm, to):
    return ((to - (frm + 5)) & 0xffffffff).to_bytes(4, "little")


def test_x86_plt_call_and_guarded_jump_not_propagated():
    code = bytearray(0x100)
    code[0x00:0x02] = b"\x90\xc3"                                       # F
    code[0x30:0x31] = b"\xc3"                                           # DP
    code[0x40:0x41] = b"\xc3"                                           # DA
    code[0x50:0x56] = b"\xe8" + _rel32(0x1050, 0x1000) + b"\xc3"        # call F; ret  -> thunk
    code[0x60:0x6b] = b"\xe8" + _rel32(0x1060, 0x1000) + b"\xe8" + _rel32(0x1065, 0x5000) + b"\xc3"
    code[0x70:0x7a] = b"\x48\x85\xff\x74\x00" + b"\xe9" + _rel32(0x1075, 0x1000)   # test; je; jmp F
    code[0x80:0x8b] = b"\xe8" + _rel32(0x1080, 0x1030) + b"\xe8" + _rel32(0x1085, 0x5000) + b"\xc3"
    code[0x90:0x95] = b"\xe9" + _rel32(0x1090, 0x1000)                  # jmp F -> thunk
    starts = [0x1000, 0x1030, 0x1040, 0x1050, 0x1060, 0x1070, 0x1080, 0x1090]
    g = LF._call_graph(bytes(code), 0x1000, starts, "x86_64")
    prop = {p["va"]: p for p in LF._propagate_from_graph(starts, g, MATCHES)}
    assert prop[0x1050]["name"] == "thunk.std::foo"
    assert prop[0x1090]["name"] == "thunk.std::foo"
    assert 0x1060 not in prop, "call F; call PLT; ret is not a forwarder"
    assert 0x1070 not in prop, "a guarded tail-jump is not a forwarder"
    assert 0x1080 not in prop, "drop glue must not call unknown targets"


def _bl(pc, to):
    return 0x94000000 | (((to - pc) >> 2) & 0x3ffffff)


def _b(pc, to):
    return 0x14000000 | (((to - pc) >> 2) & 0x3ffffff)


RET, NOP = 0xd65f03c0, 0xd503201f


def test_arm64_plt_call_and_guarded_branch_not_propagated():
    words = {}

    def put(va, *ws):
        for i, w in enumerate(ws):
            words[va + 4 * i] = w
    put(0x1000, NOP, RET)                                               # F
    put(0x1030, RET)                                                    # DP
    put(0x1040, RET)                                                    # DA
    put(0x1050, _bl(0x1050, 0x1000), RET)                               # bl F; ret -> thunk
    put(0x1060, _bl(0x1060, 0x1000), _bl(0x1064, 0x5000), RET)          # bl F; bl PLT; ret
    put(0x1070, 0xb4000040, _b(0x1074, 0x1000))                         # cbz x0,+8; b F
    put(0x1080, _bl(0x1080, 0x1030), _bl(0x1084, 0x5000), RET)          # bl DP; bl PLT; ret
    put(0x1090, _bl(0x1090, 0x1030), _bl(0x1094, 0x1040), RET)          # bl DP; bl DA; ret -> glue
    put(0x10a0, _b(0x10a0, 0x1000))                                     # b F -> thunk
    code = b"".join(struct.pack("<I", words.get(0x1000 + 4 * i, 0)) for i in range(0x30))
    starts = [0x1000, 0x1030, 0x1040, 0x1050, 0x1060, 0x1070, 0x1080, 0x1090, 0x10a0]
    g = LF._call_graph(code, 0x1000, starts, "aarch64")
    prop = {p["va"]: p for p in LF._propagate_from_graph(starts, g, MATCHES)}
    assert prop[0x1050]["name"] == "thunk.std::foo"
    assert prop[0x10a0]["name"] == "thunk.std::foo"
    assert prop[0x1090]["via"] == "drop-glue"
    assert not ({0x1060, 0x1070, 0x1080} & set(prop)), {hex(k): v for k, v in prop.items()}
