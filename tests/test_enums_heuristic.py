"""recover_enums stripped heuristic + DWARF-failure isolation (review-B regressions).

Pins: RIP-relative globals and stack-frame reloads are not enum fields; a register written between
the tag load and the compares is not attributed; one undecodable byte does not end the sweep; and a
DWARF parse failure (exception / RecursionError) does not also disable the heuristic. x86-64 and
AArch64 alike.
"""
import struct
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_enums as E  # noqa: E402

GOOD = bytes.fromhex("0fb607" "83f800" "7405" "83f801" "7405" "83f802")   # movzx eax,[rdi]; cmp 0/1/2


def test_x86_rip_and_stack_bases_skipped():
    rip = bytes.fromhex("0fb60500010000" "83f801" "7400" "83f802")    # movzx eax,[rip+0x100]
    rsp = bytes.fromhex("8b442408" "83f801" "7400" "83f802")          # mov eax,[rsp+8]
    rbp = bytes.fromhex("8b45f8" "83f801" "7400" "83f802")            # mov eax,[rbp-8] (disp<0)
    rbp2 = bytes.fromhex("8b4508" "83f801" "7400" "83f802")           # mov eax,[rbp+8]
    for code in (rip, rsp, rbp, rbp2):
        assert E._dispatch_sites(code, 0x1000) == [], code.hex()


def test_x86_clobbered_register_not_attributed():
    code = bytes.fromhex("0fb607" "83c005" "83f801" "7400" "83f802")   # ...; add eax,5; cmp; cmp
    assert E._dispatch_sites(code, 0x1000) == []
    sub = bytes.fromhex("0fb607" "b005" "83f801" "7400" "83f802")      # mov al,5 clobbers eax too
    assert E._dispatch_sites(sub, 0x1000) == []
    call = bytes.fromhex("0fb607" "83f801" "e800000000" "83f802")      # a call ends the tracking
    assert E._dispatch_sites(call, 0x1000) == []


def test_x86_earlier_site_kept_when_register_reloaded():
    # site 1 on [rdi+0] (values 0,1,2), then eax reloaded from [rsi+8] (values 3,4): both reported
    code = GOOD + bytes.fromhex("0fb64608" "83f803" "7400" "83f804")
    got = {(s["field_offset"], tuple(s["values"])) for s in E._dispatch_sites(code, 0x1000)}
    assert got == {(0, (0, 1, 2)), (8, (3, 4))}, got


def test_x86_undecodable_byte_does_not_end_sweep():
    assert E._dispatch_sites(b"\x06" + GOOD, 0x1000)                     # 0x06 invalid in 64-bit
    many = (b"\x06" + GOOD) * 50
    assert len(E._dispatch_sites(many, 0x1000)) == 50


def _a64(*words):
    return b"".join(struct.pack("<I", w) for w in words)


CMP0, CMP1, CMP2, BEQ = 0x7100001f, 0x7100041f, 0x7100081f, 0x54000040


def test_arm64_sp_fp_bases_and_clobber():
    ldrb_x0 = 0x39400000                     # ldrb w0,[x0]
    ldr_sp = 0xb94013e0                      # ldr w0,[sp,#16]
    ldr_fp = 0xb85fc3a0                      # ldur w0,[x29,#-4]
    ldr_fp2 = 0xb94013a0                     # ldr w0,[x29,#16]
    good = _a64(ldrb_x0, CMP0, BEQ, CMP1, BEQ, CMP2)
    assert E._dispatch_sites_arm64(good, 0x2000)
    for base in (ldr_sp, ldr_fp, ldr_fp2):
        assert E._dispatch_sites_arm64(_a64(base, CMP0, BEQ, CMP1, BEQ, CMP2), 0x2000) == [], hex(base)
    add = 0x11001400                         # add w0,w0,#5 between load and compares
    assert E._dispatch_sites_arm64(_a64(ldrb_x0, add, CMP0, BEQ, CMP1), 0x2000) == []
    bl = 0x94000010
    assert E._dispatch_sites_arm64(_a64(ldrb_x0, CMP0, bl, CMP1), 0x2000) == []
    # an undecodable word does not end the sweep
    assert E._dispatch_sites_arm64(_a64(0xffffffff) + good, 0x2000)


def test_iter_dies_is_iterative():
    class D:
        def __init__(self, kids):
            self.kids = kids

        def iter_children(self):
            return iter(self.kids)
    leaf = D([])
    node = leaf
    for _ in range(sys.getrecursionlimit() * 3):
        node = D([node])
    n = sum(1 for _ in E._iter_dies(node))
    assert n == sys.getrecursionlimit() * 3 + 1
    # pre-order, children in order
    root = D([D([]), D([])])
    order = list(E._iter_dies(root))
    assert order[0] is root and order[1] is root.kids[0] and order[2] is root.kids[1]


@pytest.mark.parametrize("exc", [RecursionError, ValueError])
def test_dwarf_failure_keeps_heuristic(monkeypatch, exc):
    """A DWARF parse failure must not also disable the stripped heuristic (.text was read inside
    the same try as the DWARF walk, so any exception there left .text unread)."""
    pytest.importorskip("elftools")
    dbg = ROOT / "tests" / "fixtures" / "enums" / "enum_dbg.elf64"
    seen = []

    def fake_sites(code, base, limit=256):
        seen.append((len(code), base))
        return [{"site": base, "field_offset": 0, "values": [0, 1]}]

    def boom(_ef):
        raise exc("crafted .debug_info")
    monkeypatch.setattr(E, "_dispatch_sites", fake_sites)
    monkeypatch.setattr(E, "_parse_dwarf_enums", boom)
    res = E.recover(dbg)
    assert seen and seen[0][0] > 0, "heuristic never ran on .text"
    assert res["discriminant_sites"] and res["counts"]["dispatch_sites"] == 1
    assert exc.__name__ in res.get("dwarf_error", "")
