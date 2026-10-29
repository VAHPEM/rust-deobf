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


def test_v0_label_keeps_the_function_name():
    """v0 appends the instantiating crate only to generic instances; the label used to drop the
    last path segment of EVERY v0 symbol (79% of the v0 labels of a rustc 1.97 build), naming
    `core::option::unwrap_failed` as `core::option`."""
    assert LF._v0_path("_RNvNtCsk_4core6option13unwrap_failed") == "core::option::unwrap_failed"
    assert LF._v0_path("_RNvNtNtCsk_3std2rt19lang_start_internal") == "std::rt::lang_start_internal"
    # short non-generic symbols (reported by the idioms work): the final segment survives
    assert LF._v0_path("_RNvNtCs1a2b3c_4core9panicking18panic_bounds_check") == \
        "core::panicking::panic_bounds_check"
    assert LF._v0_path("_RNvCs1a2b3c_4core9panic_fmt") == "core::panic_fmt"
    # a generic instance: its trailing instantiating crate IS dropped
    assert LF._v0_path("_RNvMs4_NtCs40k4W9msRzi_5alloc7raw_vecNtB5_11RawVecInner11finish_grow"
                       "Cs8FMd1QCh2cR_12goldberg_cff") == "alloc::raw_vec::RawVecInner::finish_grow"
    # labels of DB entries are re-derived from their symbol (old DBs carry truncated names)
    assert LF._label({"name": "core::option", "sym": "_RNvNtCsk_4core6option13unwrap_failed"}) == \
        "core::option::unwrap_failed"


def test_labels_drop_lto_suffixes_and_coff_underscore():
    # LTO-localised copies get `.<n>` suffixes that differ between builds of the same function
    assert LF.readable("_ZN5alloc6string6String4push17h602a7f5c73cf964eE.910") == "alloc::string::String::push"
    # i386 COFF (like Mach-O) prefixes one `_`: `__R...` is still a v0 symbol
    assert LF.readable("__RNvNtCsk_4core6option13unwrap_failed") == "core::option::unwrap_failed"


def _cie_fde(enc_pcrel: bool, pc: int, va: int):
    """A minimal .eh_frame: one CIE ("zR", given FDE pointer encoding) + one FDE for `pc`."""
    enc = 0x1B if enc_pcrel else 0x00
    cie_body = struct.pack("<I", 0) + b"\x01zR\x00" + b"\x01" + b"\x7c" + b"\x08" + b"\x01" + bytes([enc])
    cie_body += b"\x00" * ((-len(cie_body)) % 4)
    cie = struct.pack("<I", len(cie_body)) + cie_body
    fde_off = len(cie)
    field = fde_off + 8                                   # where pc_begin lives
    pcv = (pc - (va + field)) & 0xFFFFFFFF if enc_pcrel else pc
    fde_body = struct.pack("<I", fde_off + 4) + struct.pack("<I", pcv) + struct.pack("<I", 0x40) + b"\x00"
    fde_body += b"\x00" * ((-len(fde_body)) % 4)
    return cie + struct.pack("<I", len(fde_body)) + fde_body + b"\x00" * 4


def test_eh_frame_fde_starts():
    """A stripped i686 mingw PE has neither symbols nor .pdata: function starts come from the FDEs
    of its raw .eh_frame (absolute pointers, rebased by the image base) -- before, 0 starts and
    0 matches."""
    assert LF.eh_frame_fde_starts(_cie_fde(True, 0x401230, 0x500000), 0x500000, 4) == {0x401230}
    assert LF.eh_frame_fde_starts(_cie_fde(False, 0x00401230, 0x16000), 0x16000, 4, 0x400000) == {0x1230}
    assert LF.eh_frame_fde_starts(b"\xff" * 64, 0, 4) == set()          # garbage: nothing, no raise


def test_known_other_toolchain_is_not_pooled():
    """Signatures of another, KNOWN rustc are not pooled any more (measured: 0.4-24% precision);
    only a binary whose toolchain is unknown falls back to pooling."""
    import lief
    import gen_runtime_sigs as G
    p = ROOT / "tests" / "fixtures" / "emu" / "null64"
    b = lief.parse(str(p))
    text = next(s for s in b.sections if s.name == ".text")
    a = min(x for x in LF.function_starts(b) if text.virtual_address <= x)
    pat = bytes(text.content)[a - text.virtual_address:][:LF.SIG_LEN].hex()
    db = {"rustc-1.97.0": {"x86_64": [{"name": "probe::f", "sym": "probe_f", "pattern": pat}]}}
    assert [r["name"] for r in LF.match_binary(p, db, tool="unknown")] == ["probe::f"]
    assert LF.match_binary(p, db, tool="rustc-1.85.0") == []
    assert [r["name"] for r in LF.match_binary(p, db, tool="rustc-1.97.1")] == ["probe::f"]   # same minor
    assert [r["name"] for r in LF.match_binary(p, db, tool="rustc-1.97.0")] == ["probe::f"]
    # the bundled prebuilt-std layer: exact rustc AND arch-format only
    std = {"rustc-9.9.9": {"x86_64-elf": [{"name": "std::g", "sym": "std_g", "pattern": pat}],
                           "x86_64-pe": [{"name": "std::h", "sym": "std_h", "pattern": pat}]}}
    assert [r["name"] for r in LF.match_binary(p, {"__std__": std}, tool="rustc-9.9.9")] == ["std::g"]
    assert LF.match_binary(p, {"__std__": std}, tool="rustc-1.0.0") == []


def test_bundled_std_layer_present():
    std = LF.load_std_db()
    assert "rustc-1.97.0" in std, list(std)
    groups = std["rustc-1.97.0"]
    for key in ("x86_64-elf", "aarch64-elf", "x86_64-pe"):
        assert len(groups.get(key, [])) > 1000, (key, len(groups.get(key, [])))
    assert "__std__" in LF.load_db() and "__std__" not in LF.load_db(LF.OUT)
