"""Regression tests for false positives the CI `precision` job reported (measure_fp.py --pipeline
--corpus on the GitHub ubuntu runner's own binaries). Each test builds a small synthetic input that
reproduces the cause; none needs a real binary."""
import struct
import sys
import zlib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))

# what DWARF's .debug_str holds: file and type names (the CI run's docker / rustfmt strings)
_DWARF_TEXT = (b"/usr/include/x86_64-linux-gnu/bits\x00CK_ATTRIBUTE_PTR\x00"
               b"/rustc/0000000000000000000000000000000000000000/library/core/src/lib.rs\x00")


def _elf_with_section(tmp_path, name, flags, content):
    import lief
    from _mkelf import mkelf
    elf, _, _ = mkelf(b"\xc3")
    b = lief.ELF.parse(list(elf))
    sec = lief.ELF.Section(name)
    sec.content = list(content)
    sec.flags = flags
    b.add(sec, loaded=False)
    p = tmp_path / "dwarf.elf"
    p.write_bytes(b.write_to_bytes())
    return p


@pytest.mark.parametrize("name,flags,compressed", [
    (".debug_str", 0x800, True),       # SHF_COMPRESSED: Elf64_Chdr + zlib stream (gcc/Go -gz)
    (".zdebug_str", 0, True),          # GNU style: "ZLIB" + 8-byte BE size + zlib stream
    (".rodata_blob", 0, False),        # control: the same stream in ordinary data is a recovery
])
def test_ci_fp_compressed_dwarf_is_not_a_decoded_string(tmp_path, name, flags, compressed):
    # CI precision run 43869999822: docker 653 + rustfmt 70 "zlib" FPs were the compressed DWARF
    # sections (valid, checksummed zlib) read by recover.run's compressed-strings engine
    import recover
    z = zlib.compress(_DWARF_TEXT)
    if flags & 0x800:
        content = struct.pack("<IIQQ", 1, 0, len(_DWARF_TEXT), 1) + z      # ELFCOMPRESS_ZLIB
    elif name.startswith(".zdebug"):
        content = b"ZLIB" + struct.pack(">Q", len(_DWARF_TEXT)) + z
    else:
        content = z
    p = _elf_with_section(tmp_path, name, flags, content)
    res = recover.run(p, emulate="never", stackstrings=False, literals=False)
    got = {x["string"] for x in res["decoded"] if x.get("method") in ("zlib", "gzip")}
    if compressed:
        assert got == set(), got
    else:
        assert "CK_ATTRIBUTE_PTR" in got, res


def test_ci_fp_debug_spans_selftest_shapes(tmp_path):
    import recover_blobs as B
    z = zlib.compress(_DWARF_TEXT)
    p = _elf_with_section(tmp_path, ".debug_line", 0, z)
    spans = B.debug_spans(p)
    data = p.read_bytes()
    off = data.find(z)
    assert any(lo <= off < hi for lo, hi in spans), (spans, off)
    assert list(B.small_streams(data, skip=spans)) == []
    assert len(list(B.small_streams(data))) == 1
    assert B.debug_spans(tmp_path / "missing") == []


# --- emulation: static data read word by word ---------------------------------------------------
# cargo-fmt 1.99.1 (CI precision run 43869999822, 4 FPs): std's backtrace symbolizer, run on a forced
# path, read the first 8 bytes of each 24/32-byte slot of a .rodata string table into one buffer:
# `identifi` + ` rust-ve` + `ata is n` + ... -- every piece is static text, 0x10-0x18 bytes after
# the previous one. (Neutral words below; the shape is what matters.)
_WORDS = [b"identifier is not valid", b"rust-version attribute", b"data is not a table",
          b"collection of members", b"assertion `left == right`", b"entered unreachable code",
          b"benchmark targets only", b"example targets ignored", b"library crate type",
          b"variant index out of range", b"workspace members list", b"root package manifest",
          b"build dependencies table", b"target specific settings", b"license file missing",
          b"manifest key unknown", b"repository url invalid", b"edition field required"]


def _table(stride):
    tbl = b"".join(w[:stride].ljust(stride, b"\0") for w in _WORDS)
    return b"\x7fELF" + bytes(0x200) + tbl + bytes(0x200)


@pytest.mark.parametrize("stride,n", [(24, 12), (32, 18), (24, 18)])
def test_strided_static_read_short_is_static(stride, n):
    # guard (passes on the base code too: the cover's long-pieces rule takes short candidates)
    import recover_emulate as E
    fb = _table(stride)
    cand = b"".join(w[:8] for w in _WORDS[:n]).decode()     # 96 / 144 chars (< 160) and 144
    explained = E._static_cover(fb)
    assert explained(cand), cand


def test_ci_fp_long_strided_static_read_is_static():
    # over 160 characters the cover used only 16-byte windows: 8-byte pieces never matched one
    import recover_emulate as E
    fb = _table(24) + _table(32)
    cand = (b"".join(w[:8] for w in _WORDS) + b"".join(w[:8] for w in _WORDS[:6])).decode()
    assert len(cand) > 160
    assert E._static_cover(fb)(cand), cand


def test_strided_rule_keeps_decoded_text():
    # a decoded string is not in the file, or only in short scattered pieces: still a recovery
    import recover_emulate as E
    explained = E._static_cover(_table(24))
    assert not explained("canary::echo::schema-version-4/192.0.2.17")
    assert not explained("Zq7#kV2!pL9$wX4&mN6*bR8")


# --- emulation: the emulator's zero clock formatted into a static template ----------------------
# cargo 1.99.1 (CI precision run 43869999822): `session \`19700101T000000000Z-\` not found` -- a
# session name cargo formats from the current time, which the emulator reports as 0.
_SESSION_FILE = b"\0session `\0` not found\0no such session\0--verbose\0"


@pytest.mark.parametrize("cand", ["session `19700101T000000000Z-` not found",
                                  "session `1970-01-01T00:00:00Z` not found",
                                  "session `Thu, 01 Jan 1970 00:00:00 GMT` not found"])
def test_ci_fp_epoch_zero_timestamp_is_emulator_made(cand):
    import recover_emulate as E
    assert E._static_cover(_SESSION_FILE)(cand), cand


@pytest.mark.parametrize("cand", ["session `20261116T101500000Z-` not found",   # a real time
                                  "beacon 1970-01-01 192.0.2.5"])               # other text
def test_epoch_rule_keeps_other_text(cand):
    import recover_emulate as E
    assert not E._static_cover(_SESSION_FILE)(cand), cand


# --- compressed strings: a whole gzip'd document is a resource, not a string table --------------
# kubectl (CI precision run 43869999822, 50 "gzip" FPs): kustomize's OpenAPI schema, gzip'd JSON,
# split into lines by the compressed-strings engine.
_SCHEMA = (b'{\n  "definitions": {\n    "example.v1.ConfigArgs": {\n      "properties": {\n'
           b'        "kind": {\n          "type": "string"\n        },\n        "items": {\n'
           b'          "type": "array"\n        }\n      },\n      "type": "object"\n    }\n  }\n}\n')


def _elf_with_rodata(tmp_path, content):
    return _elf_with_section(tmp_path, ".rodata_blob", 0, content)


def test_ci_fp_gzip_json_document_is_not_decoded_strings(tmp_path):
    import gzip
    import recover
    p = _elf_with_rodata(tmp_path, gzip.compress(_SCHEMA, mtime=0))
    res = recover.run(p, emulate="never", stackstrings=False, literals=False)
    assert [x for x in res["decoded"] if x.get("method") in ("zlib", "gzip")] == [], res["decoded"]
    docs = res.get("compressed_documents", [])
    assert [(d["method"], d["kind"]) for d in docs] == [("gzip", "json")], res
    assert any("json document" in n for n in res["notes"])


def test_compressed_string_table_still_decoded(tmp_path):
    # control: a zlib string table (bench_src/encodings' shape) is still recovered string by string
    import recover
    table = b"canary::zlib::alpha-7\x00schema-version-4 ok\x00"
    p = _elf_with_rodata(tmp_path, zlib.compress(table))
    res = recover.run(p, emulate="never", stackstrings=False, literals=False)
    got = {x["string"] for x in res["decoded"] if x.get("method") == "zlib"}
    assert "canary::zlib::alpha-7" in got, res
    assert not res.get("compressed_documents")


# --- emulation: static path components / a hash formatted into a static template ----------------
# cargo 1.99.1 (CI precision run 43869999822): `lib/rustlib/src/rust/` (the sysroot joined from the
# literals `lib`, `rustlib`, `src`, `rust` by PathBuf::push) and
# `.metabuild/metabuild--2f7afcdcf57ab8e9.rs` (`metabuild-{name}-{hash}.rs`, empty name, a run-time
# hash, joined under `.metabuild`).
_CARGO_FILE = b"\0lib\0rustlib\0src\0rust\0.metabuild\0metabuild-\0.rs\0--verbose\0tmp\0"


@pytest.mark.parametrize("cand", ["lib/rustlib/src/rust/",
                                  ".metabuild/metabuild--2f7afcdcf57ab8e9.rs"])
def test_ci_fp_joined_static_path_is_static(cand):
    import recover_emulate as E
    assert E._static_cover(_CARGO_FILE)(cand), cand


@pytest.mark.parametrize("cand", ["/tmp/stage2.bin",              # a component not in the file
                                  "lib/src",                      # no 6+ char static component
                                  "update-2f7afcdcf57ab8e9.example.invalid"])
def test_path_rule_keeps_hidden_paths(cand):
    import recover_emulate as E
    assert not E._static_cover(_CARGO_FILE)(cand), cand


# --- emulation: text written through a NULL-based pointer ---------------------------------------
# cargo-fmt 1.99.1 (CI precision run 43869999822): clap's usage text `ptions]...` written at 0x10,
# a field of a zeroed struct the emulator handed in -- a store no real process can make.
def _store_text_code(dst_reg_setup: bytes, text: bytes) -> bytes:
    """dst_reg_setup leaves the destination in rdi; then 8-byte stores of `text` at [rdi+i]."""
    code = bytearray(dst_reg_setup)
    for i in range(0, len(text), 8):
        chunk = text[i:i + 8].ljust(8, b"\0")
        code += b"\x48\xb8" + chunk                       # mov rax, imm64
        code += b"\x48\x89\x47" + bytes([i])              # mov [rdi+i], rax
    return bytes(code + b"\xc3")


@pytest.mark.parametrize("where,expect", [
    (b"\x48\xc7\xc7\x10\x00\x00\x00", False),             # mov rdi, 0x10   (NULL + 16)
    (b"\x48\x8d\x7c\x24\xc0", True),                      # lea rdi, [rsp-0x40] (a stack buffer)
], ids=["null+16", "stack"])
def test_ci_fp_text_stored_through_null_pointer_not_captured(tmp_path, where, expect):
    import recover_emulate as R
    from _mkelf import mkelf
    text = b"usage: [rustfmt_options]... <files>"
    elf, text_va, _ = mkelf(_store_text_code(where, text))
    p = tmp_path / "nullstore.elf"
    p.write_bytes(elf)
    emu = R.Emulator(R.Image(str(p)))
    strings, _, _ = emu.run(text_va, len(elf))
    assert (text.decode() in strings) is expect, strings


# --- emulation: emulator-made values in Go runtime prints -------------------------------------
# docker / go 1.24 (CI precision run 43869999822): the emulator's CPUID vendor id stored register
# by register (`GenuntelineI`), the emulated stack pointer printed by the runtime, zeros from the
# emulator's zeroed memory after a static label.
_GO_FILE = (b"\0entersyscall inconsistent sp \0 [\0,\0]\0Ints: \0key \0 0\0runtime: bad pointer\0"
            + b"\0".join(bytes([c]) for c in range(0x20, 0x7f)))  # every character, alone


@pytest.mark.parametrize("cand", ["GenuntelineI", "Ints: 0 0 0 ", "key  0 0 0 0"])
def test_ci_fp_go_runtime_prints_emulator_values(cand):
    import recover_emulate as E
    assert E._static_cover(_GO_FILE)(cand), cand


def test_ci_fp_go_runtime_prints_emulator_stack_pointer():
    # Go keeps the print's pieces apart (`entersyscall inconsistent `, `sp `, ` [`, ...)
    import recover_emulate as E
    fb = b"\0entersyscall inconsistent \0sp \0bp \0 [\0,\0]\0" + \
        b"\0".join(bytes([c]) for c in b"0123456789abcdefx")
    ex = E._static_cover(fb)
    assert ex("entersyscall inconsistent sp 0x0 [0x1cb54c0,0x7f00000ffaf8]")
    # the same print with an address outside the emulator's regions is not explained this way
    assert not ex("entersyscall inconsistent sp 0x0 [0x1cb54c0,0x5a5a5a5a5a]")


@pytest.mark.parametrize("cand", ["Ints: 7 3 9 x", "beacon 192.0.2.10 0 0",
                                  "Genu-ineI-ntel-extra-text-here-not-cpuid-1"[:0] or "QZx7Genu9k"])
def test_emulator_value_rules_keep_other_text(cand):
    import recover_emulate as E
    assert not E._static_cover(_GO_FILE)(cand), cand


# --- emulation: static identifiers joined at run time / static names with flipped bits ----------
# perl 5.38 (`File::Glob` -> `File/Glob.pm`, `SV_YES:UNDEF`) and vim 9.1 (`print/prolog.ps`; forced
# paths overlaying records on stale .dynstr names: `OYObject_CallFwnctionOcj@Rgs`, `endptifProcmask`)
_C_FILE = (b"\0File::Glob\0SV_YES\0SV_ZERO\0IF_UNDEF\0print\0prolog\0.ps\0.pm\0"
           b"PyObject_CallFunctionObjArgs\0sigprocmask\0_ITM_registerTMCloneTable\0tmp\0"
           + b"\0".join(bytes([c]) for c in range(0x20, 0x7f)))   # every character, alone


@pytest.mark.parametrize("cand", ["File/Glob.pm", "SV_YES:UNDEF",
                                  "OYObject_CallFwnctionOcj@Rgs", "endptifProcmask",
                                  "__gsTL#loneTable"])
def test_ci_fp_static_identifiers_joined_or_bit_flipped(cand):
    import recover_emulate as E
    assert E._static_cover(_C_FILE)(cand), cand


@pytest.mark.parametrize("cand", ["/tmp/stage2.bin", "File:secret", "Zq7#kV2!pL9wX4mN6bR8"])
def test_identifier_rules_keep_hidden_text(cand):
    import recover_emulate as E
    assert not E._static_cover(_C_FILE)(cand), cand


def test_ci_fp_junk_factory_counts_explained_static_output():
    # 4 of a function's 6 forced outputs were explained as static: the other two (40%+ file
    # pieces) are the same artifact; a function with no explained output keeps them
    import recover_emulate as E
    fb = b"\0PyGILState_Ensure\0PyTuple_Size\0PyUnicode_FromFormat\0"
    recs = [{"string": s, "function": 0x1000, "forced": True}
            for s in ("PyGIL`EmSure", "PyTurle_Sizeee^&romFormat")]
    assert E._drop_junk_factories([dict(r) for r in recs], fb, {0x1000: 4}) == []
    assert len(E._drop_junk_factories([dict(r) for r in recs], fb, {})) == 2
    # a decoder: its forced outputs are not file pieces, whatever else it explained
    dec = [{"string": "Zq7#kV2!pL9wX4mN6bR8", "function": 0x2000, "forced": True}]
    assert len(E._drop_junk_factories(dec, fb, {0x2000: 9})) == 1


def test_ci_fp_text_in_read_only_section_not_captured(tmp_path):
    # cargo-fmt is a PIE mapped at its own VAs: its page 0 holds .interp/.dynsym, and clap's usage
    # text was "written" there at 0x10. A store into a read-only data section faults natively.
    import lief
    import recover_emulate as R
    from _mkelf import mkelf
    text = b"usage: [rustfmt_options]... <files>"
    code = _store_text_code(b"\x48\xc7\xc7" + (0x402000).to_bytes(4, "little"), text)  # mov rdi, imm32
    elf, text_va, _ = mkelf(code)
    b = lief.ELF.parse(list(elf))
    for name, flags in ((".rodata", 0x2), (".data", 0x3)):          # ALLOC / ALLOC|WRITE
        sec = lief.ELF.Section(name)
        sec.content = [0] * 0x100
        sec.flags = flags
        sec.virtual_address = 0x402000 if name == ".rodata" else 0x404000
        b.add(sec, loaded=True)
    p = tmp_path / "rostore.elf"
    p.write_bytes(b.write_to_bytes())
    img = R.Image(str(p))
    ro = next(s for s in img.binary.sections if s.name == ".rodata").virtual_address
    rw = next(s for s in img.binary.sections if s.name == ".data").virtual_address
    for dst, expect in ((ro, False), (rw, True)):
        code = _store_text_code(b"\x48\xc7\xc7" + dst.to_bytes(4, "little"), text)
        img.binary.get_section(".text").content = list(code)      # same layout, new destination
        emu = R.Emulator(img)
        strings, _, _ = emu.run(img.binary.get_section(".text").virtual_address, len(code))
        assert (text.decode() in strings) is expect, (hex(dst), strings)


# --- emulation: a 1970 clock and zeroed values ---------------------------------------------------
# cargo 1.99.1 (deeper runs than CI's 60 s): `session \`19701122T063448000Z-` (a clock derived from
# the emulated TSC, days into 1970) and `0.0.0.0:0` (a zeroed SocketAddr formatted).
_NET_FILE = b"\0session `\0` not found\0--verbose\0listening on \0" + \
    b"\0".join(bytes([c]) for c in range(0x20, 0x7f))


@pytest.mark.parametrize("cand", ["session `19701122T063448000Z-", "0.0.0.0:0"])
def test_ci_fp_1970_clock_and_zeroed_values(cand):
    import recover_emulate as E
    assert E._static_cover(_NET_FILE)(cand), cand


@pytest.mark.parametrize("cand", ["session `20261116T101500000Z-` not found", "192.0.2.10:8443",
                                  "10.0.0.1:0"])
def test_clock_and_zero_rules_keep_real_values(cand):
    import recover_emulate as E
    assert not E._static_cover(_NET_FILE)(cand), cand


# --- emulation: short mutated copies of a static string -----------------------------------------
# rustfmt 1.99.1 (CI precision run 43869999822): forced paths copied the binary's own .interp to
# the stack and changed 3 bytes: `LIninux-`, `Leminux-` (`d-linux-`), `.//jb64/l` (`\0/lib64/l`).
_INTERP_FILE = b"\0/lib64/ld-linux-x86-64.so.2\0" + b"\0".join(bytes([c]) for c in range(0x20, 0x7f))


@pytest.mark.parametrize("cand", ["LIninux-", "Leminux-", ".//jb64/l"])
def test_ci_fp_short_mutated_static_copy(cand):
    import recover_emulate as E
    assert E._static_cover(_INTERP_FILE)(cand), cand


@pytest.mark.parametrize("cand", ["canary77", "Zq7#kV2!", "lnx-q9z7"])
def test_short_mutation_rule_keeps_other_text(cand):
    import recover_emulate as E
    assert not E._static_cover(_INTERP_FILE)(cand), cand


def test_merge_keeps_static_counts_apart_from_records():
    # parallel workers' by_string maps carry `_STATIC_KEY + text -> function` entries next to the
    # records; merging two of them must not treat those ints as records (TypeError on bash)
    import recover_emulate as E
    a = {"x": {"string": "x", "function": 1, "forced": True}, E._STATIC_KEY + "s": 0x10}
    b = {"x": {"string": "x", "function": 1}, E._STATIC_KEY + "s": 0x20, E._STATIC_KEY + "t": 0x30}
    E._merge(a, b)
    assert a[E._STATIC_KEY + "s"] == 0x10 and a[E._STATIC_KEY + "t"] == 0x30
    assert "forced" not in a["x"]


# --- emulation: a temporary file's random name ----------------------------------------------------
# cargo 1.99.1 (the last FP of the mirror container's run): `@/tmp/cargo-argfile.ANmKoZ` --
# tempfile's prefix + 6 random alphanumerics from the emulator's deterministic RNG.
_TMP_FILE = b"\0/tmp/\0cargo-argfile.\0@\0" + b"\0".join(bytes([c]) for c in range(0x20, 0x7f))


@pytest.mark.parametrize("cand", ["@/tmp/cargo-argfile.ANmKoZ", "/tmp/ANmKoZ"])
def test_ci_fp_temp_file_random_name(cand):
    import recover_emulate as E
    assert E._static_cover(_TMP_FILE)(cand), cand


@pytest.mark.parametrize("cand", ["/tmp/xmrig1", "/var/tmp/AbCdEf", "http://192.0.2.5/AbC1dE",
                                  "/tmp/cargo-argfile.ANmKo"])
def test_temp_name_rule_keeps_other_paths(cand):
    import recover_emulate as E
    assert not E._static_cover(_TMP_FILE)(cand), cand


@pytest.mark.parametrize("name", ["macho_classic.dylib", "macho_chained.dylib"])
def test_read_only_pages_use_macho_segment_protection(name):
    # Mach-O section flags are type bits, not SHF_WRITE: reading them as ELF flags made __DATA
    # "read-only" and dropped Hikari's in-place constructor decrypts (tests/test_ollvm_shapes.py)
    import lief
    import recover_emulate as R
    b = lief.parse(str(ROOT / "tests" / "fixtures" / "static" / name))
    ro = R._read_only_pages(b, False)
    for s in b.sections:
        if not s.virtual_address or not s.size:
            continue
        prot = int(s.segment.init_protection)
        if prot & 2 or prot & 4:                       # writable or executable segment
            assert not ro & set(range(s.virtual_address >> 12,
                                      (s.virtual_address + s.size + 0xfff) >> 12)), s.name


# --- emulation: a nearby string table copied in long fixed-size blocks, in table order with skips -
# rustfmt 1.100.0 (CI precision run 44855259120): `_tNtCs..._4core3fmt8buildersNtB5_ffB_4core...`,
# 40-byte blocks of .dynstr v0 names, mostly forwards past gaps of 160-700 bytes, some backwards.
# The same layout here: pieces at the CI run's .dynstr offsets (relative), synthetic names.
_BLOCKS = [(0x070, b"_t"),
           (0x158, b"NtCs1aBcDeFgHiJ_4demo3fmt8buildersNtB5_"),
           (0x000, b"ffB_4demo3fmtNtB5_9Formatter26debug_stru"),
           (0x2e7, b"RNvMs3_NtNtCs1aBcDeFgHiJ_4demo3fmt8build"),
           (0x3af, b"RNvMs2_NtNtCs1aBcDeFgHiJ_4demo3fmt8bulid"),
           (0x1a7, b"fB_4demo3fmt8buildersNtB5_9DebugList6fin"),
           (0x2bf, b"_4demo3fmtNtB5_9Formatter11debug_tuple")]


def _dynstr():
    tbl = bytearray(b"\0" * 0x400)
    for off, piece in _BLOCKS:
        tbl[off:off + len(piece)] = piece
    return b"\x7fELF" + bytes(0x300) + bytes(tbl) + bytes(0x300), 4 + 0x300


def test_ci_fp_static_table_copied_in_long_blocks():
    import recover_emulate as E
    fb, _ = _dynstr()
    cand = b"".join(p for _, p in _BLOCKS)
    assert len(cand) > 160 and all(0x20 < c < 0x7f for c in cand), cand
    assert E._static_cover(fb)(cand.decode()), cand


def test_block_rule_keeps_hidden_text():
    # hidden text glued after one static block, or alone, is still a recovery
    import recover_emulate as E
    fb, base = _dynstr()
    hidden = "canary-schema-v4-192.0.2.17-" * 7
    assert not E._static_cover(fb)(hidden)
    assert not E._static_cover(fb)(_BLOCKS[1][1].decode() + hidden)
    assert not E._static_cover(fb)(_BLOCKS[1][1].decode() + hidden + _BLOCKS[2][1].decode())


# --- emulation: consecutive static strings rewritten character by character -------------------
# git 2.56.1 (Ubuntu 26.04 runner): `encoding-text-eol-lf-text-eol-crlf-...` -- a sanitizer run on
# a fake length over .rodata, every separator (NUL, space, `=`, `%`, `:`) turned into `-`.
_RODATA = (b"encoding\0text eol=lf\0text eol=crlf\0text=auto\0%s: close error\0"
           b"copy-fd: read returned %s\0version 0\0capability %s\0url has no scheme: %s\0"
           b"invalid credential line: %s\0sha1 file '%s' read error\0core.proxy\0"
           b"could not run rev-list\0destination reencoded\0external filter '%s' failed\0"
           b"flush packet write failed\0client version %d\0treeish=%s\0can-delay=1\0"
           b"%lu seconds ago\0%lu minutes ago\0%lu hours ago\0%lu days ago\0yesterday\0")


def _sanitized(raw):
    import re
    return re.sub(rb"[^A-Za-z0-9._]+", b"-", raw).strip(b"-").decode()


def test_ci_fp_static_strings_rewritten_char_by_char():
    import recover_emulate as E
    fb = b"\x7fELF" + bytes(0x200) + _RODATA + bytes(0x200)
    cand = _sanitized(_RODATA)
    assert len(cand) > 160
    assert E._static_cover(fb)(cand), cand


def test_rewrite_rule_keeps_hidden_text():
    import recover_emulate as E
    fb = b"\x7fELF" + bytes(0x200) + _RODATA + bytes(0x200)
    hidden = "-".join(["canary", "schema", "v4", "widget", "colour", "192.0.2.17"] * 6)
    assert not E._static_cover(fb)(hidden)
    # a hidden tail longer than the static head it follows is still not explained
    assert not E._static_cover(fb)(_sanitized(_RODATA[:80]) + "-" + hidden)


# --- emulation: a NULL-based pointer reading a PIE's header page --------------------------------
# git 2.56.1 (Ubuntu 26.04 runner, CI precision run 44855259120): a URL-encoding loop walked a NULL
# string field of a fake struct from address 0; the PIE is mapped at its own VAs, so it read the
# notes and .interp (`GNUDyO0lib64`). A real process never maps the first 64 KB: it would fault.
_INTERP = b"/lib64/ld-linux-x86-64.so.2"


def _pie_with_interp(src_va):
    """ET_DYN at VA 0: .interp at 0x318 (read-only, page 0), .text at 0x1000 (a copy loop reading
    len(_INTERP) bytes from absolute `src_va` -- a NULL-based pointer when it is 0x318 -- into a
    stack buffer), the same text again at 0x1100 for the control."""
    n = len(_INTERP)
    code = (b"\x31\xf6" b"\x48\x8d\x7c\x24\xc0"                       # xor esi,esi; lea rdi,[rsp-0x40]
            + b"\x8a\x86" + struct.pack("<I", src_va)                  # mov al,[rsi+src_va]
            + b"\x88\x07\x48\xff\xc6\x48\xff\xc7"                      # mov [rdi],al; inc rsi; inc rdi
            + b"\x48\x83\xfe" + bytes([n]) + b"\x75\xec\xc3")          # cmp rsi,n; jne loop; ret
    text = code.ljust(0x100, b"\x90") + _INTERP + b"\0"
    shstr = b"\0.interp\0.text\0.shstrtab\0"
    shoff = 0x1000 + len(text) + len(shstr)
    shoff = (shoff + 7) & ~7
    out = bytearray(shoff + 64 * 4)
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    struct.pack_into("<16sHHIQQQIHHHHHH", out, 0, ident, 3, 0x3e, 1, 0x1000, 64, shoff, 0, 64, 56, 1,
                     64, 4, 3)
    end = 0x1000 + len(text)
    struct.pack_into("<IIQQQQQQ", out, 64, 1, 7, 0, 0, 0, end, end, 0x1000)
    out[0x318:0x318 + n] = _INTERP
    out[0x1000:end] = text
    out[end:end + len(shstr)] = shstr

    def shdr(i, name, typ, flags, addr, off, size):
        struct.pack_into("<IIQQQQIIQQ", out, shoff + i * 64, name, typ, flags, addr, off, size, 0, 0, 1, 0)
    shdr(1, 1, 1, 2, 0x318, 0x318, n + 1)          # .interp PROGBITS A
    shdr(2, 9, 1, 6, 0x1000, 0x1000, len(text))     # .text PROGBITS AX
    shdr(3, 15, 3, 0, 0, end, len(shstr))           # .shstrtab
    return bytes(out)


@pytest.mark.parametrize("src,expect", [(0x318, False), (0x1100, True)], ids=["null+0x318", "text"])
def test_ci_fp_null_pointer_read_of_pie_header_page(tmp_path, src, expect):
    import recover_emulate as R
    p = tmp_path / "pie.elf"
    p.write_bytes(_pie_with_interp(src))
    img = R.Image(str(p))
    assert R._header_page(img.binary, img.pe) == 0x1000
    strings, _, _ = R.Emulator(img).run(0x1000, 0x100)
    assert (_INTERP.decode() in strings) is expect, strings


def test_header_page_only_for_metadata_pages(tmp_path):
    # an image whose first page holds code (mkelf: .text RWX at base + 0x1000; base 0 puts
    # nothing in page 0) or a non-PIE at 0x400000 has no header-page guard
    import recover_emulate as R
    from _mkelf import mkelf
    for base in (0x400000, 0x0):
        elf, _, _ = mkelf(b"\xc3", base=base)
        p = tmp_path / ("m%x.elf" % base)
        p.write_bytes(elf)
        img = R.Image(str(p))
        assert not R._header_page(img.binary, img.pe)


def test_header_page_span_ends_at_first_other_section():
    # lld puts a small binary's .rodata in page 0 (null64: .interp ... .dynstr, then .rodata at
    # 0x315): only the metadata before it reads as zeros, the .rodata keeps its bytes
    import recover_emulate as R
    f = ROOT / "tests" / "fixtures" / "emu" / "null64"
    if not f.is_file():
        pytest.skip("fixture missing")
    img = R.Image(str(f))
    ro = next(s for s in img.binary.sections if s.name == ".rodata")
    assert R._header_page(img.binary, img.pe) == ro.virtual_address
    emu = R.Emulator(img)
    emu._reset()
    assert bytes(emu.uc.mem_read(R.BASE + ro.virtual_address, ro.size)) == bytes(ro.content)
    assert not any(emu.uc.mem_read(R.BASE, ro.virtual_address))


# --- emulation: a fake pointer printed as a decimal integer -------------------------------------
# cargo 1.100.0 (exact CI binary, CI command, run reached further on a faster host): serde's
# `invalid type: integer \`4952364620051328414452318208\` as u128, expected struct Hints` -- the
# number is 0x100080000000000010008000, the emulator's SCRATCH + 0x8000 in both 64-bit halves.
_SERDE_FILE = b"\0invalid type: \0integer `\0` as u128\0, expected \0struct Hints\0"


def test_ci_fp_emulator_pointer_printed_as_decimal():
    import recover_emulate as E
    v = (E.SCRATCH + 0x8000) << 64 | (E.SCRATCH + 0x8000)
    cand = "integer `%d` as u128, expected struct Hints" % v
    assert E._static_cover(_SERDE_FILE)(cand), cand
    assert E._static_cover(_SERDE_FILE)("integer `%d` as u64, expected struct Hints" % E.HEAP)


@pytest.mark.parametrize("num", ["1234567890123456789012345678", "5555555555555555555555555555"])
def test_decimal_pointer_rule_keeps_other_numbers(num):
    import recover_emulate as E
    assert not E._static_cover(_SERDE_FILE)("integer `%s` as u128, expected struct Hints" % num)


# --- emulation: a block counter stored word by word ----------------------------------------------
# docker 29.4.2 (CI precision run 44869664418): Go's runtime ChaCha8 RNG stores its block counter
# as ctr, ctr+1, ctr+2, ctr+3; ctr was 0x61636978 -> `xicayicazica{ica`.
@pytest.mark.parametrize("words,size", [((0x61636978, 1), 4), ((0x2d2d2d2d41424344, -1), 8)])
def test_ci_fp_counter_words_are_numbers(words, size):
    import recover_emulate as E
    start, step = words
    fmt = "<I" if size == 4 else "<Q"
    cand = b"".join(struct.pack(fmt, start + i * step) for i in range(4)).decode()
    assert E._static_cover(b"\0unrelated static text\0")(cand), cand


@pytest.mark.parametrize("cand", ["key1key2key3", "node-a.node-b.node-c", "AAAABBBBCCCC"])
def test_counter_rule_keeps_text(cand):
    import recover_emulate as E
    assert not E._static_cover(b"\0unrelated static text\0")(cand)
