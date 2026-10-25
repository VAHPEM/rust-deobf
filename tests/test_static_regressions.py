"""Regression tests for the static-recovery fixes (Oct 2026 review).

Two kinds: pure-Python unit tests for the metadata parsers (regex, semver, git deps, C++ vs Rust
symbols, the Location loop bound, PE COFF symbol addressing), and behavioural tests on the small
committed fixtures under tests/fixtures/static/ (each benign, decoding three canary strings; built
by that directory's build.sh). Nothing is executed natively -- the binaries are only analysed.
"""
import struct
import sys

import lief
import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_callsite as RC
import recover_arm64 as RA
import recover_rust_meta as M
import gen_runtime_sigs as G

FIX = ROOT / "tests" / "fixtures" / "static"
CANARIES = ["configuration-endpoint-alpha", "telemetry-settings-path-bravo", "resource-data-file-charlie"]


# --- recover_callsite / recover_arm64 ---------------------------------------------------------

def test_short_key_does_not_crash():
    # the key sits in a 4-byte section at its end; read_va comes back short and key[k % kl] used to
    # raise IndexError and take the whole recover() down. It must return cleanly instead.
    f = FIX / "shortkey"
    if not f.is_file():
        pytest.skip("fixture missing")
    r = RC.recover(f, [])              # must not raise
    assert isinstance(r.get("records", []), list)


def test_slice_length_through_r9_recovers_like_rcx():
    # identical programs; the length slot is filled from r9 in one and rcx in the other. The
    # `r9`->`e9` bug recovered 0/3 from the r9 build; both must now recover all three canaries.
    for name in ("slice_r9", "slice_rcx"):
        f = FIX / name
        if not f.is_file():
            pytest.skip("fixture missing")
        got = {x["string"] for x in RC.recover(f, [])["records"]}
        assert all(c in got for c in CANARIES), f"{name}: recovered {got}"


def test_arm64_zero_key_is_not_a_decoder():
    # a 16-byte all-zero "key" leaves plaintext in place; the ARM path used to report the plain
    # rodata strings as decoded. With the zero-key filter it must report none of them.
    f = FIX / "a64_zerokey"
    if not f.is_file():
        pytest.skip("fixture missing")
    got = {x["string"] for x in RA.recover(f, [])["records"]}
    assert not (got & set(CANARIES)), f"zero-key plaintext reported as decoded: {got}"


# --- recover_rust_meta parsers --------------------------------------------------------------

def _one_location(path_bytes, line=10, col=5):
    base = 0x1000
    blob = bytearray(path_bytes + b"\x00")
    blob += b"\x00" * ((8 - len(blob) % 8) % 8)
    blob += struct.pack("<QQII", base, len(path_bytes), line, col)
    secs = [(base, bytes(blob))]
    src = M.find_source_paths(secs)
    return M.find_location_structs(secs, 8, src)


@pytest.mark.parametrize("path", [
    rb"C:\Users\JohnDoe\proj\src\de.rs",
    rb"C:\Users\John Doe\proj\src\de.rs",                        # a space in the path
    "C:\\Users\\Ph\u1ea1m\\proj\\src\\de.rs".encode("utf-8"),   # non-ASCII (UTF-8)
    rb"/home/u/my~proj/src/main.rs",                            # a '~'
])
def test_panic_location_survives_space_and_non_ascii_paths(path):
    locs = _one_location(path)
    assert len(locs) == 1 and locs[0][0] == path.decode("utf-8")


@pytest.mark.parametrize("ver", ["1.0.0", "1.0.0-rc.1", "0.11.0+wasi-snap", "1.0.0-rc.1+build.5"])
def test_cargo_semver_with_prerelease_and_build(ver):
    m = M.RE_CARGO.search(f"/u/.cargo/registry/src/idx/foo-{ver}/src/lib.rs")
    assert m and m.group("crate") == "foo" and m.group("ver") == ver


def test_git_dependency_is_a_crate_not_own_code():
    p = "/u/.cargo/git/checkouts/evilcrate-1a2b3c4d5e6f7a8b/0123abc/src/beacon.rs"
    crates, _ = M.fingerprint_crates([p], "", strong_rust=True)
    assert "evilcrate" in crates
    assert M.RE_CARGO_GIT.search(p), "git-checkout path must be recognised as a dependency"


def test_cpp_symbols_are_not_mistaken_for_rust():
    # _ZN... is Itanium C++ mangling too; only a legacy Rust symbol carries the 17h<hex>E hash
    assert not M.RE_RUST_HASH.search("_ZN3std6vectorIiEC1Ev")                 # C++
    assert M.RE_RUST_HASH.search("_ZN4core3fmt9Formatter3pad17h0123456789abcdefE")  # Rust legacy


def test_location_scan_bound_does_not_overrun():
    # a record whose line/col run just past the section end must not raise struct.error
    base = 0x1000
    path = b"src/main.rs\x00"
    body = bytearray(path)
    body += b"\x00" * ((8 - len(body) % 8) % 8)
    strlen = len(path) - 1
    body += struct.pack("<QQ", base, strlen)        # ptr, len ... but omit the final line/col bytes
    body += b"\x01\x00\x00"                          # a truncated line field at the very end
    M.find_location_structs([(base, bytes(body))], 8, M.find_source_paths([(base, bytes(body))]))


# --- PE COFF symbol addressing (gen_runtime_sigs.sym_va) ------------------------------------

def test_pe_coff_symbol_value_is_section_relative():
    pe = ROOT / "tests" / "fixtures" / "vm" / "rustcloak_vm_pe.exe"
    if not pe.is_file():
        pytest.skip("PE fixture missing")
    b = lief.parse(str(pe))
    text = next(s for s in b.sections if s.name == ".text")
    sym = next((s for s in b.symbols if getattr(s, "is_function", False)
                and 1 <= getattr(s, "section_idx", 0) <= len(b.sections)
                and b.sections[s.section_idx - 1].name == ".text"), None)
    assert sym is not None
    va = G.sym_va(b, sym)
    # the RVA must be text.va + the section-relative value, i.e. inside .text, not the bare value
    assert va == text.virtual_address + sym.value
    assert text.virtual_address <= va < text.virtual_address + len(bytes(text.content))
    # stripped-or-not, PE function starts come from .pdata + any symbols; must be non-empty here
    assert len(G.function_starts(b)) > 10


# --- recover_stackstrings ARM64 (movk packing + stale registers) ----------------------------

def test_arm64_stack_string_uses_movk_and_drops_stale_regs():
    import recover_stackstrings as SS
    f = FIX / "a64_stack"
    if not f.is_file():
        pytest.skip("fixture missing")
    got = [x["string"] for x in SS.recover(f).get("records", [])]
    # "hello world!" is built with mov+movk; ignoring movk lost its high bytes
    assert any("hello world" in s for s in got), got
    # a register loaded by ldrb after a mov #imm must not keep the stale immediate (a fake string)
    assert not any("telemetry-config" in s for s in got), got


# --- ioc_tags false positives ---------------------------------------------------------------

def test_ioc_tags_rejects_version_and_crate_at_version():
    from recover_callsite import ioc_tags
    assert ioc_tags("serde@1.0.197") == []            # crate@version, not an email
    assert ioc_tags("1.2.3.4.5") == []                # five dotted numbers, not an IP
    assert ioc_tags("10.66.12.7:8443") == ["ip"]      # a real IP:port still tags
    assert "email" in ioc_tags("agent@evil.example")  # a real email still tags


# --- recover_apihash (block_api scheme, wide NUL) -------------------------------------------

def test_apihash_block_api_and_wide_nul():
    import recover_apihash as A
    # the Metasploit / Cobalt Strike block_api hash (module+function ror13), the single most common
    # real scheme, must be modelled: kernel32.dll!LoadLibraryA = 0x0726774C
    assert A.block_api_hash("LoadLibraryA", "kernel32.dll") == 0x0726774C
    table, _all = A.build_table(A.BUILTIN_EXPORTS)
    assert table.get(0x0726774C) and table[0x0726774C][2] == "LoadLibraryA"
    # a wide (UTF-16) name variant must be NUL-terminated with TWO bytes, not one
    assert any(v.endswith(b"\x00\x00") for v in A.name_variants("LoadLibraryA")
               if b"\x00" in v[:-2] or len(v) > len("LoadLibraryA") + 1)


# --- recover_artifacts indicator extraction -------------------------------------------------

def test_artifacts_extract_real_paths_bare_ip_and_hiveless_registry():
    import recover_artifacts as A
    art = A.extract([r"C:\ProgramData\NorthwindSvc\state.db", "10.66.12.7",
                     "Software\\Northwind\\Agent\\Settings", "evil-c2.example.com"])
    assert r"C:\ProgramData\NorthwindSvc\state.db" in art["paths"]   # single-backslash path
    assert "10.66.12.7" in art["endpoints"]                         # bare IP no longer dropped
    assert "Software\\Northwind\\Agent\\Settings" in art["registry"]  # hive-less registry key
    assert "state.db" not in art["domains"]                         # a filename is not a domain
    assert "evil-c2.example.com" in art["domains"]                  # a real domain still tags


# --- recover_rust_strings: 32-bit width and Mach-O chained fixups ---------------------------

def test_i386_literals_recovered_with_4_byte_pointers():
    import recover_rust_strings as L
    f = FIX / "i386_literals"
    if not f.is_file():
        pytest.skip("fixture missing")
    strs = {x["string"] for x in L.recover(f).get("strings", [])}
    # an &str (ptr,len) table is 4+4 bytes on i386; read as 8+8 it found nothing
    assert {"alpha-literal-one", "bravo-literal-two"} <= strs, strs


@pytest.mark.parametrize("name", ["macho_classic.dylib", "macho_chained.dylib"])
def test_macho_literals_recovered_classic_and_chained(name):
    import recover_rust_strings as L
    f = FIX / name
    if not f.is_file():
        pytest.skip("fixture missing")
    strs = {x["string"] for x in L.recover(f).get("strings", [])}
    # a chained-fixup pointer is an encoded fixup, not the address; decoding it recovers BOTH
    # literals (only one came through before, and none in an executable with a non-zero base)
    assert {"alpha-literal-one", "bravo-literal-two"} <= strs, (name, strs)
