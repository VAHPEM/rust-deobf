"""Recall and precision on the benchmark built by scripts/build_all.sh (ARM64=1 for AArch64).

Tests for binaries that have not been built are skipped, so `pytest` works on a partial build.
The matrix is the README claim: release builds, stripped and not, ELF/PE x86-64 and AArch64.
"""
import pytest
from conftest import BUILD, CANARIES

FORMATS = [("elf", ""), ("pe", ".exe"), ("elf-arm64", "")]
STATIC = ["xor_custom", "add_custom", "sub_custom", "litcrypt", "litcrypt2"]
NO_STRINGS = ["plaintext", "muddy"]   # nothing obfuscated / AEAD: no static decoder to read


def binary(crate, fmt, ext, strip, profile="release"):
    path = BUILD / f"{crate}__{fmt}__{profile}__{strip}{ext}"
    if not path.is_file():
        pytest.skip(f"not built: {path.name}")
    return path


def static_recover(path, fmt):
    import recover_arm64
    import recover_callsite
    return (recover_arm64 if fmt == "elf-arm64" else recover_callsite).recover(path, CANARIES)


@pytest.mark.parametrize("strip", ["nostrip", "strip"])
@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", STATIC)
def test_static_recall(crate, fmt, ext, strip):
    r = static_recover(binary(crate, fmt, ext, strip), fmt)
    assert r["recall"] == 5, r.get("recovered")
    # every recovered string says where it came from
    assert all({"decoder", "call", "blob"} <= set(x) for x in r["records"])


@pytest.mark.parametrize("strip", ["nostrip", "strip"])
@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_obfstr_emulation_without_canaries(fmt, ext, strip):
    import recover_emulate
    r = recover_emulate.recover(binary("obfstr", fmt, ext, strip), [])
    texts = r["recovered_texts"]
    assert all(any(c in t for t in texts) for c in CANARIES), texts


@pytest.mark.parametrize("strip", ["nostrip", "strip"])
@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_tight_strings_by_emulation(fmt, ext, strip):
    # stack buffer decoded in place by a (vectorised) loop: exact strings, nothing else
    import recover_emulate
    r = recover_emulate.recover(binary("tight_xor", fmt, ext, strip), [])
    assert sorted(r["recovered_texts"]) == sorted(CANARIES), r["recovered_texts"]


@pytest.mark.parametrize("strip", ["nostrip", "strip"])
@pytest.mark.parametrize("fmt,ext", [("elf", ""), ("pe", ".exe")])
def test_obfstr_exact_on_x86(fmt, ext, strip):
    import recover_emulate
    r = recover_emulate.recover(binary("obfstr", fmt, ext, strip), [])
    assert sorted(r["recovered_texts"]) == sorted(CANARIES), r["recovered_texts"]


# 2026 crates. obfuse (default = polymorphic inline XOR/ADD/SUB/ROT layers in a flattened state
# machine, random keys every build), obfuse_aes (AES-256-GCM ObfuseStr), obfuse_xor (XOR through
# MBA expressions), obfany (obfstr fork: obfstr!/obfwide!/obfnum!/obfstmt!). No static decoder to
# read in any of them; the pipeline (emulation) must return the five canaries exactly -- for
# obfuse_aes that includes cutting the GCM tag left after the in-place decrypt.
EMULATED_2026 = ["obfuse", "obfuse_aes", "obfuse_xor", "obfany"]


@pytest.mark.parametrize("strip", ["nostrip", "strip"])
@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", EMULATED_2026)
def test_2026_crates_by_emulation(crate, fmt, ext, strip):
    import recover
    res = recover.run(binary(crate, fmt, ext, strip), stackstrings=False, literals=False,
                      time_budget=300)
    got = {x["string"] for x in res["decoded"]}
    assert set(CANARIES) <= got, sorted(set(CANARIES) - got)
    assert not got - set(CANARIES), sorted(got - set(CANARIES))


@pytest.mark.parametrize("strip", ["nostrip", "strip"])
@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_cryptify_default_key(fmt, ext, strip):
    import recover_cryptify
    r = recover_cryptify.recover(binary("cryptify_default", fmt, ext, strip), CANARIES)
    assert r["recall"] == 5, r


@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_cryptify_custom_key_is_reported(fmt, ext):
    import recover_cryptify
    r = recover_cryptify.recover(binary("cryptify", fmt, ext, "strip"), CANARIES)
    assert r["cryptify"] and r["recall"] == 0 and "custom CRYPTIFY_KEY" in r["note"]


@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", NO_STRINGS)
def test_no_false_positives(crate, fmt, ext):
    import recover_cryptify
    import recover_emulate
    path = binary(crate, fmt, ext, "strip")
    assert static_recover(path, fmt)["recovered_texts"] == []
    emulated = recover_emulate.recover(path, [])["recovered_texts"]
    if crate == "muddy":
        # emulation runs muddy's ChaCha20-Poly1305 decrypt: the canaries, and nothing else
        assert sorted(emulated) == sorted(CANARIES), emulated
    else:
        assert emulated == []
    assert recover_cryptify.recover(path)["recovered_texts"] == []


@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_rust_metadata(fmt, ext):
    import recover_rust_meta
    r = recover_rust_meta.recover(binary("litcrypt", fmt, ext, "strip"))
    assert r["is_rust"]
    assert r["own_source_files"] == ["src/main.rs"]
    assert r["rust_release"] is not None, r["rustc_commit"]


@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_floss_document(fmt, ext, tmp_path):
    import json
    import recover
    import floss_export
    path = binary("litcrypt", fmt, ext, "strip")
    res = recover.run(path, emulate="never")
    doc = floss_export.build_document(path, res["decoded"], res["stack"], min_length=6)
    json.dumps(doc)
    decoded = {d["string"] for d in doc["strings"]["decoded_strings"]}
    assert set(CANARIES) <= decoded
    assert all(d["decoding_routine"] and d["decoded_at"] for d in doc["strings"]["decoded_strings"])


@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_rust_literals(fmt, ext):
    # plain &str literals split out of the packed string section at their exact length
    import recover_rust_strings
    r = recover_rust_strings.recover(binary("plaintext", fmt, ext, "strip"), min_len=4)
    lits = {x["string"] for x in r["strings"]}
    assert {c + "\n" for c in CANARIES} <= lits                     # println!("{}", "...")
    assert {"permission denied", "connection refused"} <= lits      # io::ErrorKind lookup table
    assert "memory allocation of " in lits                          # format_args! template piece
    assert not any(x.startswith("& is not a char boundary") for x in lits)  # no glued length byte
    raw = binary("plaintext", fmt, ext, "strip").read_bytes()
    assert all(raw[x["offset"]:x["offset"] + x["length"]].decode() == x["string"] for x in r["strings"])


@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", STATIC + ["obfstr", "cryptify_default", "muddy"] + EMULATED_2026)
def test_literals_do_not_leak_obfuscated_canaries(crate, fmt, ext):
    import recover_rust_strings
    r = recover_rust_strings.recover(binary(crate, fmt, ext, "strip"), min_len=4)
    assert not any(c in x["string"] for c in CANARIES for x in r["strings"] + r["missed"])


@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_linear_disassembly_covers_text(fmt, ext):
    # capstone stops at the first undecodable word (AArch64 literal pools): every recoverer
    # must see the whole of .text, not the first two thirds
    import lief
    from capstone import Cs, CS_ARCH_ARM64, CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN
    from disasm import linear
    b = lief.parse(str(binary("plaintext", fmt, ext, "strip")))
    text = next(s for s in b.sections if s.name == ".text")
    code = bytes(text.content)
    md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN) if fmt == "elf-arm64" else Cs(CS_ARCH_X86, CS_MODE_64)
    last = None
    for last in linear(md, code, text.virtual_address):
        pass
    assert last.address + last.size >= text.virtual_address + len(code) - 16
