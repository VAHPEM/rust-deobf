"""Recall and precision on the benchmark built by scripts/build_all.sh (ARM64=1 for AArch64).

Tests for binaries that have not been built are skipped, so `pytest` works on a partial build.
The matrix is the README claim: release builds, stripped and not, ELF/PE x86-64 and AArch64.
"""
import pytest
from conftest import BUILD, CANARIES

FORMATS = [("elf", ""), ("pe", ".exe"), ("elf-arm64", "")]
STATIC = ["xor_custom", "add_custom", "sub_custom", "litcrypt", "litcrypt2"]
NO_STRINGS = ["plaintext", "muddy"]   # nothing obfuscated to recover / AEAD: out of scope statically


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
    assert recover_emulate.recover(path, [])["recovered_texts"] == []
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
