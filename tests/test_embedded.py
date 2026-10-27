"""Embedded-artifact recovery (scripts/recover_embedded.py).

The --selftest (via test_selftests.py) is the positive: a synthetic data region carrying an embedded
ELF, a high-entropy blob and a base64 payload, all three recovered, with plain text not misflagged.
Here we pin the detectors directly and check precision on a real benign binary.
"""
import base64
import os
import sys

from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_embedded as E  # noqa: E402

BENIGN = ROOT / "tests" / "fixtures" / "vm" / "benign_rust_std.x64"


def test_selftest():
    E._selftest()


def test_embedded_magic_requires_valid_header():
    # a bare "MZ" with no PE pointer, and a bare \x7fELF with junk e_ident, are NOT artifacts
    assert E._find_magics(b"MZ" + b"\x00" * 128) == []
    assert E._find_magics(b"\x7fELF" + b"\xff\xff\xff" + b"\x00" * 64) == []
    # a valid embedded ELF e_ident is found
    good = b"pad" + b"\x7fELF\x02\x01\x01" + b"\x00" * 64
    hits = E._find_magics(good)
    assert any(h["kind"] == "elf" and h["offset"] == 3 for h in hits)


def test_high_entropy_isolates_random_not_text():
    assert E._high_entropy_regions(b"ordinary readable text. " * 300) == []
    blob = b"A" * 2048 + os.urandom(4096) + b"B" * 2048
    hot = E._high_entropy_regions(blob)
    assert hot and any(h["entropy"] > 7.5 for h in hot)
    # the hot region overlaps the random middle, not the padding
    h = max(hot, key=lambda r: r["entropy"])
    assert 1500 < h["offset"] < 6600


def test_base64_needs_binary_decode():
    # plain-text base64 (decodes to ASCII) is skipped; a random payload is kept
    ascii_b64 = base64.b64encode(b"the quick brown fox jumped over" * 3)
    assert E._base64_runs(b"x" + ascii_b64 + b"x") == []
    payload = os.urandom(128)
    hit = E._base64_runs(b"tok:" + base64.b64encode(payload))
    assert hit and hit[0]["decoded_len"] == 128


def test_precision_on_benign_binary():
    res = E.recover(BENIGN)
    assert set(res) >= {"file_size", "embedded", "high_entropy", "base64", "counts"}
    # a normal Rust binary carries no embedded executable, packed blob, or base64 payload
    assert res["counts"] == {"embedded": 0, "high_entropy": 0, "base64": 0}, res["counts"]
