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
    payload = _rng(128).randbytes(128)     # seeded: a random payload must not make this flaky
    hit = E._base64_runs(b"tok:" + base64.b64encode(payload))
    assert hit and hit[0]["decoded_len"] == 128


def test_precision_on_benign_binary():
    res = E.recover(BENIGN)
    assert set(res) >= {"file_size", "embedded", "high_entropy", "base64", "counts"}
    # a normal Rust binary carries no embedded executable, packed blob, or base64 payload
    assert res["counts"] == {"embedded": 0, "high_entropy": 0, "base64": 0}, res["counts"]


def _rng(seed):
    import random
    return random.Random(seed)


def test_overlay_blob_at_eof_is_carved_whole(tmp_path):
    # the window loop stopped at len-_WIN-1 in strides of _STEP, so the last up-to-767 bytes were
    # never scanned: a blob flush with EOF came back truncated (wrong size and sha256)
    import hashlib
    for n in (1100, 1500, 3000):
        tail = _rng(n).randbytes(n)
        data = b"\x00" * 4096 + tail
        hot = E._high_entropy_regions(data)
        assert [(h["offset"], h["size"]) for h in hot] == [(4096, n)], (n, hot)
        assert hot[0]["sha256"] == hashlib.sha256(tail).hexdigest()
    # a whole file that is one random blob
    whole = _rng(7).randbytes(1100)
    assert [(h["offset"], h["size"]) for h in E._high_entropy_regions(whole)] == [(0, 1100)]
    # shorter than one window: nothing (and no crash)
    assert E._high_entropy_regions(_rng(8).randbytes(300)) == []


def test_macho_host_header_is_not_embedded(tmp_path):
    host = ROOT / "tests" / "fixtures" / "macho" / "litcrypt.arm64"
    if host.is_file():
        res = E.recover(host)
        assert not any(e["offset"] == 0 for e in res["embedded"]), res["embedded"][:2]
    # synthetic thin hosts, both byte orders, 64- and 32-bit
    for magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        p = tmp_path / "thin"
        p.write_bytes(magic + b"\x00" * 252)
        assert E.recover(p)["embedded"] == [], magic
    # a fat (universal) host: its own header and its slices are not embedded artifacts, but a
    # Mach-O carried elsewhere in it still is
    thin = b"\xcf\xfa\xed\xfe" + b"\x00" * 60
    fat = bytearray(0x4000)
    fat[0:8] = b"\xca\xfe\xba\xbe" + (2).to_bytes(4, "big")
    for k, off in enumerate((0x1000, 0x2000)):
        e = 8 + 20 * k
        fat[e + 8:e + 12] = off.to_bytes(4, "big")
        fat[e + 12:e + 16] = (0x400).to_bytes(4, "big")
        fat[off:off + len(thin)] = thin
    fat[0x3000:0x3000 + len(thin)] = thin                  # a genuinely embedded one
    p = tmp_path / "fat"
    p.write_bytes(bytes(fat))
    assert [(e["kind"], e["offset"]) for e in E.recover(p)["embedded"]] == [("macho64", 0x3000)]
    # fat_header_64 (0xcafebabf): 32-byte fat_arch_64 entries with an 8-byte offset
    fat64 = bytearray(0x3000)
    fat64[0:8] = b"\xca\xfe\xba\xbf" + (1).to_bytes(4, "big")
    fat64[8 + 8:8 + 16] = (0x1000).to_bytes(8, "big")
    fat64[0x1000:0x1000 + len(thin)] = thin
    p.write_bytes(bytes(fat64))
    assert E.recover(p)["embedded"] == []


def test_base64_glued_to_identifier_is_trimmed():
    payload = _rng(3).randbytes(96)
    p = base64.b64encode(payload)                          # 128 chars, unpadded
    assert len(E._base64_runs(b" " + p + b" ")) == 1
    for glue in (b"k", b"ke", b"key"):
        hit = E._base64_runs(glue + p + b" ")
        assert hit and hit[0]["offset"] == len(glue) and hit[0]["b64_len"] == len(p), (glue, hit)
        assert hit[0]["decoded_sha256"] == __import__("hashlib").sha256(payload).hexdigest()
        assert hit[0]["trimmed"] == "head"
    # a padded payload with a glued head: only the suffix can be right
    padded = base64.b64encode(_rng(4).randbytes(95))
    assert padded.endswith(b"=")
    hit = E._base64_runs(b"id" + padded + b" ")
    assert hit and hit[0]["offset"] == 2 and hit[0]["decoded_len"] == 95


def test_magic_hits_are_capped_and_reported(tmp_path):
    rec = b"PK\x03\x04" + b"\x00" * 12
    hits = E._find_magics(rec * 20000)
    assert len(hits) == E._MAX_HITS
    p = tmp_path / "flood"
    p.write_bytes(b"\x00" * 64 + rec * 20000 + b"\x7fELF\x02\x01\x01" + b"\x00" * 64)
    res = E.recover(p)
    assert res["embedded_capped"] == {"kinds": ["zip"], "max_per_kind": E._MAX_HITS}
    # a flood of one kind does not starve the others
    assert any(e["kind"] == "elf" for e in res["embedded"])
    assert "embedded_capped" not in E.recover(BENIGN)


def test_identifier_runs_are_not_base64_payloads():
    # concatenated identifiers match the base64 charset and, decoded (misaligned or not), look
    # binary; the class-change gate rejects them. Seen on benign_rust_std.x64 once glued runs are
    # trimmed to a 4-aligned length.
    words = (b"rorSizeLimitExhaustedErrorParseIntErrorEmptyInvalidDigitPosOverflowNegOverflow"
             b"NotAPowerOfTwoConnectionRefusedConnectionResetHostUnreachable")
    assert E._wordlike(words)
    assert E._base64_runs(b" " + words + b" ") == []
    assert E._wordlike(b"ZN5clang6driver9ToolChain31getTargetAndModeFromProgramNameERKNSt7")
    # real base64 of binary data is not word-like (seeded, many lengths)
    rng = _rng(11)
    for n in (48, 64, 96, 128, 300, 1000):
        assert not E._wordlike(base64.b64encode(rng.randbytes(n))), n
