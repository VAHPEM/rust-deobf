"""Crypto-primitive identification (recover_crypto.py).

The --selftest (constants-among-noise, random-noise-clean, below-threshold) runs via
test_selftests.py. This pins scan() directly and, when a system crypto library is present, that a
real binary's primitives are detected.
"""
import struct
import sys
from pathlib import Path

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_crypto as C  # noqa: E402

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


def test_scan_byte_sequences_and_constant_sets():
    blob = bytearray(b"\x00" * 64)
    blob += C.AES_SBOX
    blob += b"expand 32-byte k"
    for c in (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x428a2f98):
        blob += struct.pack("<I", c)
    hits = C.scan(bytes(blob))
    algos = {h["algo"] for h in hits}
    assert {"AES", "ChaCha20/Salsa20", "SHA-256"} <= algos
    aes = [h for h in hits if h["algo"] == "AES"][0]
    assert aes["match"] == "byte-sequence" and aes["confidence"] == "high"


def test_below_threshold_not_flagged():
    # two SHA-256 constants is below the min of 4 -> not flagged
    blob = b"\x00" * 100 + struct.pack("<I", 0x6a09e667) + struct.pack("<I", 0xbb67ae85)
    assert "SHA-256" not in {h["algo"] for h in C.scan(blob)}


def test_random_noise_clean():
    import os
    assert C.scan(os.urandom(4096)) == []


@pytest.mark.parametrize("lib", [
    "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
    "/lib/x86_64-linux-gnu/libcrypto.so.3",
])
def test_real_crypto_library(lib):
    p = Path(lib)
    if not p.is_file():
        pytest.skip(f"{lib} not present")
    res = C.recover(p)
    # libcrypto embeds AES tables and SHA constants; at least AES + one SHA must be found
    assert "AES" in res["algorithms"]
    assert any(a.startswith("SHA") for a in res["algorithms"])
    # each hit that landed in a section got a VA
    assert any(h.get("va") is not None for h in res["hits"])


# ---- regressions (review B): shared init words, SHA-512 halves, AArch64 movz/movk

_MD5_SRC = r"""
typedef unsigned int u32;
#define F(x,y,z) (((x)&(y))|(~(x)&(z)))
#define R(a,b,c,d,k,s,t) a = b + (((a + F(b,c,d) + m[k] + t) << s) | ((a + F(b,c,d) + m[k] + t) >> (32-s)))
void md5_init(u32 st[4]) { st[0]=0x67452301; st[1]=0xefcdab89; st[2]=0x98badcfe; st[3]=0x10325476; }
void md5_round1(u32 st[4], const u32 m[16]) {
  u32 a=st[0],b=st[1],c=st[2],d=st[3];
  R(a,b,c,d,0,7,0xd76aa478); R(d,a,b,c,1,12,0xe8c7b756); R(c,d,a,b,2,17,0x242070db);
  R(b,c,d,a,3,22,0xc1bdceee); R(a,b,c,d,4,7,0xf57c0faf); R(d,a,b,c,5,12,0x4787c62a);
  st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; }
"""


def _md5_obj(tmp_path, target):
    import shutil
    import subprocess
    if not shutil.which("clang"):
        pytest.skip("clang not available")
    (tmp_path / "md5.c").write_text(_MD5_SRC)
    out = tmp_path / f"md5_{target.split('-')[0]}.o"
    r = subprocess.run(["clang", f"--target={target}", "-O2", "-c", str(tmp_path / "md5.c"), "-o", str(out)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        pytest.skip("clang failed: " + r.stderr[-200:])
    return out


@pytest.mark.parametrize("target", ["x86_64-linux-gnu", "aarch64-linux-gnu"])
def test_md5_not_reported_as_sha1(tmp_path, target):
    """MD5 and SHA-1 share four IV words; an MD5 implementation must be MD5 (high, via its round
    constants -- on AArch64 built by movz/movk) and not also 'SHA-1'."""
    res = C.recover(_md5_obj(tmp_path, target))
    by = {h["algo"]: h for h in res["hits"] if h["match"] == "constant-set"}
    assert "MD5" in by and by["MD5"]["confidence"] == "high", res["hits"]
    assert "SHA-1" not in by, res["hits"]


def test_sha512_iv_is_not_sha256():
    """The SHA-512/BLAKE2b IV's high halves ARE the SHA-256 IV; a 64-bit IV table is not SHA-256,
    and an IV alone (no round constant) is at most medium confidence."""
    iv = C._CONST_SIGS["SHA-512/BLAKE2b"]["init"]
    blob = b"\x00" * 32 + b"".join(struct.pack("<Q", v) for v in iv) + b"\x00" * 32
    by = {h["algo"]: h for h in C.scan(blob)}
    assert "SHA-256" not in by, by
    assert by["SHA-512/BLAKE2b"]["confidence"] == "medium"
    # with SHA-512 round constants as well it is high
    k = C._CONST_SIGS["SHA-512/BLAKE2b"]["round"][:2]
    blob2 = blob + b"".join(struct.pack("<Q", v) for v in k)
    by2 = {h["algo"]: h for h in C.scan(blob2)}
    assert by2["SHA-512/BLAKE2b"]["confidence"] == "high" and "SHA-256" not in by2


def test_init_only_is_never_high():
    blob = b"\x00" * 16 + b"".join(struct.pack("<I", v) for v in C._CONST_SIGS["SHA-256"]["init"])
    h = [x for x in C.scan(blob) if x["algo"] == "SHA-256"]
    assert h and h[0]["confidence"] == "medium"


def test_arm64_movz_movk_decoder():
    # movz w8,#0xa478 ; movk w8,#0xd76a,lsl#16  -> 0xd76aa478
    # movz x9,#0xc908 ; movk x9,#0xf3bc,lsl#16 ; movk x9,#0xe667,lsl#32 ; movk x9,#0x6a09,lsl#48
    def movz(sf, rd, imm, hw=0):
        return (sf << 31) | 0x52800000 | (hw << 21) | (imm << 5) | rd

    def movk(sf, rd, imm, hw):
        return (sf << 31) | 0x72800000 | (hw << 21) | (imm << 5) | rd
    words = [movz(0, 8, 0xa478), movk(0, 8, 0xd76a, 1),
             movz(1, 9, 0xc908), movk(1, 9, 0xf3bc, 1), movk(1, 9, 0xe667, 2), movk(1, 9, 0x6a09, 3),
             movz(0, 10, 0x1234)]                     # lone movz: not a split constant
    code = b"".join(struct.pack("<I", w) for w in words)
    got = {(v, w) for v, w, _ in C.arm64_immediates(code, 0x100)}
    assert (0xd76aa478, 4) in got and (0x6a09e667f3bcc908, 8) in got
    assert not any(v == 0x1234 for v, _ in got)
