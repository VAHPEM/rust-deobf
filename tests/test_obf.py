"""Recovery on author-written programs obfuscated with real crates (obf_src/).

These are not the hand-rolled benchmark ciphers but third-party obfuscation crates as a real
analyst meets them. goldberg applies code-flow obfuscation plus string/integer encryption; the
test asserts the encrypted strings come back across formats and profiles. Build with
obf_src/build_obf.sh; cases skip if a binary is absent.
"""
import json
from pathlib import Path

import pytest
from conftest import BUILD, ROOT

OBF = ROOT / "obf_src"
CRATES = [p.name for p in sorted(OBF.glob("*/")) if (p / "expected.json").is_file()]
FORMATS = [("elf", ""), ("pe", ".exe"), ("elf-arm64", "")]
PROFILES = ["release", "size-lto"]
_cache = {}


def _run(path):
    if path not in _cache:
        import recover
        _cache[path] = recover.run(path, stackstrings=False, literals=False, time_budget=300)
    return _cache[path]


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", CRATES)
def test_obf_strings(crate, fmt, ext, profile):
    path = BUILD / f"{crate}__{fmt}__{profile}__strip{ext}"
    if not path.is_file():
        pytest.skip(f"not built: {path.name}")
    want = set(json.loads((OBF / crate / "expected.json").read_text())["strings"])
    got = {x["string"] for x in _run(path)["decoded"]}
    missing = sorted(w for w in want if not any(w in g for g in got))
    assert not missing, missing


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", CRATES)
def test_obf_resolved_imports(crate, fmt, ext, profile):
    """Names a crate resolves at run time (GetProcAddress) that are not in the file (§81)."""
    want = json.loads((OBF / crate / "expected.json").read_text()).get("resolved_imports", {}).get(fmt)
    if not want:
        pytest.skip(f"{crate} resolves nothing by name on {fmt}")
    path = BUILD / f"{crate}__{fmt}__{profile}__strip{ext}"
    if not path.is_file():
        pytest.skip(f"not built: {path.name}")
    got = {r["name"] for r in _run(path).get("resolved_imports", []) if not r["in_file"]}
    assert set(want) <= got, (sorted(set(want) - got), sorted(got))


ARCH = {"elf": "x86_64", "pe": "x86_64", "elf-arm64": "aarch64"}


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", CRATES)
def test_obf_unpacked_stage2(crate, fmt, ext, profile):
    """A Rust-written packer (§83): the whole std program runs as the stub, RC4-decrypts the stage-2
    into fresh RWX memory (mmap / VirtualAlloc) and calls it. unpack_emulate must stop at that call
    (the OEP) and carve exactly the decrypted stage-2."""
    want = json.loads((OBF / crate / "expected.json").read_text()).get("stage2", {}).get(ARCH[fmt])
    if not want:
        pytest.skip(f"{crate} carries no packed stage-2")
    path = BUILD / f"{crate}__{fmt}__{profile}__strip{ext}"
    if not path.is_file():
        pytest.skip(f"not built: {path.name}")
    import unpack_emulate as U
    res = U.recover(path)
    # the stage-2 runs in FRESH memory, called (not jumped to) by the stub, so emulation goes on
    # past it (a hand-off into fresh memory is followed, as UPX's ELF decompressor needs); the
    # stop reason is whatever the program does next. What must hold: the OEP is the carved,
    # executed stage-2, byte for byte
    carved = [r for r in res["_regions"] if r["executed"]]
    assert carved, {k: res.get(k) for k in ("stopped", "error", "oep")}
    assert carved[0]["_bytes"][:len(want) // 2] == bytes.fromhex(want), \
        [r["_bytes"][:16].hex() for r in carved]
    assert res["oep"] == carved[0]["va"], (res["oep"], carved[0]["va"])
