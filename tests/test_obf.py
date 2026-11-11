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

