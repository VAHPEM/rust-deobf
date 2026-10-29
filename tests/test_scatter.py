"""Recall and precision on the scatter suite and the size/LTO build profiles.

The canary benchmark (test_benchmark.py) prints five strings from main() under one profile.
These tests hold the pipeline to the shapes real programs have (bench_src/gen_projects.py):
eight indicator-shaped strings in struct fields, `match` arms, comparisons that are never
printed and a branch that never runs, built with the release profile and with
size-lto (opt-level="z", fat LTO, codegen-units=1, panic=abort) and speed-lto (opt-level=3, the
same LTO settings). They run the pipeline a user runs, `recover.run`, with default settings.
"""
import json
from pathlib import Path

import pytest
from conftest import BUILD, CANARIES, ROOT

_MAN = json.loads((ROOT / "bench_src" / "manifest.json").read_text())
SCATTER = _MAN["scatter"]
EXPECTED = _MAN["scatter_expected"]      # run-time values (litcrypt v1 mangles raw literals)
FORMATS = [("elf", ""), ("pe", ".exe"), ("elf-arm64", ""), ("elf-arm64gnu", "")]
PROFILES = ["release", "size-lto", "speed-lto"]
CRATES = ["xor_custom", "litcrypt", "litcrypt2", "obfstr", "cryptify"]
_cache = {}


def binary(name, fmt, ext, profile, strip="strip"):
    path = BUILD / f"{name}__{fmt}__{profile}__{strip}{ext}"
    if not path.is_file():
        pytest.skip(f"not built: {path.name}")
    return path


def run(path):
    if path not in _cache:
        import recover
        _cache[path] = recover.run(path, stackstrings=False, literals=False, time_budget=300)
    return _cache[path]


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", CRATES)
def test_scatter_recall(crate, fmt, ext, profile):
    # every string comes back whole: from a struct, a match arm, a comparison, a dead branch
    res = run(binary(f"scatter_{crate}", fmt, ext, profile))
    got = {x["string"] for x in res["decoded"]}
    want = set(EXPECTED[f"scatter_{crate}"])
    assert want <= got, sorted(want - got)


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", CRATES)
def test_scatter_precision(crate, fmt, ext, profile):
    # nothing but the eight strings is reported as decoded
    res = run(binary(f"scatter_{crate}", fmt, ext, profile))
    extra = {x["string"] for x in res["decoded"]} - set(EXPECTED[f"scatter_{crate}"])
    assert not extra, sorted(extra)


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_scatter_plaintext_has_nothing_decoded(fmt, ext, profile):
    # the same program with plain literals: they are static strings, not decoded ones
    res = run(binary("scatter_plaintext", fmt, ext, profile))
    assert [x["string"] for x in res["decoded"]] == []


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("fmt,ext", FORMATS)
def test_scatter_indicator_tags(fmt, ext, profile):
    # the indicator shapes are tagged, including a mutex name and a hive-less registry key
    res = run(binary("scatter_litcrypt2", fmt, ext, profile))
    tags = {x["string"]: x.get("tags", []) for x in res["decoded"]}
    want = {SCATTER[0]: "ip", SCATTER[1]: "path", SCATTER[2]: "mutex", SCATTER[3]: "url",
            SCATTER[6]: "registry"}
    for s, kind in want.items():
        assert kind in tags.get(s, []), (s, tags.get(s))


@pytest.mark.parametrize("profile", ["size-lto", "speed-lto"])
@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("crate", ["xor_custom", "add_custom", "sub_custom", "litcrypt", "litcrypt2",
                                   "obfstr", "tight_xor", "cryptify_default",
                                   "obfuse", "obfuse_aes", "obfuse_xor", "obfany"])
def test_canaries_under_lto_profiles(crate, fmt, ext, profile):
    # the original canary programs, rebuilt the way release malware is built
    res = run(binary(crate, fmt, ext, profile))
    got = {x["string"] for x in res["decoded"]}
    assert set(CANARIES) <= got, sorted(set(CANARIES) - got)


@pytest.fixture(scope="module", autouse=True)
def _dump_results():
    # RUST_DEOBF_DUMP=out.json: write every decoded string per binary (for the README table)
    yield
    import os
    out = os.environ.get("RUST_DEOBF_DUMP")
    if out:
        Path(out).write_text(json.dumps({p.name: sorted({x["string"] for x in r["decoded"]})
                                         for p, r in _cache.items()}, indent=1))
