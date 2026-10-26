"""capa + YARA rule export (export_rules.py).

The script's own --selftest (crate family ruleset, per-binary rules from synthetic facts, YAML
validity, file writers) runs via test_selftests.py. This adds end-to-end coverage of collect() on a
real committed binary and pins the capa YAML schema capa requires.
"""
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import export_rules as E  # noqa: E402

yaml = pytest.importorskip("yaml")

pytestmark = pytest.mark.filterwarnings("ignore::RuntimeWarning")


def test_static_ruleset_covers_every_crate():
    yr = {n for n, _ in E.crate_yara_rules()}
    cr = {n for n, _ in E.crate_capa_rules()}
    for crate in E.CRATE_SIGS:
        assert f"rust_obf_{E._slug(crate)}" in yr
        assert f"obfuscate-strings-with-{E._slug(crate)}-rust" in cr


def test_capa_rules_parse_and_match_schema():
    for _, rule in E.crate_capa_rules():
        doc = yaml.safe_load(E.render_capa(rule))
        meta = doc["rule"]["meta"]
        assert meta["name"] and meta["namespace"].startswith("anti-analysis/")
        assert meta["authors"] == ["rust-deobf"]
        assert meta["scopes"] == {"static": "file", "dynamic": "file"}
        assert isinstance(doc["rule"]["features"], list) and doc["rule"]["features"]


def test_collect_on_real_fixture_then_emit(tmp_path):
    """collect() runs on a committed binary without raising, and the rules it yields write out."""
    sample = ROOT / "tests" / "fixtures" / "macho" / "litcrypt.arm64"
    facts = E.collect(sample)
    assert facts["format"] == "MACHO" and facts["arch"] == "aarch64"
    assert "crates_present" in facts and "apihash" in facts and "decoder_idioms" in facts

    yara_rules = list(E.crate_yara_rules()) + E.binary_yara(facts)
    capa_rules = list(E.crate_capa_rules()) + E.binary_capa(facts)
    yp = tmp_path / "out.yar"
    E.write_yara(yp, yara_rules)
    text = yp.read_text()
    assert text.count("{") == text.count("}")          # balanced (hex strings + rule bodies)
    assert "rule rust_obf_litcrypt" in text
    written = E.write_capa(tmp_path / "capa", capa_rules)
    assert written and all(yaml.safe_load(p.read_text())["rule"]["meta"]["name"] for p in written)


def test_unsupported_input_raises(tmp_path):
    junk = tmp_path / "notabinary.txt"
    junk.write_text("hello, not a binary\n")
    with pytest.raises(E._Unsupported):
        E.collect(junk)
