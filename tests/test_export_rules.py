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


# --------------------------------------------------------------------------------------------
# Regressions: generated rules must actually COMPILE / LOAD in yara-python and capa, for any sample
# filename (non-ASCII, control chars, quotes/backslashes, very long), and --json keeps stdout clean.
# --------------------------------------------------------------------------------------------
import hashlib  # noqa: E402
import json  # noqa: E402
import subprocess  # noqa: E402

ADVERSARIAL_NAMES = [
    "sample.exe",
    "échantillon_日本語.exe",                         # non-ASCII (2- and 3-byte UTF-8)
    "a\x07b\x08c\x0cd\x00e\x7f\x1b.exe",              # control chars incl. \b \f NUL DEL ESC
    'q"uo\\te\\"d\\\\.exe',                           # quotes + backslashes (+ escaped-quote lookalike)
    "x" * 200 + ".exe",                               # 200-char name -> > 128-char identifier
    "é" * 150 + '"\\\n\t.bin',                        # long AND non-ASCII AND quote/backslash/newline
    "123-starts-with-digit.bin",
    "\U0001F600emoji.exe",                            # 4-byte UTF-8
    "..",                                             # slug is empty
]


def _facts(name, idioms=None, apihash=True):
    return {"file": "/x/" + name, "format": "PE", "arch": "x86_64", "is_rust": True,
            "crates_present": ["litcrypt", "muddy"], "decoded_count": 1,
            "apihash": ([{"const": "0x726774c", "api": "LoadLibraryA", "algo": "block_api",
                          "seed": "0x0"}] if apihash else []),
            "decoder_idioms": idioms or [{"va": 0x1200, "pattern": "{ 31 ?? 83 ?? ?? 48 }"}]}


def _ident_ok(name):
    return 0 < len(name) <= 128 and E._YARA_IDENT_RE.fullmatch(name) is not None


@pytest.mark.parametrize("name", ADVERSARIAL_NAMES, ids=range(len(ADVERSARIAL_NAMES)))
def test_yara_rules_compile_for_adversarial_filenames(name):
    yara = pytest.importorskip("yara")
    rules = list(E.crate_yara_rules()) + E.binary_yara(_facts(name))
    for rname, _ in rules:
        assert _ident_ok(rname), rname
    names = [n for n, _ in rules]
    assert len(names) == len(set(names)), "duplicate YARA rule names"
    src = "\n".join(b for _, b in rules)
    compiled = yara.compile(source=src)          # raises yara.SyntaxError on any bad escape/ident
    # the sample meta round-trips: YARA hands back exactly the filename's UTF-8 bytes
    matches = compiled.match(data=b"xx litcrypt yy")
    sample_meta = [m.meta.get("sample") for m in matches if "sample" in m.meta]
    assert sample_meta, [m.rule for m in matches]
    want = name.encode("utf-8")
    got = sample_meta[0]
    got_b = got if isinstance(got, bytes) else got.encode("utf-8", "surrogateescape")
    assert got_b.rstrip(b"\x00") == want.split(b"\x00")[0] or got_b == want


def test_yara_escape_unit():
    esc = E._yara_escape
    assert esc("plain text 123") == "plain text 123"
    assert esc('a"b') == 'a\\"b'
    assert esc("a\\b") == "a\\\\b"
    assert esc("é") == "\\xc3\\xa9"
    assert esc("\x07\b\f\n\t\x7f") == "\\x07\\x08\\x0c\\x0a\\x09\\x7f"
    # never emits a JSON-only escape YARA rejects
    for bad in ("\\u", "\\b", "\\f"):
        assert bad not in esc("é\b\f\u0007")
    # a lone surrogate (undecodable filename byte via os.fsdecode) is the original raw byte
    assert esc("a\udcffb") == "a\\xffb"


def test_long_names_truncated_with_hash_and_stay_distinct():
    a = E.binary_yara(_facts("x" * 200 + "A.exe"))
    b = E.binary_yara(_facts("x" * 200 + "B.exe"))
    na, nb = {n for n, _ in a}, {n for n, _ in b}
    assert all(_ident_ok(n) for n in na | nb)
    assert na.isdisjoint(nb), "long names sharing a prefix must not collide"
    h = hashlib.sha1(("x" * 200 + "A.exe").encode()).hexdigest()[:8]
    assert any(h in n for n in na)


def _capa_rules_module():
    return pytest.importorskip("capa.rules")


@pytest.mark.parametrize("name", ADVERSARIAL_NAMES, ids=range(len(ADVERSARIAL_NAMES)))
def test_capa_rules_load_as_one_ruleset(name, tmp_path):
    """Every emitted capa rule passes capa's own Rule.from_yaml, and the static + per-binary list
    builds ONE RuleSet (no duplicate rule names; `number` features only at a scope that allows
    them). Before the fix the apihash rule was refused (number at file scope) and the per-binary
    crate rules duplicated the static rule names."""
    R = _capa_rules_module()
    rules = list(E.crate_capa_rules()) + E.binary_capa(_facts(name))
    fnames = [f for f, _ in rules]
    assert len(fnames) == len(set(fnames)), "capa rule files would overwrite each other"
    loaded = [R.Rule.from_yaml(E.render_capa(rule)) for _, rule in rules]
    R.RuleSet(loaded)
    # and the on-disk directory loads the same way capa's CLI loads a rules dir
    written = E.write_capa(tmp_path / "capa", rules)
    assert len(written) == len(rules)
    R.RuleSet([R.Rule.from_yaml(p.read_text(encoding="utf-8")) for p in written])


def test_apihash_capa_rule_scope_allows_number():
    rule = dict(E.binary_capa(_facts("s.exe")))
    api = next(r for f, r in rule.items() if f.startswith("resolve-api-by-hash-rust"))
    assert api["rule"]["meta"]["scopes"] == {"static": "function", "dynamic": "unsupported"}


def test_capa_yaml_scalar_quotes_hostile_text():
    for s in ["a: b", "x #y", "é\x07\"\\", "- lead", "\n", "/re/i", "ok text"]:
        assert yaml.safe_load("k: " + E._yaml_scalar(s))["k"] == s


def _run_cli(args):
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "export_rules.py"), *args],
                          capture_output=True, text=True, timeout=300)


def test_json_stdout_is_pure_json_with_yara_and_capa(tmp_path):
    out = _run_cli(["--static-only", "--json", "--yara", str(tmp_path / "o.yar"),
                    "--capa", str(tmp_path / "capa")])
    assert out.returncode == 0, out.stderr
    doc = json.loads(out.stdout)                  # the whole stdout is one JSON document
    assert doc["facts"] is None and doc["yara_rules"] and doc["capa_rules"]
    assert "YARA:" in out.stderr and "capa:" in out.stderr
    assert (tmp_path / "o.yar").is_file() and any((tmp_path / "capa").iterdir())


def test_non_json_cli_still_reports_on_stdout(tmp_path):
    out = _run_cli(["--static-only", "--yara", str(tmp_path / "o.yar")])
    assert out.returncode == 0 and "YARA:" in out.stdout


def test_selftest_passes_without_pyyaml(tmp_path):
    """On a minimal install (no pyyaml) the selftest skips only the YAML-parse checks, with a note."""
    blocker = tmp_path / "noyaml"
    blocker.mkdir()
    (blocker / "sitecustomize.py").write_text(
        "import sys\n"
        "class _Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'yaml' or name.startswith('yaml.'):\n"
        "            raise ImportError('blocked for test')\n"
        "        return None\n"
        "sys.meta_path.insert(0, _Block())\n")
    env = dict(__import__("os").environ, PYTHONPATH=str(blocker))
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "export_rules.py"), "--selftest"],
                         capture_output=True, text=True, timeout=120, env=env)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "selftest OK" in out.stdout and "pyyaml" in out.stdout.lower()
