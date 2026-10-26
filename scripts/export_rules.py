#!/usr/bin/env python3
"""export_rules.py - emit capa and YARA rules from what rust-deobf recovers.

rust-deobf lives in the Mandiant tooling ecosystem (FLOSS export already), and capa + YARA are the
two detection formats that ecosystem speaks. This turns rust-deobf's facts into both:

  * a STATIC family ruleset for the Rust obfuscation crates it targets (litcrypt / litcrypt2 /
    obfstr / cryptify / muddy / goldberg) -- the upstreamable artifact, runnable on any corpus; and
  * PER-BINARY rules grounded in what was actually recovered from one sample: the crate(s) detected
    in its metadata, the hash-obfuscated API imports resolved by recover_apihash (strong, exact
    number features), and the byte idiom of each recovered decoder routine with its key/immediates
    wildcarded (a YARA hex pattern that matches the cipher shape, not this build's key).

capa consumes YAML rules (anti-analysis/obfuscation namespace); YARA consumes `.yar` text. Neither
the `yara` nor a capa install is needed to GENERATE the rules -- they are plain text.

    python3 scripts/export_rules.py --static-only --yara crates.yar --capa capa_rules/
    python3 scripts/export_rules.py sample.bin --yara sample.yar --capa sample_capa/
    python3 scripts/export_rules.py sample.bin --json
    python3 scripts/export_rules.py --selftest

Exit codes: 0 rules written, 2 usage error, 3 unsupported input (not an ELF/PE/Mach-O LIEF reads).
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

EXIT_OK, EXIT_USAGE, EXIT_UNSUPPORTED = 0, 2, 3
CAPA_NS = "anti-analysis/obfuscation/string/rust"

# Known Rust obfuscation crates rust-deobf targets. `tokens` are ASCII substrings that survive into
# the binary (a crates.io registry path in a panic Location, a symbol, a crate-named section): a
# heuristic family signal, deliberately broad. `cipher` documents the construction.
CRATE_SIGS = {
    "litcrypt":  {"tokens": ["litcrypt"],  "cipher": "XOR, runtime key (lc! macro)",
                  "ref": "https://crates.io/crates/litcrypt"},
    "litcrypt2": {"tokens": ["litcrypt2", "litcrypt_"], "cipher": "XOR, stride-permuted key",
                  "ref": "https://crates.io/crates/litcrypt2"},
    "obfstr":    {"tokens": ["obfstr"],    "cipher": "inlined XOR+ADD (no runtime decoder call)",
                  "ref": "https://crates.io/crates/obfstr"},
    "cryptify":  {"tokens": ["cryptify"],  "cipher": "XOR, crate-default or CRYPTIFY_KEY env key",
                  "ref": "https://crates.io/crates/cryptify"},
    "muddy":     {"tokens": ["muddy"],     "cipher": "ChaCha20-Poly1305 AEAD",
                  "ref": "https://crates.io/crates/muddy"},
    "goldberg":  {"tokens": ["goldberg"],  "cipher": "code-flow + string/integer encryption",
                  "ref": "https://crates.io/crates/goldberg"},
}

_IDENT_RE = re.compile(r"[^a-z0-9]+")


def _slug(s: str) -> str:
    return _IDENT_RE.sub("_", s.lower()).strip("_")


# --------------------------------------------------------------------------------------------
# capa rule emitter. capa rules are YAML; we build the exact structure capa expects and emit it
# with a tiny, dependency-free writer (the feature tree is and/or nodes over leaf features).
# --------------------------------------------------------------------------------------------
def capa_rule(name: str, features: list, namespace: str = CAPA_NS, refs: list | None = None,
              description: str = "") -> dict:
    """A capa rule as a Python dict (file scope). `features` is the feature tree (a list under a
    top-level `and`)."""
    meta = {
        "name": name,
        "namespace": namespace,
        "authors": ["rust-deobf"],
        "scopes": {"static": "file", "dynamic": "file"},
    }
    if description:
        meta["description"] = description
    if refs:
        meta["references"] = list(refs)
    return {"rule": {"meta": meta, "features": features}}


def _yaml_scalar(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    s = str(v)
    # quote when YAML could misread it (leading special, contains :/#, regex slashes, etc.)
    if s == "" or s[0] in "!&*?@`%|>-{[#,\"'" or ": " in s or s.endswith(":") or " #" in s:
        return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return s


def _emit_features(node, indent: int) -> list[str]:
    """Emit a capa feature tree. A node is either {'and'/'or'/'not': [children]} or a leaf
    {'string'/'api'/'number'/'substring'/'count(...)': value, optional 'description': ...}."""
    pad = "  " * indent
    lines = []
    if isinstance(node, dict) and set(node) & {"and", "or", "not", "optional"}:
        (op, children), = ((k, v) for k, v in node.items() if k in ("and", "or", "not", "optional"))
        lines.append(f"{pad}- {op}:")
        for child in children:
            lines += _emit_features(child, indent + 1)
        return lines
    # leaf feature: {feature_key: value[, "description": ...]}
    desc = node.get("description") if isinstance(node, dict) else None
    feats = [(k, v) for k, v in node.items() if k != "description"]
    (key, val), = feats
    line = f"{pad}- {key}: {_yaml_scalar(val)}"
    if desc:
        line += f" = {desc}"
    lines.append(line)
    return lines


def render_capa(rule: dict) -> str:
    """Render one capa rule dict to YAML text (capa's schema and indentation)."""
    r = rule["rule"]
    meta = r["meta"]
    out = ["rule:", "  meta:"]
    out.append(f"    name: {_yaml_scalar(meta['name'])}")
    out.append(f"    namespace: {_yaml_scalar(meta['namespace'])}")
    if meta.get("description"):
        out.append(f"    description: {_yaml_scalar(meta['description'])}")
    out.append("    authors:")
    for a in meta["authors"]:
        out.append(f"      - {_yaml_scalar(a)}")
    out.append("    scopes:")
    out.append(f"      static: {meta['scopes']['static']}")
    out.append(f"      dynamic: {meta['scopes']['dynamic']}")
    if meta.get("references"):
        out.append("    references:")
        for ref in meta["references"]:
            out.append(f"      - {_yaml_scalar(ref)}")
    out.append("  features:")
    for line in _emit_features({"and": r["features"]}, 2):
        out.append(line)
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------------------
# YARA rule emitter.
# --------------------------------------------------------------------------------------------
def render_yara(name: str, meta: dict, strings: list[tuple[str, str]], condition: str) -> str:
    """One YARA rule. `strings` is [(id, body)] where body is a full YARA string spec
    (e.g. '"litcrypt" ascii nocase' or '{ 31 ?? 83 }'). `condition` references the ids."""
    out = [f"rule {name}", "{", "    meta:"]
    for k, v in meta.items():
        out.append(f'        {k} = {json.dumps(str(v))}')
    if strings:
        out.append("    strings:")
        for sid, body in strings:
            out.append(f"        {sid} = {body}")
    out.append("    condition:")
    out.append(f"        {condition}")
    out.append("}")
    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------------------------
# static family ruleset (no binary needed)
# --------------------------------------------------------------------------------------------
def crate_yara_rules() -> list[tuple[str, str]]:
    rules = []
    for crate, sig in CRATE_SIGS.items():
        strings = [(f"$t{i}", f'"{t}" ascii nocase') for i, t in enumerate(sig["tokens"])]
        meta = {"author": "rust-deobf", "crate": crate, "cipher": sig["cipher"],
                "reference": sig["ref"],
                "description": f"Rust string obfuscation crate {crate} ({sig['cipher']}) - heuristic"}
        rules.append((f"rust_obf_{_slug(crate)}",
                      render_yara(f"rust_obf_{_slug(crate)}", meta, strings, "any of them")))
    return rules


def crate_capa_rules() -> list[tuple[str, dict]]:
    out = []
    for crate, sig in CRATE_SIGS.items():
        feats = [{"or": [{"string": f"/{t}/i"} for t in sig["tokens"]]}]
        rule = capa_rule(
            f"obfuscate strings with {crate} (Rust)", feats, refs=[sig["ref"]],
            description=f"{crate}: {sig['cipher']}")
        out.append((f"obfuscate-strings-with-{_slug(crate)}-rust", rule))
    return out


# --------------------------------------------------------------------------------------------
# per-binary rules
# --------------------------------------------------------------------------------------------
def _decoder_idiom(path: Path, va: int, n: int = 24) -> str | None:
    """A wildcarded YARA hex pattern for the decoder at `va`: the instruction bytes with immediate
    operands replaced by `??`, so the rule matches the cipher's instruction shape across builds
    rather than this build's key. x86/x86-64 only (capstone exposes the immediate byte offset
    there); returns None otherwise or on any failure."""
    try:
        import recover_emulate
        from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
        img = recover_emulate.Image(path)
        if img.arm:
            return None
        off = va - img.text_va
        if off < 0 or off >= len(img.code):
            return None
        code = img.code[off:off + n + 16]
        md = Cs(CS_ARCH_X86, CS_MODE_32 if img.x32 else CS_MODE_64)
        md.detail = True
        out = []
        total = 0
        for insn in md.disasm(code, va):
            if total >= n:
                break
            raw = list(insn.bytes)
            enc = insn.encoding
            # wildcard the immediate and displacement bytes (the key / offsets vary per build)
            for start, size in ((getattr(enc, "imm_offset", 0), getattr(enc, "imm_size", 0)),
                                (getattr(enc, "disp_offset", 0), getattr(enc, "disp_size", 0))):
                for k in range(start, min(start + size, len(raw))):
                    raw[k] = None
            for b in raw:
                out.append("??" if b is None else f"{b:02x}")
            total += len(raw)
        if total < 6:
            return None
        return "{ " + " ".join(out[:n * 2]) + " }"
    except Exception:
        return None


def collect(path: Path) -> dict:
    """Run the fact extractors on one binary and return the facts the rules are built from."""
    import recover
    import recover_rust_meta
    import recover_apihash

    fmt, arch, imagebase = recover.detect(path)
    if fmt is None:
        raise _Unsupported(f"{path}: not an ELF/PE/Mach-O LIEF can parse")
    meta = {}
    try:
        meta = recover_rust_meta.recover(path)
    except Exception:
        meta = {}
    crates = set((meta.get("crates") or {}).keys())
    # crate detected if its name token is a substring of a found crate name or a panic path
    panic_blob = " ".join(s.get("file", "") for s in (meta.get("panic_sites") or []))
    present = []
    for crate, sig in CRATE_SIGS.items():
        if crate in crates or any(t in panic_blob for t in sig["tokens"]) or \
                any(any(t in c for t in sig["tokens"]) for c in crates):
            present.append(crate)

    decoded, decoders = [], []
    try:
        res = recover.run(path, emulate="never", literals=False, stackstrings=False, min_len=5)
        decoded = [x["string"] for x in res.get("decoded", [])]
        seen = set()
        for x in res.get("decoded", []):
            dv = x.get("decoder")
            if isinstance(dv, int) and dv and dv not in seen:
                seen.add(dv)
                decoders.append(dv)
    except Exception:
        pass

    apihash = []
    try:
        ah = recover_apihash.recover(path, recover_apihash.BUILTIN_EXPORTS)
        apihash = ah.get("resolved", [])
    except Exception:
        pass

    idioms = []
    for dv in decoders[:8]:
        hexpat = _decoder_idiom(path, dv)
        if hexpat:
            idioms.append({"va": dv, "pattern": hexpat})

    return {"file": str(path), "format": fmt, "arch": arch,
            "is_rust": bool(meta.get("is_rust")), "crates_present": present,
            "decoded_count": len(decoded), "apihash": apihash, "decoder_idioms": idioms}


class _Unsupported(Exception):
    pass


def binary_yara(facts: dict) -> list[tuple[str, str]]:
    rules = []
    base = _slug(Path(facts["file"]).name) or "sample"
    # a crate-family rule for each crate detected here (reuses the static token set)
    for crate in facts["crates_present"]:
        sig = CRATE_SIGS[crate]
        strings = [(f"$t{i}", f'"{t}" ascii nocase') for i, t in enumerate(sig["tokens"])]
        meta = {"author": "rust-deobf", "crate": crate, "cipher": sig["cipher"],
                "sample": Path(facts["file"]).name, "reference": sig["ref"]}
        rules.append((f"rust_obf_{base}_{_slug(crate)}",
                      render_yara(f"rust_obf_{base}_{_slug(crate)}", meta, strings, "any of them")))
    # a decoder-idiom rule: the cipher's instruction shape, key wildcarded
    if facts["decoder_idioms"]:
        strings = [(f"$d{i}", pat["pattern"]) for i, pat in enumerate(facts["decoder_idioms"])]
        meta = {"author": "rust-deobf", "sample": Path(facts["file"]).name,
                "description": "recovered Rust string-decoder instruction idiom (key wildcarded)",
                "decoders": len(strings)}
        rules.append((f"rust_decoder_idiom_{base}",
                      render_yara(f"rust_decoder_idiom_{base}", meta, strings, "any of them")))
    # apihash constants: exact 4-byte little-endian immediates of each resolved hash
    if facts["apihash"]:
        strings = []
        for i, h in enumerate(facts["apihash"][:40]):
            c = int(h["const"], 16) & 0xffffffff
            le = " ".join(f"{(c >> (8 * k)) & 0xff:02x}" for k in range(4))
            strings.append((f"$h{i}", f"{{ {le} }}  // {h['api']} ({h['algo']})"))
        meta = {"author": "rust-deobf", "sample": Path(facts["file"]).name,
                "description": "hash-obfuscated API import constants resolved by rust-deobf"}
        rules.append((f"rust_apihash_{base}",
                      render_yara(f"rust_apihash_{base}", meta, strings,
                                  f"{min(2, len(strings))} of them")))
    return rules


def binary_capa(facts: dict) -> list[tuple[str, dict]]:
    out = []
    name = Path(facts["file"]).name
    for crate in facts["crates_present"]:
        sig = CRATE_SIGS[crate]
        feats = [{"or": [{"string": f"/{t}/i"} for t in sig["tokens"]]}]
        out.append((f"obfuscate-strings-with-{_slug(crate)}-rust",
                    capa_rule(f"obfuscate strings with {crate} (Rust)", feats, refs=[sig["ref"]],
                              description=f"{crate}: {sig['cipher']}")))
    if facts["apihash"]:
        feats = [{"or": [{"number": h["const"], "description": f"{h['api']} ({h['algo']})"}
                         for h in facts["apihash"][:40]]}]
        out.append(("resolve-api-by-hash-rust",
                    capa_rule("resolve API functions by hash (Rust)", feats,
                              namespace="anti-analysis/obfuscation/api/rust",
                              description="hash-obfuscated import resolution resolved by rust-deobf")))
    return out


# --------------------------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------------------------
def write_yara(out_path: Path, rules: list[tuple[str, str]]) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    header = (f"// Generated by rust-deobf export_rules.py on {now}\n"
              "// Rust string-obfuscation detection (heuristic crate fingerprints + recovered "
              "idioms).\n\n")
    out_path.write_text(header + "\n".join(body for _, body in rules), encoding="utf-8")


def write_capa(out_dir: Path, rules: list[tuple[str, dict]]) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for fname, rule in rules:
        p = out_dir / f"{fname}.yml"
        p.write_text(render_capa(rule), encoding="utf-8")
        written.append(p)
    return written


def _selftest():
    # 1. static family ruleset for every known crate, both formats
    yr = crate_yara_rules()
    cr = crate_capa_rules()
    assert len(yr) == len(CRATE_SIGS) and len(cr) == len(CRATE_SIGS)
    all_yara = "\n".join(b for _, b in yr)
    for crate in CRATE_SIGS:
        assert f"rust_obf_{_slug(crate)}" in all_yara
    # YARA structural sanity: balanced braces, each rule has condition
    assert all_yara.count("{") == all_yara.count("}")
    assert all_yara.count("rule ") == len(CRATE_SIGS)
    assert all_yara.count("condition:") == len(CRATE_SIGS)

    # 2. capa YAML is valid and has the schema capa needs
    import yaml
    for fname, rule in cr:
        text = render_capa(rule)
        doc = yaml.safe_load(text)
        assert set(doc) == {"rule"}
        m = doc["rule"]["meta"]
        assert m["name"] and m["namespace"].startswith("anti-analysis/")
        assert m["scopes"] == {"static": "file", "dynamic": "file"}
        assert isinstance(doc["rule"]["features"], list) and doc["rule"]["features"]
        # the feature tree round-trips to an and/or structure with a string leaf
        top = doc["rule"]["features"][0]
        assert "and" in top and "or" in top["and"][0]
        assert any("string" in leaf for leaf in top["and"][0]["or"])

    # 3. per-binary rules from synthetic facts (no binary needed): crate + apihash + idiom
    facts = {"file": "sample.bin", "format": "PE", "arch": "x86_64", "is_rust": True,
             "crates_present": ["litcrypt", "muddy"], "decoded_count": 7,
             "apihash": [{"const": "0x726774c", "api": "LoadLibraryA", "algo": "block_api",
                          "seed": "0x0"}],
             "decoder_idioms": [{"va": 0x1200, "pattern": "{ 31 ?? 83 ?? ?? 48 }"}]}
    byr = binary_yara(facts)
    bcr = binary_capa(facts)
    bytext = "\n".join(b for _, b in byr)
    assert "rust_obf_sample_bin_litcrypt" in bytext and "rust_apihash_sample_bin" in bytext
    assert "rust_decoder_idiom_sample_bin" in bytext and "31 ?? 83" in bytext
    assert bytext.count("{") == bytext.count("}")
    names = {n for n, _ in bcr}
    assert "resolve-api-by-hash-rust" in names and "obfuscate-strings-with-litcrypt-rust" in names
    for _, rule in bcr:
        text = render_capa(rule)
        doc = yaml.safe_load(text)
        assert doc["rule"]["meta"]["name"]
    # the apihash capa rule carries the exact constant as a number feature (raw feature tree is a
    # top-level `or` of number leaves; render_capa wraps it in `and` only on emission)
    api_rule = dict(bcr)["resolve-api-by-hash-rust"]
    nums = api_rule["rule"]["features"][0]["or"]
    assert any(n["number"] == "0x726774c" for n in nums)
    # and it survives the YAML round-trip under the emitted top-level `and`. The number leaf carries
    # capa's `= description` comment, so the YAML scalar is "0x726774c = LoadLibraryA (block_api)";
    # capa parses the hex before the `=`.
    rendered = yaml.safe_load(render_capa(api_rule))
    leaves = rendered["rule"]["features"][0]["and"][0]["or"]
    assert any(str(leaf["number"]).startswith("0x726774c") for leaf in leaves)

    # 4. file writers round-trip
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        yp = Path(d) / "crates.yar"
        write_yara(yp, crate_yara_rules())
        assert yp.read_text().count("rule rust_obf_") == len(CRATE_SIGS)
        cdir = Path(d) / "capa"
        written = write_capa(cdir, crate_capa_rules())
        assert len(written) == len(CRATE_SIGS) and all(p.exists() for p in written)
        assert yaml.safe_load(written[0].read_text())["rule"]["meta"]["authors"] == ["rust-deobf"]
    print(f"selftest OK: {len(CRATE_SIGS)} crate YARA + capa rules (valid YAML), per-binary "
          "crate/apihash/decoder-idiom rules, file writers round-trip")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?", help="a binary to derive per-sample rules from")
    ap.add_argument("--static-only", action="store_true",
                    help="emit only the crate family ruleset (no binary needed)")
    ap.add_argument("--yara", metavar="OUT", help="write YARA rules to this .yar file")
    ap.add_argument("--capa", metavar="DIR", help="write capa rule YAML files into this directory")
    ap.add_argument("--json", action="store_true", help="print the recovered facts as JSON")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)

    if a.selftest:
        _selftest()
        return EXIT_OK

    yara_rules = list(crate_yara_rules())
    capa_rules = list(crate_capa_rules())
    facts = None
    if not a.static_only:
        if not a.binary:
            ap.error("give a binary, or use --static-only for just the crate family ruleset")
        path = Path(a.binary)
        if not path.is_file():
            ap.error(f"no such file: {path}")
        try:
            facts = collect(path)
        except _Unsupported as e:
            print(f"export_rules: unsupported input: {e}", file=sys.stderr)
            return EXIT_UNSUPPORTED
        yara_rules += binary_yara(facts)
        capa_rules += binary_capa(facts)

    if a.json:
        print(json.dumps({"facts": facts, "yara_rules": [n for n, _ in yara_rules],
                          "capa_rules": [n for n, _ in capa_rules]}, indent=2))
    if a.yara:
        write_yara(Path(a.yara), yara_rules)
        print(f"YARA: {len(yara_rules)} rule(s) -> {a.yara}")
    if a.capa:
        written = write_capa(Path(a.capa), capa_rules)
        print(f"capa: {len(written)} rule file(s) -> {a.capa}/")
    if not (a.json or a.yara or a.capa):
        print(f"{len(yara_rules)} YARA rule(s), {len(capa_rules)} capa rule(s) ready "
              "(pass --yara OUT.yar and/or --capa DIR to write them)")
        if facts:
            print(f"  binary: {facts['format']}/{facts['arch']}  rust={facts['is_rust']}  "
                  f"crates={facts['crates_present']}  decoded={facts['decoded_count']}  "
                  f"apihash={len(facts['apihash'])}  idioms={len(facts['decoder_idioms'])}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
