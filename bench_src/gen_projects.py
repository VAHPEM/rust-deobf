#!/usr/bin/env python3
"""Generate benign Rust benchmark programs for evaluating string-DEOBFUSCATION tools.

Each generated program does nothing but print a set of known 'canary' strings. The
canaries are the ground truth: a recovery tool (FLOSS, or ours) is scored on how many
of them it can reproduce from the compiled binary. One program per obfuscation crate,
plus a plaintext control and a hand-written XOR case, so we can measure each crate
against the same canaries.

This is eval-set construction for defensive RE, the same shape as Mandiant's own FLOSS
test corpus. No evasion research, no payloads: the programs just print strings.
"""
from __future__ import annotations
import json, hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "bench_src"

# Canaries: harmless, distinctive strings. Deterministic per index so results are stable.
CANARIES = [
    "canary::alpha::7f3c-config-endpoint",
    "canary::bravo::build-id-20261018",
    "canary::charlie::/opt/app/resources/data.bin",
    "canary::delta::feature-flag-telemetry-off",
    "canary::echo::schema-version-4",
]

def esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')

# Each entry: crate name -> (Cargo deps lines, extra top-of-file, how to wrap one literal,
# needs_build_rs, env_key_for_build)
def main_body(wrap):
    lines = ["fn main() {"]
    for c in CANARIES:
        lines.append(f'    println!("{{}}", {wrap(c)});')
    lines.append("}")
    return "\n".join(lines)

VARIANTS = {}

# 1. plaintext control
VARIANTS["plaintext"] = {
    "deps": [],
    "header": "",
    "body": main_body(lambda c: f'"{esc(c)}"'),
    "build_rs": None, "env": None,
}

# 2. hand-written XOR (represents custom, non-crate decryptors — the realistic malware case)
xor_key = bytes.fromhex(hashlib.sha256(b"rust-string-deobf-xor-key").digest().hex())[:16]
def xor_blob(c):
    data = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(c.encode()))
    return "[" + ",".join(str(b) for b in data) + "]"
xor_decls = "\n".join(
    f"static ENC_{i}: [u8; {len(c.encode())}] = {xor_blob(c)};" for i, c in enumerate(CANARIES)
)
xor_header = f"""static XOR_KEY: [u8; {len(xor_key)}] = [{",".join(str(b) for b in xor_key)}];
{xor_decls}
#[inline(never)]
fn dex(enc: &[u8]) -> String {{
    let mut out = Vec::with_capacity(enc.len());
    for (i, b) in enc.iter().enumerate() {{ out.push(b ^ XOR_KEY[i % XOR_KEY.len()]); }}
    String::from_utf8(out).unwrap()
}}"""
xor_lines = ["fn main() {"]
for i in range(len(CANARIES)):
    xor_lines.append(f"    println!(\"{{}}\", dex(&ENC_{i}));")
xor_lines.append("}")
VARIANTS["xor_custom"] = {
    "deps": [], "header": xor_header, "body": "\n".join(xor_lines),
    "build_rs": None, "env": None,
}

# 2b. hand-written ADD/SUB ciphers (obfstr itself uses ADD; show we generalise beyond XOR)
for scheme, opname in (("add_custom", "sub"), ("sub_custom", "add")):
    # decode op is the inverse of the encode op
    key2 = bytes(bytearray((hashlib.sha256((scheme).encode()).digest())))[:16]
    def enc_blob(c, key2=key2, scheme=scheme):
        bs = c.encode()
        if scheme == "add_custom":   # cipher = plain + key ; decode = cipher - key
            data = bytes((bs[i] + key2[i % len(key2)]) & 0xff for i in range(len(bs)))
        else:                        # cipher = plain - key ; decode = cipher + key
            data = bytes((bs[i] - key2[i % len(key2)]) & 0xff for i in range(len(bs)))
        return "[" + ",".join(str(b) for b in data) + "]"
    decls = "\n".join(f"static ENC_{i}: [u8; {len(c.encode())}] = {enc_blob(c)};" for i, c in enumerate(CANARIES))
    op = "wrapping_sub" if scheme == "add_custom" else "wrapping_add"
    header = f"""static DKEY: [u8; {len(key2)}] = [{",".join(str(b) for b in key2)}];
{decls}
#[inline(never)]
fn dec(enc: &[u8]) -> String {{
    let mut out = Vec::with_capacity(enc.len());
    for (i, b) in enc.iter().enumerate() {{ out.push(b.{op}(DKEY[i % DKEY.len()])); }}
    String::from_utf8(out).unwrap()
}}"""
    lines = ["fn main() {"] + [f"    println!(\"{{}}\", dec(&ENC_{i}));" for i in range(len(CANARIES))] + ["}"]
    VARIANTS[scheme] = {"deps": [], "header": header, "body": "\n".join(lines), "build_rs": None, "env": None}

# 3. obfstr (XOR, compile-time)
VARIANTS["obfstr"] = {
    "deps": ['obfstr = "0.4"'],
    "header": "use obfstr::obfstr;",
    "body": main_body(lambda c: f'obfstr!("{esc(c)}")'),
    "build_rs": None, "env": None,
}

# 4. litcrypt (XOR, env key at compile time)
lit_lines = ["use_litcrypt!();", "fn main() {"]
for c in CANARIES:
    lit_lines.append(f'    println!("{{}}", lc!("{esc(c)}"));')
lit_lines.append("}")
VARIANTS["litcrypt"] = {
    "deps": ['litcrypt = "0.4"'],
    "header": "#[macro_use]\nextern crate litcrypt;",
    "body": "\n".join(lit_lines),
    "build_rs": None, "env": ("LITCRYPT_ENCRYPT_KEY", "benchmark-fixed-key-do-not-reuse"),
}

# 5. cryptify (compile-time, env key optional)
VARIANTS["cryptify"] = {
    "deps": ['cryptify = "3"'],
    "header": "",
    "body": main_body(lambda c: f'cryptify::encrypt_string!("{esc(c)}")'),
    "build_rs": None, "env": ("CRYPTIFY_KEY", "benchmark-fixed-key"),
}

# 5b. cryptify with its default key: no CRYPTIFY_KEY at build time, which is also what makes
#     the program print its strings when run without the variable (cryptify reads the key at
#     runtime from the same env var, falling back to the same default)
VARIANTS["cryptify_default"] = {
    "deps": ['cryptify = "3"'],
    "header": "",
    "body": main_body(lambda c: f'cryptify::encrypt_string!("{esc(c)}")'),
    "build_rs": None, "env": None,
}

# 6. muddy (ChaCha20-Poly1305 AEAD, embedded key)
VARIANTS["muddy"] = {
    "deps": ['muddy = "0.3"'],
    "header": "use muddy::muddy;",
    "body": main_body(lambda c: f'muddy!("{esc(c)}")'),
    "build_rs": None, "env": None,
}


# 4b. litcrypt2 (maintained fork of litcrypt, same lc! XOR idiom)
_lit2 = ["use_litcrypt!();", "fn main() {"] + [f'    println!("{{}}", lc!("{esc(c)}"));' for c in CANARIES] + ["}"]
VARIANTS["litcrypt2"] = {
    "deps": ['litcrypt2 = "0.1"'],
    "header": "extern crate alloc;\n#[macro_use]\nextern crate litcrypt2;",
    "body": "\n".join(_lit2),
    "build_rs": None, "env": ("LITCRYPT_ENCRYPT_KEY", "benchmark-fixed-key-2"),
}

manifest = {"canaries": CANARIES, "variants": {}}
for name, v in VARIANTS.items():
    d = SRC / name
    (d / "src").mkdir(parents=True, exist_ok=True)
    cargo = [f'[package]', f'name = "{name}"', 'version = "0.1.0"', 'edition = "2021"', "", "[dependencies]"]
    cargo += v["deps"]
    cargo += ["", "[profile.release]", "strip = false", "opt-level = 3"]
    (d / "Cargo.toml").write_text("\n".join(cargo) + "\n")
    src = (v["header"] + "\n\n" + v["body"] + "\n") if v["header"] else (v["body"] + "\n")
    (d / "src" / "main.rs").write_text(src)
    if v["build_rs"]:
        (d / "build.rs").write_text(v["build_rs"])
    manifest["variants"][name] = {
        "crate": (v["deps"][0] if v["deps"] else None),
        "env": v["env"],
        "cipher": {"plaintext":"none","xor_custom":"xor","add_custom":"add","sub_custom":"sub",
                   "obfstr":"xor","litcrypt":"xor","litcrypt2":"xor",
                   "cryptify":"xor-ish","cryptify_default":"xor-ish","muddy":"chacha20poly1305"}.get(name,"?"),
    }
(SRC / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"generated {len(VARIANTS)} projects:", ", ".join(VARIANTS))
print(f"{len(CANARIES)} canaries each")
