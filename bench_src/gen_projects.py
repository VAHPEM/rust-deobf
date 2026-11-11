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

# 2c. tight string: the ciphertext is built on the stack from immediates and decoded in place
#     by a short loop inside the caller -- no decoder function, nothing in .rodata (FLOSS calls
#     these "tight strings"). black_box keeps rustc from folding the decode at compile time.
tight_key = hashlib.sha256(b"tight-string-key").digest()[:4]
tight_fns = []
for i, c in enumerate(CANARIES):
    enc = bytes(b ^ tight_key[k % 4] for k, b in enumerate(c.encode()))
    tight_fns.append(f"""#[inline(never)]
fn tight_{i}() -> String {{
    let mut buf: [u8; {len(enc)}] = [{",".join(str(b) for b in enc)}];
    let key: [u8; 4] = std::hint::black_box([{",".join(str(b) for b in tight_key)}]);
    for (k, b) in buf.iter_mut().enumerate() {{ *b ^= key[k % 4]; }}
    String::from_utf8_lossy(&buf).into_owned()
}}""")
VARIANTS["tight_xor"] = {
    "deps": [], "header": "\n".join(tight_fns),
    "body": "fn main() {\n" + "\n".join(f'    println!("{{}}", tight_{i}());' for i in range(len(CANARIES))) + "\n}",
    "build_rs": None, "env": None,
}

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

# 7. obfuse (2026). Default features = aes-256-gcm + polymorphic + control-flow-flatten. With
#    `polymorphic` on (the default) the macro does NOT use the AEAD: each literal gets its own
#    inline closure that undoes 2-4 random XOR/ADD/SUB/ROL/ROR layers whose 32-byte keys are
#    derived at run time from 4-8 constants, inside a flattened state machine with opaque
#    predicates; decrypted lazily into a OnceLock.
#    SEEDED (VALIDATION §77/§78): without `seed = "..."` every build draws fresh keys (getrandom at
#    macro expansion) and the benchmark verdict followed the key, not the code. The per-push gate
#    therefore pins one seed per literal, chosen up front (crate + literal), never searched for a
#    passing one; behaviour under random keys is measured separately, over many builds.
#    (The seed names the literal by a hash, never by its text: a seed is a macro argument and is
#    not emitted, but the plaintext must not be able to reach the binary by any route.)
def obfuse_seeded(crate):
    def wrap(c):
        tag = hashlib.sha256(f"{crate}/{c}".encode()).hexdigest()[:16]
        return f'obfuse!("{esc(c)}", seed = "rust-deobf-bench-{tag}").as_str()'
    return wrap


VARIANTS["obfuse"] = {
    "deps": ['obfuse = "1"'],
    "header": "use obfuse::obfuse;",
    "body": main_body(obfuse_seeded("obfuse")),
    "build_rs": None, "env": None,
}
# 7b. obfuse without `polymorphic`: the real AES-256-GCM path (ObfuseStr: ciphertext+tag in
#     .rodata, key and nonce as immediates, the `aes` crate's AES-NI/soft backend picked by CPUID)
VARIANTS["obfuse_aes"] = {
    "deps": ['obfuse = { version = "1", default-features = false, features = ["aes-256-gcm"] }'],
    "header": "use obfuse::obfuse;",
    "body": main_body(obfuse_seeded("obfuse_aes")),
    "build_rs": None, "env": None,
}
# 7c. obfuse `xor` mode: XOR with a 32-byte key through Mixed Boolean-Arithmetic (MBA) expressions
VARIANTS["obfuse_xor"] = {
    "deps": ['obfuse = { version = "1", default-features = false, features = ["xor"] }'],
    "header": "use obfuse::obfuse;",
    "body": main_body(obfuse_seeded("obfuse_xor")),
    "build_rs": None, "env": None,
}

# 8. obfany (2026 fork of obfstr 0.4): XorShift keystream seeded per call site (file/line/column,
#    OBFANY_SEED), read_volatile against constant folding, the ciphertext reference hidden behind
#    xref!. Strings via obfstr! and obfwide! (UTF-16), plus obfnum! and obfstmt! (statement
#    shuffling) around two of the prints.
VARIANTS["obfany"] = {
    "deps": ['obfany = "0.1"'],
    "header": "use obfany::{obfnum, obfstmt, obfstr, obfwide};",
    "body": "\n".join([
        "fn main() {",
        f'    println!("{{}}", obfstr!("{esc(CANARIES[0])}"));',
        f'    println!("{{}}", obfstr!("{esc(CANARIES[1])}"));',
        f'    println!("{{}}", String::from_utf16_lossy(obfwide!("{esc(CANARIES[2])}")));',
        "    let mut schema: u32 = 0;",
        "    obfstmt! {",
        f'        println!("{{}}", obfstr!("{esc(CANARIES[3])}"));',
        "        schema = obfnum!(u32, 4);",
        f'        println!("{{}}", obfstr!("{esc(CANARIES[4])}"));',
        "    }",
        '    println!("{}", schema);',
        "}",
    ]),
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


# ---------------------------------------------------------------------------------------------
# "scatter" suite: the same obfuscators, used the way real programs use strings.
#
# The canary suite above prints five strings from main(), which is the friendliest possible
# shape: every literal flows straight into println!, all from one function, one build profile.
# Real code keeps strings in structs, picks them in a `match`, only *compares* against them
# (an argv flag, a mutex name) and keeps some on paths that never run. These programs put eight
# benign, indicator-shaped strings in exactly those places, and the build matrix adds the
# size-optimised, fat-LTO, panic=abort profiles release malware tends to ship with, which change
# the decoder idioms (inlining, loop shape, index wrap) the recoverers key on.
# 2026 coverage round (VALIDATION §80): strings that are never plain UTF-8 bytes in the file or
# in a Rust `&str` at run time. One canary per encoding; no crate, all hand-written except the
# zlib stream (miniz_oxide, the inflater std's own backtrace code vendors):
#   0  UTF-16LE, XOR'd per code unit, decoded and converted with String::from_utf16
#   1  UTF-16LE, XOR'd per code unit, decoded and NEVER converted: written out as UTF-16 bytes
#      (a Windows `W` API argument) -- in memory only as UTF-16
#   2  base64 text in rodata, decoded at run time (the base64 is visible; the canary is not)
#   3  hex text in rodata, decoded at run time
#   4  a zlib stream, inflated at run time
import base64 as _b64, zlib as _zlib
_WK = 0x5A3C
def _u16(c):
    units = [int.from_bytes(c.encode("utf-16-le")[i:i + 2], "little") for i in range(0, 2 * len(c), 2)]
    return "[" + ",".join(str(u ^ _WK) for u in units) + "]", len(units)
_w0, _n0 = _u16(CANARIES[0])
_w1, _n1 = _u16(CANARIES[1])
_z = _zlib.compress(CANARIES[4].encode(), 9)
VARIANTS["encodings"] = {
    "deps": ['miniz_oxide = "0.8"'],
    "header": "\n".join([
        "use std::io::Write;",
        f"static W0: [u16; {_n0}] = {_w0};",
        f"static W1: [u16; {_n1}] = {_w1};",
        f'static B64: &str = "{_b64.b64encode(CANARIES[2].encode()).decode()}";',
        f'static HEX: &str = "{CANARIES[3].encode().hex()}";',
        f"static Z: [u8; {len(_z)}] = [{','.join(str(b) for b in _z)}];",
        "#[inline(never)]",
        f"fn wide(enc: &[u16]) -> Vec<u16> {{ enc.iter().map(|u| u ^ {_WK:#x}).collect() }}",
        "#[inline(never)]",
        "fn b64(s: &str) -> String {",
        "    let mut acc = 0u32; let mut n = 0; let mut out = Vec::new();",
        "    for c in s.bytes() {",
        "        let v = match c { b'A'..=b'Z' => c - b'A', b'a'..=b'z' => c - b'a' + 26,",
        "                          b'0'..=b'9' => c - b'0' + 52, b'+' => 62, b'/' => 63, _ => continue };",
        "        acc = (acc << 6) | v as u32; n += 6;",
        "        if n >= 8 { n -= 8; out.push((acc >> n) as u8); }",
        "    }",
        "    String::from_utf8(out).unwrap()",
        "}",
        "#[inline(never)]",
        "fn unhex(s: &str) -> String {",
        "    let h = |c: u8| if c <= b'9' { c - b'0' } else { c - b'a' + 10 };",
        "    String::from_utf8(s.as_bytes().chunks(2).map(|p| h(p[0]) << 4 | h(p[1])).collect()).unwrap()",
        "}",
        "#[inline(never)]",
        "fn inflate(z: &[u8]) -> String {",
        "    String::from_utf8(miniz_oxide::inflate::decompress_to_vec_zlib(z).unwrap()).unwrap()",
        "}",
        "#[inline(never)]",
        "fn put_wide(w: &[u16]) {",
        "    let bytes: Vec<u8> = w.iter().flat_map(|u| u.to_le_bytes()).collect();",
        "    std::io::stdout().write_all(&bytes).unwrap();",
        "    println!();",
        "}",
    ]),
    "body": "\n".join([
        "fn main() {",
        "    println!(\"{}\", String::from_utf16(&wide(&W0)).unwrap());",
        "    put_wide(&wide(&W1));",
        "    println!(\"{}\", b64(B64));",
        "    println!(\"{}\", unhex(HEX));",
        "    println!(\"{}\", inflate(&Z));",
        "}",
    ]),
    "build_rs": None, "env": None,
}


SCATTER = [
    "10.66.12.7:8443",                                              # struct field, ip:port
    "C:\\ProgramData\\NorthwindSvc\\state.db",                      # struct field, Windows path
    "Global\\NW-5c1e9a",                                            # compared only (mutex name)
    "https://telemetry.northwind.example/api/v3/beacon",            # match arm, URL
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NorthwindAgent/2.1", # struct field, user agent
    "--skip-update-check",                                          # compared only (argv flag)
    "Software\\Northwind\\Agent\\Settings",                         # branch that never runs
    "nw-agent::stage=collect",                                      # match arm, prefixed id
]


def lit(c):
    """A Rust literal for c. Raw strings for anything with a backslash: litcrypt/litcrypt2 encrypt
    the literal's source text, escapes included (their README tells users to write paths as raw
    strings), so `lc!("C:\\x")` really holds a doubled backslash at run time."""
    return f'r"{c}"' if "\\" in c else f'"{esc(c)}"'


def scatter_body(s, eq):
    """s(i) -> expression yielding String for SCATTER[i]; eq(var, i) -> bool comparing &str var."""
    return f"""struct Config {{
    c2: String,
    cache: String,
    agent: String,
}}

#[inline(never)]
fn load_config() -> Config {{
    Config {{ c2: {s(0)}, cache: {s(1)}, agent: {s(4)} }}
}}

#[inline(never)]
fn already_running(name: &str) -> bool {{
    let name = std::hint::black_box(name);
    {eq("name", 2)}
}}

#[inline(never)]
fn endpoint(kind: usize) -> String {{
    match kind {{
        0 => {s(3)},
        1 => {s(7)},
        _ => String::new(),
    }}
}}

#[inline(never)]
fn skip_update(args: &[String]) -> bool {{
    args.iter().any(|a| {{ let a = a.as_str(); {eq("a", 5)} }})
}}

#[inline(never)]
fn settings_key() -> String {{
    {s(6)}
}}

fn main() {{
    let args: Vec<String> = std::env::args().collect();
    let cfg = load_config();
    let busy = already_running(args.first().map(|a| a.as_str()).unwrap_or(""));
    let ep = endpoint(std::hint::black_box(args.len() - 1));
    let skip = skip_update(&args);
    if std::hint::black_box(args.len()) > 4096 {{
        // never taken: the key is only ever built on a path that does not run
        std::process::exit(settings_key().len() as i32);
    }}
    // the strings themselves are never printed, only facts about them
    println!("{{}} {{}} {{}} {{}} {{}}", cfg.c2.len() + cfg.cache.len() + cfg.agent.len(), busy, ep.len(), skip, args.len());
}}"""


# hand-rolled XOR decoder, same key and function as xor_custom
_sx_decls = "\n".join(
    f"static SENC_{i}: [u8; {len(c.encode())}] = {xor_blob(c)};" for i, c in enumerate(SCATTER))
VARIANTS["scatter_xor_custom"] = {
    "deps": [], "header": xor_header.split("\n")[0] + "\n" + _sx_decls + "\n" + "\n".join(xor_header.split("\n")[len(CANARIES) + 1:]),
    "body": scatter_body(lambda i: f"dex(&SENC_{i})", lambda v, i: f"{v} == dex(&SENC_{i})"),
    "build_rs": None, "env": None, "suite": "scatter",
}
VARIANTS["scatter_litcrypt"] = {
    "deps": ['litcrypt = "0.4"'],
    "header": "#[macro_use]\nextern crate litcrypt;\nuse_litcrypt!();",
    "body": scatter_body(lambda i: f'lc!({lit(SCATTER[i])})', lambda v, i: f'{v} == lc!({lit(SCATTER[i])})'),
    "build_rs": None, "env": ("LITCRYPT_ENCRYPT_KEY", "benchmark-fixed-key-do-not-reuse"), "suite": "scatter",
}
VARIANTS["scatter_litcrypt2"] = {
    "deps": ['litcrypt2 = "0.1"'],
    "header": "extern crate alloc;\n#[macro_use]\nextern crate litcrypt2;\nuse_litcrypt!();",
    "body": scatter_body(lambda i: f'lc!({lit(SCATTER[i])})', lambda v, i: f'{v} == lc!({lit(SCATTER[i])})'),
    "build_rs": None, "env": ("LITCRYPT_ENCRYPT_KEY", "benchmark-fixed-key-2"), "suite": "scatter",
}
VARIANTS["scatter_obfstr"] = {
    "deps": ['obfstr = "0.4"'],
    "header": "use obfstr::obfstr;",
    "body": scatter_body(lambda i: f'obfstr!({lit(SCATTER[i])}).to_string()',
                         lambda v, i: f'{v} == obfstr!({lit(SCATTER[i])})'),
    "build_rs": None, "env": None, "suite": "scatter",
}
VARIANTS["scatter_cryptify"] = {
    "deps": ['cryptify = "3"'],
    "header": "",
    "body": scatter_body(lambda i: f'cryptify::encrypt_string!({lit(SCATTER[i])})',
                         lambda v, i: f'{v} == cryptify::encrypt_string!({lit(SCATTER[i])})'),
    "build_rs": None, "env": None, "suite": "scatter",
}
VARIANTS["scatter_plaintext"] = {
    "deps": [], "header": "",
    "body": scatter_body(lambda i: f'{lit(SCATTER[i])}.to_string()', lambda v, i: f'{v} == {lit(SCATTER[i])}'),
    "build_rs": None, "env": None, "suite": "scatter",
}

# Build profiles. `release` is the original benchmark profile; the two LTO profiles are what
# shipped Rust malware commonly uses (opt-level="z"/"s", lto, codegen-units=1, panic=abort) and
# they change inlining and loop shape. scripts/build_all.sh builds the profiles a variant lists.
PROFILES_EXTRA = """
[profile.size-lto]
inherits = "release"
opt-level = "z"
lto = "fat"
codegen-units = 1
panic = "abort"

[profile.speed-lto]
inherits = "release"
opt-level = 3
lto = "fat"
codegen-units = 1
panic = "abort"
"""

manifest = {"canaries": CANARIES, "scatter": SCATTER, "variants": {}}
for name, v in VARIANTS.items():
    d = SRC / name
    (d / "src").mkdir(parents=True, exist_ok=True)
    cargo = [f'[package]', f'name = "{name}"', 'version = "0.1.0"', 'edition = "2021"', "", "[dependencies]"]
    cargo += v["deps"]
    cargo += ["", "[profile.release]", "strip = false", "opt-level = 3"]
    cargo += PROFILES_EXTRA.splitlines()
    (d / "Cargo.toml").write_text("\n".join(cargo) + "\n")
    src = (v["header"] + "\n\n" + v["body"] + "\n") if v["header"] else (v["body"] + "\n")
    (d / "src" / "main.rs").write_text(src)
    if v["build_rs"]:
        (d / "build.rs").write_text(v["build_rs"])
    manifest["variants"][name] = {
        "crate": (v["deps"][0] if v["deps"] else None),
        "env": v["env"],
        "suite": v.get("suite", "canary"),
        "cipher": {"plaintext":"none","xor_custom":"xor","add_custom":"add","sub_custom":"sub",
                   "obfstr":"xor","litcrypt":"xor","litcrypt2":"xor",
                   "cryptify":"xor-ish","cryptify_default":"xor-ish","tight_xor":"xor",
                   "muddy":"chacha20poly1305", "obfuse":"polymorphic-xor-add-sub-rot",
                   "obfuse_aes":"aes-256-gcm", "obfuse_xor":"xor-mba", "obfany":"xor",
                   "encodings":"utf16-xor/base64/hex/zlib"}.get(name.replace("scatter_", "").replace("cryptify", "cryptify_default") if name.startswith("scatter_") else name, "?"),
    }
# What each scatter program really holds at run time. litcrypt (v1) strips one character from
# each end of the literal's *source text*, so a raw string r"C:\x" becomes `"C:\x` -- a crate
# bug the recovered strings faithfully show. The other crates hold the literal's value.
def runtime_value(variant, c):
    if variant == "scatter_litcrypt" and lit(c).startswith('r"'):
        return '"' + c
    return c


manifest["scatter_expected"] = {name: [runtime_value(name, c) for c in SCATTER]
                                for name, v in VARIANTS.items()
                                if v.get("suite") == "scatter" and name != "scatter_plaintext"}
(SRC / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"generated {len(VARIANTS)} projects:", ", ".join(VARIANTS))
print(f"{len(CANARIES)} canaries each")
