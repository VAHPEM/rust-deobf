#!/usr/bin/env python3
"""recover_rust_meta.py - Tier 3: static recovery of Rust-specific structure.

Rust binaries retain structure that survives `strip`, because it lives in read-only
data the runtime needs. This tool reads (never runs) the binary and recovers:

  1. Panic location metadata: the &'static core::panic::Location structs
     {ptr-to-filename, len, u32 line, u32 col} emitted by unwrap/expect/bounds
     checks. The filenames rebuild the source-tree layout and the line/col map
     where the program panics.
  2. Crate fingerprint + version: the ".cargo/registry/src/<index>/<crate>-<ver>/"
     prefix in those paths names each third-party crate and its exact version; the
     crate set implies capability (networking / async / TLS / serialization / crypto).
  3. Type/trait names via symbol demangling when the binary is not fully stripped.

Static and format-agnostic (ELF + PE) via LIEF. Observational only.

    python recover_rust_meta.py <binary> [--json] [--selftest]
"""
from __future__ import annotations
import argparse, json, re, struct, sys
from pathlib import Path

RE_SRC_PATH = re.compile(rb"[0-9A-Za-z_./\\:+-]*?\.rs\b")
RE_CARGO = re.compile(
    r"(?:[\\/]|^)\.cargo[\\/]registry[\\/]src[\\/][^\\/]+[\\/]"
    r"(?P<crate>[A-Za-z0-9_.-]+?)-(?P<ver>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)[\\/]")
RE_RUSTC = re.compile(r"/rustc/(?P<hash>[0-9a-f]{7,40})/")
RE_PANIC_MSG = re.compile(
    rb"thread '[^']{0,64}' panicked|called `(?:Option|Result)::unwrap\(\)`|"
    rb"attempt to [a-z ]+ with overflow|index out of bounds|capacity overflow")

# crate -> (capability tag, meaning). The capability is the triage headline.
CRATE_CAPABILITY = {
    "tokio": ("async", "async runtime"), "async-std": ("async", "async runtime"),
    "mio": ("async", "non-blocking I/O"), "futures": ("async", "async combinators"),
    "reqwest": ("net", "HTTP client"), "hyper": ("net", "HTTP"), "h2": ("net", "HTTP/2"),
    "ureq": ("net", "HTTP client"), "curl": ("net", "libcurl HTTP"),
    "tungstenite": ("net", "WebSocket"), "tonic": ("net", "gRPC"),
    "trust-dns-resolver": ("net", "DNS"), "socket2": ("net", "raw sockets"),
    "rustls": ("tls", "TLS (rustls)"), "native-tls": ("tls", "TLS (platform)"),
    "openssl": ("tls", "OpenSSL"), "webpki": ("tls", "cert validation"),
    "ring": ("crypto", "crypto primitives"), "aes": ("crypto", "AES"),
    "aes-gcm": ("crypto", "AES-GCM"), "chacha20poly1305": ("crypto", "ChaCha20-Poly1305"),
    "rsa": ("crypto", "RSA"), "sha2": ("crypto", "SHA-2"), "md-5": ("crypto", "MD5"),
    "serde": ("serde", "serialization"), "serde_json": ("serde", "JSON"),
    "bincode": ("serde", "binary serialization"), "toml": ("serde", "TOML"),
    "windows": ("winapi", "Windows API"), "windows-sys": ("winapi", "Windows API"),
    "winapi": ("winapi", "Windows API"), "ntapi": ("winapi", "NT API"),
    "sysinfo": ("recon", "host/process enumeration"),
    "whoami": ("recon", "user/host identity"),
    "base64": ("encode", "base64"), "hex": ("encode", "hex"),
    "flate2": ("compress", "zlib/gzip"), "zip": ("compress", "zip"),
}
# raw string markers for crates whose .cargo path did not survive. Kept specific
# (a bare "ring" matches "string"); only consulted once the binary is confirmed Rust.
RAW_MARKERS = {
    "tokio": "tokio-runtime", "reqwest": "reqwest::", "hyper": "hyper::",
    "rustls": "rustls::", "serde_json": "serde_json::", "windows-sys": "windows_sys::",
}


def _clean_own(p: str) -> str | None:
    """Rodata strings are not always null-separated, so the regex can glue a URL or a
    neighbouring token onto a source path. Keep the meaningful source tail only."""
    q = p.replace("\\", "/")
    m = re.search(r"(?:^|[^A-Za-z0-9])((?:src|library|tests|examples|benches)/"
                  r"[A-Za-z0-9_./-]*\.rs)$", q)
    if m:
        return m.group(1)
    if "://" in q or q.count(" ") or len(q) > 160:
        return None                       # merged junk with no clean tail
    return p


def read_sections(path: Path):
    """Return (image_base, ptr_size, [(va, bytes)], symbols) via LIEF."""
    import lief
    b = lief.parse(str(path))
    if b is None:
        raise ValueError("LIEF could not parse the file")
    secs, image_base, ptr = [], 0, 8
    fmt = b.format.name if hasattr(b, "format") else ""
    try:
        m = (b.header.machine_type.name if hasattr(b.header, "machine_type")
             else str(b.header.machine)).upper()
        if "I386" in m or "86" in m and "64" not in m:
            ptr = 4
        if "AARCH64" in m or "X86_64" in m or "AMD64" in m:
            ptr = 8
    except Exception:
        pass
    if "PE" in fmt:
        image_base = b.optional_header.imagebase
        for s in b.sections:
            secs.append((image_base + s.virtual_address, bytes(s.content)))
        ptr = 4 if b.optional_header.magic == lief.PE.PE_TYPE.PE32 else 8
    else:  # ELF / Mach-O
        for s in b.sections:
            if getattr(s, "virtual_address", 0):
                secs.append((s.virtual_address, bytes(s.content)))
    syms = []
    try:
        for s in b.symbols:
            if s.name:
                syms.append(s.name)
    except Exception:
        pass
    # Relocations carrying an addend (ELF RELA): in a PIE build the Location filename
    # pointers are stored as 0 and resolved at load, so the addend is the real string VA.
    # PE base relocations carry no addend and are skipped (PE uses absolute pointers).
    relocs = []
    try:
        for r in b.relocations:
            ad = getattr(r, "addend", 0)
            if ad:
                relocs.append((int(r.address), int(ad)))
    except Exception:
        pass
    return image_base, ptr, secs, syms, relocs


def va_read(secs, va, n):
    for base, data in secs:
        if base <= va < base + len(data):
            return data[va - base:va - base + n]
    return b""


def find_source_paths(secs):
    """All embedded *.rs source paths, de-duplicated, with their (va, length)."""
    out = {}
    for base, data in secs:
        for m in RE_SRC_PATH.finditer(data):
            raw = m.group(0)
            if len(raw) < 5 or raw.count(b".") > 8:
                continue
            try:
                s = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            # a plausible path: has a separator or a known rust root token
            if ("/" in s or "\\" in s) or s.startswith("src"):
                out.setdefault(s, (base + m.start(), len(raw)))
    return out


def find_location_structs(secs, ptr, src_by_va, relocs=None):
    """Recover core::panic::Location records = {ptr(filename), len(usize)==len(filename),
    u32 line, u32 col}. Two layouts:

    - Absolute pointers (PE, non-PIE): the filename field holds the string's VA directly,
      so scan rodata for a qword that lands on a known .rs string of the matching length.
    - Relocated pointers (PIE ELF): the field is stored as 0 and fixed up at load, so the
      real VA lives in the relocation addend. For each reloc whose addend is a known .rs
      string VA, read len/line/col from the struct bytes that follow the relocated field.

    Returns [(file, line, col)]."""
    locs = []
    fileptr = {va: (s, ln) for s, (va, ln) in src_by_va.items()}
    packP = "<Q" if ptr == 8 else "<I"
    for base, data in secs:
        step = 4  # pointers in rodata are at least 4-byte aligned
        for off in range(0, len(data) - (ptr + 8), step):
            cand = struct.unpack_from(packP, data, off)[0]
            hit = fileptr.get(cand)
            if not hit:
                continue
            s, ln = hit
            rec_len = struct.unpack_from(packP, data, off + ptr)[0]
            if rec_len != ln:
                continue
            line, col = struct.unpack_from("<II", data, off + 2 * ptr)
            if 0 < line < 2_000_000 and 0 < col < 100_000:
                locs.append((s, line, col))
    for addr, addend in (relocs or []):
        hit = fileptr.get(addend)
        if not hit:
            continue
        s, ln = hit
        rl = va_read(secs, addr + ptr, ptr)
        if len(rl) < ptr or struct.unpack_from(packP, rl, 0)[0] != ln:
            continue
        lc = va_read(secs, addr + 2 * ptr, 8)
        if len(lc) < 8:
            continue
        line, col = struct.unpack_from("<II", lc, 0)
        if 0 < line < 2_000_000 and 0 < col < 100_000:
            locs.append((s, line, col))
    # de-dup, keep deterministic order
    seen, uniq = set(), []
    for t in locs:
        if t not in seen:
            seen.add(t); uniq.append(t)
    return uniq


def fingerprint_crates(paths, raw_text, strong_rust):
    """Map .cargo registry paths -> {crate: version}. Raw-marker fallback crates are
    added only when the binary is already confirmed Rust, to avoid false positives on
    C/C++ binaries (e.g. a bare 'ring' matching 'string')."""
    crates = {}
    rustc = None
    for p in paths:
        m = RE_CARGO.search(p)
        if m:
            crates.setdefault(m.group("crate"), set()).add(m.group("ver"))
        r = RE_RUSTC.search(p.replace("\\", "/"))
        if r:
            rustc = r.group("hash")
    if strong_rust:
        for crate, marker in RAW_MARKERS.items():
            if crate not in crates and marker in raw_text:
                crates.setdefault(crate, set())  # present, version unknown
    return crates, rustc


def demangle(sym):
    """Best-effort Rust demangle (legacy _ZN..E hash-stripped). v0 (_R) left as-is."""
    if sym.startswith("_ZN") and sym.endswith("E"):
        body = sym[3:-1]
        parts, i = [], 0
        while i < len(body):
            j = i
            while j < len(body) and body[j].isdigit():
                j += 1
            if j == i:
                break
            n = int(body[i:j]); seg = body[j:j + n]; i = j + n
            if re.fullmatch(r"h[0-9a-f]{16}", seg):  # trailing hash
                continue
            parts.append(seg)
        if parts:
            return "::".join(parts)
    return sym


def recover(path: Path):
    image_base, ptr, secs, syms, relocs = read_sections(path)
    raw_text = b"\n".join(d for _, d in secs).decode("latin-1", "ignore")
    src = find_source_paths(secs)
    locs = find_location_structs(secs, ptr, src, relocs)
    rust_syms = [demangle(s) for s in syms
                 if s.startswith(("_ZN", "_R")) or "17h" in s]
    # Strong Rust evidence = structure only a Rust build produces: a cargo-registry path,
    # a /rustc/<hash>/ path, a recovered Location record, or a mangled Rust symbol. Generic
    # panic-ish substrings and loose markers do NOT count (they false-positive on C/C++).
    has_cargo = any(RE_CARGO.search(p) for p in src)
    has_rustc = any(RE_RUSTC.search(p.replace("\\", "/")) for p in src)
    strong_rust = has_cargo or has_rustc or bool(locs) or bool(rust_syms)
    crates, rustc = fingerprint_crates(src.keys(), raw_text, strong_rust)
    panic_msgs = sorted({m.group(0).decode("latin-1")
                         for _, d in secs for m in RE_PANIC_MSG.finditer(d)}) if strong_rust else []
    caps = {}
    for c in crates:
        tag, meaning = CRATE_CAPABILITY.get(c, (None, None))
        if tag:
            caps.setdefault(tag, {})[c] = meaning
    # own source files = paths that are neither rustc-internal nor a cargo registry crate,
    # cleaned of rodata strings glued on by the absence of a null separator.
    own = set()
    if strong_rust:
        for p in src:
            q = p.replace("\\", "/")
            if "/rustc/" in q or RE_CARGO.search(p):
                continue
            c = _clean_own(p)
            if c:
                own.add(c)
    own = sorted(own)
    return {
        "is_rust": strong_rust,
        "rustc_commit": rustc,
        "own_source_files": own,
        "crates": {c: sorted(v) for c, v in sorted(crates.items())},
        "capabilities": caps,
        "panic_sites": [{"file": f, "line": l, "col": c} for f, l, c in locs],
        "panic_messages": panic_msgs,
        "demangled_symbols": sorted(set(rust_syms))[:400],
        "counts": {"source_files": len(src), "panic_sites": len(locs),
                   "crates": len(crates), "rust_symbols": len(set(rust_syms))},
    }


def _selftest():
    """Build a tiny synthetic rodata blob with one Location record and check recovery."""
    import tempfile, os
    # craft an ELF-ish in-memory section set directly (bypass LIEF for the unit test)
    fn = b".cargo/registry/src/github.com-abc/reqwest-0.12.4/src/client.rs"
    base = 0x1000
    blob = bytearray()
    blob += fn + b"\x00"
    pad = (8 - len(blob) % 8) % 8
    blob += b"\x00" * pad
    rec_off = len(blob)
    blob += struct.pack("<Q", base)                 # ptr -> filename at va=base
    blob += struct.pack("<Q", len(fn))              # len
    blob += struct.pack("<II", 1234, 7)             # line, col
    secs = [(base, bytes(blob))]
    src = find_source_paths(secs)
    assert any("client.rs" in p for p in src), src
    locs = find_location_structs(secs, 8, src)
    assert (fn.decode(), 1234, 7) in locs, locs
    crates, _ = fingerprint_crates(src.keys(), "", True)
    assert crates.get("reqwest") == {"0.12.4"}, crates
    assert demangle("_ZN4core3fmt9Formatter3pad17h0123456789abcdefE") == "core::fmt::Formatter::pad"
    print("selftest OK: location struct, cargo version, demangle all recovered")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--max-list", type=int, default=60)
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return
    if not a.binary:
        ap.error("binary required (or --selftest)")
    path = Path(a.binary)
    if not path.exists():
        sys.exit(f"no such file: {path}")
    r = recover(path)
    if a.json:
        print(json.dumps(r, indent=2)); return
    c = r["counts"]
    print(f"{path.name}: rust={r['is_rust']}  source_files={c['source_files']}  "
          f"panic_sites={c['panic_sites']}  crates={c['crates']}  "
          f"rust_symbols={c['rust_symbols']}")
    if r["rustc_commit"]:
        print(f"rustc commit: {r['rustc_commit']}")
    if r["capabilities"]:
        print("\n== capability fingerprint ==")
        for tag, members in sorted(r["capabilities"].items()):
            items = ", ".join(f"{k}({v})" for k, v in members.items())
            print(f"  [{tag}] {items}")
    if r["crates"]:
        print("\n== third-party crates (name @ version) ==")
        for crate, vers in r["crates"].items():
            print(f"  {crate} @ {', '.join(vers) or '?'}")
    if r["own_source_files"]:
        print(f"\n== own source tree ({len(r['own_source_files'])}) ==")
        for p in r["own_source_files"][:a.max_list]:
            print(f"  {p}")
    if r["panic_sites"]:
        print(f"\n== panic sites ({len(r['panic_sites'])}, file:line:col) ==")
        for s in r["panic_sites"][:a.max_list]:
            print(f"  {s['file']}:{s['line']}:{s['col']}")
    if r["panic_messages"]:
        print(f"\n== panic message templates ({len(r['panic_messages'])}) ==")
        for m in r["panic_messages"][:20]:
            print(f"  {m}")


if __name__ == "__main__":
    main()
