#!/usr/bin/env python3
"""recover_apihash.py - Tier 2: resolve hash-obfuscated API imports, statically.

To hide which APIs they use, samples often resolve imports at runtime by HASH: they
carry 32-bit constants and, at load time, walk a module's export table hashing each
name until one matches. The static import table then shows nothing useful. This tool
reverses that WITHOUT running the sample: it (1) collects the candidate hash constants
compared against in `.text`, (2) hashes a corpus of known export names under every
common API-hash algorithm (plus case/UTF-16 variants), and (3) reports which constant
resolves to which API under which algorithm. The recovered import set is the triage
headline -- imports describe what a sample can do.

Bring your own export corpus for best coverage (one name per line), e.g.
`dumpbin /exports ntdll.dll` or `nm -D --defined-only lib.so`. A compact built-in list
of common Windows exports is used when none is given.

Observational: reads the binary, runs nothing.

    python recover_apihash.py <binary>
    python recover_apihash.py <binary> --names ntdll.txt kernel32.txt
    python recover_apihash.py --selftest
"""
from __future__ import annotations
import argparse, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from disasm import linear  # noqa: E402

M = 0xFFFFFFFF


def _ror(v, n):
    return ((v >> n) | (v << (32 - n))) & M


# ---- common API-hash algorithms: f(name_bytes, seed) -> u32 -------------------------
def h_ror13_add(b, seed=0):
    h = seed
    for c in b:
        h = (_ror(h, 13) + c) & M
    return h

def h_djb2(b, seed=5381):
    h = seed
    for c in b:
        h = ((h * 33) + c) & M
    return h

def h_sdbm(b, seed=0):
    h = seed
    for c in b:
        h = (c + (h << 6) + (h << 16) - h) & M
    return h

def h_fnv1a(b, seed=0x811C9DC5):
    h = seed
    for c in b:
        h = ((h ^ c) * 0x01000193) & M
    return h

def h_add_ror7(b, seed=0):
    h = seed
    for c in b:
        h = (_ror(h, 7) + c) & M
    return h

def h_murmur_ish(b, seed=0):   # a common rol5/xor variant
    h = seed
    for c in b:
        h = (((h << 5) | (h >> 27)) ^ c) & M
    return h

ALGOS = {"ror13_add": h_ror13_add, "djb2": h_djb2, "sdbm": h_sdbm,
         "fnv1a32": h_fnv1a, "add_ror7": h_add_ror7, "rol5_xor": h_murmur_ish}

BUILTIN_EXPORTS = [
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "GetProcAddress", "GetModuleHandleA",
    "GetModuleHandleW", "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "VirtualFree", "CreateThread", "CreateRemoteThread", "WriteProcessMemory",
    "ReadProcessMemory", "OpenProcess", "CreateProcessA", "CreateProcessW", "WinExec",
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle", "GetTempPathA",
    "RegOpenKeyExA", "RegSetValueExA", "RegQueryValueExA", "RegCreateKeyExA",
    "InternetOpenA", "InternetOpenUrlA", "InternetConnectA", "HttpOpenRequestA", "HttpSendRequestA", "InternetReadFile", "WSAStartup", "socket", "connect", "send",
    "recv", "WSASocketA", "GetThreadContext", "SetThreadContext", "ResumeThread",
    "QueueUserAPC", "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtWriteVirtualMemory", "NtCreateThreadEx", "RtlCreateUserThread", "LdrLoadDll",
    "LdrGetProcedureAddress", "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "GetTickCount", "CryptAcquireContextA", "CryptEncrypt", "CryptDecrypt",
    "BCryptOpenAlgorithmProvider", "BCryptGenRandom", "ShellExecuteA", "URLDownloadToFileA",
]


def name_variants(name: str):
    """A resolver may hash the name as given, uppercased, or as UTF-16LE (wide)."""
    narrow = {name.encode(), name.upper().encode(), name.lower().encode()}
    wide = {name.encode("utf-16-le"), name.upper().encode("utf-16-le"),
            name.lower().encode("utf-16-le")}
    out = set(narrow) | set(wide)
    # some hash the name WITH a terminating NUL -- one byte for a narrow name, TWO for a wide one
    out |= {b + b"\x00" for b in narrow}
    out |= {b + b"\x00\x00" for b in wide}
    return out


# modules whose exports malware commonly resolves by hash, for the combined module+function scheme
_COMMON_MODULES = ("kernel32.dll", "ntdll.dll", "kernelbase.dll", "advapi32.dll", "ws2_32.dll",
                   "wininet.dll", "winhttp.dll", "user32.dll", "urlmon.dll", "shell32.dll",
                   "crypt32.dll", "bcrypt.dll", "shlwapi.dll")


def _ror13(data: bytes) -> int:
    h = 0
    for c in data:
        h = (_ror(h, 13) + c) & M
    return h


def block_api_hash(func: str, module: str) -> int:
    """The Metasploit / Cobalt Strike block_api hash: ror13 of the UPPERCASE UTF-16LE module name
    (with its wide NUL) PLUS ror13 of the ASCII function name (with its NUL). e.g. kernel32.dll!
    LoadLibraryA = 0x0726774C. This single scheme covers most real shellcode API resolution and was
    not modelled by the per-name algorithms."""
    mod_hash = _ror13(module.upper().encode("utf-16-le") + b"\x00\x00")
    func_hash = _ror13(func.encode("ascii", "ignore") + b"\x00")
    return (mod_hash + func_hash) & M


def scan_constants(path: Path):
    """Collect 32-bit immediates compared against in .text (cmp/sub/xor reg,imm32 and
    bare mov reg,imm32) -- the pool the sample matches its running hash against."""
    import lief
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_OP_IMM
    b = lief.parse(str(path))
    base = b.optional_header.imagebase if "PE" in b.format.name else 0
    text = next((s for s in b.sections if s.name == ".text"), None)
    if text is None:
        return set()
    # hash-import resolution is common in 32-bit shellcode/loaders; decode in the binary's bitness
    # (decoding a PE32 as 64-bit misreads instruction boundaries and loses the compared constants)
    try:
        import recover_emulate as E
        mode = CS_MODE_32 if E._is_32bit(b) else CS_MODE_64
    except Exception:
        mode = CS_MODE_64
    md = Cs(CS_ARCH_X86, mode); md.detail = True
    consts = set()
    for ins in linear(md, bytes(text.content), base + text.virtual_address):
        if ins.mnemonic in ("cmp", "sub", "xor", "mov", "add", "lea"):
            for op in ins.operands:
                if op.type == CS_OP_IMM:
                    v = op.imm & M
                    if 0x1000 <= v <= 0xFFFFFFFF:   # skip tiny values / flags
                        consts.add(v)
    return consts


def build_table(names, seeds=(0, 5381, 0x811C9DC5, 0xDEADBEEF, 0x1505)):
    """hash value -> (algo, seed, name) for the first name seen, plus a parallel map hash -> set of
    all (algo, name) that produce it so a collision (one constant, several candidate names) can be
    reported instead of silently picking one. One name hashes to many values across algos."""
    table = {}
    allnames = {}
    def add(h, algo, seed, name):
        table.setdefault(h, (algo, seed, name))
        allnames.setdefault(h, set()).add((algo, name))
    for name in names:
        for var in name_variants(name):
            for algo, fn in ALGOS.items():
                for seed in seeds:
                    try:
                        h = fn(var, seed)
                    except TypeError:
                        h = fn(var)
                    add(h, algo, seed, name)
        # the combined module+function block_api scheme (module known only by convention here)
        for mod in _COMMON_MODULES:
            add(block_api_hash(name, mod), "block_api(%s)" % mod, 0, name)
    return table, allnames


def recover(path: Path, names):
    consts = scan_constants(path)
    table, allnames = build_table(names)
    hits = []
    for c in sorted(consts):
        if c in table:
            algo, seed, name = table[c]
            # distinct candidate names for this one constant: report them so a coincidental
            # collision with a large --names corpus is visible rather than silently resolved
            cands = sorted({n for _a, n in allnames.get(c, set())})
            hit = {"const": hex(c), "api": name, "algo": algo, "seed": hex(seed)}
            if len(cands) > 1:
                hit["ambiguous"] = cands
            hits.append(hit)
    return {"constants_scanned": len(consts), "corpus": len(names), "resolved": hits}


def _selftest():
    # pick an algorithm+seed, hash three known names, confirm they are recovered from a
    # constant pool that also contains decoys.
    target = ["VirtualAlloc", "LoadLibraryA", "NtWriteVirtualMemory"]
    algo, seed = "ror13_add", 0
    consts = {h_ror13_add(n.encode(), seed) for n in target} | {0x1234, 0xCAFEBABE}
    table, _all = build_table(BUILTIN_EXPORTS)
    got = {table[c][2] for c in consts if c in table}
    assert set(target) <= got, (target, got)
    # fnv1a of a wide (UTF-16) name must also resolve via the variant expansion
    c = h_fnv1a("GetProcAddress".encode("utf-16-le") + b"\x00\x00")
    assert table.get(c) and table[c][2] == "GetProcAddress", table.get(c)
    # the Metasploit/Cobalt Strike block_api hash of kernel32!LoadLibraryA
    assert block_api_hash("LoadLibraryA", "kernel32.dll") == 0x0726774C
    bc = block_api_hash("LoadLibraryA", "kernel32.dll")
    assert table.get(bc) and table[bc][2] == "LoadLibraryA", table.get(bc)
    print(f"selftest OK: recovered {sorted(set(target) & got)} from a mixed constant pool; "
          "UTF-16 variant resolved")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--names", nargs="*", default=[], help="export-name list files")
    ap.add_argument("--json", action="store_true", help="print the result dict as JSON")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return
    if not a.binary:
        ap.error("binary required or --selftest")
    names = list(BUILTIN_EXPORTS)
    for f in a.names:
        for line in Path(f).read_text(errors="ignore").splitlines():
            w = line.strip().split()
            for tok in w:
                if tok.isidentifier():
                    names.append(tok)
    names = sorted(set(names))
    r = recover(Path(a.binary), names)
    if a.json:
        import json
        print(json.dumps(r, indent=2)); return
    print(f"{Path(a.binary).name}: {r['constants_scanned']} candidate constants vs "
          f"{r['corpus']}-name corpus")
    if not r["resolved"]:
        print("no hash constant resolved to a known export. If the sample uses hash "
              "imports, pass the real target DLLs' exports with --names for coverage.")
        return
    print(f"resolved {len(r['resolved'])} hash-imported API(s):")
    for h in r["resolved"]:
        print(f"  {h['const']}  ->  {h['api']}   [{h['algo']} seed={h['seed']}]")


if __name__ == "__main__":
    main()
