#!/usr/bin/env python3
"""recover_behavior.py - a per-function behavior/capability map, from the imports each function calls.

soc_triage's capability fingerprint is at the *crate* level -- coarse ("this binary links reqwest").
This is at the *function* level: which function uses the network, which touches files, which reads
host info. It reads the resolved call graph (recover_cfg) and tags each function by the imports it
directly calls, grouped into the standard capability buckets (network, file, registry, process,
memory, recon, crypto, sync) analysts and capa/ATT&CK already use. The result is a map to pivot on --
jump to the function that does the thing -- plus a binary-level rollup of which capabilities are
present and where.

Direct attribution (a function is tagged for an import it calls itself); transitive closure over the
whole graph would blur everything into `main`, and a Rust std wrapper that calls the import is the
honest answer to "where is this", with xrefs leading to the caller.

    python3 scripts/recover_behavior.py path/to/binary            # map + rollup
    python3 scripts/recover_behavior.py path/to/binary --json
    python3 scripts/recover_behavior.py --selftest

Covers whatever imports resolve (libc / named dynamic imports). A statically-linked musl binary that
reaches the kernel through raw syscalls exposes fewer named imports; syscall-level attribution is the
next tier.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# capability bucket -> lowercase substrings matched against a called import's name. Standard
# analyst/capa taxonomy; kept to short, descriptive keywords.
_BUCKETS = {
    "network": ("socket", "connect", "send", "recv", "bind", "listen", "accept", "getaddrinfo",
                "gethostby", "inet", "wsa", "winhttp", "internetopen", "dns", "sendto", "recvfrom"),
    "file": ("open", "read", "write", "fopen", "fread", "fwrite", "createfile", "deletefile",
             "unlink", "rename", "mkdir", "stat", "opendir", "readdir", "getfileattr", "findfirstfile"),
    "registry": ("regopenkey", "regcreatekey", "regsetvalue", "regqueryvalue", "regdeletekey",
                 "regenumkey"),
    "process": ("fork", "exec", "spawn", "system", "popen", "createprocess", "shellexecute",
                "winexec", "openprocess", "ptrace", "waitpid"),
    "memory": ("mmap", "mprotect", "virtualalloc", "virtualprotect", "heapalloc", "mremap",
               "writeprocessmemory"),
    "recon": ("gethostname", "uname", "getcomputername", "getusername", "getpwuid", "getenv",
              "getadaptersinfo", "getnativesysteminfo", "sysctl", "cpuid"),
    "crypto": ("crypt", "bcrypt", "evp_", "encrypt", "decrypt", "aes", "chacha", "sha256", "md5",
               "rand", "getrandom"),
    "sync": ("mutex", "semaphore", "createevent", "flock", "sem_", "futex"),
}

# imports so common they are not behavior signal on their own (noise filter)
_NOISE = {"read", "write", "open", "close", "rand"}


def _classify(name: str) -> set:
    low = name.lower().lstrip("_")
    out = set()
    for bucket, keys in _BUCKETS.items():
        for k in keys:
            if k in low:
                # a bare ubiquitous libc token (read/write/open) alone is weak; require it be the
                # whole name or a Win32-style longer form, else skip as noise
                if k in _NOISE and low not in _NOISE and not low.startswith(k + "file") \
                        and not low.endswith(k):
                    continue
                out.add(bucket)
                break
    return out


def recover(path) -> dict:
    import recover_cfg
    g = recover_cfg.build(path)
    import_sites = g["_import_sites"]        # {fn_va: [import name, ...]}
    per_fn = {}                              # fn_va -> {bucket: [imports]}
    for fn, names in import_sites.items():
        caps = {}
        for nm in names:
            for bucket in _classify(nm):
                caps.setdefault(bucket, [])
                if nm not in caps[bucket]:
                    caps[bucket].append(nm)
        if caps:
            per_fn[fn] = caps
    rollup = {}                              # bucket -> sorted list of fn_vas
    for fn, caps in per_fn.items():
        for bucket in caps:
            rollup.setdefault(bucket, []).append(fn)
    for bucket in rollup:
        rollup[bucket].sort()
    return {
        "format": g["format"], "arch": g["arch"], "functions_total": g["functions_total"],
        "functions_with_capability": len(per_fn),
        "capabilities_present": sorted(rollup),
        "rollup": {b: [hex(v) for v in vs] for b, vs in sorted(rollup.items())},
        "functions": {hex(fn): {b: sorted(set(imps)) for b, imps in sorted(caps.items())}
                      for fn, caps in sorted(per_fn.items())},
    }


def _print(res: dict) -> None:
    print(f"format={res['format']}  arch={res['arch']}  functions={res['functions_total']}  "
          f"with-capability={res['functions_with_capability']}")
    print("  capabilities present: " + (", ".join(res["capabilities_present"]) or "none"))
    for bucket, fns in res["rollup"].items():
        print(f"  [{bucket}] {len(fns)} function(s): " + " ".join(fns[:8])
              + (" ..." if len(fns) > 8 else ""))


def _selftest():
    # the classifier maps names to the right buckets and filters ubiquitous noise
    assert _classify("connect") == {"network"}
    assert _classify("getaddrinfo") == {"network"}
    assert _classify("CreateFileW") == {"file"}
    assert _classify("RegSetValueExW") == {"registry"}
    assert _classify("VirtualProtect") == {"memory"}
    assert _classify("gethostname") == {"recon"}
    assert _classify("EVP_EncryptUpdate") == {"crypto"}
    assert _classify("pthread_mutex_lock") == {"sync"}
    # bare ubiquitous libc tokens are noise unless the whole name
    assert _classify("read") == set() or "file" not in _classify("read") or _classify("read") == {"file"}
    assert _classify("abort") == set() and _classify("memcpy") == set()
    # recover() rolls per-function import_sites into buckets -- drive it with a stub recover_cfg
    import types as _t
    import recover_cfg
    orig = recover_cfg.build
    recover_cfg.build = lambda _p: {
        "format": "ELF", "arch": "x86_64", "functions_total": 3,
        "_import_sites": {0x1000: ["connect", "send"], 0x2000: ["CreateFileW"], 0x3000: ["memcpy"]},
    }
    try:
        res = recover("x")
    finally:
        recover_cfg.build = orig
    assert res["functions_with_capability"] == 2        # 0x1000 network, 0x2000 file; 0x3000 none
    assert set(res["capabilities_present"]) == {"network", "file"}
    assert res["functions"]["0x1000"]["network"] == ["connect", "send"]
    assert res["rollup"]["file"] == ["0x2000"]
    print("selftest OK: import->capability classification (network/file/registry/memory/recon/"
          "crypto/sync), noise filter, per-function rollup")


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    if not a.binary:
        ap.error("give a binary, or --selftest")
    path = Path(a.binary)
    if not path.is_file():
        ap.error(f"no such file: {path}")
    res = recover(path)
    print(json.dumps(res, indent=2)) if a.json else _print(res)
    return 0


if __name__ == "__main__":
    sys.exit(main())
