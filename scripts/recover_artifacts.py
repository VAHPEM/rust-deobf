#!/usr/bin/env python3
"""Dynamic artifact / config recovery by runtime memory diffing (Frida).

recover_dynamic.py answers "which *strings* did the sample decode at runtime".
This tool answers the triage question one level up: "what did the sample decrypt
into memory, and what does it tell me" -- the decrypted config / C2 blob and the
indicators in it (URLs, IP:port, domains, filesystem paths, registry keys), plus
any structured blob (JSON, base64) that appeared only at runtime.

Same mechanism as recover_dynamic: spawn the target, let it decrypt its config in
memory, scan writable memory, and subtract everything already present statically
in the binary and its shared libraries. What is left is runtime-only. From that we
*extract* indicators instead of merely ranking text, because a decrypted config is
usually one contiguous blob (e.g. a JSON object) from which the useful fields must
be pulled out.

SAFETY: this executes the target AND scans its whole address space. Run it ONLY
inside an isolated analysis VM/sandbox dedicated to the sample. You are executing
untrusted code, and the scan reads all readable+writable memory of the process, so
anything else resident there (environment, other secrets, injected-agent state)
surfaces as noise and could leak in a shared environment. In a clean sandbox the
only interesting memory is the sample's own, which is the point.

    python scripts/recover_artifacts.py ./binary
    python scripts/recover_artifacts.py ./binary --argv --config prod
    python scripts/recover_artifacts.py ./binary --json          # machine-readable

Noise: in a pristine analysis VM the only runtime-only memory is the sample's own.
Outside one (a shared host, a container) the scan also surfaces environment and
injected-agent strings. Two subtractions remove most of that without a clean VM:
  --baseline PATH   run a trivial no-op program through the same scan and subtract
                    every indicator it produces -- anything that appears even when
                    an innocuous program runs is environment, not the sample's secret.
  (always)          indicators that occur verbatim in this process's environment are
                    dropped. Neither can invent a false negative on the target's own
                    decrypted config, which a no-op/the environment does not contain.
"""
from __future__ import annotations
import argparse, base64, json, os, re, subprocess, sys, time
from pathlib import Path

# ---- the memory-scan harness (shared design with recover_dynamic.py) -------------
SCAN_JS = r"""
let done = false;
function scan() {
  const out = new Set();
  for (const r of Process.enumerateRanges('rw-')) {
    let buf;
    try { buf = r.base.readByteArray(Math.min(r.size, 0x400000)); } catch (e) { continue; }
    if (!buf) continue;
    const b = new Uint8Array(buf);
    let cur = [];
    for (let i = 0; i < b.length; i++) {
      const c = b[i];
      if (c >= 0x20 && c < 0x7f) cur.push(c);
      else { if (cur.length >= MINLEN) out.add(String.fromCharCode.apply(null, cur)); cur = []; }
    }
    if (cur.length >= MINLEN) out.add(String.fromCharCode.apply(null, cur));
  }
  for (const s of out) send({ t: 'str', s: s });
  try { for (const m of Process.enumerateModules()) if (m.path) send({ t: 'mod', p: m.path }); } catch (e) {}
  send({ t: 'done' });
}
function resolve(name) {
  try { if (Module.getGlobalExportByName) return Module.getGlobalExportByName(name); } catch (e) {}
  try { for (const m of Process.enumerateModules()) { const e = m.findExportByName && m.findExportByName(name); if (e) return e; } } catch (e) {}
  return null;
}
function trigger() { if (!done) { done = true; scan(); } }
for (const name of ['write', 'exit', 'exit_group', '_exit']) {
  const a = resolve(name);
  if (a) { try { Interceptor.attach(a, { onEnter() { trigger(); } }); } catch (e) {} }
}
setTimeout(trigger, 2000);
"""


def static_strings(path: Path, min_len: int) -> set[str]:
    try:
        out = subprocess.run(["strings", "-n", str(min_len), str(path)],
                             capture_output=True, text=True, timeout=120).stdout
        return set(out.splitlines())
    except Exception:
        return set()


def run(path: Path, argv: list[str], min_len: int, timeout: float):
    try:
        import frida
    except ImportError:
        sys.exit("frida not installed: pip install frida frida-tools")
    runtime, mods = set(), set()
    device = frida.get_local_device()
    pid = device.spawn([str(path)] + argv)
    session = device.attach(pid)
    script = session.create_script(SCAN_JS.replace("MINLEN", str(min_len)))
    done = {"v": False}

    def on_message(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "str":
                runtime.add(p["s"])
            elif p.get("t") == "mod":
                mods.add(p["p"])
            elif p.get("t") == "done":
                done["v"] = True

    script.on("message", on_message)
    script.load()
    device.resume(pid)
    t0 = time.time()
    while time.time() - t0 < timeout and not done["v"]:
        time.sleep(0.1)
    for fn in (session.detach, lambda: device.kill(pid)):
        try: fn()
        except Exception: pass
    return runtime, mods


# ---- indicator / structured-blob extraction --------------------------------------
# Applied only to runtime-only memory, so these patterns do not need to be strict:
# false hits on library noise are already removed by the static subtraction.
RE_URL   = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s\"'<>\\]{3,}", re.I)
RE_IPP   = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b")
RE_IP    = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_DOM   = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
RE_WINPATH = re.compile(r"\b[A-Za-z]:\\\\(?:[^\\\s\"'<>|]+\\\\?)*[^\\\s\"'<>|]*")
RE_REG   = re.compile(r"\bHK(?:EY_)?(?:LM|CU|CR|U|CC|LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)\\[^\s\"'<>|]+", re.I)
RE_UNIXPATH = re.compile(r"(?:/[A-Za-z0-9._\-]+){2,}/?")
RE_B64   = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}\b")

# Library/agent/env noise that can survive the static subtraction (paths built at
# runtime, injected agent, environment). Kept deliberately narrow so real config
# values (which may legitimately contain words like "telemetry") are not dropped.
NOISE_PATH = re.compile(r"(?:^|/)(?:lib|lib64|usr|proc|sys|dev|frida|\.cargo|rustc|"
                        r"ld-linux|ld\.so)(?:/|$)|\.so(?:\.\d+)*$|\.dylib$|/proc/self")
NOISE_DOM  = re.compile(r"\.(?:so|dylib|rs|rlib|crate)$|^(?:core|alloc|std|frida)\.", re.I)


def is_private_or_doc_ip(ip: str) -> bool:
    try:
        o = [int(x) for x in ip.split(".")]
        return all(0 <= x <= 255 for x in o)
    except Exception:
        return False


def looks_like_json(s: str) -> bool:
    t = s.strip()
    if not (t.startswith("{") or t.startswith("[")):
        return False
    try:
        json.loads(t)
        return True
    except Exception:
        # Memory scan may truncate the blob; accept an object-ish fragment with >=2 "k":"v"
        return len(re.findall(r'"[^"]+"\s*:', t)) >= 2


def decodes_base64(s: str) -> str | None:
    if len(s) % 4 != 0 or len(s) < 24:
        return None
    try:
        raw = base64.b64decode(s, validate=True)
    except Exception:
        return None
    printable = sum(1 for b in raw if 0x20 <= b < 0x7f or b in (9, 10, 13))
    if len(raw) >= 8 and printable / len(raw) > 0.85:
        return raw.decode("latin-1", "ignore")
    return None


def extract(decoded: list[str]) -> dict:
    out = {"urls": set(), "endpoints": set(), "domains": set(), "paths": set(),
           "registry": set(), "json_blobs": set(), "base64": set(), "other_text": set()}
    for s in decoded:
        hit = False
        for m in RE_URL.finditer(s):
            out["urls"].add(m.group(0)); hit = True
        for m in RE_IPP.finditer(s):
            ip = m.group(0).split(":")[0]
            if is_private_or_doc_ip(ip):
                out["endpoints"].add(m.group(0)); hit = True
        for m in RE_REG.finditer(s):
            out["registry"].add(m.group(0)); hit = True
        for m in RE_WINPATH.finditer(s):
            out["paths"].add(m.group(0)); hit = True
        for m in RE_UNIXPATH.finditer(s):
            p = m.group(0)
            if not NOISE_PATH.search(p) and p.count("/") >= 2:
                out["paths"].add(p); hit = True
        for m in RE_DOM.finditer(s):
            d = m.group(0)
            if not NOISE_DOM.search(d) and not RE_IP.fullmatch(d):
                out["domains"].add(d)
        if looks_like_json(s):
            out["json_blobs"].add(s.strip()); hit = True
        for m in RE_B64.finditer(s):
            dec = decodes_base64(m.group(0))
            if dec:
                out["base64"].add(f"{m.group(0)}  ->  {dec}"); hit = True
        if not hit and 6 <= len(s) <= 120 and re.search(r"[A-Za-z]", s):
            out["other_text"].add(s)
    # Domains that are only the host of a URL we already report add no information.
    hosts = {re.sub(r"^[a-z]+://", "", u, flags=re.I).split("/")[0].split(":")[0]
             for u in out["urls"]}
    out["domains"] -= hosts
    return out


def runtime_only(path: Path, argv: list[str], min_len: int, timeout: float) -> list[str]:
    """Scan the target and return strings present at runtime but not statically
    (in the binary or its loaded shared libraries)."""
    static = static_strings(path, min_len)
    runtime, mods = run(path, argv, min_len, timeout)
    for m in mods:
        try:
            if Path(m).resolve() == path.resolve():
                continue
        except Exception:
            pass
        static |= static_strings(Path(m), min_len)
    return [s for s in runtime if s not in static]


def subtract(art: dict, other: dict) -> None:
    for k in art:
        art[k] -= other.get(k, set())


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--argv", nargs=argparse.REMAINDER, default=[], help="args to pass to the target")
    ap.add_argument("--min-len", type=int, default=6)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--baseline", help="trivial no-op binary; its indicators are subtracted as environment noise")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    path = Path(args.binary)
    if not path.exists():
        sys.exit(f"no such file: {path}")

    decoded = runtime_only(path, args.argv, args.min_len, args.timeout)
    art = extract(decoded)

    # Subtraction 1: indicators that occur verbatim in this process's environment.
    env_blob = "\n".join(list(os.environ.keys()) + list(os.environ.values()))
    for k in art:
        art[k] = {v for v in art[k] if (v.split("  ->  ")[0] not in env_blob)}

    # Subtraction 2: differential baseline -- indicators a no-op program also produces.
    if args.baseline:
        bpath = Path(args.baseline)
        if bpath.exists():
            base_art = extract(runtime_only(bpath, [], args.min_len, args.timeout))
            subtract(art, base_art)
        else:
            print(f"warning: baseline {bpath} not found; skipping", file=sys.stderr)

    # Cleanup: drop self-references and cross-category echoes that are not indicators.
    exe = str(path.resolve())
    url_blob = "\n".join(art["urls"])
    art["paths"] = {p for p in art["paths"]
                    if p not in exe and p not in url_blob}
    FILEEXT = {"conf", "sock", "debug", "log", "crt", "cache", "rs", "so", "dylib",
               "json", "txt", "bin", "dll", "exe", "tmp", "lock", "toml", "md", "rlib"}
    art["domains"] = {d for d in art["domains"]
                      if d.rsplit(".", 1)[-1].lower() not in FILEEXT and d not in url_blob}

    if args.json:
        print(json.dumps({k: sorted(v) for k, v in art.items()}, indent=2))
        return

    labels = [("urls", "URLs"), ("endpoints", "IP:port endpoints"), ("domains", "domains"),
              ("paths", "filesystem paths"), ("registry", "registry keys"),
              ("json_blobs", "decrypted JSON / config blobs"), ("base64", "base64 payloads")]
    total = sum(len(art[k]) for k, _ in labels)
    print(f"runtime-only strings: {len(decoded)}   indicators extracted: {total}\n")
    for key, label in labels:
        vals = sorted(art[key])
        if not vals:
            continue
        print(f"== {label} ({len(vals)}) ==")
        for v in vals:
            print(f"  {v}")
        print()
    if art["other_text"]:
        print(f"(+{len(art['other_text'])} other runtime-only text strings; "
              f"use recover_dynamic.py for full string ranking)")


if __name__ == "__main__":
    main()
