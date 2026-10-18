#!/usr/bin/env python3
"""Dynamic string recovery by runtime memory diffing (Frida).

The static recoverer (recover_callsite.py) works on simple codegen but fails on optimised
real builds, where the compiler inlines the decode and scatters the ciphertext pointer/length
through heap, struct fields and SIMD moves (see VALIDATION.md). This tool takes the standard
malware-analysis route for that case: run the sample in a controlled process, let it decode
its strings in memory, then scan writable memory and report strings that are NOT present
statically -- i.e. the ones that were decoded at runtime.

It recovers decoded strings regardless of which crate or inlining the obfuscator used, because
it never parses the decoder -- it observes the result. Coverage depends on exercising the code
paths that perform the decode (pass representative argv), exactly like sandbox detonation.

SAFETY: this executes the target. Only run binaries you intend to execute, in a sandbox/VM.
It is meant for controlled analysis of samples, not for running untrusted code on your host.

    python scripts/recover_dynamic.py ./binary                 # default run
    python scripts/recover_dynamic.py ./binary --argv --list   # pass argv to the target
    python scripts/recover_dynamic.py ./binary --min-len 8
"""
from __future__ import annotations
import argparse, subprocess, sys, time
from pathlib import Path
sys_path_added = str(Path(__file__).resolve().parent)
import sys as _sys
if sys_path_added not in _sys.path: _sys.path.insert(0, sys_path_added)
try:
    from recover_callsite import looks_like_text, english_score
except Exception:
    looks_like_text = lambda b: True
    english_score = lambda t: 1.0

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
  send({ t: 'done' });
}
// Scan when the program writes output or exits (strings are decoded by then). frida 17
// renamed the export resolver, so resolve defensively.
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


def run(path: Path, argv: list[str], min_len: int, timeout: float) -> set[str]:
    try:
        import frida
    except ImportError:
        sys.exit("frida not installed: pip install frida frida-tools")

    runtime = set()
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
            elif p.get("t") == "done":
                done["v"] = True

    script.on("message", on_message)
    script.load()
    device.resume(pid)
    t0 = time.time()
    while time.time() - t0 < timeout and not done["v"]:
        time.sleep(0.1)
    try:
        session.detach()
    except Exception:
        pass
    try:
        device.kill(pid)
    except Exception:
        pass
    return runtime


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--argv", nargs=argparse.REMAINDER, default=[], help="args to pass to the target")
    ap.add_argument("--min-len", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args()

    path = Path(args.binary)
    if not path.exists():
        sys.exit(f"no such file: {path}")

    static = static_strings(path, args.min_len)
    runtime = run(path, args.argv, args.min_len, args.timeout)
    decoded = [s for s in runtime if s not in static]
    # Memory scanning surfaces everything in RW memory, most of it runtime noise. Keep the
    # strings that read as real text (same word-likeness gate as the static tool), ranked by
    # how strongly they look like meaningful strings -- the decoded secrets rise to the top.
    import re
    NOISE = re.compile(r"^[A-Z0-9_]+=|frida|_agent|\.so|\.dylib|npm|pip|playwright|sandbox|telemetry", re.I)
    cand = [s for s in decoded
            if looks_like_text(s.encode("latin-1", "ignore")) and not NOISE.search(s)]
    scored = sorted(((english_score(s), s) for s in cand), reverse=True)
    print(f"static strings: {len(static)}   runtime strings: {len(runtime)}   "
          f"runtime-only: {len(decoded)}   text-like: {len(scored)}")
    print("recovered strings (ranked; decoded secrets rank highest):")
    for sc, s in scored:
        print(f"  [{sc:.2f}] {s}")


if __name__ == "__main__":
    main()
