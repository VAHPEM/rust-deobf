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

SAFETY: this executes the target AND scans the whole process address space. Run it ONLY inside
an isolated analysis VM/sandbox dedicated to the sample. Two reasons: (1) you are executing the
sample; (2) the memory scan reads all readable+writable memory of the process, so anything else
resident in that process or injected agent (environment, other secrets) is also surfaced as
noise -- in a shared/host environment that can leak unrelated data. In a clean sandbox the only
interesting memory is the sample's own, which is the point.

Because it executes the target, it refuses to start without --i-understand-this-executes, and
prints a warning when it cannot find signs of a VM/hypervisor (a best-effort heuristic only -- it
is not a sandbox check and a missing warning proves nothing).

    python scripts/recover_dynamic.py ./binary --i-understand-this-executes
    python scripts/recover_dynamic.py ./binary --i-understand-this-executes --argv --list
    python scripts/recover_dynamic.py ./binary --i-understand-this-executes --min-len 8
"""
from __future__ import annotations
import argparse, platform, re, subprocess, sys, time
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
  try { for (const m of Process.enumerateModules()) if (m.path) send({ t: 'mod', p: m.path }); } catch (e) {}
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


# Hypervisor / VM vendor strings seen in DMI, sysctl and WMI output.
_VM_VENDORS = re.compile(r"vmware|virtualbox|vbox|qemu|kvm|xen|parallels|hyper-v|microsoft corporation"
                         r" virtual|virtual machine|bochs|bhyve|utm|apple virtualization|amazon ec2|"
                         r"google compute|openstack", re.I)


def vm_hint() -> str | None:
    """Best-effort: a short description of why this looks like a VM/container, or None when no sign
    was found. A heuristic to catch the obvious mistake (running on the analyst's own host); it is
    not a security boundary and is trivially wrong in both directions."""
    sysname = platform.system()
    try:
        if sysname == "Linux":
            for f in ("/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name",
                      "/sys/class/dmi/id/board_vendor"):
                try:
                    txt = Path(f).read_text(errors="ignore").strip()
                except OSError:
                    continue
                if _VM_VENDORS.search(txt):
                    return f"{f}: {txt}"
            try:
                if re.search(r"^flags\s*:.*\bhypervisor\b", Path("/proc/cpuinfo").read_text(errors="ignore"), re.M):
                    return "/proc/cpuinfo: hypervisor flag"
            except OSError:
                pass
            if Path("/.dockerenv").exists() or Path("/run/.containerenv").exists():
                return "container (/.dockerenv or /run/.containerenv)"
        elif sysname == "Darwin":
            out = subprocess.run(["sysctl", "-n", "kern.hv_vmm_present"], capture_output=True,
                                 text=True, timeout=5).stdout.strip()
            if out == "1":
                return "sysctl kern.hv_vmm_present=1"
        elif sysname == "Windows":
            out = subprocess.run(["powershell", "-NoProfile", "-Command",
                                  "(Get-CimInstance Win32_ComputerSystem | "
                                  "Select-Object -ExpandProperty Model,Manufacturer) -join ' '"],
                                 capture_output=True, text=True, timeout=20).stdout
            if _VM_VENDORS.search(out):
                return f"Win32_ComputerSystem: {out.strip()}"
    except Exception:
        pass
    return None


# What the memory scan picks up from the tooling itself, not from the sample. Anchored on purpose: a
# substring/case-insensitive filter ("pip", "telemetry", ".so", "sandbox") drops real recovered
# strings -- "\\.\pipe\x" contains "pip", a C2 URL can contain "telemetry", and "evil.solutions"
# contains ".so".
_ENV_LINE = re.compile(r"^[A-Z_][A-Z0-9_]*=")              # environment block: NAME=value (upper-case)
_SHARED_LIB_PATH = re.compile(r"^/\S*\.(?:so(?:\.\d+)*|dylib)$")     # loaded module paths
_FRIDA_PATH = re.compile(r"^(?:/|[A-Za-z]:[\\/])\S*[/\\](?:frida|re\.frida)[\w.\-]*(?:[/\\]\S*)?$",
                         re.I)                                         # the injected agent's files
_FRIDA_SYMBOL = re.compile(r"^(?:frida_agent_main|frida:rpc|FridaScriptEngine)$")


def is_tool_noise(s: str) -> bool:
    return bool(_ENV_LINE.match(s) or _SHARED_LIB_PATH.match(s) or _FRIDA_PATH.match(s)
                or _FRIDA_SYMBOL.match(s))


def run(path: Path, argv: list[str], min_len: int, timeout: float):
    try:
        import frida
    except ImportError:
        sys.exit("frida not installed: pip install frida frida-tools")

    runtime = set()
    mods = set()
    device = frida.get_local_device()
    pid = None
    session = None
    try:
        pid = device.spawn([str(path)] + argv)
        session = device.attach(pid)
        script = session.create_script(SCAN_JS.replace("MINLEN", str(int(min_len))))
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
        t0 = time.monotonic()
        while time.monotonic() - t0 < timeout and not done["v"]:
            time.sleep(0.1)
    finally:
        # always tear down -- on success, on an error, and on Ctrl-C -- so the sample never keeps
        # running after this tool exits (kill first: it must happen even if detach misbehaves)
        if pid is not None:
            try:
                device.kill(pid)
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
    return runtime, mods


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary")
    ap.add_argument("--i-understand-this-executes", dest="ack", action="store_true",
                    help="required: confirms you are inside an isolated analysis VM, because this "
                         "RUNS the sample")
    ap.add_argument("--argv", nargs=argparse.REMAINDER, default=[], help="args to pass to the target")
    ap.add_argument("--min-len", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=8.0)
    args = ap.parse_args(argv)

    path = Path(args.binary)
    if not args.ack:
        ap.error("this tool EXECUTES the target. Run it only inside an isolated analysis VM "
                 "dedicated to the sample, and pass --i-understand-this-executes to confirm.")
    if not path.is_file():
        sys.exit(f"no such file: {path}")
    if args.min_len < 1:
        ap.error("--min-len must be a positive integer")
    hint = vm_hint()
    if hint:
        print(f"[recover_dynamic] VM/container signs: {hint}", file=sys.stderr)
    else:
        print("[recover_dynamic] WARNING: no VM/hypervisor signs found -- this may be a physical "
              "host. The sample is about to run. Ctrl-C now if this is not an isolated analysis VM.",
              file=sys.stderr)
        try:
            time.sleep(3)
        except KeyboardInterrupt:
            sys.exit("[recover_dynamic] aborted before the target was started")

    static = static_strings(path, args.min_len)
    try:
        runtime, mods = run(path, args.argv, args.min_len, args.timeout)
    except KeyboardInterrupt:
        sys.exit("[recover_dynamic] interrupted; the target process was killed")
    # Subtract strings that belong to loaded shared libraries (libc, ld, ...): they are
    # runtime noise, not decoded secrets. The target's own module is excluded from this
    # subtraction so we don't drop its decoded output.
    lib_strings = set()
    for m in mods:
        try:
            if Path(m).resolve() == path.resolve(): continue
        except Exception:
            pass
        lib_strings |= static_strings(Path(m), args.min_len)
    static = static | lib_strings
    decoded = [s for s in runtime if s not in static]
    # Memory scanning surfaces everything in RW memory, most of it runtime noise. Keep the
    # strings that read as real text (same word-likeness gate as the static tool), ranked by
    # how strongly they look like meaningful strings -- the decoded secrets rise to the top.
    cand = [s for s in decoded
            if looks_like_text(s.encode("latin-1", "ignore")) and not is_tool_noise(s)]
    scored = sorted(((english_score(s), s) for s in cand), reverse=True)
    print(f"static strings: {len(static)}   runtime strings: {len(runtime)}   "
          f"runtime-only: {len(decoded)}   text-like: {len(scored)}")
    print("recovered strings (ranked; decoded secrets rank highest):")
    for sc, s in scored:
        print(f"  [{sc:.2f}] {s}")


if __name__ == "__main__":
    main()
