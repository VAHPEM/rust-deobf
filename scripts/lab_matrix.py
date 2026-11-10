#!/usr/bin/env python3
"""lab_matrix.py - run the fast CI subset (`./scripts/check.sh full`) on the real lab and print one
results table, ready to paste into a new VALIDATION.md section.

Targets:
    local   this machine (whatever it is; the label comes from what was measured)
    kali    the ARM64 Kali VM, through dualvm
    win     the Windows 11 ARM64 VM, through dualvm, under an **x64** Python: native ARM64 Python
            cannot run the toolkit (no win_arm64 unicorn / capstone<6 wheels; CLAUDE.md "Test
            matrix"), so an interpreter that is not x64 is refused, not measured.

Each target gets the CURRENT WORKING TREE (git-tracked + untracked-not-ignored files, uncommitted
edits included; no .git) as one tarball, unpacks it into a fresh per-run directory and runs
`check.sh full` there under a small driver script with a real, tree-killing timeout. The remote runs
are dualvm background jobs (jobs.job_start / job_poll). dualvm stays what it is -- it runs things and
hands back raw output; reading pytest's summary line and the junit file happens here.

A target that cannot be run (VM off, SSH down, dualvm not configured, wrong interpreter, missing
dependency, timeout, a run that ends without a pytest summary) is reported as NOT MEASURED with the
reason. Nothing is ever carried over from another target.

    python3 scripts/lab_matrix.py                         # all three, markdown table
    python3 scripts/lab_matrix.py --targets kali,win      # a subset
    python3 scripts/lab_matrix.py --json                  # machine-readable (a list; one dict
                                                          #   for a single target)
    python3 scripts/lab_matrix.py --local-python ~/venv/bin/python --save /tmp/lab
    python3 scripts/lab_matrix.py --selftest              # logic only, no VM

Exit status: 0 every target measured and green; 1 a measured target has red tests; 3 nothing red
but some target was NOT MEASURED; 2 usage error; 130 interrupted (running jobs are stopped).

dualvm is imported lazily (only for kali/win): install it (`pip install -e <dual-vm-ai-agent>`) or
point --dualvm-path / $DUALVM_PATH at its checkout. Needs a git checkout of this repo (source-only:
not shipped in the wheel).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGETS = ("local", "kali", "win")
DUALVM_HOST = {"kali": "kali", "win": "windows"}
NOMINAL = {"local": "this machine (local)", "kali": "ARM64 Kali (kali)",
           "win": "Windows 11 ARM64, x64 Python (win)"}
# the win target measures x64 Python on Windows-on-ARM; an ARM64 interpreter is refused. Checked
# on sysconfig.get_platform() (the interpreter's build): on Windows-on-ARM platform.machine() says
# ARM64 for an x64 python.exe too (measured: it reports the host CPU).
EXPECT_PLATFORM = {"win": ["win-amd64"]}
EXPECT_WHY = {"win": "native ARM64 Python cannot run the toolkit (no win_arm64 unicorn / "
                     "capstone<6 wheels); point --win-python at an x64 python.exe"}
GRACE = 600            # seconds past --timeout before the controller kills a job itself (covers
                       # the dependency probe's own 300 s cap + unpacking + the driver's kill)
STOP_WAIT = 20         # seconds between the polite stop and the hard kill
LOST_AFTER = 4         # consecutive failed polls before a remote target counts as lost
# never ship these even if they are untracked-and-not-ignored
_SECRET_RE = re.compile(r"(^|/)(\.env(\..*)?|\.ssh_keys/.*|.*\.(pem|key))$")


class LabError(Exception):
    """A target could not be run; the message is the NOT MEASURED reason."""


# --------------------------------------------------------------------------------------------
# the driver: runs ON the target, under the interpreter being measured. It only runs things and
# writes raw facts (exit code, host, interpreter, dependency versions) to result.json; it does
# not read the test results. CONFIG is prepended by driver_source().
DRIVER_BODY = r'''
import json, os, platform, re, shlex, shutil, signal, subprocess, sys, sysconfig, tarfile, time, traceback

WORK = os.path.abspath(CONFIG["work"])
TREE = os.path.join(WORK, "tree")
RESULT = os.path.join(WORK, "result.json")
JUNIT = os.path.join(WORK, "junit.xml")
LOG = os.path.join(WORK, "check.log")
IS_WIN = os.name == "nt"
REQUIRED = ("pytest", "lief", "capstone", "unicorn", "z3")
OPTIONAL = ("elftools", "yaml")
_child = None
_t0 = time.time()


def host_info():
    info = {"python": sys.executable, "python_version": platform.python_version(),
            "machine": platform.machine(), "interp_platform": sysconfig.get_platform(),
            "system": platform.system(),
            "release": platform.release(), "version": platform.version(),
            "platform": platform.platform()}
    if IS_WIN:
        info["cpu"] = os.environ.get("PROCESSOR_IDENTIFIER", "")
    elif info["system"] == "Darwin":
        info["mac_ver"] = platform.mac_ver()[0]
    else:
        try:
            info["os_name"] = platform.freedesktop_os_release().get("NAME", "")
        except (OSError, AttributeError):
            pass
    return info


def write_result(**fields):
    d = {"run_id": CONFIG["run_id"], "target": CONFIG["target"],
         "duration": round(time.time() - _t0, 1)}
    d.update(host_info())
    d.update(fields)
    tmp = RESULT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f, indent=1)
    os.replace(tmp, RESULT)          # the controller never sees a half-written file


def ignore_args(check_sh):
    """check.sh full's --ignore list (fallback runner only; normally check.sh itself runs)."""
    m = re.search(r"^\s*full\)(.*?);;", check_sh, re.S | re.M)
    return re.findall(r"--ignore=tests/\S+?\.py", m.group(1)) if m else []


def find_git_bash(env, which, isfile):
    """Git for Windows' bash.exe. Never a bare `bash` from PATH on Windows: System32\\bash.exe is
    WSL, which would run the tests in Linux and measure the wrong host."""
    cands = []
    git = which("git")
    if git:
        cands.append(os.path.join(os.path.dirname(os.path.dirname(git)), "bin", "bash.exe"))
    for var, sub in (("ProgramFiles", ("Git",)), ("ProgramW6432", ("Git",)),
                     ("ProgramFiles(x86)", ("Git",)), ("LOCALAPPDATA", ("Programs", "Git"))):
        if env.get(var):
            cands.append(os.path.join(env[var], *sub, "bin", "bash.exe"))
    for c in cands:
        low = c.lower()
        if "system32" in low or "windowsapps" in low:
            continue
        if isfile(c):
            return c
    return None


def pytest_addopts(junit):
    # pytest shlex-splits PYTEST_ADDOPTS (POSIX rules): forward slashes, quoted
    return "--junitxml=" + shlex.quote(junit.replace("\\", "/")) + " -o junit_family=xunit1"


def kill_tree(p):
    if p is None or p.poll() is not None:
        return
    if IS_WIN:
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        try:
            os.killpg(p.pid, signal.SIGTERM)
            p.wait(timeout=15)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            pass
        try:
            os.killpg(p.pid, signal.SIGKILL)     # stragglers of the group, even if the leader left
        except ProcessLookupError:
            pass
    try:
        p.wait(timeout=30)
    except subprocess.TimeoutExpired:
        pass


def on_term(signum, frame):
    kill_tree(_child)
    write_result(error="stopped by the controller before the run finished", stopped=True)
    os._exit(143)


def probe_deps():
    code = ("import importlib, json\nout = {}\n"
            "for m in %r:\n"
            "    try:\n"
            "        out[m] = str(getattr(importlib.import_module(m), '__version__', '') or 'ok')\n"
            "    except Exception as e:\n"
            "        out[m] = 'MISSING: %%s: %%s' %% (type(e).__name__, e)\n"
            "print(json.dumps(out))\n") % (REQUIRED + OPTIONAL,)
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=300)
    return json.loads(r.stdout.strip().splitlines()[-1])


def main():
    global _child
    os.makedirs(WORK, exist_ok=True)
    if not IS_WIN:
        signal.signal(signal.SIGTERM, on_term)
    print("lab_matrix driver: start", flush=True)
    exp = CONFIG.get("expect_platform")
    if exp and sysconfig.get_platform() not in exp:
        return write_result(error="interpreter %s is %s, this target needs %s: %s" % (
            sys.executable, sysconfig.get_platform(), "/".join(exp), CONFIG.get("expect_why", "")))
    try:
        deps = probe_deps()
    except Exception as e:
        return write_result(error="could not probe the dependencies: %s: %s" % (type(e).__name__, e))
    missing = sorted(m for m in REQUIRED if deps.get(m, "MISSING").startswith("MISSING"))
    if missing:
        return write_result(error="required module(s) not importable: " + ", ".join(
            "%s (%s)" % (m, deps.get(m)) for m in missing), deps=deps)

    tgz = os.path.join(WORK, "tree.tgz")
    try:
        shutil.rmtree(TREE, ignore_errors=True)
        with tarfile.open(tgz, "r:gz") as tf:
            if hasattr(tarfile, "data_filter"):
                tf.extractall(TREE, filter="data")
            else:
                for m in tf.getmembers():
                    parts = m.name.replace("\\", "/").split("/")
                    if m.name.startswith(("/", "\\")) or ".." in parts or not (m.isfile() or m.isdir()):
                        raise ValueError("unexpected tar member %r" % m.name)
                tf.extractall(TREE)
    except Exception as e:
        return write_result(error="could not unpack the tree: %s: %s" % (type(e).__name__, e), deps=deps)

    py = sys.executable
    if IS_WIN:
        bash = find_git_bash(os.environ, shutil.which, os.path.isfile)
        py = py.replace("\\", "/")
    else:
        bash = shutil.which("bash")
    if bash:
        cmd, runner = [bash, "scripts/check.sh", "full"], "check.sh full"
    elif IS_WIN:
        with open(os.path.join(TREE, "scripts", "check.sh"), encoding="utf-8") as f:
            ign = ignore_args(f.read())
        if not ign:
            return write_result(error="no Git Bash, and check.sh full's ignore list could not be read",
                                deps=deps)
        cmd = [sys.executable, "-m", "pytest", "tests", "-q", "-rs"] + ign
        runner = "pytest with check.sh full's arguments (no Git Bash on this host)"
    else:
        return write_result(error="bash not found", deps=deps)

    # every RUST_DEOBF_* opt-in off: the default fast subset everywhere, and the one test that
    # executes a sample (RUST_DEOBF_DYNAMIC) stays skipped
    env = {k: v for k, v in os.environ.items() if not k.startswith("RUST_DEOBF_")}
    env.update(PYTHON=py, PYTEST_ADDOPTS=pytest_addopts(JUNIT), PYTHONUNBUFFERED="1")
    kw = {} if IS_WIN else {"preexec_fn": os.setpgrp}   # own group, same session (see kill paths)
    timed_out, rc = False, None
    with open(LOG, "wb") as log:
        _child = subprocess.Popen(cmd, cwd=TREE, env=env, stdout=log, stderr=subprocess.STDOUT,
                                  stdin=subprocess.DEVNULL, **kw)
        with open(os.path.join(WORK, "child.pid"), "w") as f:
            f.write(str(_child.pid))
        try:
            rc = _child.wait(timeout=CONFIG["timeout"])
        except subprocess.TimeoutExpired:
            timed_out = True
            kill_tree(_child)
    write_result(rc=rc, timed_out=timed_out, timeout=CONFIG["timeout"], runner=runner,
                 bash=bash, deps=deps, junit=os.path.exists(JUNIT))
    if not CONFIG.get("keep"):
        shutil.rmtree(TREE, ignore_errors=True)
        try:
            os.remove(tgz)
        except OSError:
            pass
    print("lab_matrix driver: done rc=%s timed_out=%s" % (rc, timed_out), flush=True)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        try:
            write_result(error="driver crashed: " + traceback.format_exc()[-1500:])
        finally:
            sys.exit(1)
'''


def driver_source(config):
    return ("# lab_matrix driver (generated; see scripts/lab_matrix.py)\n"
            f"import json\nCONFIG = json.loads({json.dumps(config)!r})\n" + DRIVER_BODY)


# --------------------------------------------------------------------------------------------
# snapshot of the working tree

def _git(*args, root=ROOT):
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True).stdout


def list_tree(root=ROOT):
    """Tracked + untracked-not-ignored files that exist (deleted tracked files are skipped)."""
    out = _git("ls-files", "-z", "-co", "--exclude-standard", root=root).decode("utf-8", "surrogateescape")
    files = []
    for rel in sorted(set(filter(None, out.split("\0")))):
        p = Path(root) / rel
        if _SECRET_RE.search(rel) or not (p.is_file() and not p.is_symlink()):
            continue
        files.append(rel)
    return files


def make_tarball(root, files, dest):
    """Write the files to a gzip tarball (POSIX arcnames, modes kept); return its sha256."""
    with tarfile.open(dest, "w:gz", compresslevel=6) as tf:
        for rel in files:
            tf.add(str(Path(root) / rel), arcname=rel.replace(os.sep, "/"), recursive=False)
    h = hashlib.sha256()
    with open(dest, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_meta(root=ROOT):
    try:
        desc = _git("describe", "--always", "--dirty", "--abbrev=7", root=root).decode().strip()
    except (subprocess.CalledProcessError, OSError):
        desc = "?"
    return {"describe": desc}


# --------------------------------------------------------------------------------------------
# reading the results (all interpretation lives here, never in dualvm or the driver)

_SUMMARY_TOKEN = re.compile(r"(\d+) (passed|failed|skipped|errors?|xfailed|xpassed|deselected)\b")


def parse_summary(log_text):
    """Counts from pytest's final summary line (`1 failed, 40 passed, 3 skipped in 9.1s`), or None
    when the run never printed one (crash, kill)."""
    for line in reversed((log_text or "").splitlines()[-60:]):
        s = line.strip().strip("=").strip()
        if not re.search(r"\bin [\d.]+s\b", s):
            continue
        if s.startswith("no tests ran"):
            return {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
        found = _SUMMARY_TOKEN.findall(s)
        if not found:
            continue
        c = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}
        for n, word in found:
            c["errors" if word.startswith("error") else word] = int(n)
        return c
    return None


def _case_id(tc):
    f = (tc.get("file") or "").replace("\\", "/")
    cls, name = tc.get("classname") or "", tc.get("name") or ""
    if f.endswith(".py"):
        mod = f[:-3].replace("/", ".")
        if cls == mod:
            return f"{f}::{name}"
        if cls.startswith(mod + "."):
            return f"{f}::{cls[len(mod) + 1:].replace('.', '::')}::{name}"
    return f"{cls}::{name}" if cls else name


def parse_junit(text):
    """[(test id, 'failure'|'error'), ...] from a pytest junit (xunit1) file; None if unreadable."""
    if not text:
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None
    red, seen = [], set()
    for tc in root.iter("testcase"):
        for kind in ("failure", "error"):
            if tc.find(kind) is not None:
                key = (_case_id(tc), kind)
                if key not in seen:
                    seen.add(key)
                    red.append(key)
    return red


_ARCH = {"win-amd64": "x64", "win-arm64": "ARM64", "win32": "x86", "arm64": "ARM64", "aarch64": "ARM64", "x86_64": "x86-64", "amd64": "x64", "x86": "x86",
         "i686": "x86"}


def host_label(target, res):
    """Label from what the driver MEASURED (OS + the interpreter's architecture); the nominal name
    only when nothing was measured."""
    if not res or "system" not in res:
        return NOMINAL[target]
    system = res["system"]
    # the interpreter's architecture: on Windows only sysconfig knows it (platform.machine() is
    # the host CPU there); elsewhere platform.machine() follows the interpreter (e.g. Rosetta)
    key = res.get("interp_platform") if system == "Windows" else res.get("machine")
    arch = _ARCH.get(str(key or "").lower(), key or "?")
    if system == "Darwin":
        base = f"macOS {res.get('mac_ver') or ''} {arch}".replace("  ", " ")
    elif system == "Linux":
        base = f"{(res.get('os_name') or 'Linux').split()[0]} {arch}"
    elif system == "Windows":
        build = re.findall(r"\d+", str(res.get("version", "")))
        rel = "11" if build and int(build[-1]) >= 22000 else res.get("release", "")
        base = f"Windows {rel}, {arch} Python"
        if "ARM" in str(res.get("cpu", "")).upper() and arch != "ARM64":
            base += " on an ARM64 host"
    else:
        base = f"{system} {arch}"
    return f"{base} ({target})"


def classify(target, run_id, res, log_text=None, junit_text=None, note=None):
    """One target's outcome. `res` is the driver's result.json (None if it never wrote one)."""
    out = {"target": target, "label": host_label(target, res), "status": "not_measured",
           "reason": None, "run_id": run_id}
    if res:
        out["host"] = {k: res.get(k) for k in ("system", "release", "machine", "python",
                                               "python_version", "platform") if k in res}
        for k in ("runner", "deps", "duration", "rc"):
            if k in res:
                out[k] = res[k]

    def nm(reason):
        out["reason"] = reason
        if log_text:
            out["log_tail"] = log_text.splitlines()[-25:]
        return out

    if not res:
        return nm(note or "the target wrote no result")
    if res.get("run_id") != run_id:
        return nm(f"stale result from run {res.get('run_id')!r}")
    if res.get("error"):
        return nm(res["error"] + (f" ({note})" if note else ""))
    if res.get("timed_out"):
        return nm(f"timed out after {res.get('timeout')} s (the run was killed; no counts)")
    rc = res.get("rc")
    if rc is None:
        return nm(note or "no exit code")
    counts = parse_summary(log_text)
    if counts is None:
        return nm(f"check.sh exited {rc} without a pytest summary line")
    if rc not in (0, 1):
        return nm(f"pytest exit code {rc} (interrupted / internal / usage error / no tests)")
    n_red = counts["failed"] + counts["errors"]
    if (rc == 0) != (n_red == 0):
        return nm(f"exit code {rc} contradicts the summary ({n_red} failed+errors)")
    out.update(status="measured", reason=None, **counts)
    red = parse_junit(junit_text)
    if red is None:
        out["red"] = None
        if n_red:
            out["note"] = "junit file missing/unreadable: red test names unknown"
    else:
        out["red"] = [{"test": t, "kind": k} for t, k in red]
        if len(red) != n_red:
            out["note"] = (f"junit lists {len(red)} red test(s), the summary counts {n_red} "
                           "(a teardown error counts as passed + error in the summary)")
    return out


def _cell(r):
    if r["status"] != "measured":
        return f"**NOT MEASURED**: {r['reason']}".replace("|", "\\|").replace("\n", " ")
    red = r["failed"] + r["errors"]
    head = f"{r['failed']} failed" + (f", {r['errors']} errors" if r["errors"] else "")
    head += f" / {r['passed']} passed"
    s = f"**{head}**" if red else head
    s += f" / {r['skipped']} skipped"
    for k in ("xfailed", "xpassed"):
        if r.get(k):
            s += f", {r[k]} {k}"
    return s


def render_table(results, meta):
    lines = ["| target | result |", "| --- | --- |"]
    lines += [f"| {r['label']} | {_cell(r)} |" for r in results]
    lines.append("")
    for r in results:
        if r["status"] == "measured" and r.get("red"):
            lines.append(f"Red on {r['label']}:")
            lines += [f"- `{x['test']}` ({x['kind']})" for x in r["red"]]
            lines.append("")
        if r.get("note"):
            lines.append(f"Note ({r['label']}): {r['note']}")
            lines.append("")
    lines.append(f"Tree `{meta.get('describe', '?')}` ({meta.get('files', '?')} files, "
                 f"sha256 {str(meta.get('sha256', '?'))[:12]}), run `{meta.get('run_id', '?')}`, "
                 f"{meta.get('date', '?')}; `./scripts/check.sh full` per target:")
    for r in results:
        h = r.get("host") or {}
        if h:
            lines.append(f"- {r['label']}: Python {h.get('python_version')} `{h.get('python')}`; "
                         f"{r.get('runner', '-')}; {r.get('duration', '?')} s")
    return "\n".join(lines).rstrip() + "\n"


def exit_code(results):
    if any(r["status"] == "measured" and (r["failed"] or r["errors"]) for r in results):
        return 1
    if any(r["status"] != "measured" for r in results):
        return 3
    return 0


# --------------------------------------------------------------------------------------------
# running: one controller thread (dualvm's SSH pool is a plain module dict, not thread-safe)

def _log(msg):
    print(f"[lab_matrix] {msg}", file=sys.stderr, flush=True)


def _dualvm(path=None):
    p = path or os.environ.get("DUALVM_PATH")
    if p and p not in sys.path:
        sys.path.insert(0, p)
    try:
        from dualvm import jobs, remote, shell        # noqa: PLC0415 (optional, lab only)
    except Exception as e:                            # ImportError, or KeyError on unset KALI_HOST
        raise LabError(f"dualvm unavailable ({type(e).__name__}: {e})") from None
    return jobs, remote, shell


class _Target:
    def __init__(self, name, run_id, cfg):
        self.name, self.run_id, self.cfg = name, run_id, cfg
        self.result = None
        self.deadline = None
        self.note = None

    def config(self, work):
        c = {"run_id": self.run_id, "target": self.name, "work": work,
             "timeout": self.cfg["timeout"], "keep": self.cfg["keep"]}
        if self.name in EXPECT_PLATFORM:
            c.update(expect_platform=EXPECT_PLATFORM[self.name], expect_why=EXPECT_WHY[self.name])
        return c


class LocalTarget(_Target):
    def start(self, tgz):
        self.work = tempfile.mkdtemp(prefix=f"rdlab-{self.run_id}-local-")
        shutil.copy(tgz, os.path.join(self.work, "tree.tgz"))
        drv = os.path.join(self.work, "driver.py")
        Path(drv).write_text(driver_source(self.config(self.work)), encoding="utf-8")
        py = self.cfg.get("python") or sys.executable
        kw = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" \
            else {"start_new_session": True}
        self._out = open(os.path.join(self.work, "driver.log"), "wb")
        self.p = subprocess.Popen([py, drv], cwd=self.work, stdout=self._out,
                                  stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kw)
        _log(f"local: started (pid {self.p.pid}, {py})")

    def poll(self):
        return "running" if self.p.poll() is None else "finished"

    def _read(self, name):
        try:
            return Path(self.work, name).read_bytes()
        except OSError:
            return None

    def fetch(self):
        return self._read("result.json"), self._read("check.log"), self._read("junit.xml")

    def hard_stop(self):
        if self.p.poll() is not None:
            return
        if os.name == "nt":
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(self.p.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            try:
                os.kill(self.p.pid, signal.SIGTERM)       # the driver kills its run, writes a result
                self.p.wait(timeout=STOP_WAIT)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                child = (self._read("child.pid") or b"").strip()
                for pg in ([int(child)] if child.isdigit() else []) + [self.p.pid]:
                    try:
                        os.killpg(pg, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
        try:
            self.p.wait(timeout=30)
        except subprocess.TimeoutExpired:
            pass

    def cleanup(self):
        try:
            self._out.close()
        except Exception:  # noqa: BLE001
            pass
        if not self.cfg["keep"]:
            shutil.rmtree(self.work, ignore_errors=True)


def _bounded(seconds, fn, *a, **kw):
    """fn(*a, **kw) with a wall-clock cap. dualvm's SFTP calls (upload, read_bytes, the script
    write inside job_start) have no timeout of their own, so a VM that stalls mid-transfer would
    hang the controller until TCP gives up. The call runs in a daemon thread while this (the only
    controller) thread waits -- never two dualvm calls at once. On timeout the thread is abandoned
    and raises TimeoutError; the caller must not touch that host again (its pooled connection may
    still be held by the stuck call)."""
    import threading
    box = {}

    def run():
        try:
            box["v"] = fn(*a, **kw)
        except BaseException as e:  # noqa: BLE001 - re-raised in the caller
            box["e"] = e
    th = threading.Thread(target=run, daemon=True)
    th.start()
    th.join(seconds)
    if th.is_alive():
        raise TimeoutError(f"no answer within {seconds} s")
    if "e" in box:
        raise box["e"]
    return box.get("v")


class RemoteTarget(_Target):
    CALL_CAP = 300            # seconds for one upload / job_start / poll / read-back

    def _call(self, fn, *a, **kw):
        if getattr(self, "wedged", None):
            raise TimeoutError(self.wedged)
        try:
            return _bounded(self.CALL_CAP, fn, *a, **kw)
        except TimeoutError as e:
            self.wedged = f"{self.host} stopped answering ({e}); not contacted again this run"
            raise

    def start(self, tgz):
        self.host = DUALVM_HOST[self.name]
        self.jobs, self.remote, self.shell = _dualvm(self.cfg.get("dualvm_path"))
        self.rel = f"rdlab/{self.run_id}-{self.name}"           # under the VM's samples/ dir
        self.job = f"rdlab-{self.name}-{self.run_id}"
        self.pid, self.fails = None, 0
        try:
            self._call(self.remote.upload, tgz, f"{self.rel}/tree.tgz", host=self.host)
        except Exception as e:  # noqa: BLE001 - paramiko / socket / SFTP errors
            raise LabError(f"could not reach {self.host} to upload the tree "
                           f"({type(e).__name__}: {e})") from None
        try:
            r = self._call(self.jobs.job_start, self.job,
                           script=driver_source(self.config(self.rel)),
                           host=self.host, python=self.cfg.get("python"))
        except TimeoutError as e:
            raise LabError(f"job_start on {self.host} did not answer ({e}); the job may or may "
                           f"not be running there as {self.job}") from None
        if not r.ok:
            raise LabError(f"job_start on {self.host} failed: {r.summary}")
        m = re.search(r"\bpid (\d+)", r.summary or "")
        self.pid = m.group(1) if m else None
        _log(f"{self.name}: started job {self.job} on {self.host} (pid {self.pid})")

    def poll(self):
        try:
            r = self._call(self.jobs.job_poll, self.job, tail=3, host=self.host)
        except TimeoutError:
            self.note = self.wedged
            return "lost"
        if not r.ok:
            if "no job named" in (r.summary or ""):
                self.note = f"the job vanished on {self.host}: {r.summary}"
                return "lost"
            self.fails += 1
            if self.fails >= LOST_AFTER:
                self.note = f"lost contact with {self.host}: {r.summary}"
                return "lost"
            return "running"
        self.fails = 0
        self.last_detail = r.detail or ""
        m = re.search(r"STATE=(\w+)", r.detail or "")
        return "finished" if m and m.group(1) == "FINISHED" else "running"

    def _read(self, name):
        try:
            return self._call(self.remote.read_bytes, f"samples/{self.rel}/{name}", host=self.host)
        except Exception:  # noqa: BLE001 - missing file, connection, wedged: the caller says so
            return None

    def fetch(self):
        return self._read("result.json"), self._read("check.log"), self._read("junit.xml")

    def hard_stop(self):
        if not self.pid:
            return
        try:
            if self.host == "windows":
                # the job's cmd.exe -> driver -> bash -> python: /T takes the whole tree
                self._call(self.shell.run_cmd, f"taskkill /T /F /PID {self.pid}",
                           host="windows", timeout=30)
            else:
                # TERM to the job's group (the driver's handler kills its own run group and writes a
                # result), then KILL everything left in the job's session -- the driver put its run
                # in its own group but the same session for exactly this
                self._call(self.jobs.job_poll, self.job, stop=True, host=self.host)
                time.sleep(STOP_WAIT)
                self._call(self.shell.run_cmd, f"pkill -KILL -s {self.pid}; true",
                           host=self.host, timeout=30)
        except Exception as e:  # noqa: BLE001
            self.note = ((self.note + "; ") if self.note else "") + \
                f"could not confirm the stop on {self.host} ({type(e).__name__}: {e}): " \
                f"job {self.job} (pid {self.pid}) may still be running there"

    def cleanup(self):
        pass                      # the driver removes the unpacked tree; result files stay small


def _decode(b):
    return b.decode("utf-8", "replace") if b is not None else None


def run_matrix(targets, timeout=3600, poll=15, keep=False, pythons=None, dualvm_path=None,
               save=None, root=ROOT):
    """Run check.sh full on each target; return (results, meta)."""
    pythons = pythons or {}
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + os.urandom(2).hex()
    meta = {"run_id": run_id, "date": datetime.now().strftime("%Y-%m-%d"), **tree_meta(root)}
    files = list_tree(root)
    meta["files"] = len(files)
    tmpdir = tempfile.mkdtemp(prefix="rdlab-snap-")
    tgz = os.path.join(tmpdir, "tree.tgz")
    meta["sha256"] = make_tarball(root, files, tgz)
    _log(f"snapshot {meta['describe']}: {len(files)} files, "
         f"{os.path.getsize(tgz) // 1024} KiB, run {run_id}")

    runs, results = [], {}
    try:
        for name in targets:
            cfg = {"timeout": timeout, "keep": keep, "python": pythons.get(name),
                   "dualvm_path": dualvm_path}
            t = (LocalTarget if name == "local" else RemoteTarget)(name, run_id, cfg)
            try:
                t.start(tgz)
            except LabError as e:
                results[name] = classify(name, run_id, None, note=str(e))
                _log(f"{name}: NOT MEASURED - {e}")
                continue
            except Exception as e:  # noqa: BLE001 - anything else is still "could not run"
                results[name] = classify(name, run_id, None, note=f"{type(e).__name__}: {e}")
                _log(f"{name}: NOT MEASURED - {type(e).__name__}: {e}")
                continue
            t.deadline = time.monotonic() + timeout + GRACE
            t.next_poll = 0.0
            runs.append(t)

        pending = list(runs)
        while pending:
            now = time.monotonic()
            for t in list(pending):
                if isinstance(t, RemoteTarget) and now < t.next_poll:
                    continue
                state = t.poll()
                t.next_poll = now + poll
                if state == "running" and now > t.deadline:
                    _log(f"{t.name}: past the deadline, stopping it")
                    t.hard_stop()
                    t.note = "; ".join(filter(None, [
                        f"stopped by the controller {timeout + GRACE} s after start", t.note]))
                    state = "finished"
                if state == "running":
                    continue
                res, log, junit = t.fetch()
                for _ in range(3 if isinstance(t, RemoteTarget) and res is None else 0):
                    time.sleep(3)                   # a blip while reading back != "no result"
                    res, log, junit = t.fetch()
                    if res is not None:
                        break
                try:
                    res = json.loads(res) if res else None
                except ValueError:
                    res = None
                if state == "lost" and res is None:
                    t.hard_stop()
                if state == "finished" and res is None and isinstance(t, RemoteTarget) and \
                        "__JOB_RC=" not in getattr(t, "last_detail", ""):
                    t.note = "; ".join(filter(None, [
                        "the job ended without its exit marker or a result, i.e. it was killed "
                        "from outside before the driver finished (seen on Windows with a dualvm "
                        "whose job_start used Start-Process: the job died with the SSH call)",
                        t.note]))
                results[t.name] = classify(t.name, run_id, res, _decode(log), _decode(junit),
                                           note=t.note)
                if save:
                    _save(save, t.name, res, log, junit)
                t.cleanup()
                pending.remove(t)
                r = results[t.name]
                _log(f"{t.name}: " + (f"{r['failed']} failed / {r['passed']} passed / "
                                      f"{r['skipped']} skipped" if r["status"] == "measured"
                                      else f"NOT MEASURED - {r['reason']}"))
            if pending:
                time.sleep(2)
    except KeyboardInterrupt:
        for t in runs:
            if t.name not in results:
                t.hard_stop()
                results[t.name] = classify(t.name, run_id, None,
                                           note="interrupted by the user (job stopped)")
                t.cleanup()
        raise _Interrupted([results[n] for n in targets if n in results], meta) from None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return [results[n] for n in targets], meta


class _Interrupted(Exception):
    def __init__(self, results, meta):
        super().__init__("interrupted")
        self.results, self.meta = results, meta


def _save(d, name, res, log, junit):
    os.makedirs(d, exist_ok=True)
    for suffix, data in (("result.json", json.dumps(res, indent=1).encode() if res else None),
                         ("check.log", log), ("junit.xml", junit)):
        if data is not None:
            Path(d, f"{name}.{suffix}").write_bytes(data)


# --------------------------------------------------------------------------------------------

def _selftest():
    import ast
    # the driver is valid Python and its helpers behave
    src = driver_source({"run_id": "r", "target": "win", "work": "w", "timeout": 5, "keep": False})
    ast.parse(src)
    ns = {"__name__": "lab_matrix_driver_selftest"}
    exec(compile(src, "<driver>", "exec"), ns)              # noqa: S102 - our own source
    check_sh = ("case x in\n  gate) foo --ignore=tests/test_no.py ;;\n  full)\n"
                "    exec py -m pytest tests -q -rs \\\n      --ignore=tests/test_a.py "
                "--ignore=tests/test_b.py\n    ;;\nesac\n")
    assert ns["ignore_args"](check_sh) == ["--ignore=tests/test_a.py", "--ignore=tests/test_b.py"]
    assert ns["ignore_args"]("nothing") == []
    fgb, J = ns["find_git_bash"], os.path.join          # J: the selftest runs on Windows too
    present = {J("/pf", "Git", "bin", "bash.exe"), J("/sys", "System32", "bash.exe")}
    assert fgb({"ProgramFiles": "/pf"}, lambda _: None, present.__contains__) == \
        J("/pf", "Git", "bin", "bash.exe")
    assert fgb({}, lambda _: J("/git", "cmd", "git.exe"),
               {J("/git", "bin", "bash.exe")}.__contains__) == J("/git", "bin", "bash.exe")
    # WSL's bash is never picked, even when it is the only bash there is
    assert fgb({"ProgramFiles": J("/sys", "System32")}, lambda _: None,
               {J("/sys", "System32", "Git", "bin", "bash.exe")}.__contains__) is None
    assert fgb({}, lambda _: None, present.__contains__) is None
    ao = ns["pytest_addopts"]("C:\\Users\\a b\\junit.xml")
    import shlex
    assert shlex.split(ao) == ["--junitxml=C:/Users/a b/junit.xml", "-o", "junit_family=xunit1"], ao

    # summary line
    assert parse_summary("x\n2 failed, 3 passed, 1 skipped, 1 xfailed, 2 errors in 0.02s\n") == \
        {"passed": 3, "failed": 2, "errors": 2, "skipped": 1, "xfailed": 1}
    assert parse_summary("==== 5 passed in 1.00s ====") == \
        {"passed": 5, "failed": 0, "errors": 0, "skipped": 0}
    assert parse_summary("1 error in 0.10s")["errors"] == 1
    assert parse_summary("no tests ran in 0.01s")["passed"] == 0
    assert parse_summary("Traceback ...\nKilled\n") is None
    assert parse_summary("") is None and parse_summary(None) is None

    # junit (xunit1, the shapes pytest writes)
    junit = ('<?xml version="1.0"?><testsuites><testsuite>'
             '<testcase classname="tests.test_td" name="test_t" file="tests/test_td.py"><error/></testcase>'
             '<testcase classname="tests.test_x" name="test_ok" file="tests/test_x.py"/>'
             '<testcase classname="tests.test_x" name="test_sk" file="tests/test_x.py"><skipped/></testcase>'
             '<testcase classname="tests.test_x.TestC" name="test_p[x y]" file="tests/test_x.py">'
             '<failure message="m">tb</failure></testcase>'
             '<testcase classname="tests.sub.test_y" name="t" file="tests\\sub\\test_y.py"><failure/></testcase>'
             '</testsuite></testsuites>')
    assert parse_junit(junit) == [("tests/test_td.py::test_t", "error"),
                                  ("tests/test_x.py::TestC::test_p[x y]", "failure"),
                                  ("tests/sub/test_y.py::t", "failure")], parse_junit(junit)
    assert parse_junit("") is None and parse_junit("<not xml") is None

    # classification: never a count without a clean run
    base = {"run_id": "R", "system": "Linux", "machine": "aarch64", "os_name": "Kali GNU/Linux",
            "python": "/v/bin/python3", "python_version": "3.13.1", "runner": "check.sh full"}
    ok = classify("kali", "R", dict(base, rc=0), "10 passed, 2 skipped in 3.0s", junit_text="<a/>")
    assert ok["status"] == "measured" and ok["passed"] == 10 and ok["red"] == [], ok
    assert ok["label"] == "Kali ARM64 (kali)", ok["label"]
    red = classify("kali", "R", dict(base, rc=1), "1 failed, 9 passed in 3.0s", junit)
    assert red["status"] == "measured" and red["failed"] == 1 and len(red["red"]) == 3
    assert "summary counts 1" in red["note"]
    for res, log, why in [
            (None, None, "wrote no result"),
            (dict(base, run_id="OLD", rc=0), "1 passed in 1s", "stale"),
            (dict(base, error="required module(s) not importable: unicorn"), None, "unicorn"),
            (dict(base, timed_out=True, timeout=60, rc=None), None, "timed out after 60"),
            (dict(base, rc=1), "Killed\n", "without a pytest summary"),
            (dict(base, rc=2), "1 error in 1.0s", "exit code 2"),
            (dict(base, rc=0), "1 failed, 2 passed in 1.0s", "contradicts"),
            (dict(base, rc=1), "3 passed in 1.0s", "contradicts")]:
        c = classify("kali", "R", res, log, note=None)
        assert c["status"] == "not_measured" and why in c["reason"], (why, c)
        assert "passed" not in c, c                       # no counts leak into an unmeasured row
    lost = classify("win", "R", None, note="lost contact with windows: timeout")
    assert lost["label"] == NOMINAL["win"] and "lost contact" in lost["reason"]

    # labels come from the measurement
    # measured on the Windows 11 ARM64 VM: an x64 python.exe reports machine ARM64 (the host)
    win = dict(base, system="Windows", machine="ARM64", interp_platform="win-amd64", release="10",
               version="10.0.26100", cpu="ARMv8 (64-bit) Family 8 Model 0 Revision 0, QEMU")
    assert host_label("win", win) == "Windows 11, x64 Python on an ARM64 host (win)"
    assert host_label("win", dict(win, interp_platform="win-arm64")) == "Windows 11, ARM64 Python (win)"
    assert host_label("local", dict(base, system="Darwin", machine="arm64", mac_ver="15.5")) == \
        "macOS 15.5 ARM64 (local)"

    # table: the NOT MEASURED row carries its reason, never numbers; pipes are escaped
    table = render_table([ok, red, lost], {"describe": "abc1234-dirty", "files": 3,
                                            "sha256": "f" * 64, "run_id": "R", "date": "2026-11-10"})
    assert "| Kali ARM64 (kali) | 0 failed / 10 passed / 2 skipped |" in table, table
    assert "**1 failed / 9 passed** / 0 skipped" in table
    assert f"| {NOMINAL['win']} | **NOT MEASURED**: lost contact" in table
    assert "- `tests/test_x.py::TestC::test_p[x y]` (failure)" in table
    assert "**NOT MEASURED**: a \\| b" in _cell({"status": "not_measured", "reason": "a | b"})
    assert exit_code([ok]) == 0 and exit_code([ok, lost]) == 3 and exit_code([red, lost]) == 1

    # bounded calls: value, exception and timeout all come back; a wedged host is never re-called
    assert _bounded(5, lambda x: x + 1, 1) == 2
    try:
        _bounded(5, lambda: 1 / 0)
        raise AssertionError("exception swallowed")
    except ZeroDivisionError:
        pass
    calls = []

    def slow(*_a, **_k):
        calls.append(1)
        time.sleep(3)
    rt = RemoteTarget("kali", "R", {"timeout": 1, "keep": False})
    rt.host, rt.CALL_CAP = "kali", 0.2
    rt.jobs = type("J", (), {"job_poll": staticmethod(slow)})
    rt.job = "x"
    assert rt.poll() == "lost" and "stopped answering" in rt.note
    assert rt.poll() == "lost" and calls == [1], calls      # not contacted again

    # snapshot: posix arcnames, secrets never shipped, modes kept
    with tempfile.TemporaryDirectory() as d:
        for rel in ("a.txt", "scripts/check.sh", ".env", "sub/.env.local", "k/id.pem"):
            Path(d, rel).parent.mkdir(parents=True, exist_ok=True)
            Path(d, rel).write_text(rel)
        os.chmod(Path(d, "scripts/check.sh"), 0o755)
        keep = [r for r in ("a.txt", "scripts/check.sh", ".env", "sub/.env.local", "k/id.pem")
                if not _SECRET_RE.search(r)]
        assert keep == ["a.txt", "scripts/check.sh"], keep
        out = os.path.join(d, "t.tgz")
        assert len(make_tarball(d, keep, out)) == 64
        with tarfile.open(out) as tf:
            names = {m.name: m.mode for m in tf.getmembers()}
        assert set(names) == {"a.txt", "scripts/check.sh"}
        assert os.name == "nt" or names["scripts/check.sh"] & 0o100
    print("selftest OK")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--targets", default=",".join(TARGETS),
                    help="comma list from: " + ", ".join(TARGETS) + " (default: all)")
    ap.add_argument("--timeout", type=int, default=3600,
                    help="seconds per target for check.sh full (killed past it; default 3600)")
    ap.add_argument("--poll", type=int, default=15, help="seconds between remote job polls")
    ap.add_argument("--json", action="store_true", help="print the result(s) as JSON")
    ap.add_argument("--keep", action="store_true", help="keep the unpacked trees on the targets")
    ap.add_argument("--save", metavar="DIR", help="also save each target's check.log/junit/result")
    ap.add_argument("--local-python", help="interpreter for local (default: this one)")
    ap.add_argument("--kali-python", help="interpreter on Kali (default: dualvm's KALI_PYTHON)")
    ap.add_argument("--win-python", help="x64 python.exe on Windows (default: dualvm's WIN_PYTHON_EXE)")
    ap.add_argument("--dualvm-path", help="dualvm checkout to import from (or $DUALVM_PATH)")
    ap.add_argument("--selftest", action="store_true", help="logic only, no VM")
    a = ap.parse_args(argv)
    if a.selftest:
        _selftest()
        return 0
    targets = list(dict.fromkeys(t.strip() for t in a.targets.split(",") if t.strip()))
    bad = [t for t in targets if t not in TARGETS]
    if not targets or bad:
        ap.error(f"unknown target(s) {bad}; choose from {', '.join(TARGETS)}")
    if a.timeout <= 0 or a.poll <= 0:
        ap.error("--timeout and --poll must be positive")
    if not (ROOT / ".git").exists():
        ap.error("needs a git checkout of rust-deobf (it ships the working tree)")
    pythons = {"local": a.local_python, "kali": a.kali_python, "win": a.win_python}
    try:
        results, meta = run_matrix(targets, a.timeout, a.poll, a.keep, pythons, a.dualvm_path, a.save)
        rc = exit_code(results)
    except _Interrupted as e:
        results, meta, rc = e.results, e.meta, 130
    if a.json:
        for r in results:
            r["tree"] = {k: meta.get(k) for k in ("describe", "files", "sha256", "date")}
        print(json.dumps(results[0] if len(results) == 1 else results, indent=1))
    else:
        print(render_table(results, meta), end="")
    return rc


if __name__ == "__main__":
    sys.exit(main())
