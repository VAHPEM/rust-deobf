"""lab_matrix's remote targets against the REAL labhand package with its SSH/SFTP layer stubbed.

No VM is contacted: labhand's connection getters raise, `_sftp_op` runs against an in-memory
SFTP and `ssh_exec` only records the command. labhand's .env is never read (LABHAND_ENV is
pointed at the null device before labhand is imported, and the inventory comes from the
environment each test sets). Skipped where labhand is not importable (CI: it is the private
lab-control package), so these run on the maintainer's machine.

- *lab_matrix_workdir*: results are read back from labhand's working directory
  ($LABHAND_WORKDIR), not a literal samples/ (review finding F1).
- *lab_matrix_inventory*: kali / win resolve to inventory hosts by OS, a broken inventory is
  reported as such (not as "could not reach"), the stop path follows the host's OS (F2, F3).
"""
import json
import os
import sys

import pytest

import lab_matrix

# never the real lab .env: set before labhand.hosts runs load_dotenv() at import
if "labhand.hosts" in sys.modules and os.environ.get("LABHAND_ENV") != os.devnull:
    pytest.skip("labhand was imported earlier in this process with its real .env",
                allow_module_level=True)
os.environ["LABHAND_ENV"] = os.devnull
_p = lab_matrix.lab_path()
if _p and _p not in sys.path:
    sys.path.insert(0, _p)
hosts = pytest.importorskip("labhand.hosts", reason="labhand (lab-control package) not installed")
remote = pytest.importorskip("labhand.remote")
jobs = pytest.importorskip("labhand.jobs")
shell = pytest.importorskip("labhand.shell")

_ENV_PREFIXES = ("LABHAND_HOSTS", "LABHAND_WORKDIR", "KALI_", "WIN_", "WINDOWS_", "LAB_", "W2_")
PID = "4242"


class _File:
    def __init__(self, store, path, mode):
        self.store, self.path, self.mode = store, path, mode

    def __enter__(self):
        if "r" in self.mode and self.path not in self.store:
            raise IOError(2, "No such file", self.path)
        return self

    def __exit__(self, *a):
        return False

    def write(self, data):
        self.store[self.path] = data.encode() if isinstance(data, str) else bytes(data)

    def read(self):
        return self.store[self.path]


class FakeSFTP:
    """The subset of paramiko's SFTPClient labhand's upload / write_remote / read_bytes use."""

    def __init__(self, lab):
        self.lab = lab

    def mkdir(self, p):
        self.lab.dirs.add(p)

    def stat(self, p):
        raise IOError(2, "No such file", p)

    lstat = stat

    def symlink(self, *a):
        pass

    def put(self, local, path):
        with open(local, "rb") as f:
            self.lab.files[path] = f.read()

    def file(self, path, mode="r"):
        return _File(self.lab.files, path, mode)

    def close(self):
        pass


class Lab:
    def __init__(self):
        self.files, self.dirs, self.ops = {}, set(), []      # ops: (host, kind, text)


@pytest.fixture
def lab(monkeypatch):
    for k in list(os.environ):
        if k.startswith(_ENV_PREFIXES):
            monkeypatch.delenv(k)
    lab = Lab()

    def no_connect(*a, **k):
        raise AssertionError("the test tried to open a real SSH connection")

    def sftp_op(host, fn):
        h = hosts.get(host)                       # what the real _get does first: unknown -> HostError
        lab.ops.append((h.name, "sftp", ""))
        return fn(FakeSFTP(lab))

    def ssh_exec(cmd, host=None, read_timeout=None):
        h = hosts.get(host)
        lab.ops.append((h.name, "ssh", cmd))
        if "%USERPROFILE%" in cmd:
            return "C:\\Users\\u\r\n", ""
        return f"JOB_PID={PID}\nSTATE=FINISHED\nEXIT __JOB_RC=0\n", ""

    def run_cmd(command, host=None, timeout=20):
        lab.ops.append((host, "run_cmd", command))
        return lab_matrix_vmresult(True, "ok")

    monkeypatch.setattr(remote, "_get", no_connect)
    monkeypatch.setattr(remote, "_client", no_connect)
    monkeypatch.setattr(remote, "_sftp_op", sftp_op)
    monkeypatch.setattr(remote, "ssh_exec", ssh_exec)
    monkeypatch.setattr(remote, "_WIN_HOME", {})
    monkeypatch.setattr(shell, "run_cmd", run_cmd)
    monkeypatch.setattr(lab_matrix, "STOP_WAIT", 0)
    hosts._CACHE.clear()
    yield lab
    hosts._CACHE.clear()


def lab_matrix_vmresult(ok, summary):
    from labhand._result import VMResult
    return VMResult(ok, summary)


def setenv(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    hosts._CACHE.clear()


# hosts named kali / windows (the legacy .env keys): the workdir tests isolate F1 from F3
LEGACY = dict(KALI_HOST="192.0.2.10", KALI_USER="u", WIN_HOST="192.0.2.11", WIN_USER="u")
TWO_HOSTS = dict(LABHAND_HOSTS="kali-arm,win11",
                 KALI_ARM_HOST="192.0.2.10", KALI_ARM_USER="u", KALI_ARM_OS="linux",
                 WIN11_HOST="192.0.2.11", WIN11_USER="u", WIN11_OS="windows")


def target(name, tmp_path, **cfg):
    tgz = tmp_path / "tree.tgz"
    tgz.write_bytes(b"tarball")
    c = {"timeout": 60, "keep": False, "python": None, "labhand_path": None}
    c.update(cfg)
    return lab_matrix.RemoteTarget(name, "RUN", c), str(tgz)


def driver_writes_results(lab, base):
    """What the driver leaves in its work dir: result.json, check.log, junit.xml."""
    res = {"run_id": "RUN", "rc": 0, "system": "Linux", "machine": "aarch64",
           "python": "/v/bin/python3", "python_version": "3.13.1", "runner": "check.sh full"}
    lab.files[f"{base}/result.json"] = json.dumps(res).encode()
    lab.files[f"{base}/check.log"] = b"10 passed, 2 skipped in 3.0s\n"
    lab.files[f"{base}/junit.xml"] = b"<testsuites/>"


def _uploaded_dir(lab, target_name):
    puts = [p for p in lab.files if p.endswith(f"RUN-{target_name}/tree.tgz")]
    assert len(puts) == 1, lab.files.keys()
    return puts[0].rsplit("/", 1)[0]


# ---------------------------------------------------------------------------------- workdir

@pytest.mark.parametrize("workdir", ["lab", "work/deep/er", "samples"])
@pytest.mark.parametrize("tname", ["kali", "win"])
def test_lab_matrix_workdir_results_read_from_labhand_workdir(lab, monkeypatch, tmp_path,
                                                              workdir, tname):
    setenv(monkeypatch, LABHAND_WORKDIR=workdir, **LEGACY)
    t, tgz = target(tname, tmp_path)
    t.start(tgz)
    base = f"{workdir}/rdlab/RUN-{tname}"
    assert _uploaded_dir(lab, tname) == base          # labhand put the tree under its workdir
    driver_writes_results(lab, base)                  # ... the job ran there and wrote these
    res, log, junit = t.fetch()
    assert res is not None and log is not None and junit is not None, \
        f"read back from the wrong place; files are under {base}/"
    c = lab_matrix.classify(tname, "RUN", json.loads(res), log.decode(), junit.decode())
    assert c["status"] == "measured" and c["passed"] == 10, c


def test_lab_matrix_workdir_default_is_samples(lab, monkeypatch, tmp_path):
    setenv(monkeypatch, **LEGACY)
    t, tgz = target("kali", tmp_path)
    t.start(tgz)
    assert _uploaded_dir(lab, "kali") == "samples/rdlab/RUN-kali"
    driver_writes_results(lab, "samples/rdlab/RUN-kali")
    assert t.fetch()[0] is not None


def test_lab_matrix_workdir_invalid_is_reported_before_any_transfer(lab, monkeypatch, tmp_path):
    setenv(monkeypatch, LABHAND_WORKDIR="../outside", **LEGACY)
    t, tgz = target("kali", tmp_path)
    with pytest.raises(lab_matrix.LabError) as ei:
        t.start(tgz)
    msg = str(ei.value)
    assert "LABHAND_WORKDIR" in msg and "could not reach" not in msg, msg
    assert lab.ops == [], lab.ops


# -------------------------------------------------------------------------------- inventory

@pytest.mark.parametrize("env, says", [
    (dict(LABHAND_HOSTS="Bad!"), "bad host name"),
    (dict(LABHAND_HOSTS="kali"), "KALI_HOST"),                       # listed, not configured
    (dict(LABHAND_HOSTS="kali", KALI_HOST="192.0.2.10", KALI_USER="u", KALI_OS="bsd"), "KALI_OS"),
])
def test_lab_matrix_inventory_broken_is_reported_as_inventory(lab, monkeypatch, tmp_path, env, says):
    setenv(monkeypatch, **env)
    t, tgz = target("kali", tmp_path)
    with pytest.raises(lab_matrix.LabError) as ei:
        t.start(tgz)
    msg = str(ei.value)
    assert "inventory" in msg and says in msg and "could not reach" not in msg, msg
    assert lab.ops == [], lab.ops                    # nothing was attempted


def test_lab_matrix_inventory_targets_resolve_by_os(lab, monkeypatch, tmp_path):
    setenv(monkeypatch, **TWO_HOSTS)
    for tname, host in (("kali", "kali-arm"), ("win", "win11")):
        t, tgz = target(tname, tmp_path)
        t.start(tgz)
        assert t.host == host, (tname, t.host)
        assert {h for h, _, _ in lab.ops} == {host}, lab.ops
        lab.ops.clear()


def test_lab_matrix_inventory_first_host_of_the_os_is_the_default(lab, monkeypatch, tmp_path):
    setenv(monkeypatch, LABHAND_HOSTS="w2,lab,windows",
           W2_HOST="192.0.2.12", W2_USER="u", W2_OS="windows",
           LAB_HOST="192.0.2.10", LAB_USER="u", LAB_OS="linux",
           WINDOWS_HOST="192.0.2.11", WINDOWS_USER="u", WINDOWS_OS="windows")
    t, tgz = target("win", tmp_path)
    t.start(tgz)
    assert t.host == "w2"
    t, tgz = target("kali", tmp_path)
    t.start(tgz)
    assert t.host == "lab"


def test_lab_matrix_inventory_configured_host_name(lab, monkeypatch, tmp_path):
    setenv(monkeypatch, LABHAND_HOSTS="w2,lab,windows",
           W2_HOST="192.0.2.12", W2_USER="u", W2_OS="windows",
           LAB_HOST="192.0.2.10", LAB_USER="u", LAB_OS="linux",
           WINDOWS_HOST="192.0.2.11", WINDOWS_USER="u", WINDOWS_OS="windows")
    t, tgz = target("win", tmp_path, host="windows")
    t.start(tgz)
    assert t.host == "windows"
    t, tgz = target("kali", tmp_path, host="windows")          # wrong OS: refused, named
    with pytest.raises(lab_matrix.LabError) as ei:
        t.start(tgz)
    assert "inventory" in str(ei.value) and "windows" in str(ei.value) and "linux" in str(ei.value)
    t, tgz = target("kali", tmp_path, host="nope")
    with pytest.raises(lab_matrix.LabError) as ei:
        t.start(tgz)
    assert "unknown host 'nope'" in str(ei.value) and "lab" in str(ei.value)


def test_lab_matrix_inventory_no_host_of_that_os(lab, monkeypatch, tmp_path):
    setenv(monkeypatch, LABHAND_HOSTS="lab", LAB_HOST="192.0.2.10", LAB_USER="u", LAB_OS="linux")
    t, tgz = target("win", tmp_path)
    with pytest.raises(lab_matrix.LabError) as ei:
        t.start(tgz)
    msg = str(ei.value)
    assert "inventory" in msg and "no windows host" in msg and "could not reach" not in msg, msg


def test_lab_matrix_inventory_empty_legacy_inventory(lab, monkeypatch, tmp_path):
    setenv(monkeypatch)                                         # no LABHAND_HOSTS, no KALI_HOST
    t, tgz = target("kali", tmp_path)
    with pytest.raises(lab_matrix.LabError) as ei:
        t.start(tgz)
    msg = str(ei.value)
    assert "inventory" in msg and "no linux host" in msg and "could not reach" not in msg, msg


def test_lab_matrix_inventory_legacy_keys_still_work(lab, monkeypatch, tmp_path):
    setenv(monkeypatch, **LEGACY)
    for tname, host in (("kali", "kali"), ("win", "windows")):
        t, tgz = target(tname, tmp_path)
        t.start(tgz)
        assert t.host == host


@pytest.mark.parametrize("name, osname", [("win11", "windows"), ("windows", "linux"),
                                          ("kali", "windows")])
def test_lab_matrix_inventory_stop_follows_the_os(lab, monkeypatch, tmp_path, name, osname):
    p = hosts.prefix(name)
    setenv(monkeypatch, LABHAND_HOSTS=name, **{f"{p}_HOST": "192.0.2.10", f"{p}_USER": "u",
                                               f"{p}_OS": osname})
    tname = "win" if osname == "windows" else "kali"
    t, tgz = target(tname, tmp_path)
    t.start(tgz)
    assert t.pid == PID
    lab.ops.clear()
    t.hard_stop()
    assert t.note is None, t.note
    cmds = [(h, c) for h, kind, c in lab.ops if kind == "run_cmd"]
    if osname == "windows":
        assert cmds == [(name, f"taskkill /T /F /PID {PID}")], lab.ops
    else:
        assert cmds == [(name, f"pkill -KILL -s {PID}; true")], lab.ops
