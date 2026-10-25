"""recover_dynamic.py safety rails and noise filter (no Frida, nothing is executed)."""
import pytest
from conftest import ROOT  # noqa: F401  (adds scripts/ to sys.path)

import recover_dynamic as D


@pytest.mark.parametrize("s", [
    "https://telemetry.evil-example.net/beacon",    # "telemetry" in a real C2 URL
    "\\\\.\\pipe\\x",                                # contains "pip"
    "update.evil.solutions",                        # contains ".so"
    "sandbox-check-failed",                         # contains "sandbox"
    "frida-server",                                 # an anti-analysis string the sample checks for
    "password=hunter2",                             # lower-case key=value config, not an env line
])
def test_real_strings_survive_the_noise_filter(s):
    assert not D.is_tool_noise(s)


@pytest.mark.parametrize("s", [
    "PATH=/usr/local/bin:/usr/bin",
    "LD_LIBRARY_PATH=/opt/x",
    "/usr/lib/x86_64-linux-gnu/libc.so.6",
    "/usr/lib/libSystem.B.dylib",
    "/tmp/frida-6b1c0d/frida-agent-64.so",
    "frida_agent_main",
])
def test_tooling_noise_is_dropped(s):
    assert D.is_tool_noise(s)


def test_refuses_without_explicit_opt_in(tmp_path, capsys):
    b = tmp_path / "sample"
    b.write_bytes(b"\x7fELF")
    with pytest.raises(SystemExit) as e:
        D.main([str(b)])
    assert e.value.code == 2
    assert "--i-understand-this-executes" in capsys.readouterr().err


def test_vm_hint_is_best_effort():
    h = D.vm_hint()                 # must never raise, whatever the host
    assert h is None or isinstance(h, str)


def test_process_killed_on_interrupt(monkeypatch):
    """Ctrl-C while waiting must still detach and kill the spawned target."""
    import sys
    import types
    events = []

    class Script:
        def on(self, *a): pass
        def load(self): pass

    class Session:
        def create_script(self, src): return Script()
        def detach(self): events.append("detach")

    class Device:
        def spawn(self, argv): events.append("spawn"); return 4242
        def attach(self, pid): return Session()
        def resume(self, pid): raise KeyboardInterrupt
        def kill(self, pid): events.append(("kill", pid))

    monkeypatch.setitem(sys.modules, "frida", types.SimpleNamespace(get_local_device=lambda: Device()))
    with pytest.raises(KeyboardInterrupt):
        D.run(ROOT / "README.md", [], 8, 1.0)
    assert ("kill", 4242) in events and "detach" in events
