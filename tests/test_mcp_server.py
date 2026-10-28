"""mcp_server.py JSON-RPC 2.0 edge cases (the --selftest covers the happy path end to end).

Pins the protocol rules a strict MCP client relies on: no response to ANY notification, the right
error code per malformed request, and a server that survives bad bytes on the wire.
"""
import io
import json
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import mcp_server as M  # noqa: E402

SAMPLE = ROOT / "tests" / "fixtures" / "macho" / "litcrypt.arm64"


def _serve_bytes(raw: bytes):
    out = io.StringIO()
    M.serve(io.BytesIO(raw), out)
    return [json.loads(ln) for ln in out.getvalue().splitlines() if ln.strip()]


# --- notifications never get a response ------------------------------------------------------
@pytest.mark.parametrize("method", ["ping", "tools/list", "tools/call", "initialize",
                                    "notifications/initialized", "notifications/cancelled",
                                    "no/such/method"])
def test_notification_to_any_method_gets_no_response(method):
    req = {"jsonrpc": "2.0", "method": method}
    if method == "tools/call":
        req["params"] = {"name": "detect", "arguments": {"path": str(SAMPLE)}}
    assert M.handle(req) is None


def test_notification_with_bad_params_still_silent():
    assert M.handle({"jsonrpc": "2.0", "method": "tools/call", "params": [1, 2]}) is None


def test_notifications_on_the_wire_produce_no_lines():
    raw = b"\n".join(json.dumps(r).encode() for r in [
        {"jsonrpc": "2.0", "method": "ping"},
        {"jsonrpc": "2.0", "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 7, "method": "ping"},
    ]) + b"\n"
    lines = _serve_bytes(raw)
    assert lines == [{"jsonrpc": "2.0", "id": 7, "result": {}}]


# --- error codes -------------------------------------------------------------------------------
def test_params_as_array_is_invalid_params():
    for method in ("tools/call", "tools/list", "ping", "initialize"):
        r = M.handle({"jsonrpc": "2.0", "id": 1, "method": method, "params": ["detect"]})
        assert r["error"]["code"] == M.INVALID_PARAMS, (method, r)
        assert r["id"] == 1


def test_missing_or_non_string_method_is_invalid_request():
    for req in ({"jsonrpc": "2.0", "id": 2},
                {"jsonrpc": "2.0", "id": 3, "method": 5},
                {"jsonrpc": "2.0", "id": 4, "method": None}):
        r = M.handle(req)
        assert r["error"]["code"] == M.INVALID_REQUEST, (req, r)
        assert r["id"] == req["id"]
    # no id AND no method: not a valid notification either -> still an Invalid Request (id null)
    r = M.handle({"jsonrpc": "2.0"})
    assert r["error"]["code"] == M.INVALID_REQUEST and r["id"] is None


def test_bad_jsonrpc_version_and_non_object_are_invalid_request():
    assert M.handle({"jsonrpc": "1.0", "id": 1, "method": "ping"})["error"]["code"] == M.INVALID_REQUEST
    assert M.handle([1, 2])["error"]["code"] == M.INVALID_REQUEST
    assert M.handle("ping")["error"]["code"] == M.INVALID_REQUEST
    # an id that is not a string/number/null is itself invalid
    r = M.handle({"jsonrpc": "2.0", "id": {"x": 1}, "method": "ping"})
    assert r["error"]["code"] == M.INVALID_REQUEST and r["id"] is None


def test_scalar_params_is_invalid_request():
    r = M.handle({"jsonrpc": "2.0", "id": 9, "method": "ping", "params": "bar"})
    assert r["error"]["code"] == M.INVALID_REQUEST


def test_tools_call_bad_name_or_arguments_is_invalid_params():
    for params in ({"name": ["detect"]}, {"name": 5}, {"arguments": {}},
                   {"name": "detect", "arguments": ["/x"]}, {"name": "detect", "arguments": "x"}):
        r = M.handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": params})
        assert "error" in r and r["error"]["code"] == M.INVALID_PARAMS, (params, r)


def test_unknown_method_with_id_is_method_not_found():
    r = M.handle({"jsonrpc": "2.0", "id": 6, "method": "nope"})
    assert r["error"]["code"] == M.METHOD_NOT_FOUND


# --- transport robustness ----------------------------------------------------------------------
def test_invalid_utf8_line_is_parse_error_and_server_keeps_running():
    raw = (b'\xff\xfe{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n'
           b'{"jsonrpc": "2.0", "id": 2, "method": "ping"}\n')
    lines = _serve_bytes(raw)
    assert len(lines) == 2
    assert lines[0]["error"]["code"] == M.PARSE_ERROR
    assert lines[1] == {"jsonrpc": "2.0", "id": 2, "result": {}}


def test_invalid_utf8_inside_a_string_is_replaced_not_fatal():
    raw = b'{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "detect", ' \
          b'"arguments": {"path": "/no/such/\xff\xfe"}}}\n'
    (r,) = _serve_bytes(raw)
    assert r["id"] == 3 and r["result"]["isError"]


def test_malformed_json_then_valid_request():
    lines = _serve_bytes(b'{bad json}\n\n   \n{"jsonrpc":"2.0","id":9,"method":"ping"}\n')
    assert lines[0]["error"]["code"] == M.PARSE_ERROR and lines[0]["id"] is None
    assert lines[1]["result"] == {}


def test_analysis_prints_do_not_pollute_stdout(monkeypatch):
    """Anything a tool handler prints goes to stderr; stdout carries only JSON-RPC lines."""
    def noisy(args):
        print("engine chatter on stdout")
        return {"ok": True}
    monkeypatch.setitem(M.TOOLS["detect"], "handler", noisy)
    out = io.StringIO()
    M.serve(io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                    "params": {"name": "detect", "arguments": {}}}) + "\n"), out)
    lines = out.getvalue().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["result"]["isError"] is False


def test_subprocess_strict_stdin_survives_invalid_utf8():
    """The real stdio server: a strict-decoding stdin used to raise UnicodeDecodeError outside the
    per-line try and kill the process before answering the next request."""
    raw = (b'\xc3\x28\n'
           b'{"jsonrpc": "2.0", "method": "ping"}\n'
           b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n'
           b'{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": ["x"]}\n')
    env = {"PYTHONIOENCODING": "utf-8:strict", "PATH": "/usr/bin:/bin"}
    p = subprocess.run([sys.executable, str(ROOT / "scripts" / "mcp_server.py")], input=raw,
                       capture_output=True, timeout=60, env=env)
    assert p.returncode == 0, p.stderr.decode(errors="replace")
    lines = [json.loads(ln) for ln in p.stdout.decode().splitlines() if ln.strip()]
    assert [ln.get("id") for ln in lines] == [None, 1, 2]
    assert lines[0]["error"]["code"] == M.PARSE_ERROR
    assert lines[1]["result"] == {}
    assert lines[2]["error"]["code"] == M.INVALID_PARAMS
