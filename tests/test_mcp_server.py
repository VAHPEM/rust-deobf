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


# --- annotations / push_annotations (decompiler_bridge) ----------------------------------------
sys.path.insert(0, str(ROOT / "tests"))


def _call(name, arguments, req_id=40):
    r = M.handle({"jsonrpc": "2.0", "id": req_id, "method": "tools/call",
                  "params": {"name": name, "arguments": arguments}})
    res = r["result"]
    return res, (json.loads(res["content"][0]["text"]) if not res["isError"] else
                 res["content"][0]["text"])


@pytest.fixture
def synthetic_doc(monkeypatch):
    """Serve a synthetic analysis (PE, RVAs) instead of running the engines."""
    import decompiler_bridge as DB
    from test_decompiler_bridge import FACTS, PE_HDR, _doc
    calls = []

    def fake(path, **kw):
        calls.append((str(path), kw))
        return _doc(PE_HDR, FACTS)
    monkeypatch.setattr(DB, "analyze", fake)
    monkeypatch.setattr(M, "_ANN_CACHE", {})
    return calls


def test_annotations_tool_filters_pagination_and_cache(synthetic_doc):
    res, doc = _call("annotations", {"path": str(SAMPLE)})
    assert not res["isError"] and doc["address_space"] == "rva"
    assert doc["page"]["total"] == len(doc["annotations"]) and not doc["page"]["has_more"]
    assert "untrusted_text" in doc
    _, d2 = _call("annotations", {"path": str(SAMPLE), "tier": "recover", "kind": ["rename"]})
    assert [a["address"] for a in d2["annotations"]] == ["0x2000", "0x3000"]
    _, d3 = _call("annotations", {"path": str(SAMPLE), "function": "0x3000", "image_base": "0x140000000"})
    assert {a["decompiler_address"] for a in d3["annotations"]} == {"0x140003000", "0x140002050"}
    _, d4 = _call("annotations", {"path": str(SAMPLE), "offset": 1, "limit": 2})
    assert len(d4["annotations"]) == 2 and d4["page"]["has_more"]
    assert len(synthetic_doc) == 1                      # one analysis served every call


@pytest.mark.parametrize("args,msg", [
    ({"tier": "nope"}, "unknown value"), ({"kind": 5}, "string or a list"),
    ({"function": "zz"}, "not an address"), ({"emulate": "maybe"}, "emulate"),
    ({"limit": 0}, "limit"),
])
def test_annotations_tool_bad_args_are_tool_errors(synthetic_doc, args, msg):
    res, text = _call("annotations", dict({"path": str(SAMPLE)}, **args))
    assert res["isError"] and msg in text


def test_push_annotations_loopback_only_and_dry_run_default(synthetic_doc):
    from decompiler_mocks import GhidraV2
    from test_decompiler_bridge import _ghidra_pe
    for url in ("http://192.0.2.10:8080/", "http://127.0.0.1@evil.example/"):
        res, text = _call("push_annotations", {"path": str(SAMPLE), "backend": "ghidra-mcp",
                                               "url": url})
        assert res["isError"] and ("non-loopback" in text or "credentials" in text)
    assert not synthetic_doc                             # refused before any analysis
    res, text = _call("push_annotations", {"path": str(SAMPLE), "backend": "radare",
                                           "url": "http://127.0.0.1:1/"})
    assert res["isError"] and "backend" in text
    with _ghidra_pe() as g:
        assert isinstance(g, GhidraV2)
        res, rep = _call("push_annotations", {"path": str(SAMPLE), "backend": "ghidra-mcp",
                                              "url": g.url})
        assert not res["isError"] and rep["dry_run"] is True and not g.posts()
        assert rep["mapping"]["verified"] and rep["summary"]["planned"] > 0
        res, rep = _call("push_annotations", {"path": str(SAMPLE), "backend": "ghidra-mcp",
                                              "url": g.url, "dry_run": False, "kind": "rename"})
        assert rep["summary"]["applied"] == 5 and g.funcs[0x140002000][0].startswith("rd_url_")
    res, text = _call("push_annotations", {"path": str(SAMPLE), "backend": "ghidra-mcp",
                                           "url": "http://127.0.0.1:9/", "dry_run": "no"})
    assert res["isError"] and "dry_run" in text


def test_push_annotations_unreachable_is_a_tool_error(synthetic_doc):
    res, text = _call("push_annotations", {"path": str(SAMPLE), "backend": "ida-mcp",
                                           "url": "http://127.0.0.1:9/mcp"})
    assert res["isError"] and "cannot reach ida-pro-mcp" in text


def test_annotations_tool_real_fixture_over_stdio():
    """End to end through the stdio loop on a committed fixture (no mocking): stdout stays
    JSON-RPC only even though the engines run."""
    vt = ROOT / "tests" / "fixtures" / "emu" / "vt32"
    req = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": "annotations", "arguments": {"path": str(vt), "emulate": "never",
                                                           "tier": "recover_types"}}}
    out = io.StringIO()
    M.serve(io.StringIO(json.dumps(req) + "\n"), out)
    (line,) = out.getvalue().splitlines()
    doc = json.loads(json.loads(line)["result"]["content"][0]["text"])
    assert {a["source_tier"] for a in doc["annotations"]} == {"recover_types"}
    assert any(a["text"] == "rd_vtmethod_22e4_0" for a in doc["annotations"])


@pytest.mark.parametrize("key", ["dry_run", "force", "triage"])
def test_push_annotations_booleans_are_strict(synthetic_doc, key):
    res, text = _call("push_annotations", {"path": str(SAMPLE), "backend": "ghidra-mcp",
                                           "url": "http://127.0.0.1:9/", key: "false"})
    assert res["isError"] and key in text and not synthetic_doc


@pytest.mark.parametrize("key,value", [("bookmarks", True), ("bookmarks", "yes"),
                                       ("ida_comment", "replace"), ("ghidra_comment", "plate")])
def test_push_annotations_enums_are_strict(synthetic_doc, key, value):
    res, text = _call("push_annotations", {"path": str(SAMPLE), "backend": "ida-mcp",
                                           "url": "http://127.0.0.1:9/mcp", key: value})
    assert res["isError"] and key in text and not synthetic_doc
