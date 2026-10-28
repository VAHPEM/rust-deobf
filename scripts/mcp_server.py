#!/usr/bin/env python3
"""mcp_server.py - expose rust-deobf as MCP tools over stdio.

Agents (Claude, ctf-brain, Cursor, ...) already shell out to recover.py / soc_triage.py and parse
the CLI. This serves the same facts as typed Model Context Protocol tools instead, so an agent calls
`recover` / `triage` / `metadata` / `detect` with a JSON schema and gets structured JSON back -- no
CLI parsing, no guessing flags. It is the deterministic-facts surface the llm_triage design wants:
the agent reasons over recovered facts, never the raw binary.

Transport: JSON-RPC 2.0 over stdio, newline-delimited (the MCP stdio transport). No third-party
package is required -- the protocol is implemented on the standard library -- so it runs anywhere
rust-deobf runs. Point an MCP client at it:

    {"command": "python3", "args": ["scripts/mcp_server.py"]}

Tools (each takes a `path` to a local ELF/PE/Mach-O; nothing is executed -- static + emulation only):

    detect     format / arch / imagebase
    metadata   rustc version, third-party crates @ versions, panic sites, capability fingerprint
    triage     the soc_triage card (signal, indicators, capabilities) -- fast=true skips decoding
    recover    every decoded string + the function that builds it, stack strings, literal indicators

    python3 scripts/mcp_server.py            # serve on stdio
    python3 scripts/mcp_server.py --selftest # drive the handlers without a client
"""
from __future__ import annotations

import contextlib
import json
import math
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "rust-deobf", "version": "1.0.0"}

# JSON-RPC error codes
PARSE_ERROR, INVALID_REQUEST, METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = \
    -32700, -32600, -32601, -32602, -32603


# --------------------------------------------------------------------------------------------
# tool implementations: each returns a JSON-serialisable dict. They never execute the sample.
# --------------------------------------------------------------------------------------------
def _require_file(args: dict) -> Path:
    p = args.get("path")
    if not isinstance(p, str) or not p:
        raise ValueError("missing required string argument 'path'")
    path = Path(p)
    if not path.is_file():
        raise FileNotFoundError(f"no such file: {p}")
    return path


def tool_detect(args: dict) -> dict:
    import recover
    path = _require_file(args)
    fmt, arch, imagebase = recover.detect(path)
    if fmt is None:
        return {"supported": False, "reason": "not an ELF/PE/Mach-O LIEF can parse"}
    return {"supported": True, "format": fmt, "arch": arch, "imagebase": imagebase}


def tool_metadata(args: dict) -> dict:
    import recover_rust_meta
    path = _require_file(args)
    m = recover_rust_meta.recover(path)
    rel = m.get("rust_release") or {}
    return {
        "is_rust": bool(m.get("is_rust")),
        "rustc_commit": m.get("rustc_commit"),
        "rust_release": rel.get("version"),
        "crates": m.get("crates") or {},
        "capabilities": m.get("capabilities") or {},
        "panic_sites": (m.get("counts") or {}).get("panic_sites"),
        "panic_messages": (m.get("panic_messages") or [])[:40],
    }


def tool_triage(args: dict) -> dict:
    import soc_triage
    path = _require_file(args)
    fast = bool(args.get("fast", False))
    time_budget = float(args.get("time_budget", 60.0))
    try:
        return soc_triage.triage(path, fast=fast, time_budget=time_budget)
    except soc_triage.UnsupportedInput as e:
        return {"supported": False, "reason": str(e)}


def tool_recover(args: dict) -> dict:
    import recover
    path = _require_file(args)
    emulate = args.get("emulate", "auto")
    if emulate not in ("always", "auto", "never"):
        raise ValueError("'emulate' must be one of: always, auto, never")
    time_budget = float(args.get("time_budget", 60.0))
    min_len = int(args.get("min_len", 6))
    res = recover.run(path, emulate=emulate, time_budget=time_budget, min_len=min_len,
                      literals=True, stackstrings=True)
    if res.get("format") is None:
        return {"supported": False, "reason": "not an ELF/PE/Mach-O LIEF can parse"}

    def where(x):
        if x.get("method", "").startswith("static"):
            return {"decoder": x.get("decoder"), "call": x.get("call"), "data": x.get("blob")}
        return {"function": x.get("function"), "via": "emulation"}

    return {
        "format": res["format"], "arch": res["arch"],
        "decoded": [{"string": x["string"], "tags": x.get("tags", []), "where": where(x)}
                    for x in res["decoded"]],
        "stack": [{"string": x["string"], "tags": x.get("tags", [])} for x in res["stack"]],
        "literal_indicators": [{"string": x["string"], "tags": x.get("tags", [])}
                               for x in res.get("literals", []) if x.get("tags")],
        "notes": res.get("notes", []),
        "engine_errors": res.get("errors", []),
    }


TOOLS = {
    "detect": {
        "description": "Detect a binary's format (ELF/PE/Mach-O), architecture and image base. "
                       "Does not execute the sample.",
        "handler": tool_detect,
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "path to a local binary"}},
            "required": ["path"],
        },
    },
    "metadata": {
        "description": "Rust build metadata that survives strip: rustc version, third-party crates "
                       "with exact versions, panic sites, capability fingerprint. Static only.",
        "handler": tool_metadata,
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "path to a local binary"}},
            "required": ["path"],
        },
    },
    "triage": {
        "description": "One-screen SOC triage card: format/arch, Rust toolchain, crate capability "
                       "fingerprint, indicators by tag, and a calibrated LOW/MEDIUM/HIGH signal "
                       "with its evidence. Static + emulation; never executes the sample.",
        "handler": tool_triage,
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "path to a local binary"},
                "fast": {"type": "boolean",
                         "description": "skip all decoding (metadata + literals only); signal capped at LOW"},
                "time_budget": {"type": "number", "description": "emulation budget in seconds (default 60)"},
            },
            "required": ["path"],
        },
    },
    "recover": {
        "description": "Recover obfuscated strings from a Rust binary: every decoded string and the "
                       "function that builds it, stack strings, and literal indicators. Static "
                       "call-site recovery + Unicorn emulation of functions; never executes the sample.",
        "handler": tool_recover,
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "path to a local binary"},
                "emulate": {"type": "string", "enum": ["always", "auto", "never"],
                            "description": "run emulation always, only if static finds nothing (auto), or never"},
                "time_budget": {"type": "number", "description": "emulation budget in seconds (default 60)"},
                "min_len": {"type": "integer", "description": "minimum string length (default 6)"},
            },
            "required": ["path"],
        },
    },
}


# --------------------------------------------------------------------------------------------
# JSON-RPC / MCP dispatch
# --------------------------------------------------------------------------------------------
def _result(req_id, result):
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code, message):
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _valid_id(v) -> bool:
    # JSON-RPC 2.0: an id is a string, a number or null (bool is an int subclass in Python: exclude;
    # json.loads accepts NaN/Infinity, which could not be echoed back as valid JSON)
    if isinstance(v, float):
        return math.isfinite(v)
    return v is None or (isinstance(v, (str, int)) and not isinstance(v, bool))


def handle(request):
    """Process one parsed JSON-RPC message; return a response dict, or None for a notification.

    Order matters: a structurally invalid message is an Invalid Request (-32600) even without an
    id (it is not a valid notification either); a valid notification (no `id` member) NEVER gets a
    response, whatever its method or params; only then are params checked (-32602) and the method
    dispatched (-32601 if unknown)."""
    if not isinstance(request, dict):
        return _error(None, INVALID_REQUEST, "not a JSON-RPC 2.0 request object")
    req_id = request.get("id")
    if not _valid_id(req_id):
        return _error(None, INVALID_REQUEST, "id must be a string, a number or null")
    if request.get("jsonrpc") != "2.0":
        return _error(req_id, INVALID_REQUEST, "not a JSON-RPC 2.0 request")
    method = request.get("method")
    if not isinstance(method, str):
        return _error(req_id, INVALID_REQUEST, "missing or non-string 'method'")
    params = request.get("params")
    if params is not None and not isinstance(params, (dict, list)):
        return _error(req_id, INVALID_REQUEST, "'params' must be an object or an array")
    if "id" not in request:
        return None          # a notification: no response, ever (nothing here has side effects)
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _error(req_id, INVALID_PARAMS, "'params' must be an object (named parameters)")

    if method == "initialize":
        return _result(req_id, {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        })
    if method == "ping":
        return _result(req_id, {})
    if method == "tools/list":
        return _result(req_id, {"tools": [
            {"name": name, "description": t["description"], "inputSchema": t["inputSchema"]}
            for name, t in TOOLS.items()
        ]})
    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments")
        if args is None:
            args = {}
        if not isinstance(name, str):
            return _error(req_id, INVALID_PARAMS, "'name' must be a string")
        if not isinstance(args, dict):
            return _error(req_id, INVALID_PARAMS, "'arguments' must be an object")
        tool = TOOLS.get(name)
        if tool is None:
            return _error(req_id, INVALID_PARAMS, f"unknown tool: {name}")
        try:
            payload = tool["handler"](args)
            return _result(req_id, {
                "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                "isError": False,
            })
        except (ValueError, FileNotFoundError) as e:
            # a caller error (bad path / args): a tool error result, not a protocol error
            return _result(req_id, {"content": [{"type": "text", "text": str(e)}], "isError": True})
        except Exception as e:  # noqa: BLE001 - an engine failed; surface it as a tool error
            return _result(req_id, {"content": [{"type": "text",
                           "text": f"{type(e).__name__}: {e}"}], "isError": True})
    return _error(req_id, METHOD_NOT_FOUND, f"method not found: {method}")


def serve(stdin=None, stdout=None) -> None:
    """Read newline-delimited JSON-RPC from stdin, write responses to stdout (the MCP stdio loop).

    stdin is read as BYTES (sys.stdin.buffer) and each line decoded with errors="replace" inside the
    per-line guard: a strict text stdin would raise UnicodeDecodeError on one bad byte and kill the
    server. A text stream (str lines, e.g. io.StringIO in tests) is accepted too. While a request is
    handled, sys.stdout points at stderr so a chatty engine cannot corrupt the protocol stream."""
    if stdin is None:
        stdin = getattr(sys.stdin, "buffer", sys.stdin)
    stdout = stdout or sys.stdout
    for raw in stdin:
        request = None
        try:
            line = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
            except ValueError:          # JSONDecodeError, and e.g. a lone surrogate in a \u escape
                _write(stdout, _error(None, PARSE_ERROR, "invalid JSON"))
                continue
            with contextlib.redirect_stdout(sys.stderr):
                response = handle(request)
        except Exception:  # noqa: BLE001 - never let one request kill the server
            req_id = request.get("id") if isinstance(request, dict) else None
            if isinstance(request, dict) and "id" not in request:
                continue                # a notification gets no response, not even an error
            response = _error(req_id if _valid_id(req_id) else None,
                              INTERNAL_ERROR, traceback.format_exc().splitlines()[-1])
        if response is not None:
            _write(stdout, response)


def _write(stdout, obj) -> None:
    stdout.write(json.dumps(obj) + "\n")
    stdout.flush()


def _selftest():
    import io

    # initialize handshake
    init = handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["protocolVersion"] == PROTOCOL_VERSION
    assert init["result"]["serverInfo"]["name"] == "rust-deobf"
    # a notification returns nothing
    assert handle({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    # tools/list advertises all four with input schemas requiring a path
    tl = handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    tools = {t["name"]: t for t in tl["result"]["tools"]}
    assert set(tools) == {"detect", "metadata", "triage", "recover"}
    for t in tools.values():
        assert t["inputSchema"]["required"] == ["path"]
    # unknown method / unknown tool
    assert handle({"jsonrpc": "2.0", "id": 3, "method": "nope"})["error"]["code"] == METHOD_NOT_FOUND
    bad = handle({"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                  "params": {"name": "ghost", "arguments": {}}})
    assert bad["error"]["code"] == INVALID_PARAMS
    # a tool call with a missing file is a tool error, not a protocol error
    miss = handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                   "params": {"name": "detect", "arguments": {"path": "/no/such/file"}}})
    assert miss["result"]["isError"] and "no such file" in miss["result"]["content"][0]["text"]

    # every notification is silent (even to a request-style method); malformed requests get the
    # specific JSON-RPC code; a bad UTF-8 line is a parse error and the loop keeps serving
    assert handle({"jsonrpc": "2.0", "method": "ping"}) is None
    assert handle({"jsonrpc": "2.0", "method": "tools/list"}) is None
    assert handle({"jsonrpc": "2.0", "id": 20, "method": "tools/call",
                   "params": ["detect"]})["error"]["code"] == INVALID_PARAMS
    assert handle({"jsonrpc": "2.0", "id": 21})["error"]["code"] == INVALID_REQUEST
    assert handle({"jsonrpc": "2.0", "id": float("nan"),
                   "method": "ping"})["error"]["code"] == INVALID_REQUEST
    out0 = io.StringIO()
    serve(io.BytesIO(b'\xff{"x"\n{"jsonrpc":"2.0","id":22,"method":"ping"}\n'), out0)
    l0 = [json.loads(ln) for ln in out0.getvalue().splitlines()]
    assert l0[0]["error"]["code"] == PARSE_ERROR and l0[1] == _result(22, {})

    # end to end on a committed fixture: detect + metadata + recover over the stdio loop
    sample = ROOT.parent / "tests" / "fixtures" / "macho" / "litcrypt.arm64"
    reqs = "\n".join(json.dumps(r) for r in [
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
         "params": {"name": "detect", "arguments": {"path": str(sample)}}},
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
         "params": {"name": "recover", "arguments": {"path": str(sample), "emulate": "never"}}},
    ])
    out = io.StringIO()
    serve(io.StringIO(reqs), out)
    lines = [json.loads(ln) for ln in out.getvalue().splitlines() if ln.strip()]
    assert len(lines) == 2
    det = json.loads(lines[0]["result"]["content"][0]["text"])
    assert det["format"] == "MACHO" and det["arch"] == "aarch64"
    rec = json.loads(lines[1]["result"]["content"][0]["text"])
    assert rec["format"] == "MACHO" and "decoded" in rec and "notes" in rec
    # malformed JSON on the wire -> a parse error response, server stays up
    out2 = io.StringIO()
    serve(io.StringIO('{bad json}\n{"jsonrpc":"2.0","id":9,"method":"ping"}'), out2)
    pl = [json.loads(ln) for ln in out2.getvalue().splitlines() if ln.strip()]
    assert pl[0]["error"]["code"] == PARSE_ERROR and pl[1]["result"] == {}
    print("selftest OK: MCP initialize/tools-list/tools-call over stdio, 4 tools, tool-error vs "
          "protocol-error handling, end-to-end detect+recover on a fixture")


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--selftest" in argv:
        _selftest()
        return 0
    if "-h" in argv or "--help" in argv:
        print(__doc__)
        return 0
    serve()
    return 0


if __name__ == "__main__":
    sys.exit(main())
