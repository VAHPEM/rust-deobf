"""In-process stand-ins for the decompiler MCP plugins decompiler_bridge.py talks to.

Each implements only the subset of the real HTTP API the bridge calls, with the real paths,
parameter names, reply shapes and validation, taken from the plugins' source:

* GhidraMCP 2.x -- github.com/LaurieWired/GhidraMCP (tag 2.0, 1e98025):
  extension/src/main/java/com/lauriewired/ghidramcp/http/BackendHttpServer.java (routes, GET/POST
  enforcement -> 405, Origin header / foreign Host -> 403, trailing slash stripped),
  http/Request.java (query + form body merged, URLDecoder: '+' is a space), http/Json.java
  ({"success", "data"} / {"success": false, "error": {code, message}}), core/Model.java (snake_case
  records), core/GhidraAnalysisService.java (functionAt = at or containing; setComment: "" clears),
  core/McpException.java (FUNCTION_NOT_FOUND 404, MISSING_PARAMETER 400, NO_PROGRAM 409).
* GhidraMCP 1.x -- same repo, tag 1.4: src/main/java/com/lauriewired/GhidraMCPPlugin.java (plain
  text replies, always HTTP 200; parsePostParams keeps a pair only when split("=") has 2 parts;
  getFunctionByAddress = exact getFunctionAt; disassembleFunction "ADDR: INSN ; comment" lines).
* ida-pro-mcp -- github.com/mrexodia/ida-pro-mcp (c133c38): src/ida_pro_mcp/ida_mcp/zeromcp/mcp.py
  (POST /mcp, initialize -> Mcp-Session-Id, notifications -> 202, tools/call -> {content,
  structuredContent, isError}, resources/read, Host/Origin checks), ida_mcp/api_core.py
  (server_health, lookup_funcs), ida_mcp/api_modify.py (append_comments + _append_comment_text
  dedupe, set_comments, rename(batch.func), add_bookmark), ida_mcp/api_resources.py
  (ida://idb/metadata), ida_mcp/utils.py (parse_address: int(addr, 0)), ida_mcp/api_python.py
  (py_eval: @unsafe -- absent from tools/list when disabled; exec with a separate locals dict, the
  last expression's str() is "result", an exception gives result "" + a traceback in "stderr").
  The fake idc/ida_funcs/idaapi/ida_hexrays modules py_eval sees are backed by the mock's state.
"""
from __future__ import annotations

import ast
import json
import threading
import traceback
import types
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Base(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    state = None

    def log_message(self, *a):
        pass

    def _raw(self, code, body: bytes, ctype="application/json; charset=utf-8", headers=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""


def _serve(handler_cls, state):
    cls = type("H", (handler_cls,), {"state": state})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    state.url_base = "http://127.0.0.1:%d" % srv.server_address[1]
    state.server = srv
    return srv


class Server:
    """Context manager: `with GhidraV2(...) as g: g.url ...`."""

    handler = None

    def __enter__(self):
        _serve(self.handler, self)
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


# ------------------------------------------------------------------------------------------------
# GhidraMCP 2.x
# ------------------------------------------------------------------------------------------------
class _GhidraV2Handler(_Base):
    def _ok(self, data):
        self._raw(200, json.dumps({"success": True, "data": data}).encode())

    def _err(self, status, code, msg):
        self._raw(status, json.dumps({"success": False,
                                      "error": {"code": code, "message": msg}}).encode())

    def _handle(self, method):
        st = self.state
        st.requests.append({"method": method, "raw_path": self.path,
                            "headers": dict(self.headers)})
        if "Origin" in self.headers:
            return self._err(403, "FORBIDDEN", "Cross-origin requests are not allowed")
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
        if host and host not in ("127.0.0.1", "localhost", "[::1]"):
            return self._err(403, "FORBIDDEN", "Cross-origin requests are not allowed")
        u = urllib.parse.urlsplit(self.path)
        path = u.path[:-1] if len(u.path) > 1 and u.path.endswith("/") else u.path
        params = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
        body = self._body()
        if body:
            params.update(urllib.parse.parse_qsl(body.decode("utf-8"), keep_blank_values=True))
        st.requests[-1].update(path=path, params=params)
        routes = {"/health": "GET", "/program_info": "GET", "/function": "GET",
                  "/disassemble_function": "GET", "/set_decompiler_comment": "POST",
                  "/set_disassembly_comment": "POST", "/rename_function_by_address": "POST"}
        if path not in routes:
            return self._err(404, "UNKNOWN_ENDPOINT", "Unknown endpoint: " + path)
        if routes[path] != method:
            return self._err(405, "METHOD_NOT_ALLOWED", f"{path} requires {routes[path]}")
        if path == "/health":
            return self._ok({"status": "ok", "version": "2.0.0", "ghidra_version": "12.1.4",
                             "mode": "gui", "capabilities": [],
                             "program": {"name": st.name} if st.program_open else None})
        if not st.program_open:
            return self._err(409, "NO_PROGRAM", "No program is open")

        def req(name, allow_empty=False):
            v = params.get(name)
            if v is None or (v == "" and not allow_empty):
                raise KeyError(name)
            return v
        try:
            if path == "/program_info":
                return self._ok({"name": st.name, "image_base": "%08x" % st.image_base,
                                 "entry_points": ["%08x" % e for e in st.entry_points],
                                 "sha256": st.sha256, "executable_format": st.fmt,
                                 "pointer_size": 8})
            if path == "/function":
                f = st.function_at(st.parse(req("address")))
                if f is None:
                    return self._err(404, "FUNCTION_NOT_FOUND", "No function found at or containing")
                return self._ok({"name": st.funcs[f][0], "address": "%08x" % f,
                                 "signature": "undefined %s(void)" % st.funcs[f][0]})
            if path == "/disassemble_function":
                f = st.function_at(st.parse(req("address")))
                if f is None:
                    return self._err(404, "FUNCTION_NOT_FOUND", "No function found")
                off, lim = int(params.get("offset", 0)), int(params.get("limit", 500))
                ins = st.funcs[f][1]
                items = [{"address": "%08x" % a, "bytes": "90", "instruction": "NOP",
                          "comment": st.comments.get(("EOL", a))} for a in ins[off:off + lim]]
                return self._ok({"items": items, "offset": off, "limit": lim, "total": len(ins),
                                 "has_more": off + len(items) < len(ins)})
            if path in ("/set_decompiler_comment", "/set_disassembly_comment"):
                a = st.parse(req("address"))
                c = req("comment", allow_empty=True)
                kind = "PRE" if path == "/set_decompiler_comment" else "EOL"
                if c == "":
                    st.comments.pop((kind, a), None)
                else:
                    st.comments[(kind, a)] = c
                return self._ok({"address": "%08x" % a, "comment_type": kind,
                                 "comment": st.comments.get((kind, a))})
            if path == "/rename_function_by_address":
                f = st.function_at(st.parse(req("function_address")))
                new = req("new_name")
                if f is None:
                    return self._err(404, "FUNCTION_NOT_FOUND", "No function found")
                old = st.funcs[f][0]
                st.funcs[f][0] = new
                return self._ok({"address": "%08x" % f, "old_name": old, "new_name": new})
        except KeyError as e:
            return self._err(400, "MISSING_PARAMETER", f"Missing required parameter '{e.args[0]}'")
        except ValueError as e:
            return self._err(400, "BAD_ADDRESS", str(e))

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


class GhidraV2(Server):
    handler = _GhidraV2Handler

    def __init__(self, image_base, funcs, entry_points=(), sha256=None, name="sample",
                 fmt="Portable Executable (PE)", program_open=True):
        """funcs: {entry: (name, [instruction addresses])} in Ghidra's (absolute) addresses."""
        self.image_base = image_base
        self.funcs = {a: [n, sorted(ins)] for a, (n, ins) in funcs.items()}
        self.entry_points = list(entry_points)
        self.sha256 = sha256
        self.name = name
        self.fmt = fmt
        self.program_open = program_open
        self.comments = {}
        self.requests = []

    @property
    def url(self):
        return self.url_base + "/"

    @staticmethod
    def parse(text):
        t = text.strip()
        if t.lower().startswith("0x"):
            t = t[2:]
        return int(t, 16)

    def function_at(self, a):
        if a in self.funcs:
            return a
        for f, (_n, ins) in self.funcs.items():
            if ins and f <= a <= max(ins):
                return f
        return None

    def posts(self):
        return [r for r in self.requests if r["method"] == "POST"]


# ------------------------------------------------------------------------------------------------
# GhidraMCP 1.x (plain text)
# ------------------------------------------------------------------------------------------------
class _GhidraLegacyHandler(_Base):
    def _text(self, s, code=200):
        self._raw(code, s.encode("utf-8"), "text/plain; charset=utf-8")

    def _post_params(self, body: bytes):
        params = {}
        for pair in body.decode("utf-8").split("&"):
            kv = [x for x in pair.split("=")]
            while kv and kv[-1] == "":            # Java String.split drops trailing empties
                kv.pop()
            if len(kv) == 2:
                params[urllib.parse.unquote_plus(kv[0])] = urllib.parse.unquote_plus(kv[1])
        return params

    def do_GET(self):
        st = self.state
        u = urllib.parse.urlsplit(self.path)
        q = dict(urllib.parse.parse_qsl(u.query))
        st.requests.append({"method": "GET", "path": u.path, "params": q})
        if u.path == "/methods":
            return self._text("\n".join(n for n, _ in st.funcs.values()))
        if u.path == "/get_function_by_address":
            a = int(q["address"], 16)
            if a not in st.funcs:
                return self._text(f"No function found at address {q['address']}")
            return self._text("Function: %s at %08x\nSignature: undefined %s(void)\nEntry: %08x"
                              "\nBody: %08x - %08x" % (st.funcs[a][0], a, st.funcs[a][0], a, a,
                                                       max(st.funcs[a][1])))
        if u.path == "/disassemble_function":
            a = int(q["address"], 16)
            f = next((f for f, (_n, ins) in st.funcs.items() if f <= a <= max(ins)), None)
            if f is None:
                return self._text(f"No function found at or containing address {q['address']}")
            lines = []
            for i in st.funcs[f][1]:
                c = st.eol.get(i)
                lines.append("%08x: NOP %s" % (i, ("; " + c) if c is not None else ""))
            return self._text("\n".join(lines) + "\n")
        self._text("No context found for request", 404)

    def do_POST(self):
        st = self.state
        u = urllib.parse.urlsplit(self.path)
        p = self._post_params(self._body())
        st.requests.append({"method": "POST", "path": u.path, "params": p})
        if u.path in ("/set_decompiler_comment", "/set_disassembly_comment"):
            if "address" not in p or "comment" not in p:
                return self._text("Failed to set comment")
            store = st.pre if u.path == "/set_decompiler_comment" else st.eol
            store[int(p["address"], 16)] = p["comment"]
            return self._text("Comment set successfully")
        if u.path == "/rename_function_by_address":
            a = int(p["function_address"], 16)
            if a not in st.funcs:
                return self._text("Failed to rename function")
            st.funcs[a][0] = p["new_name"]
            return self._text("Function renamed successfully")
        self._text("No context found for request", 404)


class GhidraLegacy(Server):
    handler = _GhidraLegacyHandler

    def __init__(self, funcs):
        self.funcs = {a: [n, sorted(ins)] for a, (n, ins) in funcs.items()}
        self.pre, self.eol, self.requests = {}, {}, []

    @property
    def url(self):
        return self.url_base + "/"


# ------------------------------------------------------------------------------------------------
# ida-pro-mcp
# ------------------------------------------------------------------------------------------------
def _append_comment_text(current: str, new_text: str, *, dedupe: bool):
    # verbatim logic of ida_mcp/api_modify.py::_append_comment_text
    normalized_new = new_text.strip()
    if dedupe and normalized_new:
        existing_entries = [line.strip() for line in current.splitlines()]
        if normalized_new in existing_entries:
            return current, True
    if not current:
        return new_text, False
    if not new_text:
        return current, False
    joiner = "" if current.endswith("\n") else "\n"
    return f"{current}{joiner}{new_text}", False


class _IdaHandler(_Base):
    def do_GET(self):
        self._raw(405, b"Method Not Allowed", "text/plain")

    def do_POST(self):
        st = self.state
        host = (self.headers.get("Host") or "").rsplit(":", 1)[0].lower()
        if host not in ("127.0.0.1", "localhost", "[::1]"):
            return self._raw(403, b"Invalid Host", "text/plain")
        if self.headers.get("Origin"):
            return self._raw(403, b"Invalid Origin", "text/plain")
        if urllib.parse.urlsplit(self.path).path != "/mcp":
            return self._raw(404, b"Not Found", "text/plain")
        msg = json.loads(self._body())
        st.requests.append({"msg": msg, "headers": dict(self.headers)})
        sid = self.headers.get("Mcp-Session-Id")
        if msg.get("method") == "initialize":
            sid = sid or str(uuid.uuid4())
            st.sessions.add(sid)
        elif st.require_session and sid not in st.sessions:
            return self._raw(400, b"Missing Mcp-Session-Id header", "text/plain")
        if "id" not in msg:
            return self._raw(202, b"", headers={"Mcp-Session-Id": sid} if sid else None)
        result = self.dispatch(msg["method"], msg.get("params") or {})
        reply = {"jsonrpc": "2.0", "id": msg["id"], "result": result}
        body = json.dumps(reply).encode()
        hdr = {"Mcp-Session-Id": sid} if sid else {}
        if st.sse:
            return self._raw(200, b"event: message\ndata: " + body + b"\n\n", "text/event-stream", hdr)
        self._raw(200, body, "application/json", hdr)

    def dispatch(self, method, params):
        st = self.state
        if method == "initialize":
            return {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                    "serverInfo": {"name": "ida-pro-mcp", "version": "1.0.0"}}
        if method == "resources/read":
            if params.get("uri") == "ida://idb/metadata":
                return {"contents": [{"uri": params["uri"], "mimeType": "application/json",
                                      "text": json.dumps({"base": hex(st.imagebase),
                                                          "sha256": st.sha256})}]}
            return {"contents": [], "isError": True}
        if method == "tools/list":
            names = ["server_health", "lookup_funcs", "append_comments", "set_comments",
                     "rename", "add_bookmark"] + (["py_eval"] if st.py_eval else [])
            return {"tools": [{"name": n, "description": n, "inputSchema": {"type": "object"}}
                              for n in names]}
        if method != "tools/call":
            return {}
        name, args = params.get("name"), dict(params.get("arguments") or {})
        if st.database is not None:
            if args.pop("database", None) != st.database:
                return {"content": [{"type": "text", "text": "missing database"}], "isError": True}
        try:
            result = getattr(self, "tool_" + name)(**args)
        except Exception as e:                      # a TypeError on unknown args too, like the RPC
            return {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}],
                    "isError": True}
        return {"content": [{"type": "text", "text": json.dumps(result)}],
                "structuredContent": result if isinstance(result, dict) else {"result": result},
                "isError": False}

    def _func(self, ea):
        for s, (_n, end) in self.state.funcs.items():
            if s <= ea < end:
                return s
        return None

    def tool_server_health(self):
        return {"status": "ok", "imagebase": hex(self.state.imagebase), "module": "sample",
                "input_path": "/x/sample", "auto_analysis_ready": True}

    def tool_lookup_funcs(self, queries):
        out = []
        for q in ([queries] if isinstance(queries, str) else queries):
            ea = int(q, 0)
            f = self._func(ea)
            if f is None:
                out.append({"query": q, "fn": None, "error": "Not a function"})
            else:
                n, end = self.state.funcs[f]
                out.append({"query": q, "fn": {"addr": hex(f), "name": n, "size": hex(end - f)},
                            "error": None})
        return out

    def tool_append_comments(self, items):
        st = self.state
        res = []
        for it in ([items] if isinstance(items, dict) else items):
            ea = int(it["addr"], 0)
            scope = it.get("scope", "auto")
            f = self._func(ea)
            if scope == "func" or (scope == "auto" and f is not None and f == ea):
                if f is None:
                    res.append({"addr": it["addr"], "error": f"No function found at {hex(ea)}"})
                    continue
                cur = st.func_cmts.get(f, "")
                new, skipped = _append_comment_text(cur, it["comment"], dedupe=it.get("dedupe", True))
                if skipped:
                    res.append({"addr": it["addr"], "scope": "func", "skipped": True})
                    continue
                st.func_cmts[f] = new
                res.append({"addr": it["addr"], "scope": "func", "appended": True})
                continue
            cur = st.cmts.get(ea, "")
            new, skipped = _append_comment_text(cur, it["comment"], dedupe=it.get("dedupe", True))
            if skipped:
                res.append({"addr": it["addr"], "scope": "line", "skipped": True})
                continue
            st.cmts[ea] = new
            res.append({"addr": it["addr"], "scope": "line", "appended": True})
        return res

    def tool_set_comments(self, items):
        res = []
        for it in ([items] if isinstance(items, dict) else items):
            self.state.cmts[int(it["addr"], 0)] = it["comment"]
            res.append({"addr": it["addr"]})
        return res

    def tool_rename(self, batch):
        out = []
        for it in batch.get("func") or []:
            ea = int(it["addr"], 0)
            f = self._func(ea)
            if f is None:
                out.append({"addr": it["addr"], "name": it["name"], "error": "Function not found"})
                continue
            clash = [s for s, (n, _e) in self.state.funcs.items() if n == it["name"] and s != f]
            if clash:
                out.append({"addr": it["addr"], "error": f"name already used at {hex(clash[0])}"})
                continue
            old = self.state.funcs[f][0]
            self.state.funcs[f][0] = it["name"]
            out.append({"addr": it["addr"], "old": old, "new": it["name"]})
        return {"func": out, "summary": {"total": len(out)}}

    def tool_py_eval(self, code, new_locals=False):
        if not self.state.py_eval:
            raise TypeError("unknown tool py_eval")
        st = self.state
        st.py_codes.append(code)
        bad = 0xFFFFFFFFFFFFFFFF
        funcs = st.funcs

        def get_func(ea):
            for s0, (_n, end) in funcs.items():
                if s0 <= ea < end:
                    return types.SimpleNamespace(start_ea=s0, end_ea=end)
            return None
        slots = list(st.bookmarks.items())
        idc = types.SimpleNamespace(
            BADADDR=bad,
            get_cmt=lambda ea, rpt: st.cmts.get(ea) if not rpt else None,
            set_cmt=lambda ea, text, rpt: bool(st.cmts.__setitem__(ea, text) or True),
            get_func_cmt=lambda ea, rpt: st.func_cmts.get(get_func(ea).start_ea) if not rpt else None,
            set_func_cmt=lambda ea, text, rpt: bool(st.func_cmts.__setitem__(get_func(ea).start_ea, text)
                                                    or True),
            get_bookmark=lambda slot: slots[slot][0] if slot < len(slots) else bad,
            get_bookmark_desc=lambda slot: slots[slot][1] if slot < len(slots) else None)
        mods = {"idc": idc, "ida_funcs": types.SimpleNamespace(get_func=get_func),
                "idaapi": types.SimpleNamespace(BADADDR=bad),
                "ida_hexrays": types.SimpleNamespace(mark_cfunc_dirty=lambda ea: True),
                "json": json}

        def imp(name, *a, **k):
            if name not in mods:
                raise ImportError(name)
            return mods[name]
        g = {"__builtins__": dict(__builtins__ if isinstance(__builtins__, dict)
                                  else vars(__builtins__), __import__=imp)}
        loc = {}
        try:
            tree = ast.parse(code)
            if tree.body and isinstance(tree.body[-1], ast.Expr):
                exec(compile(ast.Module(body=tree.body[:-1], type_ignores=[]), "<s>", "exec"), g, loc)
                g.update(loc)
                res = str(eval(compile(ast.Expression(body=tree.body[-1].value), "<s>", "eval"), g))
            else:
                exec(code, g, loc)
                res = ""
            return {"result": res, "stdout": "", "stderr": ""}
        except Exception:
            return {"result": "", "stdout": "", "stderr": traceback.format_exc()}

    def tool_add_bookmark(self, addr, name, prefix="idaMCP: "):
        self.state.bookmarks[int(addr, 0)] = prefix + name
        return {"addr": addr, "ok": True, "title": prefix + name}


class Ida(Server):
    handler = _IdaHandler

    def __init__(self, imagebase, funcs, sha256=None, sse=False, require_session=False,
                 database=None, py_eval=True):
        """funcs: {start: (name, end)} in IDA (absolute) addresses."""
        self.imagebase = imagebase
        self.funcs = {a: [n, e] for a, (n, e) in funcs.items()}
        self.sha256 = sha256
        self.sse = sse
        self.require_session = require_session
        self.database = database
        self.py_eval = py_eval
        self.py_codes = []
        self.sessions = set()
        self.cmts, self.func_cmts, self.bookmarks = {}, {}, {}
        self.requests = []

    @property
    def url(self):
        return self.url_base + "/mcp"

    def tool_calls(self, name=None):
        return [r["msg"]["params"] for r in self.requests
                if r["msg"].get("method") == "tools/call"
                and (name is None or r["msg"]["params"]["name"] == name)]
