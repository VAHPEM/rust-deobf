"""decompiler_bridge.py: neutral annotations, address mapping, and the GhidraMCP / ida-pro-mcp
adapters against in-process stand-ins of their real HTTP APIs (tests/decompiler_mocks.py cites the
plugin source each one follows). No Ghidra or IDA is needed; what that leaves unverified is listed
in VALIDATION.md."""
import json
import subprocess
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests"))
import decompiler_bridge as DB  # noqa: E402
from decompiler_mocks import GhidraLegacy, GhidraV2, Ida  # noqa: E402

FIX = ROOT / "tests" / "fixtures"
TRICKY = 'a&b=c+d%20e#f\n"q" Phạm ✓ ‮evil\\x'


def _doc(hdr, facts, sha=None):
    ann, notes = DB.build_annotations(hdr, facts)
    doc = DB.document(Path("/nonexistent/sample"), hdr, facts, ann, notes)
    doc["sha256"] = sha
    return doc


PE_HDR = {"format": "PE", "arch": "x86_64", "address_space": "rva", "address_base": 0,
          "file_image_base": 0x140000000, "entry": 0x1010, "pie": True}
FACTS = {
    "recover": {
        "decoded": [
            {"string": "https://update.example/a", "function": 0x2000, "tags": ["url"]},
            {"string": TRICKY, "function": 0x2000, "tags": []},
            {"string": "config-key", "decoder": 0x3000, "call": 0x2050, "tags": []},
        ],
        "stack": [{"string": "stackmade", "pc": 0x2060}],
        "libfuncs": [{"va": 0x4000, "name": "core::fmt::write"},
                     {"va": 0x4100, "name": "core::fmt::write"}],   # same label twice
    },
    "libfuncs_propagated": [{"va": 0x4200, "name": "alloc::dealloc", "via": "thunk"}],
    "types": {"vtables": [{"va": 0x8000, "size": 16, "align": 8, "methods": [0x4300, 0x2000]}]},
    "meta": {"rust_release": {"version": "1.97.0"}, "rustc_commit": "2d8144b7880597b6e6d3",
             "crates": {"serde": ["1.0.200"]}},
    "locations": [(0x9000, "src/main.rs", 12, 5)],
    "triage": {"triage_signal": "MEDIUM", "signal_reasons": ["5 decoded strings"]},
}


def _ghidra_pe(**kw):
    ib = 0x140000000
    funcs = {ib + 0x1010: ("entry", [ib + 0x1010, ib + 0x1014]),
             ib + 0x2000: ("FUN_140002000", [ib + 0x2000, ib + 0x2050, ib + 0x2060]),
             ib + 0x3000: ("my_decoder", [ib + 0x3000]),          # the analyst named it
             ib + 0x4000: ("FUN_140004000", [ib + 0x4000]),
             ib + 0x4100: ("FUN_140004100", [ib + 0x4100]),
             ib + 0x4200: ("FUN_140004200", [ib + 0x4200]),
             ib + 0x4300: ("FUN_140004300", [ib + 0x4300])}
    return GhidraV2(ib, funcs, entry_points=[ib + 0x1010], **kw)


# --- neutral annotations -----------------------------------------------------------------------
def test_annotations_are_single_line_escaped_and_prefixed():
    doc = _doc(PE_HDR, FACTS)
    comments = [a for a in doc["annotations"] if a["kind"] == "comment"]
    assert comments and all(a["text"].startswith(DB.PREFIX) for a in comments)
    for a in doc["annotations"]:
        assert "\n" not in a["text"] and "\r" not in a["text"] and "‮" not in a["text"]
    tricky = [a["text"] for a in comments if "Phạm" in a["text"]]
    assert tricky == [DB.PREFIX + 'decodes "a&b=c+d%20e#f\\n\\"q\\" Phạm ✓ '
                      '\\u202eevil\\\\x"']


def test_annotation_fields_tiers_and_address_space():
    doc = _doc(PE_HDR, FACTS)
    assert doc["address_space"] == "rva" and doc["address_base"] == "0x0"
    assert doc["file_image_base"] == "0x140000000" and doc["entry"] == "0x1010"
    by = {(a["address"], a["kind"], a["source_tier"]) for a in doc["annotations"]}
    assert ("0x2050", "comment", "recover") in by                 # decoder call site
    assert ("0x2060", "comment", "recover_stackstrings") in by
    assert ("0x8000", "comment", "recover_types") in by and ("0x8000", "bookmark", "recover_types") in by
    assert ("0x9000", "comment", "recover_rust_meta") in by       # panic Location record
    assert ("0x1010", "comment", "soc_triage") in by and ("0x1010", "bookmark", "soc_triage") in by
    for a in doc["annotations"]:
        assert set(a) == {"address", "kind", "scope", "text", "source_tier", "function"}
        assert a["kind"] in DB.KINDS and a["scope"] in DB.SCOPES and a["source_tier"] in DB.TIERS
    call = next(a for a in doc["annotations"] if a["address"] == "0x2050")
    assert call["scope"] == "instruction" and call["function"] == "0x3000"


def test_renames_one_per_address_priority_and_unique():
    doc = _doc(PE_HDR, FACTS)
    names = {a["address"]: a["text"] for a in doc["annotations"] if a["kind"] == "rename"}
    # a decoder that is also a vtable method keeps its rd_<tag> name (decoded beats vtmethod)
    assert names["0x2000"] == "rd_url_https_update_example_a"
    assert names["0x4000"] == "lib_core_fmt_write"
    assert names["0x4100"] == "lib_core_fmt_write_4100"           # same label: made unique
    assert names["0x4200"] == "lib_alloc_dealloc"
    assert names["0x4300"] == "rd_vtmethod_8000_0"
    assert len([a for a in doc["annotations"] if a["kind"] == "rename"]) == len(names)
    assert all(DB._OURS.match(n) for n in names.values())


def test_filters_and_decompiler_addresses():
    doc = _doc(PE_HDR, FACTS)
    f = DB.filter_annotations(doc["annotations"], tiers=["recover"], kinds=["rename"])
    assert [a["address"] for a in f] == ["0x2000", "0x3000"]
    f = DB.filter_annotations(doc["annotations"], function=0x3000)
    assert {a["address"] for a in f} == {"0x3000", "0x2050"}     # its own + the call into it
    DB.with_decompiler_addresses(doc, 0x140000000)
    assert all(int(a["decompiler_address"], 16) == int(a["address"], 16) + 0x140000000
               for a in doc["annotations"])


# --- address mapping ---------------------------------------------------------------------------
def test_pe_rva_maps_to_ghidra_image_base_and_exact_requests():
    doc = _doc(PE_HDR, FACTS)
    with _ghidra_pe() as g:
        r = DB.push(doc, "ghidra-mcp", g.url, rate=0)
        assert r["mapping"]["delta"] == 0x140000000 and r["mapping"]["verified"] is True
        assert r["summary"]["failed"] == 0, r["results"]
        posts = g.posts()
        assert {p["path"] for p in posts} == {"/set_decompiler_comment", "/rename_function_by_address"}
        for p in posts:
            assert p["headers"]["Content-Type"].startswith("application/x-www-form-urlencoded")
            assert "Origin" not in p["headers"]
            assert set(p["params"]) in ({"address", "comment"}, {"function_address", "new_name"})
            a = p["params"].get("address") or p["params"]["function_address"]
            assert a.startswith("0x14000") and a == a.lower()
        # comments land at absolute VAs and are the merged rust-deobf block for the address
        pre = g.comments[("PRE", 0x140002000)].split("\n")
        assert all(ln.startswith(DB.PREFIX) for ln in pre) and len(pre) >= 3
        assert ("PRE", 0x140002050) in g.comments and ("PRE", 0x140009000) in g.comments
        names = {a: v[0] for a, v in g.funcs.items()}
        assert names[0x140002000] == "rd_url_https_update_example_a"
        assert names[0x140003000] == "my_decoder"                 # analyst name kept
        assert names[0x140001010] == "entry"
        assert names[0x140004100] == "lib_core_fmt_write_4100"


def test_injection_characters_survive_the_form_encoding():
    doc = _doc(PE_HDR, FACTS)
    with _ghidra_pe() as g:
        DB.push(doc, "ghidra-mcp", g.url, rate=0)
        stored = g.comments[("PRE", 0x140002000)]
        plan = DB.plan(doc["annotations"], 0x140000000)
        expected = dict((a, "\n".join(lines)) for a, _s, lines in plan["comments"])
        assert stored == expected[0x140002000]
        assert 'a&b=c+d%20e#f\\n\\"q\\" Phạm' in stored


def test_elf_pie_ghidra_rebased_to_0x100000():
    hdr = {"format": "ELF", "arch": "x86_64", "address_space": "va", "address_base": 0,
           "file_image_base": 0, "entry": 0x1050, "pie": True}
    facts = {"recover": {"decoded": [{"string": "hello-world", "function": 0x1460}]}}
    doc = _doc(hdr, facts)
    funcs = {0x101050: ("entry", [0x101050]), 0x101460: ("FUN_00101460", [0x101460])}
    with GhidraV2(0x100000, funcs, entry_points=[0x101050], fmt="ELF") as g:
        r = DB.push(doc, "ghidra-mcp", g.url, rate=0)
        assert r["mapping"]["delta"] == 0x100000 and r["mapping"]["verified"]
        assert g.funcs[0x101460][0] == "rd_str_hello_world"
        assert ("PRE", 0x101460) in g.comments


def test_elf_non_pie_link_base_and_ida_reporting_zero():
    hdr = {"format": "ELF", "arch": "x86_64", "address_space": "va", "address_base": 0x400000,
           "file_image_base": 0x400000, "entry": 0x401000, "pie": False}
    doc = _doc(hdr, {"recover": {"decoded": [{"string": "hello-world", "function": 0x401100}]}})
    funcs = {0x401000: ("start", 0x401010), 0x401100: ("sub_401100", 0x401180)}
    # IDA's imagebase for this ELF may be reported as 0 while it keeps the link addresses: the
    # first candidate (0 - 0x400000) fails the probe, "addresses as linked" verifies
    with Ida(0, funcs) as ida:
        r = DB.push(doc, "ida-mcp", ida.url, rate=0)
        assert r["mapping"]["delta"] == 0 and r["mapping"]["verified"]
        assert "kept as loaded" in r["mapping"]["how"]
        assert ida.funcs[0x401100][0] == "rd_str_hello_world"
    with GhidraV2(0x400000, {0x401000: ("entry", [0x401000]),
                             0x401100: ("FUN_00401100", [0x401100])},
                  entry_points=[0x401000], fmt="ELF") as g:
        r = DB.push(doc, "ghidra-mcp", g.url, rate=0)
        assert r["mapping"]["delta"] == 0 and r["mapping"]["verified"]


def test_ida_pie_at_zero_and_macho():
    hdr = {"format": "ELF", "arch": "aarch64", "address_space": "va", "address_base": 0,
           "file_image_base": 0, "entry": 0x1050, "pie": True}
    doc = _doc(hdr, {"recover": {"decoded": [{"string": "hello-world", "function": 0x1460}]}})
    with Ida(0, {0x1050: ("start", 0x1060), 0x1460: ("sub_1460", 0x1500)}) as ida:
        r = DB.push(doc, "ida-mcp", ida.url, rate=0)
        assert r["mapping"]["delta"] == 0 and r["mapping"]["verified"]
    mo = {"format": "MACHO", "arch": "aarch64", "address_space": "va",
          "address_base": 0x100000000, "file_image_base": 0x100000000, "entry": 0x100000e90,
          "pie": True}
    doc = _doc(mo, {"recover": {"decoded": [{"string": "hello-world", "function": 0x100000ca0}]}})
    with GhidraV2(0x100000000, {0x100000e90: ("entry", [0x100000e90]),
                                0x100000ca0: ("FUN_100000ca0", [0x100000ca0])},
                  entry_points=[0x100000e90], fmt="Mac OS X Mach-O") as g:
        r = DB.push(doc, "ghidra-mcp", g.url, rate=0)
        assert r["mapping"]["delta"] == 0 and g.funcs[0x100000ca0][0] == "rd_str_hello_world"


def test_unverifiable_mapping_is_refused_and_image_base_override():
    doc = _doc(PE_HDR, FACTS)
    with _ghidra_pe() as g:
        g.image_base = 0x180000000                     # a rebased/other program: probes miss
        g.entry_points = []
        with pytest.raises(DB.BridgeError) as e:
            DB.push(doc, "ghidra-mcp", g.url, rate=0)
        assert e.value.code == DB.EXIT_REFUSED and "could not verify" in str(e.value)
        assert not g.posts()
        r = DB.push(doc, "ghidra-mcp", g.url, rate=0, image_base=0x140000000, dry_run=True)
        assert r["mapping"]["verified"] and r["mapping"]["delta"] == 0x140000000
        with pytest.raises(DB.BridgeError):
            DB.push(doc, "ghidra-mcp", g.url, rate=0, image_base=0x10000000, dry_run=True)
        r = DB.push(doc, "ghidra-mcp", g.url, rate=0, image_base=0x10000000, dry_run=True,
                    force=True)
        assert r["mapping"]["verified"] is False


def test_sha256_mismatch_refused_unless_forced():
    doc = _doc(PE_HDR, FACTS, sha="a" * 64)
    with _ghidra_pe(sha256="b" * 64) as g:
        with pytest.raises(DB.BridgeError) as e:
            DB.push(doc, "ghidra-mcp", g.url, rate=0)
        assert e.value.code == DB.EXIT_REFUSED and "not this file" in str(e.value)
        assert not g.posts()
        r = DB.push(doc, "ghidra-mcp", g.url, rate=0, force=True, dry_run=True)
        assert any("sha256 differs" in n for n in r["notes"])
    with _ghidra_pe(sha256="A" * 64) as g:                 # case-insensitive match
        DB.push(_doc(PE_HDR, FACTS, sha="a" * 64), "ghidra-mcp", g.url, rate=0, dry_run=True)


# --- idempotency / dry-run / comment modes -----------------------------------------------------
def test_ghidra_pre_idempotent_and_dry_run_writes_nothing():
    doc = _doc(PE_HDR, FACTS)
    with _ghidra_pe() as g:
        dry = DB.push(doc, "ghidra-mcp", g.url, rate=0, dry_run=True)
        assert not g.posts() and dry["summary"]["planned"] > 0
        assert not g.comments and g.funcs[0x140002000][0] == "FUN_140002000"
        DB.push(doc, "ghidra-mcp", g.url, rate=0)
        state = (dict(g.comments), {a: v[0] for a, v in g.funcs.items()})
        r2 = DB.push(doc, "ghidra-mcp", g.url, rate=0)
        assert (g.comments, {a: v[0] for a, v in g.funcs.items()}) == state
        renames = [x for x in r2["results"] if x["op"] == "rename"]
        assert all(x["status"] in ("unchanged", "skipped") for x in renames)
        assert {x["status"] for x in r2["results"] if x["op"] == "bookmark"} == {"skipped"}


def test_ghidra_eol_merges_keeps_analyst_text_and_is_idempotent():
    doc = _doc(PE_HDR, FACTS)
    with _ghidra_pe() as g:
        g.comments[("EOL", 0x140002050)] = "analyst: interesting call"
        g.comments[("EOL", 0x140002060)] = DB.PREFIX + "a stale fact from an older run"
        DB.push(doc, "ghidra-mcp", g.url, rate=0, ghidra_comment="eol")
        c = g.comments[("EOL", 0x140002050)].split("\n")
        assert c[0] == "analyst: interesting call" and c[1].startswith(DB.PREFIX)
        assert "stale" not in g.comments[("EOL", 0x140002060)]
        n = len(g.posts())
        r2 = DB.push(doc, "ghidra-mcp", g.url, rate=0, ghidra_comment="eol")
        assert [p["path"] for p in g.posts()[n:]] == []                # nothing rewritten
        assert all(x["status"] in ("unchanged", "skipped") for x in r2["results"]
                   if x["op"] == "comment")
        # a data address (vtable, Location) has no function: EOL cannot be read -> not written
        assert ("EOL", 0x140008000) not in g.comments


def test_ghidra_no_program_open():
    with GhidraV2(0x140000000, {}, program_open=False) as g:
        with pytest.raises(DB.BridgeError) as e:
            DB.push(_doc(PE_HDR, FACTS), "ghidra-mcp", g.url, rate=0)
        assert e.value.code == DB.EXIT_BACKEND and "no program is open" in str(e.value)


def test_ghidra_legacy_plain_text_api():
    ib = 0x140000000
    funcs = {ib + 0x1010: ("entry", [ib + 0x1010]),
             ib + 0x2000: ("FUN_140002000", [ib + 0x2000, ib + 0x2050, ib + 0x2060])}
    doc = _doc(PE_HDR, FACTS)
    with GhidraLegacy(funcs) as g:
        with pytest.raises(DB.BridgeError) as e:            # 1.x cannot report an image base
            DB.push(doc, "ghidra-mcp", g.url, rate=0)
        assert e.value.code == DB.EXIT_REFUSED and "--image-base" in str(e.value)
        r = DB.push(doc, "ghidra-mcp", g.url, rate=0, image_base=ib)
        assert r["server"]["api"].startswith("GhidraMCP 1.x") and r["mapping"]["verified"]
        assert g.funcs[ib + 0x2000][0] == "rd_url_https_update_example_a"
        assert g.pre[ib + 0x2000].count(DB.PREFIX) >= 3
        assert 'a&b=c+d%20e#f' in g.pre[ib + 0x2000]       # survived the 1.x split("=") parser
        # EOL merge through the text disassembly, multi-line analyst comment preserved
        g.eol[ib + 0x2050] = "line one\nline two"
        DB.push(doc, "ghidra-mcp", g.url, rate=0, image_base=ib, ghidra_comment="eol")
        assert g.eol[ib + 0x2050].startswith("line one\nline two\n" + DB.PREFIX)
        before = dict(g.eol)
        DB.push(doc, "ghidra-mcp", g.url, rate=0, image_base=ib, ghidra_comment="eol")
        assert g.eol == before


# --- ida-pro-mcp -------------------------------------------------------------------------------
def _ida_pe(**kw):
    ib = 0x140000000
    funcs = {ib + 0x1010: ("start", ib + 0x1020),
             ib + 0x2000: ("sub_140002000", ib + 0x2100),
             ib + 0x3000: ("my_decoder", ib + 0x3010),
             ib + 0x4000: ("sub_140004000", ib + 0x4010),
             ib + 0x4100: ("sub_140004100", ib + 0x4110),
             ib + 0x4200: ("sub_140004200", ib + 0x4210),
             ib + 0x4300: ("sub_140004300", ib + 0x4310)}
    return Ida(ib, funcs, **kw)


@pytest.mark.parametrize("sse", [False, True])
def test_ida_push_exact_calls_session_and_idempotency(sse):
    doc = _doc(PE_HDR, FACTS)
    with _ida_pe(sse=sse, require_session=True) as ida:
        r = DB.push(doc, "ida-mcp", ida.url, rate=0)
        assert r["summary"]["failed"] == 0, r["results"]
        assert r["mapping"]["delta"] == 0x140000000 and r["mapping"]["verified"]
        first = ida.requests[0]
        assert first["msg"]["method"] == "initialize" and "Mcp-Session-Id" not in first["headers"]
        sid = {rq["headers"].get("Mcp-Session-Id") for rq in ida.requests[1:]}
        assert len(sid) == 1 and None not in sid                     # the session id is reused
        calls = ida.tool_calls("append_comments")
        items = [it for c in calls for it in c["arguments"]["items"]]
        assert all(set(it) == {"addr", "comment", "dedupe", "scope"} for it in items)
        assert all(it["addr"].startswith("0x14000") and it["dedupe"] is True for it in items)
        assert {it["scope"] for it in items if it["addr"] == "0x140002000"} == {"auto"}
        assert {it["scope"] for it in items if it["addr"] == "0x140002050"} == {"line"}
        assert all("\n" not in it["comment"] and it["comment"].startswith(DB.PREFIX) for it in items)
        fc = ida.func_cmts[0x140002000].split("\n")
        assert all(ln.startswith(DB.PREFIX) for ln in fc) and ida.cmts[0x140002050]
        (ren,) = ida.tool_calls("rename")
        assert {f["addr"] for f in ren["arguments"]["batch"]["func"]} == \
            {"0x140002000", "0x140004000", "0x140004100", "0x140004200", "0x140004300"}
        assert ida.funcs[0x140003000][0] == "my_decoder"
        assert not ida.tool_calls("add_bookmark") and not ida.bookmarks
        state = (dict(ida.cmts), dict(ida.func_cmts), {a: v[0] for a, v in ida.funcs.items()})
        r2 = DB.push(doc, "ida-mcp", ida.url, rate=0)
        assert (ida.cmts, ida.func_cmts, {a: v[0] for a, v in ida.funcs.items()}) == state
        assert {x["status"] for x in r2["results"] if x["op"] == "comment"} == {"unchanged"}
        assert len(ida.tool_calls("rename")) == 1                    # nothing left to rename


def test_ida_keeps_analyst_comments_bookmarks_opt_in_dry_run_and_database():
    doc = _doc(PE_HDR, FACTS)
    with _ida_pe(database="s1") as ida:
        ida.func_cmts[0x140002000] = "analyst note"
        dry = DB.push(doc, "ida-mcp", ida.url, rate=0, dry_run=True, ida_database="s1")
        writes = [c for c in ida.tool_calls() if c["name"] in
                  ("append_comments", "set_comments", "rename", "add_bookmark")]
        assert not writes and dry["summary"]["planned"] > 0
        assert all(c["arguments"].get("database") == "s1" for c in ida.tool_calls())
        DB.push(doc, "ida-mcp", ida.url, rate=0, bookmarks=True, ida_database="s1")
        assert ida.func_cmts[0x140002000].startswith("analyst note\n" + DB.PREFIX)
        assert ida.bookmarks[0x140008000].startswith(DB.PREFIX + "vtable")
        assert set(ida.tool_calls("add_bookmark")[0]["arguments"]) == {"addr", "name", "prefix",
                                                                       "database"}
    with _ida_pe(database="s1") as ida:                  # supervisor needs `database`
        with pytest.raises(DB.BridgeError) as e:
            DB.push(doc, "ida-mcp", ida.url, rate=0)
        assert "missing database" in str(e.value)


def test_ida_set_mode_and_sha_from_metadata_resource():
    doc = _doc(PE_HDR, FACTS, sha="c" * 64)
    with _ida_pe(sha256="d" * 64) as ida:
        with pytest.raises(DB.BridgeError) as e:
            DB.push(doc, "ida-mcp", ida.url, rate=0)
        assert e.value.code == DB.EXIT_REFUSED
    with _ida_pe(sha256="c" * 64) as ida:
        DB.push(doc, "ida-mcp", ida.url, rate=0, ida_comment="set")
        assert ida.cmts[0x140002000].count("\n") >= 2 and not ida.tool_calls("append_comments")


# --- transport safety --------------------------------------------------------------------------
@pytest.mark.parametrize("url", ["http://192.0.2.10:8080/", "http://127.0.0.1@evil.example/",
                                 "http://user:pw@127.0.0.1:8080/", "ftp://127.0.0.1/",
                                 "http://127.0.0.1:notaport/", "http://evil.example/"])
def test_non_loopback_or_odd_urls_refused(url):
    with pytest.raises(DB.BridgeError) as e:
        DB.check_url(url)
    assert e.value.code == DB.EXIT_USAGE


def test_loopback_forms_accepted_and_allow_remote():
    for u in ("http://127.0.0.1:8080/", "http://localhost:13337/mcp", "http://[::1]:8080/",
              "http://127.0.0.2:1/"):
        assert DB.check_url(u) == u
    assert DB.check_url("http://192.0.2.10:8080/", allow_remote=True)


def test_unreachable_server_clear_error_and_cli_exit_code(tmp_path):
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()                                            # nothing listens there now
    doc = _doc(PE_HDR, FACTS)
    for backend, what in (("ghidra-mcp", "GhidraMCP"), ("ida-mcp", "ida-pro-mcp")):
        with pytest.raises(DB.BridgeError) as e:
            DB.push(doc, backend, "http://127.0.0.1:%d/" % port, rate=0, timeout=3)
        assert e.value.code == DB.EXIT_BACKEND and f"cannot reach {what}" in str(e.value)
    f = tmp_path / "ann.json"
    f.write_text(json.dumps(doc))
    p = subprocess.run([sys.executable, str(ROOT / "scripts" / "decompiler_bridge.py"),
                        "--from-json", str(f), "--backend", "ghidra-mcp",
                        "--url", "http://127.0.0.1:%d/" % port, "--timeout", "3"],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == DB.EXIT_BACKEND and "cannot reach GhidraMCP" in p.stderr


def test_redirects_are_not_followed():
    hits = []

    class R(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            hits.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://192.0.2.1/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), R)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        with pytest.raises(DB.BridgeError) as e:
            DB.push(_doc(PE_HDR, FACTS), "ghidra-mcp", "http://127.0.0.1:%d/" % srv.server_address[1],
                    rate=0, timeout=3)
        assert "redirect" in str(e.value) and hits == ["/health"]
    finally:
        srv.shutdown()
        srv.server_close()


def test_rate_limit_spaces_requests():
    import time
    with _ghidra_pe() as g:
        c = DB.HttpClient(g.url, rate=20)
        t0 = time.monotonic()
        for _ in range(5):
            c.request("GET", "health")
        assert time.monotonic() - t0 >= 4 / 20 - 0.01


# --- CLI + real fixtures -----------------------------------------------------------------------
def _cli(*args, timeout=300):
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "decompiler_bridge.py"), *args],
                          capture_output=True, text=True, timeout=timeout)


def test_cli_from_json_push_report(tmp_path):
    doc = _doc(PE_HDR, FACTS)
    f = tmp_path / "ann.json"
    f.write_text(json.dumps(doc), encoding="utf-8")
    with _ghidra_pe() as g:
        p = _cli("--from-json", str(f), "--backend", "ghidra-mcp", "--url", g.url, "--json",
                 "--rate", "0", "--tier", "recover", "--kind", "rename")
        assert p.returncode == 0, p.stderr
        rep = json.loads(p.stdout)
        assert {r["op"] for r in rep["results"]} == {"rename"}
        assert rep["summary"]["applied"] == 1                       # 0x3000 is the analyst's
        assert {x["path"] for x in g.posts()} == {"/rename_function_by_address"}
    assert _cli("--from-json", str(f), "--backend", "ghidra-mcp",
                "--url", "http://192.0.2.10:8080/").returncode == DB.EXIT_USAGE
    bad = tmp_path / "bad.json"
    bad.write_text('{"annotations": [{"kind": "comment"}]}')
    assert _cli("--from-json", str(bad)).returncode == DB.EXIT_USAGE


def test_cli_json_on_real_fixture_vtable_and_mapping():
    p = _cli(str(FIX / "emu" / "vt32"), "--image-base", "0x10000", "--emulate", "never")
    assert p.returncode == 0, p.stderr
    doc = json.loads(p.stdout)
    assert doc["format"] == "ELF" and doc["address_space"] == "va" and doc["pie"] is True
    vt = [a for a in doc["annotations"] if a["source_tier"] == "recover_types"]
    assert any(a["kind"] == "rename" and a["text"] == "rd_vtmethod_22e4_0" for a in vt)
    assert all(int(a["decompiler_address"], 16) == int(a["address"], 16) + 0x10000
               for a in doc["annotations"])
    assert doc["sha256"] and len(doc["sha256"]) == 64


@pytest.mark.parametrize("rel,space,base,entry", [
    ("emu/pe64.exe", "rva", 0, 0x1010),
    ("static/shortkey", "va", 0x400000, 0x401000),
    ("strenc/rustcloak_lazy.x64", "va", 0, 0x1050),
    ("macho/litcrypt.arm64", "va", 0x100000000, 0x100000e90),
])
def test_layout_address_space(rel, space, base, entry):
    h = DB.layout(FIX / rel)
    assert (h["address_space"], h["address_base"], h["entry"]) == (space, base, entry)
    if space == "rva":
        assert h["file_image_base"] == 0x140000000


def test_unsupported_input(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"not a binary")
    with pytest.raises(DB.UnsupportedInput):
        DB.layout(f)
    assert _cli(str(f)).returncode == DB.EXIT_UNSUPPORTED


def test_panic_location_record_addresses_match_the_engine():
    import recover_rust_meta
    path = FIX / "vm" / "benign_rust_std.x64"
    meta = recover_rust_meta.recover(path)
    locs = DB._panic_location_vas(path, meta)
    sites = {(p["file"], p["line"], p["col"]) for p in meta["panic_sites"]}
    assert locs and len(locs) <= len(sites) and len(locs) >= 0.9 * len(sites)
    assert all((f, ln, c) in sites for _va, f, ln, c in locs)
    import lief
    b = lief.parse(str(path))
    secs = [(s.virtual_address, s.virtual_address + s.size) for s in b.sections if s.virtual_address]
    assert all(any(lo <= va < hi for lo, hi in secs) for va, *_ in locs)


def test_analyze_real_fixture_decoded_strings():
    doc = DB.analyze(FIX / "strenc" / "rustcloak_lazy.x64", time_budget=20)
    ren = {a["address"]: a["text"] for a in doc["annotations"] if a["kind"] == "rename"
           and a["source_tier"] == "recover"}
    assert ren and all(n.startswith("rd_str_rustcloak_flatten_demo") for n in ren.values())
    dec = [a for a in doc["annotations"] if a["kind"] == "comment" and a["source_tier"] == "recover"]
    assert any('"rustcloak::flatten-demo::ok"' in a["text"] for a in dec)
    assert doc["program"]["triage_signal"] in ("LOW", "MEDIUM", "HIGH")
    assert not doc["engine_errors"]


# --- regressions from the post-implementation review ---------------------------------------------
def test_plan_does_not_double_escape_and_sanitizes_foreign_documents():
    doc = _doc(PE_HDR, FACTS)
    p = DB.plan(doc["annotations"], 0)
    marks = dict(p["bookmarks"])
    assert "\\\\\\\\" not in marks[0x2000] and "\\\\x" in marks[0x2000]   # escaped once only
    own = [ln for _a, _s, lines in p["comments"] for ln in lines]
    assert DB.plan(doc["annotations"], 0)["comments"] == p["comments"] and own
    foreign = [{"address": "0x10", "kind": "comment", "scope": "function", "source_tier": "recover",
                "text": DB.PREFIX + "x\n" + DB.PREFIX + "forged"},
               {"address": "0x10", "kind": "rename", "scope": "function", "source_tier": "recover",
                "text": "bad name; rm"},
               {"address": "0x20", "kind": "bookmark", "scope": "function", "source_tier": "recover",
                "text": "a\nb"}]
    fp = DB.plan(foreign, 0)
    assert fp["comments"] == [(0x10, "function", [DB.PREFIX + "x\\n" + DB.PREFIX + "forged"])]
    assert fp["renames"] == [] and fp["bookmarks"] == [(0x20, "a\\nb")]


def test_decompiler_address_below_image_base_is_none():
    hdr = {"format": "ELF", "arch": "x86_64", "address_space": "va", "address_base": 0x400000,
           "file_image_base": 0x400000, "entry": 0x401000, "pie": False}
    doc = _doc(hdr, {"recover": {"decoded": [{"string": "hello-world", "function": 0x401100}]}})
    DB.with_decompiler_addresses(doc, 0)
    assert {a["decompiler_address"] for a in doc["annotations"]} == {"0x1100"}
    DB.with_decompiler_addresses(doc, 0x400000 - 0x401100 - 1)
    assert all(a["decompiler_address"] is None for a in doc["annotations"])


def test_legacy_eol_parser_ignores_address_like_continuations():
    ib = 0x140000000
    with GhidraLegacy({ib + 0x2000: ("FUN_140002000", [ib + 0x2000, ib + 0x2050])}) as g:
        g.eol[ib + 0x2000] = "first\nabc: looks like an address"
        be = DB.make_backend("ghidra-mcp", g.url, rate=0)
        be.connect()
        assert be._read_eol(ib + 0x2000) == "first\nabc: looks like an address"
        assert be._read_eol(ib + 0x2050) == ""
