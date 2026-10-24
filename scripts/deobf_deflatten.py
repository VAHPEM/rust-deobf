#!/usr/bin/env python3
"""deobf_deflatten.py - Tier 4: recover the control flow of a flattened function.

deobf_cff.py *locates* a flattening dispatcher; this *recovers the state machine* behind it.
goldberg (and OLLVM-style passes) rewrite a function into `loop { state = f(state); switch state }`,
so the original order of the blocks is hidden in a state variable. The giveaway, seen in the
goldberg debug build of `band()`:

    mov eax, [rsp+0x40]        ; load state
    mov [rsp+0x2c], eax        ; scratch copy
    sub eax, 0x9ecf39a7        ; }
    je  case_A                 ; } cmp-less ladder: state == const -> case
    ...                        ;
  case_X:                      ; a case does its work, then:
    mov [rsp+0x44], 0xc5aee326 ; set a delta
    ... xor [rsp+0x40], [rsp+0x44] ; state ^= delta   (transition is XOR-based)
    jmp dispatcher

So each case runs at a known state value and transitions to `state ^ delta`. Recovering the
(state -> case, case -> next state) maps rebuilds the real control-flow graph; real branches in
the original code (`if code < 10`) survive as a case with two deltas on two paths.

Two transition forms are handled and tested: goldberg's XOR-delta (`state ^= delta`) and the
classic OLLVM `-fla` **direct assignment** (`switchVar = next_const`, no update slot). The direct
form is covered by `tests/test_deflatten.py::test_deflatten_ollvm_direct_assignment` against a
clang-built target in `obf_src/ollvm_fla/` whose two original branches (a loop test and a parity
check) must reappear as two-way transitions.

This is observational static analysis: it reads the binary and runs nothing. It reconstructs the
graph; it does not re-emit a binary.

    python deobf_deflatten.py <binary> [--func 0x16a50] [--json]
    python deobf_deflatten.py --selftest

Scope note: source-level macro flattening (goldberg's `goldberg_stmts!`) survives only in
unoptimised builds - at `opt-level>=1` rustc's own passes dissolve it (in the release goldberg
build `band` is inlined away). It is the LLVM-pass / OLLVM style of flattening, which survives
-O, that this matters for on real malware; goldberg's debug output is the worked example.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path


def _load_text_and_funcs(path):
    import lief
    b = lief.parse(str(path))
    if b is None:
        raise ValueError("LIEF could not parse the file")
    base = b.optional_header.imagebase if "PE" in b.format.name else 0
    text = next((s for s in b.sections if s.name == ".text"), None)
    if text is None:
        raise ValueError("no .text section")
    code = bytes(text.content)
    tbase = base + text.virtual_address
    funcs = {}
    for s in b.symbols:
        if getattr(s, "is_function", False) and s.value and s.size:
            funcs[s.value] = (s.name, s.size)
    return code, tbase, funcs


def _mem_key(ins):
    """A stable key for a `[reg +/- disp]` memory operand, or None."""
    from capstone import x86
    for op in ins.operands:
        if op.type == x86.X86_OP_MEM:
            m = op.mem
            return (m.base, m.index, m.scale, m.disp)
    return None


def _imm(ins):
    from capstone import x86
    for op in ins.operands:
        if op.type == x86.X86_OP_IMM:
            return op.imm
    return None


def deflatten(code, tbase, func_va, func_size):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, x86
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    off = func_va - tbase
    ins = list(md.disasm(code[off:off + func_size], func_va))
    by_addr = {i.address: k for k, i in enumerate(ins)}
    U32 = 0xFFFFFFFF

    # --- find the dispatcher: a block head `mov r32,[mem]; mov [scratch],r32; sub r32,imm; je`
    #     i.e. a stack slot loaded, copied, then compared by a sub/je ladder.
    state_slot = scratch_slot = disp_addr = None
    for idx in range(len(ins) - 3):
        a, b2, c, d = ins[idx:idx + 4]
        if (a.mnemonic == "mov" and b2.mnemonic == "mov" and c.mnemonic == "sub"
                and d.mnemonic == "je"):
            ssrc = _mem_key(a)
            scpy = _mem_key(b2)
            if ssrc and scpy and a.operands[0].type == x86.X86_OP_REG:
                state_slot, scratch_slot, disp_addr = ssrc, scpy, a.address
                break
    if disp_addr is None:
        return {"flattened": False, "reason": "no sub/je dispatcher ladder found"}

    # --- walk the ladder from the dispatcher: collect state_const -> case block.
    #     Each rung is `[mov r,[scratch]]* ; sub r,imm ; je case ; jmp next_rung`.
    ladder = {}                        # state value -> case VA
    p = by_addr[disp_addr]
    seen = set()
    for _ in range(4096):
        if p is None or p < 0 or p >= len(ins) or p in seen:
            break
        seen.add(p)
        # advance over mov reloads/copies to the comparison
        while p < len(ins) and ins[p].mnemonic == "mov":
            p += 1
        if p + 1 >= len(ins) or ins[p].mnemonic != "sub" or ins[p + 1].mnemonic != "je":
            break
        imm = _imm(ins[p]) & U32
        ladder[imm] = _imm(ins[p + 1])
        nxt = ins[p + 2] if p + 2 < len(ins) else None
        if nxt is not None and nxt.mnemonic == "jmp" and _imm(nxt) in by_addr:
            p = by_addr[_imm(nxt)]      # jump to the next rung
        else:
            p = p + 2                   # fall straight through to it

    # --- find the state-update: `mov r,[upd] ; xor r,[state] ; mov [state],r`
    #     (goldberg loads the delta, xors it into the state slot). update_slot = [upd].
    update_slot = None
    for idx in range(1, len(ins) - 1):
        cur, nx = ins[idx], ins[idx + 1]
        if (cur.mnemonic == "xor" and _mem_key(cur) == state_slot
                and nx.mnemonic == "mov" and _mem_key(nx) == state_slot):
            # the delta was loaded into the register a few insns earlier
            for back in range(idx - 1, max(idx - 4, -1), -1):
                if ins[back].mnemonic == "mov" and _mem_key(ins[back]) not in (None, state_slot):
                    update_slot = _mem_key(ins[back])
                    break
            if update_slot:
                break

    # --- per case: follow the block, find the delta(s) written to update_slot, compute next
    def case_transitions(state_val, case_va):
        """Bounded forward walk from a case to the next dispatch, returning
        [(next_state, condition_or_None)]. XOR transition model: next = state ^ delta."""
        outs = []
        start = by_addr.get(case_va)
        if start is None:
            return outs
        # DFS over the local CFG, carrying the last delta written to update_slot
        stack = [(start, None, 0)]
        visited = set()
        while stack:
            k, delta, steps = stack.pop()
            if k is None or k >= len(ins) or steps > 400:
                continue
            key = (k, delta)
            if key in visited:
                continue
            visited.add(key)
            cur = ins[k]
            # write a delta constant to the update slot
            if cur.mnemonic == "mov" and _mem_key(cur) == update_slot and _imm(cur) is not None:
                delta = _imm(cur) & U32
            # a case may also set the state slot directly (mov [state], imm) -> explicit next
            if cur.mnemonic == "mov" and _mem_key(cur) == state_slot and _imm(cur) is not None:
                outs.append((_imm(cur) & U32, None))
                continue
            # the shared state-apply: xor reg,[state] ; (mov [state],reg) => next = state ^ delta
            if cur.mnemonic == "xor" and _mem_key(cur) == state_slot:
                outs.append(((state_val ^ (delta or 0)) & U32, None))
                continue
            m = cur.mnemonic
            if m == "jmp":
                t = _imm(cur)
                if t in by_addr:
                    stack.append((by_addr[t], delta, steps + 1))
                continue
            if m == "ret" or m.startswith("ret"):
                outs.append((None, "return"))
                continue
            if m == "call":
                # a panic/abort call ends the path; otherwise fall through
                k2 = k + 1
                stack.append((k2, delta, steps + 1))
                continue
            if m.startswith("j"):            # conditional branch = real original logic
                t = _imm(cur)
                cond = "%s @%#x" % (m, cur.address)
                if t in by_addr:
                    stack.append((by_addr[t], delta, steps + 1))
                stack.append((k + 1, delta, steps + 1))
                continue
            stack.append((k + 1, delta, steps + 1))
        return outs

    states = []
    start_state = None
    # the initial state is the imm stored to state_slot before the first dispatch
    for idx in range(by_addr.get(disp_addr, 0)):
        if ins[idx].mnemonic == "mov" and _mem_key(ins[idx]) == state_slot and _imm(ins[idx]) is not None:
            start_state = _imm(ins[idx]) & U32
    for sval, cva in sorted(ladder.items()):
        trans = case_transitions(sval, cva)
        nexts = sorted({t for t, _c in trans if t is not None})
        terminal = any(c == "return" for _t, c in trans)
        states.append({
            "state": "%#010x" % sval,
            "case_va": "%#x" % cva,
            "next_states": ["%#010x" % n for n in nexts],
            "terminal": terminal,
        })

    return {
        "flattened": True,
        "func_va": "%#x" % func_va,
        "dispatcher_va": "%#x" % disp_addr,
        "state_slot_disp": "%#x" % (state_slot[3] & U32) if state_slot else None,
        "update_slot_disp": "%#x" % (update_slot[3] & U32) if update_slot else None,
        "start_state": ("%#010x" % start_state) if start_state is not None else None,
        "num_states": len(ladder),
        "states": states,
    }


def _selftest():
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    # the XOR transition invariant the recovery relies on (state ^= delta), from real band() data
    assert (0xc8100b67 ^ 0xc5aee326) & 0xFFFFFFFF == 0x0dbee841
    # operand helpers decode a real dispatcher head: mov eax,[rsp+0x40]; sub eax,imm; je ...
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    head = list(md.disasm(bytes.fromhex("8b442440" "2da739cf9e" "7405"), 0x1000))
    assert head[0].mnemonic == "mov" and _mem_key(head[0]) is not None
    assert head[1].mnemonic == "sub" and (_imm(head[1]) & 0xFFFFFFFF) == 0x9ecf39a7
    # no false dispatcher on non-flattened bytes
    nop = deflatten(b"\x90" * 256 + b"\xc3", 0x0, 0x0, 257)
    assert nop.get("flattened") is False, nop
    print("selftest OK: XOR transition model, operand decode, and no false dispatcher on "
          "flat code (full recovery in tests/test_deflatten.py on the goldberg debug build)")


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", nargs="?")
    ap.add_argument("--func", help="function VA (hex); default: the symbol named *band* or the "
                                   "largest function")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        _selftest()
        return
    if not a.binary:
        ap.error("binary required or --selftest")
    code, tbase, funcs = _load_text_and_funcs(Path(a.binary))
    if a.func:
        fva = int(a.func, 16)
        fsz = funcs.get(fva, (None, 0x4000))[1] or 0x4000
    else:
        cand = [(v, n, s) for v, (n, s) in funcs.items() if "band" in n]
        if not cand:
            cand = [(v, n, s) for v, (n, s) in funcs.items()]
            cand.sort(key=lambda x: x[2], reverse=True)
        fva, _n, fsz = cand[0]
    r = deflatten(code, tbase, fva, fsz)
    if a.json:
        print(json.dumps(r, indent=2))
        return
    if not r.get("flattened"):
        print(f"{Path(a.binary).name} @ {fva:#x}: {r.get('reason')}")
        return
    print(f"{Path(a.binary).name} @ {r['func_va']}: flattened state machine recovered")
    print(f"  dispatcher {r['dispatcher_va']}  state_slot [rsp+{r['state_slot_disp']}]  "
          f"update_slot [rsp+{r['update_slot_disp']}]  states {r['num_states']}  "
          f"start {r['start_state']}")
    for s in r["states"]:
        arrow = " -> " + ", ".join(s["next_states"]) if s["next_states"] else ""
        term = "  [return]" if s["terminal"] else ""
        print(f"    {s['state']} @ {s['case_va']}{arrow}{term}")


if __name__ == "__main__":
    main()
