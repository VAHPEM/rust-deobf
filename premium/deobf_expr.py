#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: Ve (VAHPEM) <ve0912084386@gmail.com>
#
# Dual-licensed: AGPL-3.0-or-later OR a commercial license.
# Commercial licensing: Ve (VAHPEM) <ve0912084386@gmail.com>
"""deobf_expr.py - Tier 4: provable simplification of obfuscated expressions.

Two building blocks of code deobfuscation, done soundly with an SMT solver (z3) so a
claimed simplification is PROVEN over all inputs, not guessed from a few samples:

  * MBA (mixed boolean-arithmetic) simplification. Obfuscators replace `x + y` with
    things like `(x ^ y) + 2*(x & y)` or `(x | y) + (x & y)`. Given such an
    expression we test it for equivalence against a library of simple normal forms
    over n-bit words; z3 proves the match for every input or returns a counterexample.

  * Opaque-predicate classification. A predicate like `(x*x - x) % 2 == 0` or
    `(x | 1) != 0` is constant for all inputs; z3 decides always-true / always-false /
    input-dependent, so dead branches guarded by opaque predicates can be removed.

Expressions are written in a small, safe grammar over unsigned n-bit variables
(default 32): + - * & | ^ ~ << >> and comparisons == != < <= > >=, with int literals
and single-letter variables. Parsed with Python's `ast` under a strict operator
allowlist -- no eval of arbitrary code.

    python deobf_expr.py mba    "(x ^ y) + 2*(x & y)"
    python deobf_expr.py opaque "(x*x - x) & 1 == 0"
    python deobf_expr.py equiv  "(x|y)-(x&y)" "x^y"
    python deobf_expr.py --selftest
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
# premium module: find both premium/ (sibling premium modules) and the Apache core in scripts/
for _p in (str(_Path(__file__).resolve().parent), str(_Path(__file__).resolve().parent.parent / 'scripts')):
    if _p not in _sys.path:
        _sys.path.insert(0, _p)

import argparse, ast, sys

try:
    import z3
except ImportError:
    z3 = None

_ALLOWED_BIN = {ast.Add, ast.Sub, ast.Mult, ast.BitAnd, ast.BitOr, ast.BitXor,
                ast.LShift, ast.RShift}
_ALLOWED_UNARY = {ast.Invert, ast.USub}
_ALLOWED_CMP = {ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE}


def _collect_vars(node, acc):
    if isinstance(node, ast.Name):
        acc.add(node.id)
    for c in ast.iter_child_nodes(node):
        _collect_vars(c, acc)


def _build(node, env, nbits):
    """Translate a whitelisted AST node into a z3 bit-vector expression."""
    if isinstance(node, ast.Expression):
        return _build(node.body, env, nbits)
    if isinstance(node, ast.BinOp):
        if type(node.op) not in _ALLOWED_BIN:
            raise ValueError(f"operator not allowed: {type(node.op).__name__}")
        a = _build(node.left, env, nbits); b = _build(node.right, env, nbits)
        op = type(node.op)
        return {ast.Add: lambda: a + b, ast.Sub: lambda: a - b, ast.Mult: lambda: a * b,
                ast.BitAnd: lambda: a & b, ast.BitOr: lambda: a | b,
                ast.BitXor: lambda: a ^ b, ast.LShift: lambda: a << b,
                ast.RShift: lambda: z3.LShR(a, b)}[op]()         # logical (unsigned) shift
    if isinstance(node, ast.UnaryOp):
        if type(node.op) not in _ALLOWED_UNARY:
            raise ValueError("unary operator not allowed")
        v = _build(node.operand, env, nbits)
        return ~v if isinstance(node.op, ast.Invert) else -v
    if isinstance(node, ast.Name):
        if node.id not in env:
            env[node.id] = z3.BitVec(node.id, nbits)
        return env[node.id]
    if isinstance(node, ast.Constant) and isinstance(node.value, int):
        return z3.BitVecVal(node.value, nbits)
    raise ValueError(f"unsupported syntax: {ast.dump(node)}")


def parse_expr(text, nbits, env=None):
    if z3 is None:
        sys.exit("z3 not installed: pip install z3-solver")
    env = {} if env is None else env
    tree = ast.parse(text, mode="eval")
    return _build(tree, env, nbits), env


def parse_predicate(text, nbits):
    """Parse 'LHS <cmp> RHS' into a z3 boolean (unsigned comparisons)."""
    if z3 is None:
        sys.exit("z3 not installed: pip install z3-solver")
    tree = ast.parse(text, mode="eval")
    if not (isinstance(tree.body, ast.Compare) and len(tree.body.ops) == 1):
        raise ValueError("predicate must be exactly one comparison, e.g. 'x & 1 == 0'")
    if type(tree.body.ops[0]) not in _ALLOWED_CMP:
        raise ValueError("comparison operator not allowed")
    env = {}
    lhs = _build(tree.body.left, env, nbits)
    rhs = _build(tree.body.comparators[0], env, nbits)
    op = type(tree.body.ops[0])
    pred = {ast.Eq: lambda: lhs == rhs, ast.NotEq: lambda: lhs != rhs,
            ast.Lt: lambda: z3.ULT(lhs, rhs), ast.LtE: lambda: z3.ULE(lhs, rhs),
            ast.Gt: lambda: z3.UGT(lhs, rhs), ast.GtE: lambda: z3.UGE(lhs, rhs)}[op]()
    return pred, env


def prove_equiv(text_a, text_b, nbits):
    """Return (True, None) if a == b for all inputs, else (False, counterexample dict)."""
    env = {}
    a, env = parse_expr(text_a, nbits, env)
    b, env = parse_expr(text_b, nbits, env)
    s = z3.Solver()
    s.add(a != b)
    if s.check() == z3.unsat:
        return True, None
    m = s.model()
    return False, {str(d): m[d].as_long() for d in m.decls()}


# Normal forms an MBA expression is most often hiding. Each is tested for provable
# equivalence; the first that matches (with the same variable set) is the simplification.
_NORMAL_FORMS = [
    "x + y", "x - y", "y - x", "x ^ y", "x & y", "x | y", "~x", "x + x", "2*x",
    "x", "y", "0", "x & ~y", "y & ~x", "~x & ~y", "~(x & y)", "~(x | y)", "~(x ^ y)",
]


def simplify_mba(text, nbits):
    """Try to prove `text` equals one of the simple normal forms. Returns the simplest
    equivalent form (by string length) or None if none match."""
    varset = set()
    _collect_vars(ast.parse(text, mode="eval"), varset)
    matches = []
    for nf in _NORMAL_FORMS:
        nf_vars = set()
        _collect_vars(ast.parse(nf, mode="eval"), nf_vars)
        if not nf_vars <= varset:          # normal form must not invent a new variable
            continue
        ok, _ = prove_equiv(text, nf, nbits)
        if ok:
            matches.append(nf)
    return min(matches, key=len) if matches else None


def classify_opaque(text, nbits):
    """Classify a predicate as 'always-true', 'always-false', or 'input-dependent'."""
    pred, _ = parse_predicate(text, nbits)
    s = z3.Solver(); s.add(z3.Not(pred))
    if s.check() == z3.unsat:
        return "always-true", None
    witness_false = {str(d): s.model()[d].as_long() for d in s.model().decls()}
    s = z3.Solver(); s.add(pred)
    if s.check() == z3.unsat:
        return "always-false", None
    witness_true = {str(d): s.model()[d].as_long() for d in s.model().decls()}
    return "input-dependent", {"true_when": witness_true, "false_when": witness_false}


def _selftest():
    n = 32
    # classic MBA identities obfuscators use for +, -, ^, |
    cases = [
        ("(x ^ y) + 2*(x & y)", "x + y"),
        ("(x | y) + (x & y)",   "x + y"),
        ("(x | y) - (x & y)",   "x ^ y"),
        ("x - (x & y)",         "x & ~y"),
        ("(x & y) + (x | y) - y", "x"),
    ]
    for obf, simple in cases:
        ok, cex = prove_equiv(obf, simple, n)
        assert ok, (obf, simple, cex)
        got = simplify_mba(obf, n)
        assert got is not None and prove_equiv(got, simple, n)[0], (obf, got, simple)
    # a NON-identity must be caught with a counterexample
    ok, cex = prove_equiv("(x ^ y) + (x & y)", "x + y", n)
    assert not ok and cex is not None
    # opaque predicates
    assert classify_opaque("(x*x - x) & 1 == 0", n)[0] == "always-true"   # x^2-x always even
    assert classify_opaque("(x | 1) == 0", n)[0] == "always-false"
    assert classify_opaque("x & 1 == 0", n)[0] == "input-dependent"
    print("selftest OK: MBA identities proven+simplified, non-identity caught, "
          "opaque predicates classified")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", nargs="?", choices=["mba", "opaque", "equiv"])
    ap.add_argument("args", nargs="*")
    ap.add_argument("--bits", type=int, default=32)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return
    if a.mode == "mba":
        text = a.args[0]
        r = simplify_mba(text, a.bits)
        print(f"{text}  ==>  {r}" if r else f"{text}  ==>  (no simpler normal form proven)")
    elif a.mode == "opaque":
        verdict, w = classify_opaque(a.args[0], a.bits)
        print(f"{a.args[0]}  ==>  {verdict}")
        if w:
            print(f"  e.g. true when {w['true_when']}, false when {w['false_when']}")
    elif a.mode == "equiv":
        ok, cex = prove_equiv(a.args[0], a.args[1], a.bits)
        print("EQUIVALENT (proven for all inputs)" if ok
              else f"NOT equivalent; counterexample {cex}")
    else:
        ap.error("mode required (mba|opaque|equiv) or --selftest")


if __name__ == "__main__":
    main()
