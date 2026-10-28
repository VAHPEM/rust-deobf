"""Picklable fake target tables for tests/test_fuzz.py.

run_isolated() ships `targets_fn` to a forkserver/spawn child, which imports it by module path, so
these must be module-level functions in an importable module (not lambdas in the test). Not a test
module itself (no test_ prefix), so pytest does not collect it."""
import os
import time


def big_result(_time_budget, _active):
    """One uncontrolled finding whose pickled result is far larger than a pipe buffer (~64 KB)."""
    def boom(_p):
        raise MemoryError("x" * 200_000)
    return [("image", boom, False)]


def hang(_time_budget, _active):
    def stuck_in_parser(_p):
        time.sleep(3600)
    return [("detect", lambda _p: None, True), ("meta", stuck_in_parser, False)]


def native_abort(_time_budget, _active):
    def crash_natively(_p):
        os.abort()
    return [("strings", crash_natively, False)]


def clean(_time_budget, _active):
    return [("image", lambda _p: None, False)]
