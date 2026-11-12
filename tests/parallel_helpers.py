"""Picklable stand-ins for recover_emulate._worker, for tests/test_parallel_workers.py.

The pool ships the submitted function to a forkserver/spawn child by module path, so it must be a
module-level function in an importable module (not a closure in the test). Not a test module (no
test_ prefix), so pytest does not collect it."""
import os
import signal


def worker_killed_if_lowest(path, share, *rest):
    """recover_emulate._worker, except that the worker whose share holds the binary's lowest
    function address dies the way an OOM-killed process does (SIGKILL; os._exit where there is no
    SIGKILL). Exactly one share holds it, whatever the worker count."""
    import recover_emulate
    lowest = min(f for f, _ in recover_emulate.Image(path).functions())
    if lowest in share:
        if hasattr(signal, "SIGKILL"):
            os.kill(os.getpid(), signal.SIGKILL)
        os._exit(1)
    return recover_emulate._worker(path, share, *rest)
