"""Async state-machine recovery (scripts/recover_async.py).

The --selftest (hand-assembled x86-64 jump-table and AArch64 compare-chain dispatches) runs in the
selftest gate. Here a real program with a hand-written `block_on` executor (no crates) is compiled
at test time -- nested async fns, a loop with an await, async blocks, a `Box<dyn Future>` -- with
symbols stripped (`-C strip=symbols`), and the recovered machines are checked against the source:
one machine per coroutine instance, the exact suspend-point count per async fn (identified through
the `&Location` the resume panics carry, which survives stripping), and the nesting edges. Builds
for the host arch; also AArch64 when the musl target is installed. Skips without rustc.
"""
import json
import platform
import shutil
import subprocess
import sys

import pytest
from conftest import ROOT

sys.path.insert(0, str(ROOT / "scripts"))
import recover_async as RA  # noqa: E402

PROGRAM = r"""
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

struct YieldNow(bool);
impl Future for YieldNow {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.0 { Poll::Ready(()) } else { self.0 = true; cx.waker().wake_by_ref(); Poll::Pending }
    }
}

async fn leaf(x: u64) -> u64 {
    YieldNow(false).await;
    x.wrapping_mul(3) ^ 0x55
}

async fn middle(n: u64) -> u64 {
    let a = leaf(n).await;
    let b = leaf(a.wrapping_add(1)).await;
    a.wrapping_add(b)
}

async fn looper(n: u64) -> u64 {
    let mut s = 0u64;
    for i in 0..n { s = s.wrapping_add(leaf(i).await); }
    s
}

fn boxed(n: u64) -> Pin<Box<dyn Future<Output = u64>>> {
    Box::pin(async move { middle(n).await.wrapping_add(1) })
}

async fn top(n: u64) -> u64 {
    let a = middle(n).await;
    let b = looper(n).await;
    let c = boxed(n).await;
    let d = async { leaf(7).await.wrapping_add(n) }.await;
    a ^ b ^ c ^ d
}

fn noop_raw() -> RawWaker {
    fn clone(_: *const ()) -> RawWaker { noop_raw() }
    fn noop(_: *const ()) {}
    static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    RawWaker::new(std::ptr::null(), &VT)
}

fn block_on<F: Future>(fut: F) -> F::Output {
    let mut fut = std::pin::pin!(fut);
    let waker = unsafe { Waker::from_raw(noop_raw()) };
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) { return v; }
    }
}

fn main() {
    let n = std::env::args().count() as u64 + 2;
    println!("{}", block_on(top(n)));
}
"""


def _line(marker):
    """1-based source line of the first line containing `marker`."""
    for i, ln in enumerate(PROGRAM.lstrip("\n").splitlines(), 1):
        if marker in ln:
            return i
    raise AssertionError(marker)


# source line of each coroutine (where its &Location points) -> awaits in the source
AWAITS = {_line("async fn leaf"): 1, _line("async fn middle"): 2, _line("async fn looper"): 1,
          _line("Box::pin(async move"): 1, _line("async fn top"): 4,
          _line("let d = async {"): 1}


def _aarch64_target():
    try:
        out = subprocess.check_output(["rustup", "target", "list", "--installed"], text=True)
        return "aarch64-unknown-linux-musl" in out
    except Exception:
        return False


def _build(tmp_path, target=None):
    src = tmp_path / "hand.rs"
    src.write_text(PROGRAM.lstrip("\n"))
    out = tmp_path / ("hand_" + (target or "host"))
    cmd = ["rustc", "--edition", "2021", "-O", "-C", "strip=symbols", str(src), "-o", str(out)]
    if target:
        cmd += ["--target", target, "-C", "linker=rust-lld", "-C", "link-self-contained=yes"]
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=tmp_path)
    if r.returncode != 0:
        pytest.skip("build failed: " + r.stderr.strip()[-300:])
    exe = out if out.exists() else out.with_suffix(".exe")
    if not exe.exists():
        pytest.skip("no output binary")
    return exe


def _check(res, arch):
    assert res["supported"] and res["arch"] == arch
    ms = res["machines"]
    by_id = {m["id"]: m for m in ms}
    # every machine is anchored to its async fn by the &Location of its resume panic
    assert all(m["source"] and m["source"]["file"].endswith("hand.rs") for m in ms), ms
    lines = {m["source"]["line"] for m in ms}
    assert lines == set(AWAITS), (sorted(lines), sorted(AWAITS))
    # exact suspend-point count per coroutine, and a consistent dispatch everywhere
    for m in ms:
        assert m["suspend_points"] == AWAITS[m["source"]["line"]], (m["source"], m["suspend_points"])
        assert m["validated"], m["notes"]
        assert {"0", "1", "2"} <= set(m["states"])
        assert m["states"]["1"]["name"] == "Returned" and m["states"]["2"]["name"] == "Panicked"
    # leaf is inlined three times (into middle, looper and the async block), the rest once
    count = {ln: sum(m["source"]["line"] == ln for m in ms) for ln in AWAITS}
    assert count[_line("async fn leaf")] == 3 and len(ms) == 8, count
    # the two coroutines emitted as their own functions are poll functions with self-relative state
    polls = [m for m in ms if m["role"] == "poll"]
    assert {m["source"]["line"] for m in polls} == {_line("async fn middle"), _line("Box::pin(async move")}
    assert all(m["state_field"]["base"] == "self" for m in polls)
    assert len(res["poll_functions"]) == 2
    boxed = next(m for m in polls if m["source"]["line"] == _line("Box::pin(async move"))
    middle = next(m for m in polls if m["source"]["line"] == _line("async fn middle"))
    # boxed -> awaits middle through a direct call to middle's poll
    inner = boxed["states"]["3"]["inner"]
    assert inner["kind"] == "direct" and inner.get("machine") == middle["id"], inner
    assert boxed["size"]["vtable"] and boxed["size"]["vtable"] >= boxed["size"]["min_from_accesses"]
    # middle -> two inlined leaf awaits
    for k in ("3", "4"):
        i = middle["states"][k]["inner"]
        assert i["kind"] == "inlined" and by_id[i["machine"]]["source"]["line"] == _line("async fn leaf")
    # top (inlined into block_on/main): middle direct, looper inlined, boxed through the dyn vtable
    top = next(m for m in ms if m["source"]["line"] == _line("async fn top"))
    kinds = [top["states"][str(k)]["inner"] for k in range(3, 7)]
    assert kinds[0]["kind"] == "direct" and kinds[0].get("machine") == middle["id"], kinds
    assert by_id[kinds[1]["machine"]]["source"]["line"] == _line("async fn looper"), kinds
    assert kinds[2]["kind"] == "dyn" and kinds[2]["dyn_future_poll"] and kinds[2]["machine"] == boxed["id"]
    assert by_id[kinds[3]["machine"]]["source"]["line"] == _line("let d = async {"), kinds
    assert res["runtime"]["detected"] == []


@pytest.mark.skipif(not shutil.which("rustc"), reason="rustc not available")
def test_hand_executor_host(tmp_path):
    exe = _build(tmp_path)
    host = platform.machine().lower()
    arch = "aarch64" if host in ("aarch64", "arm64") else "x86_64"
    res = RA.recover(exe)
    _check(res, arch)
    # the --json CLI contract: the lone result dict, nothing else on stdout
    out = subprocess.run([sys.executable, str(ROOT / "scripts" / "recover_async.py"), "--json", str(exe)],
                         capture_output=True, text=True, check=True).stdout
    assert json.loads(out)["counts"]["machines"] == len(res["machines"])


@pytest.mark.skipif(not (shutil.which("rustc") and _aarch64_target()),
                    reason="aarch64-unknown-linux-musl target not installed")
def test_hand_executor_aarch64(tmp_path):
    if platform.machine().lower() in ("aarch64", "arm64"):
        pytest.skip("host build already covers AArch64")
    _check(RA.recover(_build(tmp_path, "aarch64-unknown-linux-musl")), "aarch64")


def test_no_async_no_machines(tmp_path):
    """A binary without the anchors yields nothing (and no error)."""
    fx = ROOT / "tests" / "fixtures" / "vm" / "plain.x64"
    if not fx.exists():
        pytest.skip("fixture missing")
    res = RA.recover(fx)
    assert res["machines"] == [] and res["counts"]["candidates"] == 0
