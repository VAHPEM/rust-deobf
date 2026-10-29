"""Async state-machine recovery (scripts/recover_async.py).

The --selftest (hand-assembled x86-64 jump-table and AArch64 compare-chain dispatches) runs in the
selftest gate. Here a real program with a hand-written `block_on` executor (no crates) is compiled
at test time -- nested async fns, a loop with an await, async blocks, a `Box<dyn Future>` -- with
symbols stripped (`-C strip=symbols`), and the recovered machines are checked against the source:
one machine per coroutine instance, the exact suspend-point count per async fn (identified through
the `&Location` the resume panics carry, which survives stripping), and the nesting edges. Builds
for the host arch; also AArch64 / i386 / Mach-O / PE when those targets are installed, and under
rustc 1.70, 1.85 and 1.99 when those toolchains are installed. The outer future is boxed so `top`
survives as a real poll function on every rustc -- a bare top-level future is inlined into the
executor, and rustc 1.99 linearizes it away entirely (so looper/top/the async block would vanish).
Skips without rustc.
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
    let fut: Pin<Box<dyn Future<Output = u64>>> = Box::pin(top(n));
    println!("{}", block_on(fut));
}
"""


PROGRAM_INLINE = PROGRAM.replace(
    "    let fut: Pin<Box<dyn Future<Output = u64>>> = Box::pin(top(n));\n    println!(\"{}\", block_on(fut));",
    "    println!(\"{}\", block_on(top(n)));")


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


def _target(name):
    try:
        out = subprocess.check_output(["rustup", "target", "list", "--installed"], text=True)
        return name in out.split()
    except Exception:
        return False


def _aarch64_target():
    return _target("aarch64-unknown-linux-musl")


def _toolchain(tc):
    try:
        out = subprocess.check_output(["rustup", "toolchain", "list"], text=True)
        return any(ln.split()[0].startswith(tc) for ln in out.splitlines() if ln.strip())
    except Exception:
        return False


TBD = """--- !tapi-tbd
tbd-version:     4
targets:         [ arm64-macos ]
install-name:    '/usr/lib/libSystem.B.dylib'
current-version: 1311
exports:
  - targets:         [ arm64-macos ]
    symbols:         [ _dyld_stub_binder ]
...
"""


def _build(tmp_path, target=None, program=None, toolchain=None):
    src = tmp_path / "hand.rs"
    src.write_text((program or PROGRAM).lstrip("\n"))
    out = tmp_path / ("hand_" + (target or "host"))
    rustc = ["rustc"] + ([f"+{toolchain}"] if toolchain else [])
    cmd = rustc + ["--edition", "2021", "-O", "-C", "strip=symbols", str(src), "-o", str(out)]
    if target and target.endswith("-apple-darwin"):
        # no macOS SDK here: link with ld64.lld against stub libSystem/libc/libm, imports left
        # to dynamic lookup -- a real Mach-O executable for static analysis (not runnable)
        stub = tmp_path / "stub"
        stub.mkdir(exist_ok=True)
        tbd = TBD if target.startswith("aarch64") else TBD.replace("arm64-macos", "x86_64-macos")
        for n in ("c", "m", "System"):
            (stub / f"lib{n}.tbd").write_text(tbd)
        cmd = rustc + ["--edition", "2021", "-O", str(src), "-o", str(out), "--target", target,
                       "-C", "linker=rust-lld", "-C", "linker-flavor=ld64.lld",
                       "-C", f"link-arg=-L{stub}", "-C", "link-arg=-undefined",
                       "-C", "link-arg=dynamic_lookup"]
    elif target:
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
    # every state write-back is pinned to a concrete value (set): no machine stays "computed".
    # boxed's own poll writes its next state through a setcc/select, not a `mov imm`, so this
    # only holds once value sets through those are followed.
    assert all(m["writes_check"] in ("confirmed", "computed") for m in ms)
    assert all(m["writes_check"] == "confirmed" for m in ms), \
        [(m["id"], m["writes_check"]) for m in ms if m["writes_check"] != "confirmed"]
    # leaf is inlined four times (twice into middle, into looper and into the async block), the
    # rest once; middle's two copies share one state field but no resume target -> two machines
    count = {ln: sum(m["source"]["line"] == ln for m in ms) for ln in AWAITS}
    assert count[_line("async fn leaf")] == 4 and len(ms) == 9, count
    # the coroutines emitted as their own poll functions (reached by a direct or vtable call, not
    # inlined into a caller): middle, the boxed async block, and top (its future is boxed in main)
    polls = [m for m in ms if m["role"] == "poll"]
    assert {m["source"]["line"] for m in polls} == {
        _line("async fn middle"), _line("Box::pin(async move"), _line("async fn top")}
    assert all(m["state_field"]["base"] == "self" for m in polls)
    assert len(res["poll_functions"]) == 3
    boxed = next(m for m in polls if m["source"]["line"] == _line("Box::pin(async move"))
    middle = next(m for m in polls if m["source"]["line"] == _line("async fn middle"))
    # boxed -> awaits middle through a direct call to middle's poll
    inner = boxed["states"]["3"]["inner"]
    assert inner["kind"] == "direct" and inner.get("machine") == middle["id"], inner
    assert boxed["size"]["vtable"] and boxed["size"]["vtable"] >= boxed["size"]["min_from_accesses"]
    # middle -> two inlined leaf awaits, each its own copy of leaf's machine at the same offset
    leafs = []
    for k in ("3", "4"):
        i = middle["states"][k]["inner"]
        assert i["kind"] == "inlined" and by_id[i["machine"]]["source"]["line"] == _line("async fn leaf")
        leafs.append(by_id[i["machine"]])
    assert leafs[0]["id"] != leafs[1]["id"]
    assert leafs[0]["state_field"] == leafs[1]["state_field"]
    # top (its own poll function): middle direct, looper inlined, boxed through the dyn vtable
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


DYN2 = r"""
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

#[inline(never)]
fn first(n: u64) -> Pin<Box<dyn Future<Output = u64>>> {
    Box::pin(async move { YieldNow(false).await; n.wrapping_mul(7) })
}

#[inline(never)]
fn second(n: u64) -> Pin<Box<dyn Future<Output = u64>>> {
    Box::pin(async move { YieldNow(false).await; YieldNow(false).await; n ^ 0x99 })
}

async fn both(n: u64) -> u64 {
    let a = first(n).await;
    let b = second(a).await;
    let c = first(b).await;
    a ^ b ^ c
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
    println!("{}", block_on(both(n)));
}
"""


@pytest.mark.skipif(not shutil.which("rustc"), reason="rustc not available")
@pytest.mark.parametrize("target", [None, "aarch64-unknown-linux-musl"])
def test_dyn_await_resolved_per_call_site(tmp_path, target):
    """One coroutine (`both`) awaits two different `Pin<Box<dyn Future>>` types through the same
    vtable slot: a straight-line awaiter's awaits resolve per call site to their own boxed
    coroutine (first, second, first), not "ambiguous because the function references two vtables".

    `both` is the top-level future here, so <=1.97 inlines it into the executor as a single
    straight-line first-poll (the sweet spot: each await's vtable is pinned at its call site);
    rustc 1.99 linearizes the top-level future away entirely. The boxed `first`/`second` always
    survive as their own poll functions. Where `both` survives, the exact per-site chain is
    checked; the boxed futures are checked either way."""
    if target and not _aarch64_target():
        pytest.skip("aarch64-unknown-linux-musl target not installed")
    exe = _build(tmp_path, target, DYN2)
    res = RA.recover(exe)
    by_line = {m["source"]["line"]: m for m in res["machines"]}
    lines = DYN2.lstrip("\n").splitlines()
    ln = {k: next(i for i, t in enumerate(lines, 1) if k in t) for k in
          ("n.wrapping_mul(7)", "n ^ 0x99", "async fn both")}
    first_m, second_m = by_line[ln["n.wrapping_mul(7)"]], by_line[ln["n ^ 0x99"]]
    # the boxed futures are found either way; whether each keeps its own poll function is the
    # compiler's choice (rustc 1.99 on native AArch64 inlines `first` into its caller's poll)
    assert first_m["role"] in ("poll", "inlined") and second_m["role"] in ("poll", "inlined")
    assert all(m["size"]["vtable"] for m in (first_m, second_m) if m["role"] == "poll")
    assert first_m["suspend_points"] == 1 and second_m["suspend_points"] == 2
    both = by_line.get(ln["async fn both"])
    if both is not None:
        got = [both["states"][str(k)]["inner"] for k in (3, 4, 5)]
        assert all(i["kind"] == "dyn" and i["dyn_future_poll"] for i in got), got
        assert [i.get("machine") for i in got] == [first_m["id"], second_m["id"], first_m["id"]], got


@pytest.mark.skipif(not (shutil.which("rustc") and _target("i686-unknown-linux-musl")),
                    reason="i686-unknown-linux-musl target not installed")
def test_hand_executor_i386(tmp_path):
    """i386: cdecl stack arguments (self at [esp+8] behind the sret pointer), GOT-relative PIC
    jump tables (`[pic + idx*4 - d]`, the PC base fetched by `call $+5; pop`), fastcc self in
    ecx. The boxed program recovers the full nesting on every rustc; the i386 specifics are the
    self location of a poll function and the dyn vtable slot (0xc = slot 3 at 4-byte pointers)."""
    res = RA.recover(_build(tmp_path, "i686-unknown-linux-musl"))
    assert res["supported"] and res["arch"] == "x86"
    ms = res["machines"]
    assert {m["source"]["line"] for m in ms} == set(AWAITS)
    for m in ms:
        assert m["suspend_points"] == AWAITS[m["source"]["line"]], (m["source"], m["suspend_points"])
        assert m["validated"], m["notes"]
    top = next(m for m in ms if m["source"]["line"] == _line("async fn top"))
    boxed = next(m for m in ms if m["source"]["line"] == _line("Box::pin(async move"))
    # a poll function's self arrives either on the stack (cdecl: [esp+4] sret ptr, [esp+8] self)
    # or in a fastcc register (ecx/edx) -- LLVM picks per function, and 1.99 moved some to edx
    for m in ms:
        if m["role"] == "poll":
            assert m["self_register"] in ("[esp+0x8]", "ecx", "edx"), (m["id"], m["self_register"])
    assert any(m["self_register"] == "[esp+0x8]" for m in ms if m["role"] == "poll")
    # top awaits the boxed future through the dyn Future vtable (slot 3 = 0xc at 4-byte pointers)
    dyn = next(st["inner"] for st in top["states"].values()
               if st.get("inner", {}).get("kind") == "dyn")
    assert dyn["slot_offset"] == 12 and dyn.get("machine") == boxed["id"], dyn


@pytest.mark.skipif(not (shutil.which("rustc") and _target("i686-unknown-linux-musl")),
                    reason="i686-unknown-linux-musl target not installed")
def test_i386_armless_executor_tolerant(tmp_path):
    """The unboxed executor (`block_on(top(n))`): older rustc inlines `top` into the executor and
    register-promotes its dispatch, dropping the Returned/Panicked arms (an "armless" machine with
    both states reaching one trap); rustc 1.99 linearizes it away so there is none. Either way:
    at most one armless machine, and every machine still validates with an exact suspend count."""
    res = RA.recover(_build(tmp_path, "i686-unknown-linux-musl", PROGRAM_INLINE))
    armless = [m for m in res["machines"] if not m["source"]]
    assert len(armless) <= 1, [m["id"] for m in armless]
    for m in armless:
        assert m["states"]["1"]["target"] == m["states"]["2"]["target"]  # arms merged into a trap
        assert m["suspend_points"] == AWAITS[_line("async fn top")]
    for m in res["machines"]:
        if m["source"]:
            assert m["suspend_points"] == AWAITS[m["source"]["line"]], m["source"]
            assert m["validated"], m["notes"]


def _check_by_location(res):
    """Every machine names its async fn through its resume panic's &Location: one per coroutine
    of the source, each with exactly the source's number of awaits."""
    ms = [m for m in res["machines"] if m["source"]]
    assert {m["source"]["line"] for m in ms} == set(AWAITS), sorted({m["source"]["line"] for m in ms})
    for m in ms:
        assert m["suspend_points"] == AWAITS[m["source"]["line"]], (m["source"], m["suspend_points"])
        assert m["validated"], m["notes"]


@pytest.mark.parametrize("target,arch", [("aarch64-apple-darwin", "aarch64"),
                                         ("x86_64-apple-darwin", "x86_64")])
@pytest.mark.skipif(not shutil.which("rustc"), reason="rustc not available")
def test_hand_executor_macho(tmp_path, target, arch):
    """Mach-O, symbols stripped: function starts come from LC_FUNCTION_STARTS. The x86-64 variant
    also exercises Apple's jump tables, which sit inside the code section (not a data section)."""
    if not _target(target):
        pytest.skip(f"{target} target not installed")
    exe = _build(tmp_path, target)
    if shutil.which("llvm-strip"):
        subprocess.run(["llvm-strip", str(exe)], check=False)
    res = RA.recover(exe)
    assert res["format"] == "MACHO" and res["arch"] == arch
    _check_by_location(res)
    assert len(res["machines"]) == 9 and len(res["poll_functions"]) == 3


@pytest.mark.skipif(not shutil.which("rustup"), reason="rustup not available")
@pytest.mark.parametrize("toolchain", ["1.70.0", "1.85.0"])
def test_hand_executor_older_rustc(tmp_path, toolchain):
    """Older rustc: 1.70 panics with `core::panicking::panic("`async fn` resumed after ...")`
    (the message pointer is sometimes hoisted above the dispatch), 1.85 already uses the
    panic_const helpers."""
    if not _toolchain(toolchain):
        pytest.skip(f"toolchain {toolchain} not installed")
    _check_by_location(RA.recover(_build(tmp_path, toolchain=toolchain)))


def test_no_async_no_machines(tmp_path):
    """A binary without the anchors yields nothing (and no error)."""
    fx = ROOT / "tests" / "fixtures" / "vm" / "plain.x64"
    if not fx.exists():
        pytest.skip("fixture missing")
    res = RA.recover(fx)
    assert res["machines"] == [] and res["counts"]["candidates"] == 0
