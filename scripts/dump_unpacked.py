#!/usr/bin/env python3
"""dump_unpacked.py - Tier 2: dump the unpacked stage-2 a packer reveals at runtime.

A packer bootstraps, decompresses/decrypts stage-2 into a fresh region, flips it
executable, and jumps in. The same memory-observation idea behind recover_dynamic.py
captures it: watch for the moment a writable region becomes executable (the W->X flip
every unpacker performs) and for entropy dropping from high (packed/compressed) to low
(native code), then dump that region and carve any PE image out of it.

Two layers:
  * dynamic (Frida, VM only): hook VirtualProtect / mprotect; when a region gains EXEC,
    dump it; when the process asks to exit (and on early/late timers) dump the MAIN MODULE's
    in-memory image -- the unpacked program, even when the packer never flips a page through
    the API (UPX) -- plus a file-layout copy (image_*.fixed.exe) the static tiers can parse;
    also sweep RW memory for MZ/PE images that were not in the file. The sample's stdio is
    piped away so it cannot corrupt our output.
    Each dump is saved; this script then carves and reports them. (Runs on the analysis
    VM, like the other dynamic tools.)
  * static core (carve_pes, shannon_entropy): parse dumped regions, locate embedded PE
    images, and measure the entropy drop. Unit-tested here; reused by the dynamic layer.

SAFETY: the dynamic layer executes the sample. Run it ONLY in an isolated analysis VM.

    python dump_unpacked.py --frida ./packed.bin            # dump+carve on the VM
    python dump_unpacked.py --carve region_0.bin            # carve an already-dumped blob
    python dump_unpacked.py --selftest
"""
from __future__ import annotations
import argparse, json, math, struct, sys
from pathlib import Path


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


def carve_pes(blob: bytes, max_hits=16):
    """Find embedded PE images in a dumped region. For each 'MZ' whose e_lfanew points at
    a 'PE\\0\\0', read the COFF/optional header and return (offset, size, meta)."""
    out = []
    i = 0
    while i < len(blob) - 0x40 and len(out) < max_hits:
        j = blob.find(b"MZ", i)
        if j < 0:
            break
        i = j + 2
        if j + 0x3C + 4 > len(blob):
            continue
        e_lfanew = struct.unpack_from("<I", blob, j + 0x3C)[0]
        pe = j + e_lfanew
        if e_lfanew < 0x40 or pe + 0x18 > len(blob):
            continue
        if blob[pe:pe + 4] != b"PE\x00\x00":
            continue
        machine, nsec = struct.unpack_from("<HH", blob, pe + 4)
        opt_off = pe + 0x18
        if opt_off + 2 > len(blob):
            continue
        magic = struct.unpack_from("<H", blob, opt_off)[0]
        is64 = magic == 0x20B
        size_img = None
        # SizeOfImage lives at offset 56 in the optional header (both PE32/PE32+)
        if opt_off + 60 <= len(blob):
            size_img = struct.unpack_from("<I", blob, opt_off + 56)[0]
        out.append({"offset": j, "pe_offset": pe, "machine": hex(machine),
                    "sections": nsec, "pe_plus": is64,
                    "size_of_image": size_img,
                    "entropy_here": round(shannon_entropy(blob[j:j + 0x1000]), 3)})
    return out


# ---- dynamic layer (Frida; runs on the analysis VM only) ---------------------------
FRIDA_JS = r"""
// Capture the unpacked image a packer produces at run time. Three triggers, so a stub that never
// flips a page to EXEC through the API (UPX: its stage-2 section is RWX from the start) or a
// short-lived sample (done before any timer) is still captured:
//   1. a VirtualProtect / mprotect call that grants EXEC -> dump that range
//   2. the process asking to exit (ExitProcess / exit / _exit) -> dump the MAIN MODULE's image as
//      it is in memory now (headers + every section, unpacked), before the exit runs
//   3. timed sweeps (early and late) -> the main module image again, plus any MZ/PE in RW memory
// Works on Windows and POSIX; frida 17 API, resolved defensively.
function resolve(n){ try{ if(Module.getGlobalExportByName) return Module.getGlobalExportByName(n);}catch(e){}
  try{ for(const m of Process.enumerateModules()){ const e=m.findExportByName&&m.findExportByName(n); if(e) return e; } }catch(e){} return null; }
function dumpRange(base, size, kind){
  try{ const buf = base.readByteArray(Math.min(size, 0x2000000));
       if(buf) send({t:'dump', addr: base.toString(), size: size, kind: kind||'exec'}, buf); }catch(e){}
}
let mainDumps = 0;
function exeByHandle(){
  // Windows: GetModuleHandleW(NULL) is the executable's base by definition (it reads the PEB's
  // ImageBaseAddress); its size comes from the PE header's SizeOfImage. Module enumeration is not
  // reliable here (x64 emulation on Windows-on-ARM did not list the exe at all).
  const gmh = resolve('GetModuleHandleW');
  if(!gmh) return null;
  try{
    const base = new NativeFunction(gmh, 'pointer', ['pointer'])(ptr(0));
    if(base.isNull()) return null;
    const lfanew = base.add(0x3c).readU32();
    const soi = base.add(lfanew + 24 + 56).readU32();          // OptionalHeader.SizeOfImage
    if(soi <= 0 || soi > 0x40000000) return null;
    return {name: TARGET_NAME || 'exe', base: base, size: soi, path: TARGET_NAME};
  }catch(e){ return null; }
}
function mainModule(){
  const h = exeByHandle();
  if(h) return h;
  // the executable we spawned, found BY NAME: neither Process.mainModule nor enumerateModules()[0]
  // is reliably it (under x64 emulation on Windows-on-ARM both returned SHELL32.dll)
  const want = (typeof TARGET_NAME === 'string' ? TARGET_NAME : '').toLowerCase();
  try{
    for(const m of Process.enumerateModules()){
      const n = (m.name || '').toLowerCase(), p = (m.path || '').toLowerCase();
      if(want && (n === want || p.endsWith('\\' + want) || p.endsWith('/' + want))) return m;
    }
  }catch(e){}
  try{ if(Process.mainModule) return Process.mainModule; }catch(e){}
  try{ return Process.enumerateModules()[0]; }catch(e){ return null; }
}
function dumpMain(reason, sync){
  if(mainDumps >= 4) return;                       // bounded: early sweep, late sweep, exit
  const m = mainModule();
  if(!m) return;
  mainDumps++;
  // read range by range (a guard / no-access page would fail a single big read); the receiver
  // reassembles them at their offsets from the module base
  const end = m.base.add(m.size);
  let ranges = [];
  try{ ranges = Process.enumerateRanges({protection:'r--', coalesce:false}); }catch(e){}
  for(const r of ranges){
    const lo = r.base.compare(m.base) < 0 ? m.base : r.base;
    const rEnd = r.base.add(r.size), hi = rEnd.compare(end) > 0 ? end : rEnd;
    if(hi.compare(lo) <= 0) continue;
    try{ const buf = lo.readByteArray(Math.min(hi.sub(lo).toInt32(), 0x4000000));
         if(buf) send({t:'image', base: m.base.toString(), off: lo.sub(m.base).toInt32(),
                       size: m.size, path: m.path, reason: reason}, buf); }catch(e){}
  }
  send({t:'image_end', reason: reason, sync: !!sync});
  // at exit the process dies right after this hook returns: block until the host confirms it has
  // the image, or the queued messages are lost with the process
  if(sync){ try{ recv('ack', function(){}).wait(); }catch(e){} }
}
const PAGE_EXEC_MASK = 0xf0;                       // PAGE_EXECUTE* bits on Windows
const vp = resolve('VirtualProtect');
if(vp) Interceptor.attach(vp, { onEnter(a){ this.addr=a[0]; this.size=a[1].toInt32(); this.np=a[2].toInt32(); },
  onLeave(){ if(this.np & PAGE_EXEC_MASK) dumpRange(this.addr, this.size, 'exec'); } });
const mp = resolve('mprotect');
if(mp) Interceptor.attach(mp, { onEnter(a){ this.addr=a[0]; this.size=a[1].toInt32(); this.prot=a[2].toInt32(); },
  onLeave(){ if(this.prot & 4) dumpRange(this.addr, this.size, 'exec'); } });   // PROT_EXEC=4
for(const n of ['ExitProcess','exit','_exit','_Exit']){
  const f = resolve(n);
  if(f) Interceptor.attach(f, { onEnter(){ dumpMain('exit:'+n, true); send({t:'done'}); } });
}
function sweep(final){
  dumpMain(final ? 'late' : 'early');
  for(const r of Process.enumerateRanges('rw-')){ let b; try{ b=r.base.readByteArray(Math.min(r.size,0x400000)); }catch(e){ continue; }
    if(!b) continue; const u=new Uint8Array(b);
    for(let i=0;i+1<u.length;i++){ if(u[i]==0x4d&&u[i+1]==0x5a){ dumpRange(r.base.add(i), Math.min(r.size-i,0x400000), 'mz'); break; } } }
  if(final) send({t:'done'});
}
setTimeout(function(){ sweep(false); }, 300);
setTimeout(function(){ sweep(true); }, 2500);
"""


def run_frida(path: Path, argv, timeout, outdir: Path):
    try:
        import frida
    except ImportError:
        sys.exit("frida not installed: pip install frida frida-tools")
    outdir.mkdir(parents=True, exist_ok=True)
    dev = frida.get_local_device()
    # stdio="pipe": the sample's own stdout/stderr must not leak into ours (it would corrupt the
    # --json output of unpack.py); it is drained and discarded
    pid = dev.spawn([str(Path(path).resolve())] + list(argv), stdio="pipe")
    dev.on("output", lambda *_: None)
    sess = None
    try:
        sess = dev.attach(pid)
        return _drive(dev, pid, sess, outdir, timeout, Path(path).name)
    finally:
        # always detach and kill the spawned sample -- including when attach/load/the wait raises,
        # which used to leave a suspended process behind
        for fn in ((sess.detach if sess is not None else None), lambda: dev.kill(pid)):
            if fn is None:
                continue
            try:
                fn()
            except Exception:
                pass


def _drive(dev, pid, sess, outdir: Path, timeout, target_name=""):
    dumps, done = [], {"v": False}
    images = {}                      # reason -> {"base", "size", "path", "chunks": [(off, bytes)]}
    scr = sess.create_script(f"const TARGET_NAME = {json.dumps(target_name)};\n" + FRIDA_JS)

    def on_msg(msg, data):
        if msg.get("type") != "send":
            return
        p = msg["payload"]
        t = p.get("t")
        if t == "dump" and data:
            fn = outdir / f"region_{len(dumps)}_{p['addr']}_{p.get('kind', 'exec')}.bin"
            fn.write_bytes(data)
            dumps.append(fn)
        elif t == "image" and data:
            im = images.setdefault(p["reason"], {"base": p["base"], "size": p["size"],
                                                 "path": p.get("path"), "chunks": []})
            im["chunks"].append((p["off"], data))
        elif t == "image_end":
            fn = _write_image(outdir, p["reason"], images.pop(p["reason"], None))
            if fn:
                dumps.append(fn)
            if p.get("sync"):
                try:
                    scr.post({"type": "ack"})      # release the exit hook
                except Exception:
                    pass
        elif t == "done":
            done["v"] = True

    scr.on("message", on_msg)
    scr.load(); dev.resume(pid)
    import time
    t0 = time.time()
    while time.time() - t0 < timeout and not done["v"]:
        time.sleep(0.1)
    time.sleep(0.2)                  # let in-flight messages (an exit-time image) arrive
    return dumps


_MAX_IMAGE = 0x4000000               # 64 MB: a main-module image larger than this is not rebuilt


def pe_image_to_file_layout(img: bytes):
    """A PE dumped from memory is in MEMORY layout: section i sits at its VirtualAddress, not at
    PointerToRawData. Rewrite each section header so raw == virtual (PointerToRawData =
    VirtualAddress, SizeOfRawData = VirtualSize clamped to the dump), which lets LIEF / the static
    tiers parse the dump as a file. Returns the patched bytes, or None if `img` is not a PE image."""
    if len(img) < 0x40 or img[:2] != b"MZ":
        return None
    e = struct.unpack_from("<I", img, 0x3c)[0]
    if e + 24 > len(img) or img[e:e + 4] != b"PE\0\0":
        return None
    nsec, optsz = struct.unpack_from("<H", img, e + 6)[0], struct.unpack_from("<H", img, e + 20)[0]
    sec = e + 24 + optsz
    if nsec == 0 or nsec > 96 or sec + 40 * nsec > len(img):
        return None
    out = bytearray(img)
    for i in range(nsec):
        h = sec + 40 * i
        vsize, va = struct.unpack_from("<II", out, h + 8)
        if va >= len(out):
            struct.pack_into("<II", out, h + 16, 0, 0)       # beyond the dump: no raw data
            continue
        size = min(vsize or 0x1000, len(out) - va)
        struct.pack_into("<II", out, h + 16, size, va)       # SizeOfRawData, PointerToRawData
    return bytes(out)


def _write_image(outdir: Path, reason, im):
    """Reassemble a main-module image from its readable ranges (unreadable gaps stay zero) and
    write it as image_<reason>_<base>.bin. Returns the path, or None when there is nothing."""
    if not im or not im["chunks"]:
        return None
    size = min(int(im["size"]), _MAX_IMAGE)
    buf = bytearray(size)
    for off, data in im["chunks"]:
        if 0 <= off < size:
            buf[off:off + len(data)] = data[:size - off]
    tag = "".join(c if c.isalnum() else "_" for c in str(reason))[:32]
    fn = outdir / f"image_{tag}_{im['base']}.bin"
    fn.write_bytes(bytes(buf))
    fixed = pe_image_to_file_layout(bytes(buf))
    if fixed is not None:            # also a parseable copy for the static tiers
        (outdir / f"image_{tag}_{im['base']}.fixed.exe").write_bytes(fixed)
    return fn


def report_region(path: Path):
    blob = path.read_bytes()
    pes = carve_pes(blob)
    print(f"{path.name}: {len(blob)} bytes  entropy={shannon_entropy(blob):.3f}")
    if not pes:
        print("  no embedded PE carved (region may be raw shellcode, not a PE image)")
    for p in pes:
        print(f"  PE @ +{p['offset']:#x}  {'PE32+' if p['pe_plus'] else 'PE32'}  "
              f"machine={p['machine']}  sections={p['sections']}  "
              f"SizeOfImage={p['size_of_image']}  hdr_entropy={p['entropy_here']}")


def _selftest():
    # entropy ordering: zeros < text < random
    assert shannon_entropy(b"\x00" * 4096) < 1.0
    import os
    assert shannon_entropy(os.urandom(4096)) > 7.5
    # build a minimal valid PE header and embed it inside a larger buffer; carve it back.
    pe = bytearray(b"MZ" + b"\x00" * 0x3e)                 # 64-byte DOS header
    struct.pack_into("<I", pe, 0x3c, 0x40)                 # e_lfanew -> 0x40
    pe += b"PE\x00\x00"                                     # PE signature at 0x40
    pe += struct.pack("<HH", 0x8664, 3)                    # machine x86-64, 3 sections
    pe += b"\x00" * (0x14 - 4)                              # rest of COFF header
    pe += struct.pack("<H", 0x20B)                         # optional magic PE32+
    pe += b"\x00" * 54
    pe += struct.pack("<I", 0x4000)                        # SizeOfImage at opt+56
    pe += b"\x00" * 64
    region = b"\xcc" * 1000 + bytes(pe) + b"\xcc" * 500
    hits = carve_pes(region)
    assert hits and hits[0]["offset"] == 1000 and hits[0]["pe_plus"] and \
        hits[0]["sections"] == 3 and hits[0]["size_of_image"] == 0x4000, hits
    # a memory-layout image: one section at RVA 0x1000; the file-layout rewrite points raw at it
    mem = bytearray(0x3000)
    hdr = bytearray(pe)
    struct.pack_into("<H", hdr, 0x40 + 6, 1)                # 1 section
    struct.pack_into("<H", hdr, 0x40 + 20, 0xF0)            # SizeOfOptionalHeader
    mem[:len(hdr)] = hdr
    sh = 0x40 + 24 + 0xF0
    mem[sh:sh + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", mem, sh + 8, 0x1800, 0x1000, 0x200, 0x400)  # vsize, va, raw size/ptr
    fixed = pe_image_to_file_layout(bytes(mem))
    assert struct.unpack_from("<II", fixed, sh + 16) == (0x1800, 0x1000), "raw != virtual"
    assert pe_image_to_file_layout(b"\0" * 64) is None and pe_image_to_file_layout(b"MZ" + b"\0" * 70) is None
    # image reassembly from per-range chunks leaves unreadable gaps zero and clamps to the size
    import tempfile
    d = Path(tempfile.mkdtemp())
    fn = _write_image(d, "exit:ExitProcess", {"base": "0x140000000", "size": 0x3000, "path": "x",
                                              "chunks": [(0, b"MZ" + b"A" * 10), (0x2000, b"B" * 0x2000)]})
    b = fn.read_bytes()
    assert len(b) == 0x3000 and b[:2] == b"MZ" and b[0x1000:0x1004] == b"\0" * 4 and b[-1:] == b"B"
    assert _write_image(d, "x", None) is None
    for f in d.iterdir():
        f.unlink()
    d.rmdir()
    print(f"selftest OK: entropy ordering holds; carved PE32+ @ +{hits[0]['offset']:#x} "
          f"sections={hits[0]['sections']} SizeOfImage={hits[0]['size_of_image']:#x}; "
          "memory-image reassembly + file-layout rewrite")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--frida", metavar="BIN", help="spawn BIN on the VM, dump W->X regions")
    ap.add_argument("--carve", metavar="BLOB", help="carve an already-dumped region file")
    ap.add_argument("--argv", nargs=argparse.REMAINDER, default=[])
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--outdir", default="unpacked_dumps")
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        _selftest(); return
    if a.carve:
        report_region(Path(a.carve)); return
    if a.frida:
        dumps = run_frida(Path(a.frida), a.argv, a.timeout, Path(a.outdir))
        print(f"dumped {len(dumps)} region(s) to {a.outdir}/")
        for d in dumps:
            report_region(d)
        return
    ap.error("one of --frida / --carve / --selftest required")


if __name__ == "__main__":
    main()
