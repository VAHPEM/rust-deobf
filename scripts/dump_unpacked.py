#!/usr/bin/env python3
"""dump_unpacked.py - Tier 2: dump the unpacked stage-2 a packer reveals at runtime.

A packer bootstraps, decompresses/decrypts stage-2 into a fresh region, flips it
executable, and jumps in. The same memory-observation idea behind recover_dynamic.py
captures it: watch for the moment a writable region becomes executable (the W->X flip
every unpacker performs) and for entropy dropping from high (packed/compressed) to low
(native code), then dump that region and carve any PE image out of it.

Two layers:
  * dynamic (Frida, VM only): hook VirtualProtect / mprotect; when a region gains EXEC,
    dump it; at exit, also sweep RW memory for MZ/PE images that were not in the file.
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
import argparse, math, struct, sys
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
// Watch the W->X flip every unpacker performs, and dump the region when it gains EXEC.
// Works on Windows (VirtualProtect) and POSIX (mprotect); resolve defensively (frida 17).
const PAGE_EXEC = [0x10,0x20,0x40,0x80];           // Win PAGE_EXECUTE* constants
function resolve(n){ try{ if(Module.getGlobalExportByName) return Module.getGlobalExportByName(n);}catch(e){}
  try{ for(const m of Process.enumerateModules()){ const e=m.findExportByName&&m.findExportByName(n); if(e) return e; } }catch(e){} return null; }
function dumpRange(base, size){
  try{ const buf = base.readByteArray(Math.min(size, 0x2000000));
       if(buf) send({t:'dump', addr: base.toString(), size: size}, buf); }catch(e){}
}
const vp = resolve('VirtualProtect');
if(vp) Interceptor.attach(vp, { onEnter(a){ this.addr=a[0]; this.size=a[1].toInt32(); this.np=a[2].toInt32(); },
  onLeave(){ if(PAGE_EXEC.indexOf(this.np & 0xf0)>=0 || (this.np & 0xf0)) dumpRange(this.addr, this.size); } });
const mp = resolve('mprotect');
if(mp) Interceptor.attach(mp, { onEnter(a){ this.addr=a[0]; this.size=a[1].toInt32(); this.prot=a[2].toInt32(); },
  onLeave(){ if(this.prot & 4) dumpRange(this.addr, this.size); } });   // PROT_EXEC=4
// backstop: sweep for MZ/PE in RW memory shortly after start
function sweep(){ for(const r of Process.enumerateRanges('rw-')){ let b; try{ b=r.base.readByteArray(Math.min(r.size,0x400000)); }catch(e){ continue; }
  if(!b) continue; const u=new Uint8Array(b); for(let i=0;i+1<u.length;i++){ if(u[i]==0x4d&&u[i+1]==0x5a){ dumpRange(r.base.add(i), Math.min(r.size-i,0x400000)); break; } } } send({t:'done'}); }
setTimeout(sweep, 2500);
"""


def run_frida(path: Path, argv, timeout, outdir: Path):
    try:
        import frida
    except ImportError:
        sys.exit("frida not installed: pip install frida frida-tools")
    outdir.mkdir(parents=True, exist_ok=True)
    dumps, done = [], {"v": False}
    dev = frida.get_local_device()
    pid = dev.spawn([str(path)] + argv)
    sess = dev.attach(pid)
    scr = sess.create_script(FRIDA_JS)

    def on_msg(msg, data):
        if msg.get("type") == "send":
            p = msg["payload"]
            if p.get("t") == "dump" and data:
                fn = outdir / f"region_{len(dumps)}_{p['addr']}.bin"
                fn.write_bytes(data)
                dumps.append(fn)
            elif p.get("t") == "done":
                done["v"] = True

    scr.on("message", on_msg)
    scr.load(); dev.resume(pid)
    import time
    t0 = time.time()
    while time.time() - t0 < timeout and not done["v"]:
        time.sleep(0.1)
    for fn in (sess.detach, lambda: dev.kill(pid)):
        try: fn()
        except Exception: pass
    return dumps


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
    print(f"selftest OK: entropy ordering holds; carved PE32+ @ +{hits[0]['offset']:#x} "
          f"sections={hits[0]['sections']} SizeOfImage={hits[0]['size_of_image']:#x}")


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
