"""Cross-binary library-function identification (recover_libfuncs.py).

Signatures generated from one program's unstripped build must identify the same std/library
functions in a *different, stripped* program of the same toolchain, with no misidentification.
Ground truth is the target's own symbols (read from its nostrip build). Cases skip if the
required builds are absent, so this runs wherever build_all.sh has produced ELF/PE/ARM64 output.
"""
import lief
import pytest
from pathlib import Path
from conftest import BUILD

import recover_libfuncs as L

# (format, extension) pairs; the target is matched stripped, truth read from its nostrip build
FORMATS = [("elf", ""), ("pe", ".exe"), ("elf-arm64", "")]
# reference program (signatures) -> target program (identification); distinct programs
PAIRS = [("litcrypt", "xor_custom"), ("obfstr", "add_custom")]
PROFILE = "release"


def _truth(nostrip: Path):
    import gen_runtime_sigs as G
    b = lief.parse(str(nostrip))
    text = next((s for s in b.sections if s.name == ".text"), None)
    assert text is not None
    base, clen = text.virtual_address, len(bytes(text.content))
    truth = {}
    for s in b.symbols:
        if not getattr(s, "is_function", False):
            continue
        va = G.sym_va(b, s)                    # PE COFF values are section-relative; sym_va -> RVA
        if va and base <= va < base + clen:
            truth[va] = L.readable(s.name)
    return truth


@pytest.mark.parametrize("fmt,ext", FORMATS)
@pytest.mark.parametrize("ref,tgt", PAIRS)
def test_cross_binary_identification(ref, tgt, fmt, ext):
    ref_bin = BUILD / f"{ref}__{fmt}__{PROFILE}__nostrip{ext}"
    tgt_strip = BUILD / f"{tgt}__{fmt}__{PROFILE}__strip{ext}"
    tgt_nostrip = BUILD / f"{tgt}__{fmt}__{PROFILE}__nostrip{ext}"
    for p in (ref_bin, tgt_strip, tgt_nostrip):
        if not p.is_file():
            pytest.skip(f"not built: {p.name}")

    db = L.generate([ref_bin])                       # in-memory DB from the reference only
    assert db, "no signatures generated from reference build"
    res = L.match_binary(tgt_strip, db)

    truth = _truth(tgt_nostrip)
    wrong, no_truth, correct = [], 0, 0
    for r in res:
        t = truth.get(r["va"])
        if t is None:
            no_truth += 1
        elif t == r["name"]:
            correct += 1
        else:
            wrong.append((hex(r["va"]), r["name"], t))

    # every identified address must be a real function in the target, named correctly
    assert not wrong, f"misidentified: {wrong[:5]}"
    assert no_truth == 0, f"{no_truth} matches at addresses with no function in the target"
    assert correct >= 30, f"only {correct} library functions identified (expected many)"
