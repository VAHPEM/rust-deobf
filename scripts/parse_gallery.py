#!/usr/bin/env python3
"""parse_gallery.py - turn the rust-malware-gallery README into a machine-readable manifest.

The gallery (github.com/decoderloop/rust-malware-gallery) is writeups + sample hashes, not
binaries. This extracts, per family: aliases, writeup links, and sample SHA-256 hashes with
their download source. The manifest drives evaluation (which families/samples to fetch in an
isolated VM) and gives rust-deobf a hash -> family map for triage attribution. Samples are
never stored here; only hashes.

    python parse_gallery.py rust-malware-gallery/README.md -o gallery/manifest.json
"""
import argparse
import json
import re

HASH = re.compile(r"\b([0-9a-f]{64})\b")
DL = re.compile(r"\[(MalwareBazaar|MalShare|VirusTotal|Malpedia)\]\((https?://[^)]+)\)", re.I)


def parse(text):
    families = []
    cur = None
    section = None
    for line in text.splitlines():
        m = re.match(r"^##\s+(?!#)(.+?)\s*$", line)
        if m and not line.startswith("### "):
            title = m.group(1).strip()
            if title.lower() in ("about",):
                cur = None
                continue
            cur = {"family": title, "aliases": [], "writeups": [], "samples": []}
            families.append(cur)
            section = None
            continue
        if cur is None:
            continue
        h = re.match(r"^###\s+(.+?)\s*$", line)
        if h:
            section = h.group(1).strip().lower()
            continue
        if section == "aliases" and line.strip():
            cur["aliases"] = [a.strip() for a in re.split(r"[,/]", line.strip()) if a.strip()]
        if section == "writeups":
            for mm in re.finditer(r"\[([^\]]+)\]\((https?://[^)]+)\)", line):
                cur["writeups"].append({"title": mm.group(1), "url": mm.group(2)})
        if section == "samples":
            hm = HASH.search(line.lower())
            if hm:
                dl = DL.search(line)
                cur["samples"].append({"sha256": hm.group(1),
                                       "source": dl.group(1) if dl else None,
                                       "url": dl.group(2) if dl else None})
    return [f for f in families if f["samples"] or f["writeups"]]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("readme")
    ap.add_argument("-o", "--out", default="gallery/manifest.json")
    a = ap.parse_args()
    fams = parse(open(a.readme, encoding="utf-8").read())
    hashes = sum(len(f["samples"]) for f in fams)
    manifest = {"source": "github.com/decoderloop/rust-malware-gallery",
                "note": "hashes only; fetch samples from the listed source in an isolated VM",
                "families": fams,
                "hash_to_family": {s["sha256"]: f["family"] for f in fams for s in f["samples"]}}
    with open(a.out, "w") as fh:
        json.dump(manifest, fh, indent=1)
    print("%d families, %d sample hashes -> %s" % (len(fams), hashes, a.out))


if __name__ == "__main__":
    main()
