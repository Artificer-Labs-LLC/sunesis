"""two-engines provider CLI.

  python3 -m two_engines analyze <x86-64-elf> --corpus corpus --out proof/run1

Runs Kuna and Ghidra over the target, identifies functions against the
harvested corpus (Function ID + BSim), grades cross-engine disagreement,
and writes report.json + report.md into the output directory.

Follows the provider shape used by REA: a provider is selected by id
(provider.json: "two-engines"), opens a binary, and returns structured
evidence records with limitations attached - never bare conclusions.
"""
import argparse
import hashlib
import json
import os
import shutil
import sys

from . import PROVIDER_ID, __version__
from . import disagree, ghidra_engine, kuna_engine, match

LIMITATIONS = [
    "BSim similarity is exact cosine computed locally over the lshcosine "
    "feature vectors Ghidra's BSim generator emits (the same similarity "
    "family the medium_64 template names), but without BSim's LSH "
    "bucketing/index and significance weighting - scores rank like "
    "BSim's, they are not BSim-server values.",
    "The Ghidra Function ID index is stored as JSON of FidService hash "
    "pairs rather than a binary .fidb; the hashes are Ghidra's own, the "
    "container is ours (inspectable, diffable).",
    "Identification coverage is exactly the corpus in corpus/manifest.json "
    "- a mini-harvest, not a universal library database.",
    "Disagreement grading is deterministic and feature-based; a 'favoured' "
    "engine is a heuristic verdict with its rule stated, not ground truth.",
    "BSim claims require >=4 vector features and >=0.9 cosine; corpus "
    "functions whose vectors tie exactly are reported as one ambiguous "
    "record with all tied names, never resolved arbitrarily. BSim "
    "vectors provably cannot separate some siblings (the SHA-1/SHA-256/"
    "MD5 *_Update functions are vector-identical) - there, Function ID "
    "evidence is the discriminating channel.",
    "x86-64 ELF only in this slice.",
    "Input asymmetry, measured: Kuna's pseudocode is captured AFTER its "
    "Function ID pass has renamed library functions, while Ghidra's "
    "pseudocode is captured from its unidentified analysis (the corpus "
    "FID index is JSON, not a .fidb Ghidra's analyzer could consume). "
    "Ghidra therefore renders more placeholder names and conservative "
    "types than it would with FID applied internally; some rendering "
    "divergence is attributable to this asymmetry rather than to the "
    "decompiler cores.",
]


def _load_ranges(path):
    """(lo, hi) virtual-address ranges of the ELF's LOAD segments."""
    import subprocess
    try:
        out = subprocess.run(["readelf", "-lW", path], capture_output=True,
                             text=True, check=True).stdout
    except Exception:
        return []
    ranges = []
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == "LOAD":
            vaddr = int(parts[2], 16)
            ranges.append((vaddr, vaddr + int(parts[5], 16)))
    return ranges


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def analyze(target, corpus_dir, out_dir):
    target = os.path.abspath(target)
    corpus_dir = os.path.abspath(corpus_dir)
    out_dir = os.path.abspath(out_dir)
    work = os.path.join(out_dir, "work")
    os.makedirs(work, exist_ok=True)
    fid_db = os.path.join(corpus_dir, "two-engines.fid")
    if not os.path.exists(fid_db):
        fid_db = None

    print("[1/5] kuna: listing (fid off/on) + decompile-all")
    kuna_plain = kuna_engine.functions(target)
    kuna_fid = kuna_engine.functions(target, fid_db=fid_db) if fid_db else kuna_plain
    kuna_dec = kuna_engine.decompile_all(target, fid_db=fid_db)

    print("[2/5] ghidra: headless analysis + export")
    projloc = os.path.join(work, "ghidra_projects")
    for suffix in (".rep", ".gpr"):
        p = os.path.join(projloc, "target" + suffix)
        if os.path.isdir(p):
            shutil.rmtree(p)
        elif os.path.exists(p):
            os.remove(p)
    header, gfuncs = ghidra_engine.headless_export(
        [target], projloc, "target", os.path.join(work, "ghidra_export.jsonl"),
        decompile=True)
    image_base = int(header.get("image_base", "0"), 16)

    print("[3/5] bsim: target signatures + corpus vectors")
    bsim_target_xml = os.path.join(work, "bsim_target_xml")
    ghidra_engine.bsim_generatesigs_xml(projloc, "target", bsim_target_xml)
    # Corpus vectors live in per-build XML dirs (provenance = build id).
    corpus_vecs = []
    bsim_xml_root = os.path.join(corpus_dir, "bsim_xml")
    for bid in sorted(os.listdir(bsim_xml_root)):
        for c in ghidra_engine.parse_bsim_xml_dir(os.path.join(bsim_xml_root, bid)):
            c["build"] = bid
            corpus_vecs.append(c)
    target_vecs = ghidra_engine.parse_bsim_xml_dir(bsim_target_xml)
    for t in target_vecs:
        try:
            t["key"] = int(t["address"], 16) - image_base
        except ValueError:
            t["key"] = None
    target_vecs = [t for t in target_vecs if t["key"] is not None]

    print("[4/5] matching: fid (both channels) + bsim")
    fs, fo = match.load_fid_index(corpus_dir)
    fid_g = match.fid_ghidra_matches(gfuncs, fs, fo)
    fid_k = match.fid_kuna_matches(kuna_fid, kuna_plain)
    bsim = match.bsim_matches(target_vecs, corpus_vecs)

    print("[5/5] merging + disagreement grading")
    known_names = set()
    for f in list(kuna_fid.values()) + list(kuna_dec.values()):
        known_names.add(f["name"])
    for rec in gfuncs.values():
        known_names.add(rec["name"])
    for m in list(fid_g.values()) + list(fid_k.values()) + list(bsim.values()):
        known_names.update(m["names"])

    # name -> address oracle for call-set resolution: every name either
    # engine (or an identification record) attaches to an address in
    # this binary. First claim wins; conflicts keep the earlier engine's.
    name_addrs = {}
    for src in (kuna_fid, kuna_dec):
        for a, f in src.items():
            if f.get("name"):
                name_addrs.setdefault(f["name"], a)
    for a, rec in gfuncs.items():
        if rec.get("name"):
            name_addrs.setdefault(rec["name"], a)
    for book in (fid_g, fid_k, bsim):
        for a, m in book.items():
            for n in m["names"]:
                name_addrs.setdefault(n, a)
    load_ranges = _load_ranges(target)

    addrs = sorted(set(kuna_dec) | set(gfuncs))
    functions = []
    n_ident = n_dis = 0
    kinds = {}
    for a in addrs:
        ident = []
        if a in fid_k:
            ident.append(fid_k[a])
        if a in fid_g:
            ident.append(fid_g[a])
        if a in bsim:
            ident.append(bsim[a])
        if ident:
            n_ident += 1
        grec = gfuncs.get(a)
        krec = kuna_dec.get(a)
        dis = disagree.compare(
            krec, {"pseudocode": grec.get("pseudocode"),
                   "return_type": grec.get("return_type", ""),
                   "error": None,
                   "decompile_error": grec.get("decompile_error")} if grec else None,
            known_names, image_base=image_base, name_addrs=name_addrs)
        if dis and dis["kind"] == "engine_gap" and load_ranges and \
                not any(lo <= a < hi for lo, hi in load_ranges):
            dis["favour_reason"] += (
                " (address lies outside the ELF's loaded segments: an "
                "import-table pseudo-entry only one engine materializes "
                "as a function)")
        if dis:
            n_dis += 1
            kinds[dis["kind"]] = kinds.get(dis["kind"], 0) + 1
        functions.append({
            "address": hex(a),
            "names": {"kuna": (kuna_fid.get(a) or {}).get("name")
                      or (krec or {}).get("name"),
                      "ghidra": (grec or {}).get("name")},
            "identification": ident,
            "pseudocode": {"kuna": (krec or {}).get("pseudocode"),
                           "ghidra": (grec or {}).get("pseudocode")},
            "disagreement": dis,
        })

    manifest_path = os.path.join(corpus_dir, "manifest.json")
    corpus_info = {}
    if os.path.exists(manifest_path):
        m = json.load(open(manifest_path))
        corpus_info = {"builds": [b["build_id"] for b in m["builds"]]}
    report = {
        "provider": {"id": PROVIDER_ID, "version": __version__},
        "target": {"path": os.path.abspath(target), "sha256": _sha256(target)},
        "engines": {"kuna": kuna_engine.version(), "ghidra": "12.1.4"},
        "corpus": corpus_info,
        "summary": {"functions": len(functions),
                    "identified": n_ident,
                    "disagreements": n_dis,
                    "disagreements_by_kind": kinds},
        "functions": functions,
        "limitations": LIMITATIONS,
    }
    with open(os.path.join(out_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
    with open(os.path.join(out_dir, "report.md"), "w") as f:
        f.write(render_md(report))
    print(json.dumps(report["summary"], indent=2))
    return report


def render_md(r):
    s = r["summary"]
    lines = [f"# Two-engines witness report",
             "",
             f"Target: `{os.path.basename(r['target']['path'])}` "
             f"(sha256 `{r['target']['sha256'][:16]}…`)",
             f"Engines: Kuna {r['engines']['kuna']} · Ghidra {r['engines']['ghidra']}",
             f"Corpus builds: {', '.join(r['corpus'].get('builds', []))}",
             "",
             f"Functions: {s['functions']} · identified: {s['identified']} · "
             f"disagreements: {s['disagreements']} {s['disagreements_by_kind']}",
             "",
             "## Identified functions",
             "",
             "| address | name | method | evidence |",
             "|---|---|---|---|"]
    for fn in r["functions"]:
        for m in fn["identification"]:
            ev = m["evidence"]
            evs = (f"sim {ev['similarity']}" if "similarity" in ev else
                   f"{ev.get('full_hash', '')[:12]}…" if "full_hash" in ev else
                   f"{ev.get('before', '')} → {ev.get('after', '')}")
            lines.append(f"| {fn['address']} | {', '.join(m['names'])} | "
                         f"{m['method']} ({m['strength']}) | {evs} |")
    lines += ["", "## Disagreements", "",
              "| address | kind | confidence | favoured |",
              "|---|---|---|---|"]
    for fn in r["functions"]:
        d = fn["disagreement"]
        if d:
            lines.append(f"| {fn['address']} | {d['kind']} | {d['confidence']} "
                         f"| {d['favoured']} |")
    lines += ["", "## Limitations", ""]
    lines += [f"- {x}" for x in r["limitations"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="two_engines")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze")
    a.add_argument("target")
    a.add_argument("--corpus", required=True)
    a.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    os.makedirs(args.out, exist_ok=True)
    analyze(args.target, args.corpus, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
