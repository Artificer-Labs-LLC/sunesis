"""Kuna engine adapter (Apache-2.0 engine, driven as a subprocess).

Kuna is a Rust port/rework of the Ghidra decompiler pipeline. We drive its
CLI in JSON mode:
  kuna functions <bin> --json [--option listing on --option fid on]
  kuna decompile-all <bin> --json [same options]
with the environment variable kuna_fid_db pointing at a .fid database
built by `kuna fid build` (see harvest/). With the fid option on, Kuna
renames placeholder functions (sub_*/FUN_*) whose masked full hash matches
exactly one database name - its analog of Ghidra's Function ID analyzer.
"""
import json
import os
import subprocess

KUNA = os.environ.get("KUNA_BIN", os.path.expanduser("~/.local/bin/kuna"))


def _run(args, fid_db=None, timeout=1200):
    env = dict(os.environ)
    if fid_db:
        env["kuna_fid_db"] = fid_db
    r = subprocess.run([KUNA] + args, env=env, capture_output=True,
                       text=True, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"kuna {' '.join(args[:2])} failed: {r.stderr[-500:]}")
    return json.loads(r.stdout)


def version():
    r = subprocess.run([KUNA, "--version"], capture_output=True, text=True)
    return r.stdout.strip()


def functions(binary, fid_db=None):
    args = ["functions", binary, "--json"]
    if fid_db:
        args += ["--option", "listing", "on", "--option", "fid", "on"]
    d = _run(args, fid_db=fid_db)
    return {f["address"]: f for f in d["functions"]}


def decompile_all(binary, fid_db=None, max_fn_seconds=60):
    args = ["decompile-all", binary, "--json",
            "--max-fn-seconds", str(max_fn_seconds)]
    if fid_db:
        args += ["--option", "listing", "on", "--option", "fid", "on"]
    d = _run(args, fid_db=fid_db, timeout=2400)
    out = {}
    for f in d["functions"]:
        out[f["address"]] = {
            "name": f["name"],
            "size": f.get("size"),
            "pseudocode": f.get("code"),
            "error": f.get("error"),
            "unstructured_gotos": f.get("unstructured_gotos"),
        }
    return out
