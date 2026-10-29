"""Ghidra engine adapter (Apache-2.0 engine, driven headlessly).

Two surfaces:
  * analyzeHeadless + ExportProgram.java - per-function records with
    prototypes, call sets, Ghidra Function ID hashes (FidService) and
    decompiler pseudocode.
  * the `bsim` command-line tool - generates BSim feature-vector
    signatures for a project (generatesigs) and dumps a signature
    database back to XML (dumpsigs). Similarity over those vectors is
    computed in match.py; scores are BSim-vector similarities computed
    locally, not the BSim server's LSH scores (see README limitations).
"""
import json
import os
import subprocess
import xml.etree.ElementTree as ET

GHIDRA = os.environ.get("GHIDRA_HOME", os.path.expanduser("~/.local/opt/ghidra"))
HEADLESS = os.path.join(GHIDRA, "support", "analyzeHeadless")
BSIM = os.path.join(GHIDRA, "support", "bsim")
SLICE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _env():
    e = dict(os.environ)
    e["JAVA_HOME"] = os.environ.get("JAVA_HOME", os.path.expanduser("~/.local/opt/jdk-21"))
    e["PATH"] = os.path.join(e["JAVA_HOME"], "bin") + os.pathsep + e.get("PATH", "")
    return e


def _run(cmd, timeout=3600):
    r = subprocess.run(cmd, env=_env(), capture_output=True, text=True,
                       timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError(f"{os.path.basename(cmd[0])} failed: "
                           f"{(r.stdout + r.stderr)[-800:]}")
    return r


def headless_export(files, project_loc, project_name, out_jsonl,
                    decompile=True):
    os.makedirs(project_loc, exist_ok=True)
    if os.path.exists(out_jsonl):
        os.remove(out_jsonl)
    cmd = [HEADLESS, project_loc, project_name,
           "-processor", "x86:LE:64:default", "-cspec", "gcc",
           "-scriptPath", os.path.join(SLICE, "ghidra_scripts"),
           "-postScript", "ExportProgram.java", out_jsonl,
           "decompile" if decompile else "nodecompile"]
    for f in files:
        cmd += ["-import", f]
    _run(cmd)
    return parse_export(out_jsonl)


def parse_export(path):
    """Return {vaddr_int: record}. Addresses are normalized by the
    program image base so they line up with ELF virtual addresses
    (what Kuna reports)."""
    header = {}
    funcs = {}
    current_base = 0
    for line in open(path):
        d = json.loads(line)
        if d.get("kind") == "header":
            header = d
            current_base = int(d["image_base"], 16)
            continue
        rec = dict(d)
        rec["vaddr"] = int(d["address"], 16) - current_base
        funcs[rec["vaddr"]] = rec
    return header, funcs


def bsim_generatesigs_xml(project_loc, project_name, xml_dir):
    os.makedirs(xml_dir, exist_ok=True)
    _run([BSIM, "generatesigs", f"ghidra:{project_loc}/{project_name}",
          xml_dir, "--config", "medium_64", "--overwrite"])


def bsim_dumpsigs(db_url, xml_dir):
    os.makedirs(xml_dir, exist_ok=True)
    _run([BSIM, "dumpsigs", db_url, xml_dir])


def parse_bsim_xml_dir(xml_dir):
    """Parse BSim signature XML into function vector records.

    The bsim tool writes one extensionless file per executable under
    sigs_<md5>/ directories, in this shape:
      <description><execlist>
        <exe><md5>..</md5><name>crc32.o</name>...</exe>
        <fdesc name="crc32" addr="0x1003f8">
          <lshcosine><hash tf="5">0xe04d1c8</hash>...</lshcosine>
        </fdesc> ...
    Returns [{exe, exe_md5, name, address, vector:{hash:tf}}].
    """
    out = []
    for dirpath, _dirs, files in os.walk(xml_dir):
        for fn in sorted(files):
            path = os.path.join(dirpath, fn)
            try:
                root = ET.parse(path).getroot()
            except ET.ParseError:
                continue
            exe_name, exe_md5 = "", ""
            for el in root.iter():
                if el.tag == "exe":
                    for c in el:
                        if c.tag == "name":
                            exe_name = c.text or ""
                        elif c.tag == "md5":
                            exe_md5 = c.text or ""
                elif el.tag == "fdesc":
                    vec = {}
                    for child in el:
                        for h in child:
                            if h.tag == "hash":
                                vec[h.text.strip()] = float(h.get("tf", 1))
                    out.append({"exe": exe_name, "exe_md5": exe_md5,
                                "name": el.get("name", ""),
                                "address": el.get("addr", ""),
                                "vector": vec, "selfsig": None})
    return out
