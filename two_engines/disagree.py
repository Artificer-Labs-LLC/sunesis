"""Cross-engine disagreement grading.

The two decompilers are independent witnesses. Where they agree, the
record is quiet. Where they diverge, the divergence itself is the
finding: this module classifies it (call set / control structure / type
signature / rendering / engine gap), attaches the raw feature evidence
both sides produced, grades confidence in the *classification* (not in
either engine), and names a favoured engine only when a stated rule
fires - otherwise the record says "unresolved" and keeps the evidence
attached for adjudication against the instruction stream.

Rules are deterministic and deliberately simple; their limits are part
of the record (see README).
"""
import difflib
import re

PLACEHOLDER = re.compile(r"\b(?:sub|FUN)_[0-9a-fA-F]+\b")
CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def _normalize(code):
    code = PLACEHOLDER.sub("FN", code or "")
    return re.sub(r"\s+", " ", code).strip()


_SUB = re.compile(r"^sub_([0-9a-fA-F]+)$")
_FUN = re.compile(r"^FUN_([0-9a-fA-F]+)$")


def _callee(token, image_base, name_addrs=None):
    """Resolve one callee spelling to a comparable identity string.

    Both engines spell unknown callees by address - Kuna sub_<vaddr>,
    Ghidra FUN_<va> - so placeholders resolve to '@<vaddr>'. Real names
    resolve through name_addrs when the name is known to live at an
    address in this binary: after a FID rename, one engine calls a
    function by its recovered name while the other still spells the
    raw address, and the two spellings must compare equal. Comparing
    raw spellings instead made nearly every function 'disagree' about
    its call set (measured: 133 of 157, then 97 of 157)."""
    m = _SUB.match(token)
    if m:
        return "@%#x" % int(m.group(1), 16)
    m = _FUN.match(token)
    if m:
        return "@%#x" % (int(m.group(1), 16) - image_base)
    if name_addrs and token in name_addrs:
        return "@%#x" % name_addrs[token]
    return token


def features(code, known_names, image_base=0, name_addrs=None):
    code = code or ""
    raw = {m.group(1) for m in CALL.finditer(code)}
    calls = {_callee(t, image_base, name_addrs) for t in raw
             if t in known_names or _SUB.match(t) or _FUN.match(t)}
    return {
        "calls": sorted(calls),
        "gotos": len(re.findall(r"\bgoto\b", code)),
        "loops": len(re.findall(r"\bwhile\s*\(|\bfor\s*\(|\bdo\s*\{", code)),
        "similarity_base": _normalize(code),
    }


def _return_type(code):
    if not code:
        return ""
    # Ghidra prefixes some headers with /* WARNING: ... */ comment
    # blocks; strip comments or the warning text parses as the type.
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    first = code.strip().split("(", 1)[0]
    parts = first.split()
    return " ".join(parts[:-1]) if len(parts) > 1 else ""


_TYPE_ALIASES = {"uint": "unsigned int", "ulong": "unsigned long",
                 "uchar": "unsigned char", "uint64": "unsigned long long",
                 "int64": "long long", "ushort": "unsigned short"}


def _norm_type(t):
    """Normalize a rendered return type for cross-engine comparison.

    Returns None when the type is a non-claim: Ghidra's undefined /
    undefinedN means 'no type asserted', which must not count as a
    conflicting claim against the other engine's inferred type
    (comparing raw prototype metadata produced 37 phantom
    type_signature records, nearly all of this shape)."""
    t = re.sub(r"\s+", " ", (t or "").strip().lower())
    if not t or re.fullmatch(r"undefined\d*", t):
        return None
    return _TYPE_ALIASES.get(t, t)


def compare(kuna_rec, ghidra_rec, known_names, image_base=0, name_addrs=None):
    """kuna_rec/ghidra_rec: {'pseudocode':..., 'prototype':...} or None.
    Returns None on agreement, else a disagreement record."""
    k_code = (kuna_rec or {}).get("pseudocode")
    g_code = (ghidra_rec or {}).get("pseudocode")
    if not k_code and not g_code:
        return None
    if not k_code or not g_code:
        present = "ghidra" if g_code else "kuna"
        return {"kind": "engine_gap",
                "confidence": "high",
                "favoured": present,
                "favour_reason": f"only {present} produced pseudocode",
                "evidence": {"kuna_error": (kuna_rec or {}).get("error"),
                             "ghidra_error": (ghidra_rec or {}).get("decompile_error")}}
    kf = features(k_code, known_names, image_base, name_addrs)
    gf = features(g_code, known_names, image_base, name_addrs)
    sim = difflib.SequenceMatcher(None, kf["similarity_base"],
                                  gf["similarity_base"]).ratio()
    ev = {"token_similarity": round(sim, 4),
          "kuna_calls": kf["calls"], "ghidra_calls": gf["calls"],
          "kuna_gotos": kf["gotos"], "ghidra_gotos": gf["gotos"],
          "kuna_loops": kf["loops"], "ghidra_loops": gf["loops"]}
    kcalls, gcalls = set(kf["calls"]), set(gf["calls"])
    if kcalls != gcalls:
        diff = kcalls ^ gcalls
        conf = "high" if len(diff) >= 2 or (bool(kcalls) != bool(gcalls)
                                            and max(len(kcalls), len(gcalls)) >= 2) \
            else "medium"
        favoured, reason = "unresolved", "call sets differ; adjudicate against the instruction stream"
        resolved_side = None
        if kcalls and not gcalls:
            resolved_side = "kuna"
        elif gcalls and not kcalls:
            resolved_side = "ghidra"
        if resolved_side:
            favoured = resolved_side
            reason = f"only {resolved_side} resolved call target(s) {sorted(diff)}"
        return {"kind": "call_set", "confidence": conf, "favoured": favoured,
                "favour_reason": reason, "evidence": ev}
    if kf["gotos"] != gf["gotos"] or kf["loops"] != gf["loops"]:
        return {"kind": "control_structure", "confidence": "medium",
                "favoured": "unresolved",
                "favour_reason": "structured renderings differ in gotos/loops; "
                                 "adjudicate against the instruction stream",
                "evidence": ev}
    # Compare the types both engines actually rendered in their code
    # headers; Ghidra's separate prototype metadata (often 'undefined'
    # where its own rendering says 'uint') is kept as evidence only.
    krt_raw, grt_raw = _return_type(k_code), _return_type(g_code)
    krt, grt = _norm_type(krt_raw), _norm_type(grt_raw)
    if krt and grt and krt != grt:
        ev["kuna_return_type"] = krt_raw
        ev["ghidra_return_type"] = grt_raw
        ev["ghidra_prototype_return_type"] = (ghidra_rec or {}).get("return_type", "")
        return {"kind": "type_signature", "confidence": "medium",
                "favoured": "unresolved",
                "favour_reason": "declared return types differ",
                "evidence": ev}
    if sim < 0.80:
        return {"kind": "rendering", "confidence": "low",
                "favoured": "unresolved",
                "favour_reason": "features agree; text diverges below the "
                                 "similarity floor - cosmetic-leaning, unverified",
                "evidence": ev}
    return None
