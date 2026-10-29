# Proof run — method and results

## Method

Target: `tests/planted.stripped` — a planted fixture (source and ground
truth in `tests/GROUND_TRUTH.md`) with four custom functions of known
semantics plus real zlib 1.3.1 and OpenSSL SHA-256 code statically
linked in, then stripped of symbols. Correct identification is measured
against the unstripped binary's symbol table (the oracle): a claim
counts as correct only if the true name appears in the record, and any
confident record naming a *different* function counts as wrong.

## Headline results (canonical run, `proof/canonical/report.json`)

- 157 functions in the merged witness record; both engines produced
  pseudocode for the overwhelming majority.
- **108 of 126 oracle library functions correctly named** by at least
  one identification channel.
- **Zero confident-but-wrong identifications.** Every wrong-looking
  first impression in early runs traced to one of two honest causes,
  both now handled in the open (below).
- 11 BSim records are graded **ambiguous**: distinct corpus functions
  whose BSim vectors tie exactly at the top score (e.g. the target at
  0xa8e0 ties `MD5_Update` / `SHA1_Update` / `SHA256_Update` at cosine
  1.0 — the *_Update siblings are vector-identical even at 113
  features). All tied names are attached; FID evidence discriminates.

## The misses (18), by cause

- **CRT glue** (`_init`, `_start`, `_fini`, `frame_dummy`,
  `register_tm_clones`, `deregister_tm_clones`, `__do_global_dtors_aux`):
  not library code and not in the corpus — correct silence.
- **Sub-floor wrappers** (`crc32_combine`, `crc32_combine_gen`,
  `adler32_combine`, `adler32_combine64`, `zlibVersion`,
  `zlibCompileFlags`, `_tr_flush_bits`): 2–3-feature functions. Their
  vectors are too small to support a claim, and FID declined them too.
- **`get_crc_table`**: Ghidra's Function ID hasher produced no hash
  for it during the corpus build — a corpus-coverage gap, recorded in
  the corpus build log.
- **SHA-224 variants + `SHA256_Transform`**: at the margin of the
  OpenSSL subset — silent rather than wrong (in an earlier, unguarded
  run, `SHA256_Transform` was confidently mislabelled `MD5_Transform`;
  the guards below exist because of that measurement).

## One graded disagreement, quoted in full

`planted_mulhi128` (ground truth: return the high 64 bits of the
128-bit product `a * b`; for `(2^64-1, 0x10)` the true answer is `0xF`,
and the binary prints exactly that):

Kuna:
```c
unsigned long sub_125c(unsigned long a0, unsigned long a1)
{
  return SUB168(ZEXT816(a0) * ZEXT816(a1), 8);
}
```

Ghidra:
```c
undefined8 FUN_0010125c(ulong param_1, ulong param_2)
{
  undefined1 auVar1 [16];
  undefined1 auVar2 [16];
  auVar1._8_8_ = 0;
  auVar1._0_8_ = param_1;
  auVar2._8_8_ = 0;
  auVar2._0_8_ = param_2;
  return SUB168(auVar1 * auVar2, 8);
}
```

Both engines recovered the semantics — the same `SUB168(..., 8)`
extraction — through visibly different machinery: Kuna widens the
operands in-register; Ghidra materializes two 16-byte temporaries and
stores the operands field-wise. The grader records this as
`rendering`, confidence **low**, favoured **unresolved**, token
similarity 0.27: the feature checks (call set, loops, gotos) agree,
the text diverges. That is the correct verdict — divergence of
*rendering*, not of meaning — and both texts stay attached to the
record for anyone who wants to adjudicate further.

The other planted functions behave the same way: no identification
claims (they are not library code), graded records attached. `main`
carries the run's most interesting `call_set` record (medium): the
engines genuinely differ on the stack-canary call — Ghidra lists
`__stack_chk_fail` among main's callees; Kuna's rendering folds the
canary path differently.

## Disagreement census (canonical run)

| kind | count | reading |
|---|---|---|
| rendering | 100 | feature checks agree; text diverges (naming, temporaries, type spellings) — low confidence by design |
| type_signature | 17 | genuine rendered-return-type conflicts, e.g. Ghidra `void` vs Kuna `unsigned long` for `crc32` — mostly the documented input asymmetry |
| engine_gap | 14 | 13 import-table pseudo-entries only Ghidra materializes (flagged as such in the record) + `register_tm_clones` |
| control_structure | 12 | goto/loop structure differs |
| call_set | 9 | includes the canary asymmetry and one genuine same-shape/different-target case in OpenSSL's ctype helpers |

## Grader artifacts found and fixed during this proof

The first end-to-end run reported a disagreement for **all 157**
functions. Three measurement bugs, each found by inspecting records
against the oracle, each fixed and re-measured:

1. Call sets compared raw name spellings (`sub_fcf0` vs
   `FUN_0010fcf0`) — 133 phantom `call_set` records. Fixed by
   resolving placeholder spellings to addresses, then by resolving
   FID-renamed names through a name→address oracle (a renamed callee
   must equal its raw-address spelling): 133 → 97 → 9.
2. Ghidra prefixes some headers with `/* WARNING: ... */` comment
   blocks, which a naive header parse read as the return type — 37
   phantom `type_signature` records. Fixed by stripping comments
   before parsing: 37 → 17, and the survivors are genuine conflicts.
3. BSim claims on tiny vectors and exact ties — small wrappers scored
   cosine 1.0 against the wrong siblings. Fixed with a significance
   floor (≥4 features, ≥0.9) and tie-to-ambiguous grading: confident
   wrong claims went to zero.

The lesson the slice is built on: an unexamined grader manufactures
disagreement (and agreement) just as surely as an unexamined engine.
Every number above was recounted from the report file itself, not
from console output.

## FID at scale — the fully static target

`tests/planted.static.stripped` (same source, fully static, -O2;
1,178 functions by Ghidra's count, 1,175 by Kuna's) exercises
identification where glibc code is physically present:

- **fid-ghidra: 178 matches** — including the glibc core
  (`memcpy`, `memset`, `memmove`, `memchr`, `strlen`, `strcmp`,
  `strcpy`, and 5 `malloc`-family records) and 51 zlib names.
- **fid-kuna: 111 witnessed renames** — zlib and OpenSSL families
  rename correctly, but **not one glibc name**. The same corpus, the
  same target: Ghidra's FidService channel carries glibc from
  relocatable-object corpus to linked static binary, and Kuna's
  byte-exact matcher (as driven here) does not. Recorded as a
  channel asymmetry, not smoothed over: for glibc-heavy targets the
  fid-ghidra channel is currently the load-bearing one.
