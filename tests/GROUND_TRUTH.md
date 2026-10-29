# Ground truth for the planted fixture

Source: `planted.c` in this directory. Build: `build_planted.sh`.
The analyzed target is `planted.stripped` (symbols removed with
`strip --strip-all`); `planted` is the same binary before stripping and
serves as the name oracle. Both print, when run:

```
crc=8594afc8 xorfold=6ebb06fb mulhi=000000000000000f sumcap=2334 dispatch=44 sha0=eb25
```

## Custom functions (semantics by source)

| function | truth |
|---|---|
| `planted_xorfold` | acc=0x811C9DC5; per byte: acc ^= b, acc = rotl32(acc,5); return acc ^ (len * 0x9E3779B9) |
| `planted_mulhi128` | high 64 bits of the full 128-bit product a*b. For (2^64-1, 0x10): 0xF |
| `planted_dispatch` | op 0→+1, 1→+2, 2 falls through to 3's handler →+4, 3→+4, else identity. dispatch(2,40)=44 |
| `planted_sumcap` | sums buf[0..n); returns the partial sum early once it exceeds 1,000,000 |
| `op_add1/2/4`, `op_id` | table targets for `planted_dispatch` |

## Library code physically present in the target

* zlib 1.3.1, the local gcc -O1 build (whole static archive linked in).
* OpenSSL SHA-256 family from the distribution libcrypto.a subset
  (SHA256_Init/Update/Final + sha256_block_data_order + cpuid helpers),
  statically linked.
* libc present only as dynamic imports (PLT) - *not* embedded; see
  `../corpus/SUBSTITUTIONS.md` for why, and `planted.static.stripped`
  for the fully-static variant used by the FID-at-scale check.
