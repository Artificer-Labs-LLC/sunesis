# Corpus substitutions and deviations - recorded honestly

The slice spec asked for a mini-harvest of glibc / OpenSSL / zlib,
"2 compilers x 3 optimization levels". Reality on the build machine
refused parts of that; every substitution is recorded here.

1. **Second compiler: absent.** The machine carries exactly one C
   compiler (gcc 13.3.0; no clang, no second gcc). zlib was therefore
   built with gcc at -O0/-O1/-O2 (three optimization levels, one
   compiler). The second provenance axis is the *distribution's own
   builds* (Ubuntu packages: different toolchain vintage and flag set),
   harvested as `zlib-distro`, `glibc-distro-subset`,
   `openssl-distro-subset`. Provenance is recorded per build in
   `manifest.json`. Nothing in the corpus claims to be a clang build.

2. **glibc from source: not built.** A from-source glibc build was out
   of scope for a mini-harvest; the corpus instead carries a curated
   subset of objects extracted from the distribution's `libc.a`
   (malloc, the mem*/str* core, snprintf/vsnprintf - 15 objects).
   The full glibc is *not* in the corpus; only those objects are.

3. **OpenSSL from source: not built.** Same reasoning: a curated subset
   of the distribution's `libcrypto.a` (the SHA-1/SHA-256/SHA-512 and
   MD5 families including the x86-64 assembly block functions, AES misc,
   and the cpuid/ctype/thread helpers the SHA closure needs).

4. **glibc inside the primary test target: refused by the linker.**
   Statically linking glibc subset objects into a dynamically-linked
   executable fails: glibc's own objects (malloc.o is the worst) depend
   on libc-private symbols (`__libc_message_impl`, tunables,
   low-level-lock internals) that the shared libc does not export for
   this use. The primary fixture therefore embeds zlib + the OpenSSL
   subset and keeps libc as dynamic imports. glibc *identification* is
   exercised instead on `tests/planted.static.stripped`, a fully static
   binary of the same source (FID channels only).

5. **SHA256 one-shot API: swapped for Init/Update/Final.** In this
   OpenSSL version the one-shot `SHA256()` routes through the EVP /
   provider stack, which would have dragged ~9,500 functions into the
   fixture. The fixture calls the low-level Init/Update/Final API -
   the same SHA-256 code, honestly labelled in the source.

6. **BSim scoring: exact local cosine over genuine BSim vectors.** The
   `bsim` CLI generates BSim feature vectors and commits them to a
   database, but its `dumpsigs` cannot dump a whole database (it demands
   one executable at a time), so the provider reads per-build signature
   XML written by the same generator. The medium_64 template's vectors
   are literally named `lshcosine`: cosine is the similarity family.
   What we skip is BSim's LSH bucketing/index and significance
   weighting; scores rank like BSim's, they are not BSim-server values.

7. **Ghidra FID storage: JSON of FidService hashes, not a .fidb.**
   Hashes are computed by Ghidra's own FidService (the Function ID
   analyzer's algorithm); the index container is JSON so the corpus is
   inspectable and diffable. A real `.fid` database *is* built and used
   on the Kuna side (`corpus/two-engines.fid`, via `kuna fid build`).
