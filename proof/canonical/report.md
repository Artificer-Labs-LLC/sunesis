# Two-engines witness report

Target: `planted.stripped` (sha256 `6b6da5f77d4da76f…`)
Engines: Kuna kuna 1.833 · Ghidra 12.1.4
Corpus builds: glibc-distro-subset, openssl-distro-subset, zlib-1.3.1-gcc13-O0, zlib-1.3.1-gcc13-O1, zlib-1.3.1-gcc13-O2, zlib-distro

Functions: 157 · identified: 108 · disagreements: 152 {'rendering': 100, 'type_signature': 17, 'control_structure': 12, 'engine_gap': 14, 'call_set': 9}

## Identified functions

| address | name | method | evidence |
|---|---|---|---|
| 0x14b0 | multmodp | fid-kuna (full-hash rename) | sub_14b0 → multmodp |
| 0x14b0 | multmodp | fid-ghidra (full+specific) | 655616679978… |
| 0x14b0 | multmodp | bsim (strong) | sim 1.0 |
| 0x14de | x2nmodp | fid-kuna (full-hash rename) | sub_14de → x2nmodp |
| 0x14de | x2nmodp | fid-ghidra (full+specific) | 468208649615… |
| 0x14de | x2nmodp | bsim (strong) | sim 1.0 |
| 0x1528 | crc_word | fid-kuna (full-hash rename) | sub_1528 → crc_word |
| 0x1528 | crc_word | fid-ghidra (full+specific) | 420277083055… |
| 0x1528 | crc_word | bsim (strong) | sim 1.0 |
| 0x1559 | crc32_z | fid-kuna (full-hash rename) | sub_1559 → crc32_z |
| 0x1559 | crc32_z | fid-ghidra (full+specific) | -54192319203… |
| 0x1559 | crc32_z | bsim (strong) | sim 1.0 |
| 0x18a8 | adler32, crc32 | fid-ghidra (full+specific) | -23440346588… |
| 0x18b4 | crc32_combine64 | fid-kuna (full-hash rename) | sub_18b4 → crc32_combine64 |
| 0x18b4 | crc32_combine64 | fid-ghidra (full+specific) | 125283283329… |
| 0x18b4 | crc32_combine64 | bsim (strong) | sim 1.0 |
| 0x18e5 | crc32_combine_gen64 | fid-kuna (full-hash rename) | sub_18e5 → crc32_combine_gen64 |
| 0x18e5 | crc32_combine_gen64 | fid-ghidra (full+specific) | -36870534054… |
| 0x18e5 | crc32_combine_gen64 | bsim (strong) | sim 1.0 |
| 0x1900 | crc32_combine_op | fid-kuna (full-hash rename) | sub_1900 → crc32_combine_op |
| 0x1900 | crc32_combine_op | fid-ghidra (full+specific) | 383436729454… |
| 0x1900 | crc32_combine_op | bsim (strong) | sim 1.0 |
| 0x1915 | compress2 | fid-kuna (full-hash rename) | sub_1915 → compress2 |
| 0x1915 | compress2 | fid-ghidra (full+specific) | -60734561368… |
| 0x1915 | compress2 | bsim (strong) | sim 1.0 |
| 0x1a3e | compress | fid-kuna (full-hash rename) | sub_1a3e → compress |
| 0x1a3e | compress | fid-ghidra (full+specific) | 971090207695… |
| 0x1a56 | compressBound | fid-ghidra (full+specific) | -57171098026… |
| 0x1a56 | compressBound | bsim (strong) | sim 1.0 |
| 0x1a78 | uncompress2 | fid-kuna (full-hash rename) | sub_1a78 → uncompress2 |
| 0x1a78 | uncompress2 | fid-ghidra (full+specific) | 422988600939… |
| 0x1a78 | uncompress2 | bsim (strong) | sim 1.0 |
| 0x1c2b | uncompress | fid-ghidra (full+specific) | -89263121252… |
| 0x1c47 | slide_hash | fid-kuna (full-hash rename) | sub_1c47 → slide_hash |
| 0x1c47 | slide_hash | fid-ghidra (full+specific) | 309437942157… |
| 0x1c47 | slide_hash | bsim (strong) | sim 1.0 |
| 0x1cb5 | deflateStateCheck | fid-kuna (full-hash rename) | sub_1cb5 → deflateStateCheck |
| 0x1cb5 | deflateStateCheck | fid-ghidra (full+specific) | -37488691167… |
| 0x1cb5 | deflateStateCheck | bsim (strong) | sim 1.0 |
| 0x1d3b | putShortMSB | fid-kuna (full-hash rename) | sub_1d3b → putShortMSB |
| 0x1d3b | putShortMSB | fid-ghidra (full+specific) | -73394655932… |
| 0x1d3b | putShortMSB | bsim (strong) | sim 1.0 |
| 0x1d69 | longest_match | fid-kuna (full-hash rename) | sub_1d69 → longest_match |
| 0x1d69 | longest_match | fid-ghidra (full+specific) | -30753939487… |
| 0x1d69 | longest_match | bsim (strong) | sim 1.0 |
| 0x1f5d | read_buf | fid-kuna (full-hash rename) | sub_1f5d → read_buf |
| 0x1f5d | read_buf | fid-ghidra (full+specific) | 419882329166… |
| 0x1f5d | read_buf | bsim (strong) | sim 1.0 |
| 0x1fe0 | fill_window | fid-kuna (full-hash rename) | sub_1fe0 → fill_window |
| 0x1fe0 | fill_window | fid-ghidra (full+specific) | 209649738229… |
| 0x1fe0 | fill_window | bsim (strong) | sim 1.0 |
| 0x227c | flush_pending | fid-kuna (full-hash rename) | sub_227c → flush_pending |
| 0x227c | flush_pending | fid-ghidra (full+specific) | 564546512168… |
| 0x227c | flush_pending | bsim (strong) | sim 1.0 |
| 0x22f2 | deflate_slow | fid-kuna (full-hash rename) | sub_22f2 → deflate_slow |
| 0x22f2 | deflate_slow | fid-ghidra (full+specific) | 385603200726… |
| 0x22f2 | deflate_slow | bsim (strong) | sim 1.0 |
| 0x28f1 | deflate_fast | fid-kuna (full-hash rename) | sub_28f1 → deflate_fast |
| 0x28f1 | deflate_fast | fid-ghidra (full+specific) | 670235351331… |
| 0x28f1 | deflate_fast | bsim (strong) | sim 1.0 |
| 0x2d63 | deflate_stored | fid-kuna (full-hash rename) | sub_2d63 → deflate_stored |
| 0x2d63 | deflate_stored | fid-ghidra (full+specific) | -30508206271… |
| 0x2d63 | deflate_stored | bsim (strong) | sim 1.0 |
| 0x3246 | deflateSetDictionary | fid-kuna (full-hash rename) | sub_3246 → deflateSetDictionary |
| 0x3246 | deflateSetDictionary | fid-ghidra (full+specific) | -73750075913… |
| 0x3246 | deflateSetDictionary | bsim (strong) | sim 1.0 |
| 0x348e | deflateGetDictionary | fid-kuna (full-hash rename) | sub_348e → deflateGetDictionary |
| 0x348e | deflateGetDictionary | fid-ghidra (full+specific) | -82598586487… |
| 0x348e | deflateGetDictionary | bsim (strong) | sim 1.0 |
| 0x350b | deflateResetKeep | fid-kuna (full-hash rename) | sub_350b → deflateResetKeep |
| 0x350b | deflateResetKeep | fid-ghidra (full+specific) | 140598863869… |
| 0x350b | deflateResetKeep | bsim (strong) | sim 1.0 |
| 0x35c8 | deflateReset | fid-kuna (full-hash rename) | sub_35c8 → deflateReset |
| 0x35c8 | deflateReset | fid-ghidra (full+specific) | -43746074207… |
| 0x35c8 | deflateReset | bsim (strong) | sim 1.0 |
| 0x36b6 | deflateSetHeader | fid-kuna (full-hash rename) | sub_36b6 → deflateSetHeader |
| 0x36b6 | deflateSetHeader | fid-ghidra (full+specific) | 583802017645… |
| 0x36b6 | deflateSetHeader | bsim (strong) | sim 1.0 |
| 0x36ea | deflatePending | fid-kuna (full-hash rename) | sub_36ea → deflatePending |
| 0x36ea | deflatePending | fid-ghidra (full+specific) | 918948778763… |
| 0x36ea | deflatePending | bsim (strong) | sim 1.0 |
| 0x3733 | deflatePrime | fid-kuna (full-hash rename) | sub_3733 → deflatePrime |
| 0x3733 | deflatePrime | fid-ghidra (full+specific) | 260808037680… |
| 0x3733 | deflatePrime | bsim (strong) | sim 1.0 |
| 0x37db | deflateTune | fid-kuna (full-hash rename) | sub_37db → deflateTune |
| 0x37db | deflateTune | fid-ghidra (full+specific) | -97571812260… |
| 0x37db | deflateTune | bsim (strong) | sim 1.0 |
| 0x382e | deflateBound | fid-kuna (full-hash rename) | sub_382e → deflateBound |
| 0x382e | deflateBound | fid-ghidra (full+specific) | 425970128446… |
| 0x382e | deflateBound | bsim (strong) | sim 1.0 |
| 0x398a | deflate | fid-kuna (full-hash rename) | sub_398a → deflate |
| 0x398a | deflate | fid-ghidra (full+specific) | 377781648013… |
| 0x398a | deflate | bsim (strong) | sim 0.9997 |
| 0x4a99 | deflateParams | fid-kuna (full-hash rename) | sub_4a99 → deflateParams |
| 0x4a99 | deflateParams | fid-ghidra (full+specific) | -63333339254… |
| 0x4a99 | deflateParams | bsim (strong) | sim 1.0 |
| 0x4c48 | deflateEnd | fid-kuna (full-hash rename) | sub_4c48 → deflateEnd |
| 0x4c48 | deflateEnd | fid-ghidra (full+specific) | 912861099421… |
| 0x4c48 | deflateEnd | bsim (strong) | sim 1.0 |
| 0x4cdf | deflateInit2_ | fid-kuna (full-hash rename) | sub_4cdf → deflateInit2_ |
| 0x4cdf | deflateInit2_ | fid-ghidra (full+specific) | 920626444393… |
| 0x4cdf | deflateInit2_ | bsim (strong) | sim 0.9988 |
| 0x4fb7 | deflateInit_ | fid-kuna (full-hash rename) | sub_4fb7 → deflateInit_ |
| 0x4fb7 | deflateInit_ | fid-ghidra (full+specific) | 416486426012… |
| 0x4fe1 | deflateCopy | fid-ghidra (full+specific) | -84337798461… |
| 0x4fe1 | deflateCopy | bsim (strong) | sim 1.0 |
| 0x51f0 | inflateStateCheck | fid-kuna (full-hash rename) | sub_51f0 → inflateStateCheck |
| 0x51f0 | inflateStateCheck | fid-ghidra (full+specific) | 761909952053… |
| 0x51f0 | inflateStateCheck | bsim (strong) | sim 1.0 |
| 0x5241 | syncsearch | fid-kuna (full-hash rename) | sub_5241 → syncsearch |
| 0x5241 | syncsearch | fid-ghidra (full+specific) | 236829338257… |
| 0x5241 | syncsearch | bsim (strong) | sim 1.0 |
| 0x52b0 | updatewindow | fid-kuna (full-hash rename) | sub_52b0 → updatewindow |
| 0x52b0 | updatewindow | fid-ghidra (full+specific) | 218567955500… |
| 0x52b0 | updatewindow | bsim (strong) | sim 1.0 |
| 0x53c1 | inflateResetKeep | fid-kuna (full-hash rename) | sub_53c1 → inflateResetKeep |
| 0x53c1 | inflateResetKeep | fid-ghidra (full+specific) | 575564819780… |
| 0x53c1 | inflateResetKeep | bsim (strong) | sim 1.0 |
| 0x5475 | inflateReset | fid-kuna (full-hash rename) | sub_5475 → inflateReset |
| 0x5475 | inflateReset | fid-ghidra (full+specific) | 396737021673… |
| 0x5475 | inflateReset | bsim (strong) | sim 1.0 |
| 0x54b0 | inflateReset2 | fid-kuna (full-hash rename) | sub_54b0 → inflateReset2 |
| 0x54b0 | inflateReset2 | fid-ghidra (full+specific) | 765456899907… |
| 0x54b0 | inflateReset2 | bsim (strong) | sim 1.0 |
| 0x5554 | inflateInit2_ | fid-kuna (full-hash rename) | sub_5554 → inflateInit2_ |
| 0x5554 | inflateInit2_ | fid-ghidra (full+specific) | -67515573800… |
| 0x5554 | inflateInit2_ | bsim (strong) | sim 1.0 |
| 0x5639 | inflateInit_ | fid-kuna (full-hash rename) | sub_5639 → inflateInit_ |
| 0x5639 | inflateInit_ | fid-ghidra (full+specific) | -13171302860… |
| 0x5655 | inflatePrime | fid-kuna (full-hash rename) | sub_5655 → inflatePrime |
| 0x5655 | inflatePrime | fid-ghidra (full+specific) | 884389127575… |
| 0x5655 | inflatePrime | bsim (strong) | sim 1.0 |
| 0x56d4 | inflate | fid-ghidra (full+specific) | -29937834063… |
| 0x56d4 | inflate | bsim (strong) | sim 1.0 |
| 0x7463 | inflateEnd | fid-kuna (full-hash rename) | sub_7463 → inflateEnd |
| 0x7463 | inflateEnd | fid-ghidra (full+specific) | 805621266856… |
| 0x7463 | inflateEnd | bsim (strong) | sim 1.0 |
| 0x74b2 | inflateGetDictionary | fid-kuna (full-hash rename) | sub_74b2 → inflateGetDictionary |
| 0x74b2 | inflateGetDictionary | fid-ghidra (full+specific) | -88606642815… |
| 0x74b2 | inflateGetDictionary | bsim (strong) | sim 1.0 |
| 0x752f | inflateSetDictionary | fid-kuna (full-hash rename) | sub_752f → inflateSetDictionary |
| 0x752f | inflateSetDictionary | fid-ghidra (full+specific) | 130277896144… |
| 0x752f | inflateSetDictionary | bsim (strong) | sim 1.0 |
| 0x75e9 | inflateGetHeader | fid-kuna (full-hash rename) | sub_75e9 → inflateGetHeader |
| 0x75e9 | inflateGetHeader | fid-ghidra (full+specific) | 383064106747… |
| 0x75e9 | inflateGetHeader | bsim (strong) | sim 1.0 |
| 0x7624 | inflateSync | fid-kuna (full-hash rename) | sub_7624 → inflateSync |
| 0x7624 | inflateSync | fid-ghidra (full+specific) | -15205396198… |
| 0x7624 | inflateSync | bsim (strong) | sim 1.0 |
| 0x7792 | inflateSyncPoint | fid-kuna (full-hash rename) | sub_7792 → inflateSyncPoint |
| 0x7792 | inflateSyncPoint | fid-ghidra (full+specific) | -53291559746… |
| 0x7792 | inflateSyncPoint | bsim (strong) | sim 1.0 |
| 0x77c5 | inflateCopy | fid-kuna (full-hash rename) | sub_77c5 → inflateCopy |
| 0x77c5 | inflateCopy | fid-ghidra (full+specific) | 895496689019… |
| 0x77c5 | inflateCopy | bsim (strong) | sim 1.0 |
| 0x7a42 | inflateUndermine | fid-kuna (full-hash rename) | sub_7a42 → inflateUndermine |
| 0x7a42 | inflateUndermine | fid-ghidra (full+specific) | 308627958503… |
| 0x7a42 | inflateUndermine | bsim (strong) | sim 1.0 |
| 0x7a6f | inflateValidate | fid-kuna (full-hash rename) | sub_7a6f → inflateValidate |
| 0x7a6f | inflateValidate | fid-ghidra (full+specific) | -82055118198… |
| 0x7a6f | inflateValidate | bsim (strong) | sim 1.0 |
| 0x7aa8 | inflateMark | fid-kuna (full-hash rename) | sub_7aa8 → inflateMark |
| 0x7aa8 | inflateMark | fid-ghidra (full+specific) | -32785174619… |
| 0x7aa8 | inflateMark | bsim (strong) | sim 1.0 |
| 0x7afe | inflateCodesUsed | fid-ghidra (full+specific) | 863773624113… |
| 0x7afe | inflateCodesUsed | bsim (strong) | sim 1.0 |
| 0x7b33 | inflate_table | fid-ghidra (full+specific) | 866966944355… |
| 0x7b33 | inflate_table | bsim (strong) | sim 1.0 |
| 0x8133 | bi_flush | fid-kuna (full-hash rename) | sub_8133 → bi_flush |
| 0x8133 | bi_flush | fid-ghidra (full+specific) | -36496186151… |
| 0x8133 | bi_flush | bsim (strong) | sim 1.0 |
| 0x81b5 | bi_windup | fid-kuna (full-hash rename) | sub_81b5 → bi_windup |
| 0x81b5 | bi_windup | fid-ghidra (full+specific) | -18625984578… |
| 0x81b5 | bi_windup | bsim (strong) | sim 1.0 |
| 0x8228 | init_block | fid-kuna (full-hash rename) | sub_8228 → init_block |
| 0x8228 | init_block | fid-ghidra (full+specific) | -23912468095… |
| 0x8228 | init_block | bsim (strong) | sim 1.0 |
| 0x82b0 | pqdownheap | fid-kuna (full-hash rename) | sub_82b0 → pqdownheap |
| 0x82b0 | pqdownheap | fid-ghidra (full+specific) | -76216258237… |
| 0x82b0 | pqdownheap | bsim (strong) | sim 1.0 |
| 0x83a0 | build_tree | fid-kuna (full-hash rename) | sub_83a0 → build_tree |
| 0x83a0 | build_tree | fid-ghidra (full+specific) | -18082932935… |
| 0x83a0 | build_tree | bsim (strong) | sim 1.0 |
| 0x88a2 | scan_tree | fid-kuna (full-hash rename) | sub_88a2 → scan_tree |
| 0x88a2 | scan_tree | fid-ghidra (full+specific) | -22327331223… |
| 0x88a2 | scan_tree | bsim (strong) | sim 1.0 |
| 0x898d | send_tree | fid-kuna (full-hash rename) | sub_898d → send_tree |
| 0x898d | send_tree | fid-ghidra (full+specific) | 188494128622… |
| 0x898d | send_tree | bsim (strong) | sim 1.0 |
| 0x8f89 | compress_block | fid-kuna (full-hash rename) | sub_8f89 → compress_block |
| 0x8f89 | compress_block | fid-ghidra (full+specific) | 856965520489… |
| 0x8f89 | compress_block | bsim (strong) | sim 1.0 |
| 0x942e | _tr_init | fid-kuna (full-hash rename) | sub_942e → _tr_init |
| 0x942e | _tr_init | fid-ghidra (full+specific) | 533158532509… |
| 0x942e | _tr_init | bsim (strong) | sim 1.0 |
| 0x949f | _tr_stored_block | fid-kuna (full-hash rename) | sub_949f → _tr_stored_block |
| 0x949f | _tr_stored_block | fid-ghidra (full+specific) | 727508559773… |
| 0x949f | _tr_stored_block | bsim (strong) | sim 1.0 |
| 0x95ca | _tr_align | fid-kuna (full-hash rename) | sub_95ca → _tr_align |
| 0x95ca | _tr_align | fid-ghidra (full+specific) | 257407073238… |
| 0x95ca | _tr_align | bsim (strong) | sim 1.0 |
| 0x96a7 | _tr_flush_block | fid-kuna (full-hash rename) | sub_96a7 → _tr_flush_block |
| 0x96a7 | _tr_flush_block | fid-ghidra (full+specific) | 901916927218… |
| 0x96a7 | _tr_flush_block | bsim (strong) | sim 1.0 |
| 0x9c07 | _tr_tally | fid-ghidra (full+specific) | 104595681452… |
| 0x9c07 | _tr_tally | bsim (strong) | sim 1.0 |
| 0x9cff | zError | fid-kuna (full-hash rename) | sub_9cff → zError |
| 0x9cff | zError | fid-ghidra (full+specific) | 544461099352… |
| 0x9cff | zError | bsim (strong) | sim 1.0 |
| 0x9d26 | zcalloc | fid-kuna (full-hash rename) | sub_9d26 → zcalloc |
| 0x9d26 | zcalloc | fid-ghidra (full+specific) | 914065050140… |
| 0x9d26 | zcalloc | bsim (strong) | sim 1.0 |
| 0x9d3d | zcfree | fid-ghidra (full+specific) | 256532873477… |
| 0x9d52 | adler32_combine_ | fid-kuna (full-hash rename) | sub_9d52 → adler32_combine_ |
| 0x9d52 | adler32_combine_ | fid-ghidra (full+specific) | 462423343888… |
| 0x9d52 | adler32_combine_ | bsim (strong) | sim 1.0 |
| 0x9e41 | adler32_z | fid-kuna (full-hash rename) | sub_9e41 → adler32_z |
| 0x9e41 | adler32_z | fid-ghidra (full+specific) | -23338334961… |
| 0x9e41 | adler32_z | bsim (strong) | sim 1.0 |
| 0xa259 | adler32, crc32 | fid-ghidra (full+specific) | -23440346588… |
| 0xa279 | inflate_fast | fid-ghidra (full+specific) | 157285997217… |
| 0xa279 | inflate_fast | bsim (strong) | sim 1.0 |
| 0xa840 | SHA224_Init | fid-ghidra (full+specific) | -71217736061… |
| 0xa840 | SHA224_Init, SHA256_Init | bsim (ambiguous) | sim 1.0 |
| 0xa890 | SHA256_Init | fid-ghidra (full+specific) | -71217736061… |
| 0xa890 | SHA224_Init, SHA256_Init | bsim (ambiguous) | sim 1.0 |
| 0xa8e0 | SHA256_Update | fid-ghidra (full+specific) | 799167953380… |
| 0xa8e0 | MD5_Update, SHA1_Update, SHA256_Update | bsim (ambiguous) | sim 1.0 |
| 0xab00 | SHA256_Final | fid-kuna (full-hash rename) | sub_ab00 → SHA256_Final |
| 0xab00 | SHA256_Final | fid-ghidra (full+specific) | -90270601210… |
| 0xab00 | SHA256_Final | bsim (strong) | sim 1.0 |
| 0xad10 | OPENSSL_atomic_add | fid-kuna (full-hash rename) | sub_ad10 → OPENSSL_atomic_add |
| 0xad10 | OPENSSL_atomic_add | fid-ghidra (full+specific) | -87797489144… |
| 0xad10 | OPENSSL_atomic_add | bsim (strong) | sim 1.0 |
| 0xad30 | OPENSSL_rdtsc | fid-kuna (full-hash rename) | sub_ad30 → OPENSSL_rdtsc |
| 0xad30 | OPENSSL_rdtsc | fid-ghidra (full+specific) | -13504458025… |
| 0xad30 | OPENSSL_rdtsc | bsim (strong) | sim 1.0 |
| 0xad40 | OPENSSL_ia32_cpuid | fid-kuna (full-hash rename) | sub_ad40 → OPENSSL_ia32_cpuid |
| 0xad40 | OPENSSL_ia32_cpuid | fid-ghidra (full+specific) | -73262818729… |
| 0xad40 | OPENSSL_ia32_cpuid | bsim (strong) | sim 1.0 |
| 0xaf30 | OPENSSL_cleanse | fid-ghidra (full+specific) | -70272518290… |
| 0xaf30 | OPENSSL_cleanse | bsim (strong) | sim 1.0 |
| 0xafa0 | CRYPTO_memcmp | fid-ghidra (full+specific) | -48490791201… |
| 0xafa0 | CRYPTO_memcmp | bsim (strong) | sim 1.0 |
| 0xb000 | OPENSSL_wipe_cpu | fid-kuna (full-hash rename) | sub_b000 → OPENSSL_wipe_cpu |
| 0xb000 | OPENSSL_wipe_cpu | fid-ghidra (full+specific) | -80743218269… |
| 0xb070 | OPENSSL_instrument_bus | fid-ghidra (full+specific) | -64226883037… |
| 0xb070 | OPENSSL_instrument_bus | bsim (strong) | sim 1.0 |
| 0xb0d0 | OPENSSL_instrument_bus2 | fid-kuna (full-hash rename) | sub_b0d0 → OPENSSL_instrument_bus2 |
| 0xb0d0 | OPENSSL_instrument_bus2 | fid-ghidra (full+specific) | -22555853016… |
| 0xb0d0 | OPENSSL_instrument_bus2 | bsim (strong) | sim 1.0 |
| 0xb140 | OPENSSL_ia32_rdrand_bytes | fid-ghidra (full+specific) | -24332141054… |
| 0xb140 | OPENSSL_ia32_rdrand_bytes, OPENSSL_ia32_rdseed_bytes | bsim (ambiguous) | sim 1.0 |
| 0xb1b0 | OPENSSL_ia32_rdseed_bytes | fid-ghidra (full+specific) | -55448486697… |
| 0xb1b0 | OPENSSL_ia32_rdrand_bytes, OPENSSL_ia32_rdseed_bytes | bsim (ambiguous) | sim 1.0 |
| 0xb240 | sha256_block_data_order | fid-ghidra (full+specific) | 806042950886… |
| 0xb240 | sha256_block_data_order | bsim (strong) | sim 1.0 |
| 0xc700 | sha256_block_data_order_shaext | fid-kuna (full-hash rename) | sub_c700 → sha256_block_data_order_shaext |
| 0xc700 | sha256_block_data_order_shaext | fid-ghidra (full+specific) | 636971651779… |
| 0xc700 | sha256_block_data_order_shaext | bsim (strong) | sim 1.0 |
| 0xca40 | sha256_block_data_order_ssse3 | fid-kuna (full-hash rename) | sub_ca40 → sha256_block_data_order_ssse3 |
| 0xca40 | sha256_block_data_order_ssse3 | fid-ghidra (full+specific) | 504623555806… |
| 0xca40 | sha256_block_data_order_ssse3 | bsim (strong) | sim 1.0 |
| 0xd900 | sha256_block_data_order_avx | fid-ghidra (full+specific) | -62635826676… |
| 0xd900 | sha256_block_data_order_avx | bsim (strong) | sim 1.0 |
| 0xe800 | sha256_block_data_order_avx2 | fid-ghidra (full+specific) | 508422407948… |
| 0xe800 | sha256_block_data_order_avx2 | bsim (strong) | sim 1.0 |
| 0xfc30 | ossl_strtouint64 | fid-kuna (full-hash rename) | sub_fc30 → ossl_strtouint64 |
| 0xfc30 | ossl_strtouint64 | fid-ghidra (full+specific) | -46703345442… |
| 0xfc30 | ossl_strtouint64 | bsim (strong) | sim 1.0 |
| 0xfcf0 | OPENSSL_cpuid_setup | fid-ghidra (full+specific) | -19753229177… |
| 0xfcf0 | OPENSSL_cpuid_setup | bsim (strong) | sim 1.0 |
| 0xfe90 | ossl_ctype_check | fid-ghidra (full+specific) | -38693111179… |
| 0xfe90 | ossl_ctype_check | bsim (strong) | sim 1.0 |
| 0xfec0 | ossl_ascii_isdigit, ossl_isdigit | fid-ghidra (full+specific) | 762638006599… |
| 0xfec0 | ossl_ascii_isdigit, ossl_isdigit, ossl_islower, ossl_isupper | bsim (ambiguous) | sim 1.0 |
| 0xfee0 | ossl_isupper | fid-ghidra (full+specific) | 762638006599… |
| 0xfee0 | ossl_ascii_isdigit, ossl_isdigit, ossl_islower, ossl_isupper | bsim (ambiguous) | sim 1.0 |
| 0xff00 | ossl_islower | fid-ghidra (full+specific) | 762638006599… |
| 0xff00 | ossl_ascii_isdigit, ossl_isdigit, ossl_islower, ossl_isupper | bsim (ambiguous) | sim 1.0 |
| 0xff20 | ossl_tolower | fid-ghidra (full+specific) | -72457325042… |
| 0xff20 | ossl_tolower, ossl_toupper | bsim (ambiguous) | sim 1.0 |
| 0xff40 | ossl_toupper | fid-ghidra (full+specific) | -72457325042… |
| 0xff40 | ossl_tolower, ossl_toupper | bsim (ambiguous) | sim 1.0 |
| 0xff60 | ossl_ascii_isdigit | fid-kuna (full-hash rename) | sub_ff60 → ossl_ascii_isdigit |
| 0xff60 | ossl_ascii_isdigit, ossl_isdigit | fid-ghidra (full+specific) | 762638006599… |
| 0xff60 | ossl_ascii_isdigit, ossl_isdigit, ossl_islower, ossl_isupper | bsim (ambiguous) | sim 1.0 |

## Disagreements

| address | kind | confidence | favoured |
|---|---|---|---|
| 0x1000 | rendering | low | unresolved |
| 0x1020 | rendering | low | unresolved |
| 0x10b0 | rendering | low | unresolved |
| 0x10c0 | rendering | low | unresolved |
| 0x10d0 | rendering | low | unresolved |
| 0x10e0 | rendering | low | unresolved |
| 0x10f0 | rendering | low | unresolved |
| 0x1100 | rendering | low | unresolved |
| 0x1110 | rendering | low | unresolved |
| 0x1120 | rendering | low | unresolved |
| 0x1130 | type_signature | medium | unresolved |
| 0x1140 | control_structure | medium | unresolved |
| 0x1170 | rendering | low | unresolved |
| 0x11a0 | engine_gap | high | ghidra |
| 0x11e0 | rendering | low | unresolved |
| 0x1220 | call_set | medium | unresolved |
| 0x1229 | rendering | low | unresolved |
| 0x125c | rendering | low | unresolved |
| 0x127e | rendering | low | unresolved |
| 0x12b6 | rendering | low | unresolved |
| 0x12e7 | call_set | medium | unresolved |
| 0x14b0 | control_structure | medium | unresolved |
| 0x14de | rendering | low | unresolved |
| 0x1528 | rendering | low | unresolved |
| 0x154d | type_signature | medium | unresolved |
| 0x1559 | rendering | low | unresolved |
| 0x18a8 | type_signature | medium | unresolved |
| 0x18b4 | rendering | low | unresolved |
| 0x18db | type_signature | medium | unresolved |
| 0x18e5 | rendering | low | unresolved |
| 0x18f6 | type_signature | medium | unresolved |
| 0x1900 | rendering | low | unresolved |
| 0x1915 | call_set | medium | unresolved |
| 0x1a3e | type_signature | medium | unresolved |
| 0x1a56 | rendering | low | unresolved |
| 0x1a78 | call_set | medium | unresolved |
| 0x1c2b | type_signature | medium | unresolved |
| 0x1c47 | rendering | low | unresolved |
| 0x1cb5 | rendering | low | unresolved |
| 0x1d3b | rendering | low | unresolved |
| 0x1d69 | control_structure | medium | unresolved |
| 0x1f5d | rendering | low | unresolved |
| 0x1fe0 | rendering | low | unresolved |
| 0x227c | rendering | low | unresolved |
| 0x22f2 | control_structure | medium | unresolved |
| 0x28f1 | control_structure | medium | unresolved |
| 0x2d63 | rendering | low | unresolved |
| 0x3246 | rendering | low | unresolved |
| 0x348e | rendering | low | unresolved |
| 0x350b | rendering | low | unresolved |
| 0x35c8 | rendering | low | unresolved |
| 0x36b6 | rendering | low | unresolved |
| 0x36ea | rendering | low | unresolved |
| 0x3733 | rendering | low | unresolved |
| 0x37db | rendering | low | unresolved |
| 0x382e | rendering | low | unresolved |
| 0x398a | rendering | low | unresolved |
| 0x4a99 | rendering | low | unresolved |
| 0x4c48 | rendering | low | unresolved |
| 0x4cdf | rendering | low | unresolved |
| 0x4fb7 | type_signature | medium | unresolved |
| 0x4fe1 | rendering | low | unresolved |
| 0x51f0 | rendering | low | unresolved |
| 0x5241 | rendering | low | unresolved |
| 0x52b0 | rendering | low | unresolved |
| 0x53c1 | rendering | low | unresolved |
| 0x5475 | rendering | low | unresolved |
| 0x54b0 | rendering | low | unresolved |
| 0x5554 | rendering | low | unresolved |
| 0x5639 | type_signature | medium | unresolved |
| 0x5655 | rendering | low | unresolved |
| 0x56d4 | call_set | medium | unresolved |
| 0x7463 | rendering | low | unresolved |
| 0x74b2 | rendering | low | unresolved |
| 0x752f | rendering | low | unresolved |
| 0x75e9 | rendering | low | unresolved |
| 0x7624 | call_set | medium | unresolved |
| 0x7792 | rendering | low | unresolved |
| 0x77c5 | rendering | low | unresolved |
| 0x7a42 | rendering | low | unresolved |
| 0x7a6f | rendering | low | unresolved |
| 0x7aa8 | rendering | low | unresolved |
| 0x7afe | rendering | low | unresolved |
| 0x7b33 | call_set | medium | unresolved |
| 0x8133 | rendering | low | unresolved |
| 0x81b5 | control_structure | medium | unresolved |
| 0x8228 | rendering | low | unresolved |
| 0x82b0 | rendering | low | unresolved |
| 0x83a0 | call_set | medium | unresolved |
| 0x88a2 | rendering | low | unresolved |
| 0x898d | rendering | low | unresolved |
| 0x8f89 | rendering | low | unresolved |
| 0x942e | rendering | low | unresolved |
| 0x949f | rendering | low | unresolved |
| 0x95c0 | rendering | low | unresolved |
| 0x95ca | rendering | low | unresolved |
| 0x96a7 | rendering | low | unresolved |
| 0x9c07 | rendering | low | unresolved |
| 0x9ce9 | type_signature | medium | unresolved |
| 0x9cff | type_signature | medium | unresolved |
| 0x9d26 | rendering | low | unresolved |
| 0x9d3d | rendering | low | unresolved |
| 0x9d52 | rendering | low | unresolved |
| 0x9e41 | control_structure | medium | unresolved |
| 0xa259 | type_signature | medium | unresolved |
| 0xa265 | type_signature | medium | unresolved |
| 0xa26f | type_signature | medium | unresolved |
| 0xa279 | rendering | low | unresolved |
| 0xa840 | rendering | low | unresolved |
| 0xa890 | rendering | low | unresolved |
| 0xa8e0 | control_structure | medium | unresolved |
| 0xaae0 | type_signature | medium | unresolved |
| 0xaaf0 | rendering | low | unresolved |
| 0xab00 | type_signature | medium | unresolved |
| 0xad00 | type_signature | medium | unresolved |
| 0xad10 | rendering | low | unresolved |
| 0xad30 | rendering | low | unresolved |
| 0xad40 | control_structure | medium | unresolved |
| 0xaf30 | rendering | low | unresolved |
| 0xafa0 | rendering | low | unresolved |
| 0xb000 | rendering | low | unresolved |
| 0xb070 | rendering | low | unresolved |
| 0xb0d0 | rendering | low | unresolved |
| 0xb140 | control_structure | medium | unresolved |
| 0xb1b0 | control_structure | medium | unresolved |
| 0xb240 | rendering | low | unresolved |
| 0xc700 | rendering | low | unresolved |
| 0xca40 | rendering | low | unresolved |
| 0xd900 | rendering | low | unresolved |
| 0xe800 | rendering | low | unresolved |
| 0xfc30 | call_set | high | unresolved |
| 0xfcf0 | control_structure | medium | unresolved |
| 0xfe90 | rendering | low | unresolved |
| 0xfec0 | rendering | low | unresolved |
| 0xfee0 | rendering | low | unresolved |
| 0xff00 | rendering | low | unresolved |
| 0xff20 | rendering | low | unresolved |
| 0xff40 | rendering | low | unresolved |
| 0xff60 | rendering | low | unresolved |
| 0x18000 | engine_gap | high | ghidra |
| 0x18008 | engine_gap | high | ghidra |
| 0x18010 | engine_gap | high | ghidra |
| 0x18018 | engine_gap | high | ghidra |
| 0x18020 | engine_gap | high | ghidra |
| 0x18028 | engine_gap | high | ghidra |
| 0x18030 | engine_gap | high | ghidra |
| 0x18038 | engine_gap | high | ghidra |
| 0x18040 | engine_gap | high | ghidra |
| 0x18048 | engine_gap | high | ghidra |
| 0x18050 | engine_gap | high | ghidra |
| 0x18058 | engine_gap | high | ghidra |
| 0x18060 | engine_gap | high | ghidra |

## Limitations

- BSim similarity is exact cosine computed locally over the lshcosine feature vectors Ghidra's BSim generator emits (the same similarity family the medium_64 template names), but without BSim's LSH bucketing/index and significance weighting - scores rank like BSim's, they are not BSim-server values.
- The Ghidra Function ID index is stored as JSON of FidService hash pairs rather than a binary .fidb; the hashes are Ghidra's own, the container is ours (inspectable, diffable).
- Identification coverage is exactly the corpus in corpus/manifest.json - a mini-harvest, not a universal library database.
- Disagreement grading is deterministic and feature-based; a 'favoured' engine is a heuristic verdict with its rule stated, not ground truth.
- BSim claims require >=4 vector features and >=0.9 cosine; corpus functions whose vectors tie exactly are reported as one ambiguous record with all tied names, never resolved arbitrarily. BSim vectors provably cannot separate some siblings (the SHA-1/SHA-256/MD5 *_Update functions are vector-identical) - there, Function ID evidence is the discriminating channel.
- x86-64 ELF only in this slice.
- Input asymmetry, measured: Kuna's pseudocode is captured AFTER its Function ID pass has renamed library functions, while Ghidra's pseudocode is captured from its unidentified analysis (the corpus FID index is JSON, not a .fidb Ghidra's analyzer could consume). Ghidra therefore renders more placeholder names and conservative types than it would with FID applied internally; some rendering divergence is attributable to this asymmetry rather than to the decompiler cores.
