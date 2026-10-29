#!/usr/bin/env bash
# Build the planted fixture binaries (see GROUND_TRUTH.md).
# Primary target: dynamic libc, static zlib (local -O1 build) + OpenSSL
# subset. Stress target: fully static (used for the FID-at-scale check).
set -euo pipefail
cd "$(dirname "$0")"
SLICE="$(cd .. && pwd)"
Z="-I$SLICE/harvest/zlib-1.3.1"
ZLIB_O1="$SLICE/corpus/builds/zlib-1.3.1-gcc13-O1/libz.a"
CRYPTO_SUBSET="$SLICE/corpus/builds/openssl-distro-subset/subset.a"

gcc -O1 -Wno-deprecated-declarations $Z -o planted planted.c \
  -Wl,-Bstatic "$ZLIB_O1" "$CRYPTO_SUBSET" -Wl,-Bdynamic -ldl -pthread
cp planted planted.stripped && strip --strip-all planted.stripped

gcc -O2 -static -Wno-deprecated-declarations $Z -o planted.static planted.c \
  "$ZLIB_O1" -lcrypto -ldl -pthread
cp planted.static planted.static.stripped && strip --strip-all planted.static.stripped
echo "built: planted planted.stripped planted.static planted.static.stripped"
./planted.stripped
./planted.static.stripped
