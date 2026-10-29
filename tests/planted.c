/*
 * planted.c - ground-truth fixture for the two-engines slice.
 *
 * Every custom function below has semantics known exactly, because this
 * source is the truth. The library calls (zlib, OpenSSL, libc) are real:
 * the binary is linked statically so the library code is physically
 * present in the image, then stripped - identification must recover the
 * library function names from fingerprints and similarity alone.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>
#include <openssl/sha.h>

/* The planted functions must survive as real functions in the image:
 * no inlining, no cloning away. */
#define PLANTED __attribute__((noinline))

/* Planted custom function 1: XOR-fold checksum with a rotate.
 * truth: for each byte b of buf: acc ^= b; acc = rotl32(acc, 5); finally
 * acc ^= len * 0x9E3779B9. */
PLANTED static unsigned int planted_xorfold(const unsigned char *buf, unsigned long len)
{
    unsigned int acc = 0x811C9DC5u;
    unsigned long i;
    for ( i = 0; i < len; ++i ) {
        acc ^= buf[i];
        acc = (acc << 5) | (acc >> 27);
    }
    return acc ^ (unsigned int)(len * 0x9E3779B9ul);
}

/* Planted custom function 2 (divergence bait): high 64 bits of the full
 * 128-bit product of two 64-bit values. Decompilers historically render
 * the 128-bit intermediate very differently (explicit __int128, SUBPIECE
 * constructs, or undefined1[16] temporaries). */
PLANTED static unsigned long planted_mulhi128(unsigned long a, unsigned long b)
{
    unsigned __int128 full = (unsigned __int128)a * (unsigned __int128)b;
    return (unsigned long)(full >> 64);
}

/* Planted custom function 3 (divergence bait): dispatch through a small
 * function-pointer table selected by a switch with deliberate fallthrough.
 * truth: op 0 -> +1, op 1 -> +2, op 2 falls into op 3's handler (+4),
 * op 3 -> +4, anything else -> identity. */
static int op_add1(int x) { return x + 1; }
static int op_add2(int x) { return x + 2; }
static int op_add4(int x) { return x + 4; }
static int op_id(int x)   { return x; }

typedef int (*op_fn)(int);
static op_fn const op_table[4] = { op_add1, op_add2, op_add4, op_add4 };

PLANTED static int planted_dispatch(int op, int x)
{
    int sel;
    switch ( op ) {
        case 0: sel = 0; break;
        case 1: sel = 1; break;
        case 2: /* fallthrough intended: shares op 3's handler */
        case 3: sel = 3; break;
        default: return op_id(x);
    }
    return op_table[sel](x);
}

/* Planted custom function 4 (divergence bait): loop with an unsigned
 * counter compared against a signed bound - signedness renderings differ
 * between decompilers. truth: sums buf[0..n) but stops early, returning
 * the partial sum, if the running sum exceeds 1000000. */
PLANTED static unsigned int planted_sumcap(const unsigned char *buf, int n)
{
    unsigned int sum = 0;
    unsigned int i;
    for ( i = 0; i < (unsigned int)n; ++i ) {
        sum += buf[i];
        if ( sum > 1000000u )
            return sum;
    }
    return sum;
}

int main(void)
{
    const char *msg = "two engines, one witness";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    unsigned char packed[128];
    unsigned char back[128];
    uLong packed_len = sizeof(packed);
    uLong back_len = sizeof(back);
    int dispatch_result;

    /* Real zlib: compress + uncompress + crc32. */
    if ( compress(packed, &packed_len, (const Bytef *)msg, strlen(msg) + 1) != Z_OK )
        return 2;
    if ( uncompress(back, &back_len, packed, packed_len) != Z_OK )
        return 3;
    if ( strcmp((const char *)back, msg) != 0 )
        return 4;

    /* Real OpenSSL: SHA-256 over the message (low-level API: the one-shot
     * SHA256() in this OpenSSL version routes through the whole EVP /
     * provider stack, which is not what this fixture is about). */
    {
        SHA256_CTX sha_ctx;
        SHA256_Init(&sha_ctx);
        SHA256_Update(&sha_ctx, (const unsigned char *)msg, strlen(msg));
        SHA256_Final(digest, &sha_ctx);
    }

    dispatch_result = planted_dispatch(2, 40);   /* truth: 44 (fallthrough) */

    printf("crc=%08lx xorfold=%08x mulhi=%016lx sumcap=%u dispatch=%d sha0=%02x%02x\n",
           crc32(crc32(0L, Z_NULL, 0), (const Bytef *)msg, strlen(msg)),
           planted_xorfold((const unsigned char *)msg, strlen(msg)),
           planted_mulhi128(0xFFFFFFFFFFFFFFFFul, 0x10ul),
           planted_sumcap((const unsigned char *)msg, (int)strlen(msg)),
           dispatch_result,
           digest[0], digest[1]);
    return 0;
}
