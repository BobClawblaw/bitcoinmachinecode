/* tests/test_block_strip.c -- block_strip_witness (daemon/block_strip.c):
 * the stripped serialization served for a bare MSG_BLOCK request.
 *
 * Proof against a REAL segwit block (fixture blk_700038.bin, mainnet
 * 700038): the stripped output length must equal Core's strippedsize
 * (20118, read from the oracle), the header must be byte-identical, and --
 * the load-bearing check -- the merkle root recomputed over the stripped
 * transactions' txids must equal the block header's committed merkle root.
 * That last one proves the CONTENT is right, not merely the length: the
 * merkle tree commits to non-witness txids, so a correct strip reproduces
 * it exactly. Plus: stripping an already-stripped block is a no-op.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char u8;
extern long block_strip_witness(const u8* blk, long blen, u8* out, long cap);
extern void sha256d(u8 out[32], const void* msg, long long len);

#define STRIPPEDSIZE_700038 20118

static int fails = 0;
static void ck(const char* l, int cond){
    if (cond) printf("  ok  %s\n", l);
    else { printf("  FAIL %s\n", l); fails++; }
}

static unsigned long rd_vi(const u8* p, const u8* end, unsigned* c){
    *c = 0; if (p >= end) return 0;
    if (p[0] < 0xfd){ *c = 1; return p[0]; }
    if (p[0] == 0xfd){ *c = 3; return (unsigned long)p[1] | ((unsigned long)p[2]<<8); }
    if (p[0] == 0xfe){ *c = 5; return (unsigned long)p[1]|((unsigned long)p[2]<<8)|((unsigned long)p[3]<<16)|((unsigned long)p[4]<<24); }
    *c = 9; unsigned long v=0; for(int i=0;i<8;i++) v|=(unsigned long)p[1+i]<<(8*i); return v;
}

/* merkle root over the stripped block's per-tx double-sha256 (txids) */
static void merkle_of_stripped(const u8* blk, long blen, u8 out[32]){
    const u8* end = blk + blen;
    const u8* p = blk + 80;
    unsigned cc; unsigned long ntx = rd_vi(p, end, &cc); p += cc;
    static u8 ids[16000][32]; unsigned long n = 0;
    for (unsigned long t = 0; t < ntx; t++){
        const u8* s = p;
        p += 4;                                   /* version */
        unsigned long nin = rd_vi(p, end, &cc); p += cc;
        for (unsigned long i = 0; i < nin; i++){
            p += 36; unsigned long sl = rd_vi(p, end, &cc); p += cc + sl + 4;
        }
        unsigned long nout = rd_vi(p, end, &cc); p += cc;
        for (unsigned long i = 0; i < nout; i++){
            p += 8; unsigned long sl = rd_vi(p, end, &cc); p += cc + sl;
        }
        p += 4;                                   /* locktime */
        sha256d(ids[n++], s, (long long)(p - s)); /* stripped tx == txid preimage */
    }
    /* fold the merkle tree */
    while (n > 1){
        unsigned long m = 0;
        for (unsigned long i = 0; i < n; i += 2){
            u8 pair[64];
            memcpy(pair, ids[i], 32);
            memcpy(pair + 32, ids[i + 1 < n ? i + 1 : i], 32);   /* dup last if odd */
            sha256d(ids[m++], pair, 64);
        }
        n = m;
    }
    memcpy(out, ids[0], 32);
}

int main(void){
    FILE* f = fopen("tests/fixtures/blk_700038.bin", "rb");
    if (!f){ fprintf(stderr, "fixture missing\n"); return 2; }
    static u8 blk[64<<10]; long blen = (long)fread(blk, 1, sizeof blk, f); fclose(f);
    ck("fixture loaded", blen > 80);

    static u8 out[64<<10];
    long sl = block_strip_witness(blk, blen, out, sizeof out);
    ck("strip succeeded", sl > 0);
    ck("stripped length == Core strippedsize (20118)", sl == STRIPPEDSIZE_700038);
    ck("header byte-identical", sl >= 80 && memcmp(out, blk, 80) == 0);
    ck("stripped is shorter than the full block", sl < blen);

    /* the content proof: merkle root of the stripped txs == committed root */
    u8 root[32];
    merkle_of_stripped(out, sl, root);
    ck("merkle root of the stripped block == header's committed root",
       memcmp(root, blk + 36, 32) == 0);

    /* idempotence: stripping the stripped block changes nothing */
    static u8 out2[64<<10];
    long sl2 = block_strip_witness(out, sl, out2, sizeof out2);
    ck("re-strip is a no-op", sl2 == sl && memcmp(out2, out, sl) == 0);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
