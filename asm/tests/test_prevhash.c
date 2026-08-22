/* test_prevhash.c -- 100% AI-generated harness for Stage A reorg/fork-choice
 * primitive #3: the prevhash validation gate
 * (store_get_tip_hash/store_validates_prevhash in bitcoin_store.asm).
 * Pure validation functions -- NOT wired into any append path (Stage B).
 * Runs in a throwaway temp dir.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_tmpdir.h"

extern int store_init(void* st);
extern int store_append(void* st, const void* hash, const void* raw, unsigned long long len);
extern int store_get_tip_hash(void* st, unsigned char out_hash[32]);
extern int store_validates_prevhash(void* st, const unsigned char header[80]);

/* state struct layout must mirror bitcoin_store.asm (see tests/test_store.c) */
struct St {
    unsigned long long cur_blk_fd, idx_fd, idx_len;
    int tip_height, cur_file_no, cur_file_pos, magic, pad, pad2, prune_height;
};

static int failures = 0;
static void cki(const char* l, long g, long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }

static void make_header(unsigned char hdr[80], const unsigned char prevhash[32]){
    memset(hdr, 0, 80);
    hdr[0]=0x01; /* version, arbitrary */
    memcpy(hdr+4, prevhash, 32);
    /* merkle root (36..67), time/bits/nonce (68..79) left as zero -- this
     * gate only inspects bytes [4..35], so the rest is don't-care here. */
}

int main(void){
    tt_isolate();
    /* ---- edge case: empty store ---- */
    {
        struct St st; memset(&st, 0, sizeof st);
        cki("store_init (empty)", store_init(&st), 1);
        unsigned char out[32];
        cki("get_tip_hash on empty store", store_get_tip_hash(&st, out), -1);
        unsigned char hdr[80]; unsigned char zero[32]={0};
        make_header(hdr, zero);
        cki("validates_prevhash on empty store", store_validates_prevhash(&st, hdr), -1);
        unlink("index.dat");
    }

    /* ---- edge case: single-block store (genesis only) ---- */
    {
        struct St st; memset(&st, 0, sizeof st);
        cki("store_init (single block)", store_init(&st), 1);
        unsigned char h0[32]; for (int i=0;i<32;i++) h0[i]=(unsigned char)(0x11*(i+1));
        unsigned char raw[16]; memset(raw, 0xAB, sizeof raw);
        cki("append genesis", store_append(&st, h0, raw, sizeof raw), 0);

        unsigned char got[32];
        cki("get_tip_hash after 1 block", store_get_tip_hash(&st, got), 1);
        cki("get_tip_hash matches h0", memcmp(got, h0, 32)==0, 1);

        unsigned char hdr_match[80]; make_header(hdr_match, h0);
        cki("validates_prevhash matching genesis tip", store_validates_prevhash(&st, hdr_match), 1);

        unsigned char wrong[32]; memset(wrong, 0x99, 32);
        unsigned char hdr_mismatch[80]; make_header(hdr_mismatch, wrong);
        cki("validates_prevhash mismatching genesis tip", store_validates_prevhash(&st, hdr_mismatch), 0);

        unlink("blk00000.dat"); unlink("index.dat");
    }

    /* ---- multi-block store: gate always checks against the CURRENT tip,
     * not some earlier block ---- */
    {
        struct St st; memset(&st, 0, sizeof st);
        cki("store_init (multi block)", store_init(&st), 1);
        unsigned char h0[32], h1[32], h2[32];
        for (int i=0;i<32;i++){ h0[i]=(unsigned char)(0x01+i); h1[i]=(unsigned char)(0x41+i); h2[i]=(unsigned char)(0x81+i); }
        unsigned char raw[10]; memset(raw, 0xCD, sizeof raw);
        cki("append h0", store_append(&st, h0, raw, sizeof raw), 0);
        cki("append h1", store_append(&st, h1, raw, sizeof raw), 1);
        cki("append h2", store_append(&st, h2, raw, sizeof raw), 2);

        unsigned char got[32];
        cki("get_tip_hash == h2", store_get_tip_hash(&st, got), 1);
        cki("tip hash content == h2", memcmp(got, h2, 32)==0, 1);

        unsigned char hdr_h2[80]; make_header(hdr_h2, h2);
        cki("validates against current tip (h2) matches", store_validates_prevhash(&st, hdr_h2), 1);

        unsigned char hdr_h1[80]; make_header(hdr_h1, h1);
        cki("validates against stale tip (h1) rejected", store_validates_prevhash(&st, hdr_h1), 0);

        unsigned char hdr_h0[80]; make_header(hdr_h0, h0);
        cki("validates against genesis (h0) rejected once tip has advanced", store_validates_prevhash(&st, hdr_h0), 0);

        unlink("blk00000.dat"); unlink("index.dat");
    }

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
