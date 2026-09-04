/* test_cons.c -- 100% AI-generated harness for the assembly bitcoin_cons.asm
 * cons_verify: full block consensus check (PoW + merkle + coinbase + bounds).
 * The valid block and its merkle root come from validation/block_oracle.py.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern int  cons_verify(const void* block, unsigned long len, void* txid_scratch, unsigned long cap);
extern void sha256d(unsigned char out[32], const void *msg, long len);
/* VAL-6: merkle_root now RETURNS the mutation flag (CVE-2012-2459) in eax.
 * The .asm never had a declared return type here; callers that ignore it are
 * unaffected (SysV: eax is caller-saved scratch either way). */
extern long merkle_root(unsigned char out[32], unsigned char hashes[], unsigned long n);
extern int  pow_check(const unsigned char hdr[80]);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int tx_parse(unsigned long long info[8], const void* tx, unsigned long long txlen);

/* ---- Python-oracle-verified block builder (mirrors block_oracle.py) ---- */
static void put_u32(unsigned char* p, unsigned v){ p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24; }
static void put_u64(unsigned char* p, unsigned long long v){ for(int i=0;i<8;i++){p[i]=v&0xff;v>>=8;} }

static unsigned long mk_coinbase(unsigned char* out, unsigned char extra){
    unsigned char* p=out; int o=0;
    put_u32(p+0,1); o+=4;                 /* version */
    p[o]=1; o+=1;                          /* n_in=1 */
    memset(p+o,0,32); o+=32;               /* prevout null */
    put_u32(p+o,0xffffffff); o+=4;         /* index */
    /* scriptSig: 0x51 then extra then four zero bytes (exactly like the oracle) */
    unsigned char scr[8]; int sl=0; scr[sl++]=0x51; scr[sl++]=extra;
    scr[sl++]=0; scr[sl++]=0; scr[sl++]=0; scr[sl++]=0;
    p[o]=sl; o+=1; memcpy(p+o,scr,sl); o+=sl;
    put_u32(p+o,0xffffffff); o+=4;         /* seq */
    p[o]=1; o+=1;                          /* n_out=1 */
    put_u64(p+o, 50ULL*100000000ULL); o+=8;
    p[o]=1; o+=1;                          /* scriptPubKey len */
    p[o]=0x51; o+=1;                       /* OP_TRUE */
    put_u32(p+o,0); o+=4;                  /* locktime */
    return o;
}
static unsigned long mk_normal(unsigned char* out, const unsigned char* prev_txid){
    unsigned char* p=out; int o=0;
    put_u32(p+0,1); o+=4;
    p[o]=1; o+=1;                          /* n_in=1 */
    memcpy(p+o, prev_txid, 32); o+=32;     /* prevout = coinbase txid */
    put_u32(p+o,0); o+=4;                  /* index */
    p[o]=1; o+=1;  p[o]=0x51; o+=1;        /* scriptSig: push 1 */
    put_u32(p+o,0xffffffff); o+=4;         /* seq */
    p[o]=1; o+=1;                          /* n_out=1 */
    put_u64(p+o, 49ULL*100000000ULL); o+=8;
    p[o]=1; o+=1;  p[o]=0x51; o+=1;
    put_u32(p+o,0); o+=4;                  /* locktime */
    return o;
}

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }

/* expected merkle root from the oracle for this 2-tx construction */
static const unsigned char MR[32] = {
    0xbc,0x88,0xee,0xc6,0x33,0x6c,0x88,0xb8,0xe8,0x92,0xfc,0x55,0xf5,0xef,0x7f,0x17,
    0x80,0xac,0x67,0x48,0xc2,0xd2,0x35,0x17,0xd7,0x52,0x77,0x44,0x00,0xf3,0xd5,0xc9};

int main(void){
    unsigned char cb[128], nb[128];
    unsigned long cbl = mk_coinbase(cb, 0x11);
    unsigned char cbid[32]; sha256d(cbid, cb, cbl);
    unsigned long nbl = mk_normal(nb, cbid);
    /* build the block: header(80) + cb + n */
    unsigned char hdr[80];
    memset(hdr,0,80);
    put_u32(hdr,1);                    /* version */
    memcpy(hdr+36, MR, 32);            /* merkle root (from full 2-tx tree) */
    put_u32(hdr+68, 1700000000);
    put_u32(hdr+72, 0x207fffff);       /* easy bits */
    put_u32(hdr+76, 0);                /* nonce 0 valid under easy target */
    unsigned char block[2048];
    memcpy(block, hdr, 80);
    unsigned long o=80;
    block[o]=2; o+=1;            /* tx-count CompactSize: 2 transactions (wire field) */
    memcpy(block+o, cb, cbl); o+=cbl;
    memcpy(block+o, nb, nbl); o+=nbl;
    unsigned long blen = o;
    printf("block len = %lu (oracle said 209)\n", blen);
    static unsigned char scratch[64*32];

    /* valid block accepted */
    cki("cons_verify valid block", cons_verify(block, blen, scratch, 64), 1);

    /* tampered merkle root -> reject */
    unsigned char bad_merk[2048]; memcpy(bad_merk, block, blen); bad_merk[36]^=0x01;
    cki("cons_verify bad merkle rejected", cons_verify(bad_merk, blen, scratch, 64), 0);

    /* trailing garbage -> reject */
    unsigned char bad_trail[2049]; memcpy(bad_trail, block, blen); bad_trail[blen]=0xff;
    cki("cons_verify trailing garbage rejected", cons_verify(bad_trail, blen+1, scratch, 64), 0);

    /* truncated block -> reject */
    cki("cons_verify truncated rejected", cons_verify(block, 60, scratch, 64), 0);

    /* non-coinbase-first: make tx[0] have n_in=0 (not a coinbase) -> reject */
    unsigned char bad_cb[2048]; memcpy(bad_cb, block, blen);
    /* wire-valid block: hdr(80) + tx-count(1@80) + tx0 starts at 81.
     * tx0 version(4)=81..84, so n_in is at byte 85. */
    bad_cb[85] = 0;                    /* n_in=0 for first tx */
    /* that changes tx boundaries/txid... cons_verify requires n_in==1 for tx0 -> reject */
    cki("cons_verify non-coinbase-first rejected", cons_verify(bad_cb, blen, scratch, 64), 0);

    /* capacity too small (cap=1, but 2 txs) -> reject */
    cki("cons_verify cap too small rejected", cons_verify(block, blen, scratch, 1), 0);

    /* ---- VAL-6 (audit 2026-09-03): CVE-2012-2459 merkle mutation. ----
     * A 3-leaf tree [A,B,C] folds C with a duplicate of itself: root =
     * H(H(A,B), H(C,C)). A 4-leaf list [A,B,C,C] folds (C,C) as a REAL
     * sibling pair and gets the SAME root -- so a 4-tx block [cb,n1,n2,n2]
     * shares both the merkle root and the block hash of the genuine 3-tx
     * block [cb,n1,n2]. Core computes BlockMerkleRoot(block,&mutated) and
     * rejects the mutated variant with bad-txns-duplicate WITHOUT
     * invalidating the header, so the genuine block can still arrive.
     * Our store paths store on cons_verify success, so before this fix the
     * mutated block was ARCHIVED under the real hash and permanently
     * displaced the genuine one. */
    {
        unsigned char cb2[128], n1[128], n2[128];
        unsigned long cbl2 = mk_coinbase(cb2, 0x11);
        unsigned char cbid2[32]; sha256d(cbid2, cb2, cbl2);
        unsigned long n1l = mk_normal(n1, cbid2);
        unsigned char n1id[32]; sha256d(n1id, n1, n1l);
        unsigned long n2l = mk_normal(n2, n1id);
        unsigned char n2id[32]; sha256d(n2id, n2, n2l);

        /* merkle root of the genuine 3-leaf tree (via the function itself is
         * circular for ACCEPTANCE, so pin the premise non-circularly first:
         * root == H(H(CB,N1), H(N2,N2)) computed with sha256d directly). */
        unsigned char AB[64], CC[64], ABC_root[32];
        memcpy(AB, cbid2, 32); memcpy(AB+32, n1id, 32);
        sha256d(AB, AB, 64);                       /* P = H(CB||N1) */
        memcpy(CC, n2id, 32); memcpy(CC+32, n2id, 32);
        sha256d(CC, CC, 64);                       /* Q = H(N2||N2) */
        memcpy(AB+32, CC, 32);
        sha256d(ABC_root, AB, 64);                 /* root = H(P||Q) */

        /* header with that root; mine a nonce under 0x207fffff */
        unsigned char h2[80]; memset(h2,0,80);
        put_u32(h2,1);
        memcpy(h2+36, ABC_root, 32);
        put_u32(h2+68, 1700000001);
        put_u32(h2+72, 0x207fffff);
        unsigned long nn = 0;
        while (!pow_check(h2) && nn < 200000000UL){ put_u32(h2+76,(unsigned)nn); nn++; }
        cki("mutation fixture: mined a PoW-valid header", pow_check(h2), 1);

        /* genuine 3-tx block */
        static unsigned char blk3[4096], blk4[4096];
        memcpy(blk3, h2, 80);
        unsigned long o3 = 80;
        blk3[o3++] = 3;
        memcpy(blk3+o3, cb2, cbl2); o3 += cbl2;
        memcpy(blk3+o3, n1, n1l);   o3 += n1l;
        memcpy(blk3+o3, n2, n2l);   o3 += n2l;
        static unsigned char scratch2[64*32];
        cki("cons_verify accepts the genuine 3-tx block",
            cons_verify(blk3, o3, scratch2, 64), 1);

        /* mutated 4-tx variant: SAME header (same hash!), tx list + one
         * duplicate of the tail tx. Its merkle root equals the 3-tx root --
         * verify that premise first (the CVE), then require the reject. */
        memcpy(blk4, h2, 80);
        unsigned long o4 = 80;
        blk4[o4++] = 4;
        memcpy(blk4+o4, cb2, cbl2); o4 += cbl2;
        memcpy(blk4+o4, n1, n1l);   o4 += n1l;
        memcpy(blk4+o4, n2, n2l);   o4 += n2l;
        memcpy(blk4+o4, n2, n2l);   o4 += n2l;
        unsigned char leaves[4*32], root4[32];
        memcpy(leaves+0, cbid2, 32); memcpy(leaves+32, n1id, 32);
        memcpy(leaves+64, n2id, 32); memcpy(leaves+96, n2id, 32);
        merkle_root(root4, leaves, 4);
        cki("CVE premise: 4-leaf mutated tree has the SAME root",
            memcmp(root4, ABC_root, 32)==0, 1);
        cki("cons_verify REJECTS the mutated 4-tx block (bad-txns-duplicate)",
            cons_verify(blk4, o4, scratch2, 64), 0);

        /* the mutation flag itself: [A,B,A,B] -> level-1 identical pair */
        unsigned char L[4*32], R[32];
        memset(L+0, 0x11, 32); memset(L+32, 0x22, 32);
        memcpy(L+64, L+0, 32);   memcpy(L+96, L+32, 32);
        long mut = (long)merkle_root(R, L, 4);
        cki("merkle_root flags [A,B,A,B] as mutated", mut, 1);
        unsigned char L2[2*32];
        memset(L2, 0x11, 32); memset(L2+32, 0x22, 32);
        mut = (long)merkle_root(R, L2, 2);
        cki("merkle_root does NOT flag [A,B]", mut, 0);
        unsigned char L3[3*32];
        memset(L3, 0x11, 32); memset(L3+32, 0x22, 32); memset(L3+64, 0x33, 32);
        mut = (long)merkle_root(R, L3, 3);
        cki("merkle_root does NOT flag the legitimate odd tail [A,B,C]", mut, 0);
    }

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
