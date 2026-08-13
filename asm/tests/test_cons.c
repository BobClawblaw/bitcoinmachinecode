/* test_cons.c -- 100% AI-generated harness for the assembly bitcoin_cons.asm
 * cons_verify: full block consensus check (PoW + merkle + coinbase + bounds).
 * The valid block and its merkle root come from validation/block_oracle.py.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern int  cons_verify(const void* block, unsigned long len, void* txid_scratch, unsigned long cap);
extern void sha256d(unsigned char out[32], const void *msg, long len);
extern void merkle_root(unsigned char out[32], unsigned char hashes[], unsigned long n);
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

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
