/* Regression: block 482566 tx 1499 (txid bc5f2956...c359), the live replay's
 * 2026-08-22 "p2wpkh signature invalid" reject. Root cause: in
 * tx_verify_block_connect_all's Phase 1, sv_classify_segwit ran on the raw
 * utxo_lsm_get spk pointer and the returned witness-program pointer was
 * STORED (in->wprog) for Phase 2 -- but that pointer is only valid until the
 * next utxo_lsm_get call (the same documented contract that makes Phase 1
 * copy the spk itself into g_spk_pool). Every later resolve in the block
 * overwrote the buffer, so native-segwit inputs verified against another
 * entry's bytes: hash160(pubkey) mismatched a garbage program and the block
 * was rejected. P2SH-wrapped segwit never hit it (its program points into
 * the tx's own scriptSig bytes), which is why hundreds of nested-segwit
 * blocks replayed fine before the first native P2WPKH spend resolved from
 * the store's transient-buffer path blew up.
 *
 * This test drives the REAL block through tx_verify_block_connect_all with a
 * utxo_lsm_get that is maximally adversarial-but-legal: every call returns
 * its spk through ONE reused static buffer. Old code fails ("p2wpkh
 * signature invalid" on tx 1499); fixed code (wprog stored as an offset into
 * the pooled spk copy) accepts the block. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

typedef struct { const u8* ptr; u64 len; u8 txid[32]; u32 pn_in; } block_tx_t;
extern int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                       const u8 block_hash32[32], void* lst, void* u, void* bx,
                                       u64* fail_tx_index, const char** reason);
extern void block_hash(u8 out[32], const u8 hdr[80]);

/* ---- prevout table: (txid_wire,vout) -> (value, spk) ---- */
typedef struct { u8 key[36]; u64 value; u32 spklen; u8 spk[10000]; } prev_t;
static prev_t* g_prev; static long g_nprev;
static int prev_cmp(const void* a, const void* b){ return memcmp(a, b, 36); }

/* Adversarial-but-legal store: the returned spk pointer aims into ONE
 * static buffer that the very next call overwrites -- exactly the
 * "pointer only valid until the next call" contract utxo_lsm_get documents. */
long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                  u64* value, u64* height, u64* coinbase,
                  const u8** spk, unsigned long* spklen){
    (void)lst; (void)u;
    static u8 scratch[10000];
    u8 key[36]; memcpy(key, txid, 32); memcpy(key+32, &index, 4);
    prev_t* e = bsearch(key, g_prev, g_nprev, sizeof(prev_t), prev_cmp);
    if (!e) return 0;
    memset(scratch, 0xEE, sizeof scratch);        /* poison the previous caller's view */
    memcpy(scratch, e->spk, e->spklen);
    *value = e->value; *height = 1; *coinbase = 0;
    *spk = scratch; *spklen = e->spklen;
    return 1;
}
long bidx_get(void* bx, u32 tx_index, const u8 txid[32], u32 index,
              u64* value, u64* height, u64* coinbase,
              const u8** spk, unsigned long* spklen){
    (void)bx;(void)tx_index;(void)txid;(void)index;(void)value;(void)height;(void)coinbase;(void)spk;(void)spklen;
    return -1;   /* bx==NULL is passed below; never called */
}

static u64 rd_cs(const u8** p){ u64 v=**p; (*p)++; if(v<0xfd) return v;
    if(v==0xfd){ v=(*p)[0]|((u64)(*p)[1]<<8); *p+=2; return v; }
    if(v==0xfe){ v=(*p)[0]|((u64)(*p)[1]<<8)|((u64)(*p)[2]<<16)|((u64)(*p)[3]<<24); *p+=4; return v; }
    v=0; for(int i=0;i<8;i++) v|=(u64)(*p)[i]<<(8*i); *p+=8; return v; }

/* witness-aware tx walker: returns tx length, sets *n_in */
static u64 tx_walk(const u8* p, u32* n_in){
    const u8* s = p; p += 4;
    int wit = (p[0]==0x00 && p[1]==0x01); if (wit) p += 2;
    u64 nin = rd_cs(&p); *n_in = (u32)nin;
    for (u64 i=0;i<nin;i++){ p += 36; u64 sl = rd_cs(&p); p += sl + 4; }
    u64 nout = rd_cs(&p);
    for (u64 i=0;i<nout;i++){ p += 8; u64 sl = rd_cs(&p); p += sl; }
    if (wit) for (u64 i=0;i<nin;i++){ u64 ni = rd_cs(&p);
        for (u64 j=0;j<ni;j++){ u64 il = rd_cs(&p); p += il; } }
    p += 4;
    return (u64)(p - s);
}

static int hx(const char* h, u8* out, int cap){ int n=0; for(; h[0]&&h[1]&&n<cap; h+=2,n++){ unsigned v; sscanf(h,"%2x",&v); out[n]=(u8)v; } return n; }

int main(void){
    FILE* fb = fopen("tests/fixtures/blk_482566.bin","rb");
    FILE* fp = fopen("tests/fixtures/blk_482566.prevouts","r");
    if(!fb||!fp){ printf("SKIP: fixtures absent (run validation/fetch_block_prevouts.py 482566)\n"); return 0; }
    static u8 blk[1<<21]; long blen = fread(blk,1,sizeof blk,fb); fclose(fb);

    g_prev = calloc(6000, sizeof(prev_t));
    char line[8192];
    while(fgets(line,sizeof line,fp)){
        char txh[80], spkh[6000]; unsigned idx; unsigned long long val;
        if(sscanf(line,"%79s %u %llu %5999s",txh,&idx,&val,spkh)!=4) continue;
        prev_t* e = &g_prev[g_nprev++];
        u8 disp[32]; hx(txh,disp,32);
        for(int k=0;k<32;k++) e->key[k]=disp[31-k];      /* wire order */
        memcpy(e->key+32,&idx,4);
        e->value = val; e->spklen = (u32)hx(spkh,e->spk,sizeof e->spk);
    }
    fclose(fp);
    qsort(g_prev, g_nprev, sizeof(prev_t), prev_cmp);
    printf("loaded %ld prevouts (single-reused-buffer store)\n", g_nprev);

    u8 bh[32]; block_hash(bh, blk);
    const u8* p = blk + 80; u64 ntx = rd_cs(&p);
    static block_tx_t txs[8192];
    if (ntx > 8192){ printf("FAIL ntx=%llu\n",(unsigned long long)ntx); return 1; }
    for (u64 t=0; t<ntx; t++){
        u32 nin; u64 tl = tx_walk(p, &nin);
        txs[t].ptr = p; txs[t].len = tl; txs[t].pn_in = nin;
        memset(txs[t].txid, 0, 32);   /* unused by tx_verify_block_connect_all */
        p += tl;
    }
    if (p != blk + blen){ printf("FAIL parse: consumed %ld of %ld bytes\n",(long)(p-blk),blen); return 1; }

    u64 fail_tx = 0; const char* reason = "?";
    int ok = tx_verify_block_connect_all(txs, ntx, 482566, bh, NULL, NULL, NULL, &fail_tx, &reason);
    if (ok != 1){
        printf("FAIL block 482566 rejected: tx=%llu %s\n",(unsigned long long)fail_tx, reason);
        printf("TESTS FAILED (1 failures)\n"); return 1;
    }
    printf("PASS block 482566 verified with a transient-spk store (wprog stays valid)\n");
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}

/* bitcoin_txval_modern.c's mempool-path resolver -- never reached here */
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk, unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr,"unexpected mempool_resolve_confirmed_utxo\n"); abort();
}
