/* tests/test_addr_index_tail.c -- the live address index
 * (daemon/addr_index_tail.c), hermetic.
 *
 *   1. classify: the shared classifier (addr_index_fmt.h) keys every
 *      indexable script shape and rejects the rest.
 *   2. journal semantics via the real writer path: hand-built blocks with a
 *      real coinbase + spends go through axt_on_block with a stubbed undo
 *      stream; the reader must show ADDs as balance, cancel them on DELs,
 *      credit "received" for spent history, and name both funders and
 *      spenders in the txid list.
 *   3. crash discipline: a torn final record is truncated back onto the
 *      82-byte grid at boot.
 *   4. reorg: axt_on_truncate drops records above the new tip by height
 *      from the file end (records are strictly height-ascending).
 *
 * The store is a REAL bitcoin_store (store_init/store_append) so heights,
 * tips and store reads behave exactly as in the daemon; only undo data is
 * stubbed (per-height record lists), because real undo files come from the
 * live UTXO apply path this test deliberately does not drag in.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "test_tmpdir.h"
#include "../daemon/addr_index_fmt.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8* hash32, const void* blk, long len);
extern void sha256d(u8 out[32], const void* p, unsigned long n);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);

extern void axt_boot(void* store_buf);
extern void axt_on_block(void* store_buf, long h, const u8* blk, long blen);
extern void axt_on_truncate(void* store_buf);
extern int  axt_active(void);
extern long axt_covered(void);
extern long axt_probe_covered(void);
extern long axt_read_address(int type, const u8 hash[32], u64* balance, u64* received,
                             long* nutxo, u8* txids, long txid_cap);
typedef int (*undo_cb)(void*, const u8*, u32, u64, u32, u8, const u8*, unsigned short);
extern void axt_set_undo_replay(long (*)(long, undo_cb, void*));

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* ---- stub undo store: per-height spent-prevout lists -------------------- */
typedef struct { u8 txid[32]; u32 vout; u64 value; u8 script[64]; unsigned short slen; } stub_spent;
static stub_spent g_spent[16][8];
static int g_nspent[16];

static long stub_undo_replay(long h, undo_cb cb, void* ctx){
    if (h < 0 || h >= 16) return -1;
    for (int i = 0; i < g_nspent[h]; i++){
        stub_spent* s = &g_spent[h][i];
        if (!cb(ctx, s->txid, s->vout, s->value, (u32)h, 0, s->script, s->slen)) return -1;
    }
    return g_nspent[h];
}

/* ---- tiny tx/block builder ---------------------------------------------- */
static long mk_tx(u8* out, const u8 prev_txid[32], u32 prev_vout,
                  const u8* spk, int spklen, u64 value, u8 tag){
    long n = 0;
    memcpy(out + n, "\x01\x00\x00\x00", 4); n += 4;           /* version   */
    out[n++] = 1;                                              /* nin       */
    if (prev_txid) memcpy(out + n, prev_txid, 32); else memset(out + n, 0, 32);
    n += 32;
    for (int i = 0; i < 4; i++) out[n++] = (u8)((prev_txid ? prev_vout : 0xffffffffu) >> (8*i));
    out[n++] = 2; out[n++] = 0x51; out[n++] = tag;             /* scriptSig (tag varies txid) */
    memcpy(out + n, "\xff\xff\xff\xff", 4); n += 4;            /* sequence  */
    out[n++] = 1;                                              /* nout      */
    for (int i = 0; i < 8; i++) out[n++] = (u8)(value >> (8*i));
    out[n++] = (u8)spklen; memcpy(out + n, spk, (size_t)spklen); n += spklen;
    memset(out + n, 0, 4); n += 4;                             /* locktime  */
    return n;
}

static long mk_block(u8* out, const u8 prev_hash[32], const u8* txs, long txlen, int ntx){
    memset(out, 0, 80);
    out[0] = 1;
    if (prev_hash) memcpy(out + 4, prev_hash, 32);
    out[68] = 0x29;                                            /* some time */
    out[72] = 0xff; out[73] = 0xff; out[74] = 0x7f; out[75] = 0x20;
    long n = 80;
    out[n++] = (u8)ntx;
    memcpy(out + n, txs, (size_t)txlen); n += txlen;
    return n;
}

static u8 SPK_A[25], SPK_B[22];                                /* P2PKH, P2WPKH */

int main(void){
    tt_isolate();

    printf("== 1: shared classifier ==\n");
    { u8 h[32];
      memset(SPK_A, 0, sizeof SPK_A);
      SPK_A[0]=0x76; SPK_A[1]=0xa9; SPK_A[2]=0x14; memset(SPK_A+3, 0xAA, 20);
      SPK_A[23]=0x88; SPK_A[24]=0xac;
      ck("P2PKH classifies", axf_classify(SPK_A, 25, h) == AXF_P2PKH && h[0]==0xAA && h[20]==0);
      SPK_B[0]=0x00; SPK_B[1]=0x14; memset(SPK_B+2, 0xBB, 20);
      ck("P2WPKH classifies", axf_classify(SPK_B, 22, h) == AXF_P2WPKH && h[0]==0xBB);
      u8 tr[34]; tr[0]=0x51; tr[1]=0x20; memset(tr+2, 0xCC, 32);
      ck("P2TR classifies", axf_classify(tr, 34, h) == AXF_P2TR && h[31]==0xCC);
      u8 opret[2] = {0x6a, 0x00};
      ck("OP_RETURN is not indexable", axf_classify(opret, 2, h) == AXF_INVALID); }

    printf("\n== 2: journal semantics through the real writer ==\n");
    static u8 store[4096];
    ck("store_init", store_init(store) == 1);
    axt_set_undo_replay(stub_undo_replay);

    /* h0: genesis (recorded no-op), h1: coinbase pays A, h2: coinbase pays B
     * and tx spends h1's A output to B */
    static u8 tx[512], blk[2048], blkhash[32];
    static u8 txid_cb1[32], txid_spend[32];
    u8 scratch[4096];

    long tl = mk_tx(tx, NULL, 0, SPK_A, 25, 5000, 1);
    long bl = mk_block(blk, NULL, tx, tl, 1);
    sha256d(blkhash, blk, 80);
    ck("append genesis", store_append(store, blkhash, blk, bl) == 0);

    tl = mk_tx(tx, NULL, 0, SPK_A, 25, 100, 2);                /* cb pays A */
    bl = mk_block(blk, blkhash, tx, tl, 1);
    tx_txid(txid_cb1, tx, (unsigned long)tl, scratch, sizeof scratch);
    sha256d(blkhash, blk, 80);
    ck("append h1", store_append(store, blkhash, blk, bl) == 1);

    axt_boot(store);
    ck("boot: active, covered=1", axt_active() && axt_covered() == 1);

    u64 bal, rcv; long nu; static u8 txids[64 * 32];
    u8 keyA[32]; memset(keyA, 0, 32); memset(keyA, 0xAA, 20);
    long nt = axt_read_address(AXF_P2PKH, keyA, &bal, &rcv, &nu, txids, 64);
    ck("A: balance=100 received=100 utxos=1 (the h1 coinbase)",
       bal == 100 && rcv == 100 && nu == 1 && nt == 1 &&
       memcmp(txids, txid_cb1, 32) == 0);

    /* h2: two txs -- a coinbase paying B 50, and a spend of A's h1 output
     * paying B 90. The stub undo for h2 reports A's output spent. */
    { static u8 txs[1024];
      long t1 = mk_tx(txs, NULL, 0, SPK_B, 22, 50, 3);
      long t2 = mk_tx(txs + t1, txid_cb1, 0, SPK_B, 22, 90, 4);
      tx_txid(txid_spend, txs + t1, (unsigned long)t2, scratch, sizeof scratch);
      bl = mk_block(blk, blkhash, txs, t1 + t2, 2);
      sha256d(blkhash, blk, 80);
      ck("append h2", store_append(store, blkhash, blk, bl) == 2);
      memcpy(g_spent[2][0].txid, txid_cb1, 32);
      g_spent[2][0].vout = 0; g_spent[2][0].value = 100;
      memcpy(g_spent[2][0].script, SPK_A, 25); g_spent[2][0].slen = 25;
      g_nspent[2] = 1;
      axt_on_block(store, 2, blk, bl); }
    ck("covered=2", axt_covered() == 2);

    nt = axt_read_address(AXF_P2PKH, keyA, &bal, &rcv, &nu, txids, 64);
    ck("A after spend: balance=0 received=100 utxos=0",
       bal == 0 && rcv == 100 && nu == 0);
    { int have_spender = 0;
      for (long i = 0; i < nt; i++) if (!memcmp(txids + i*32, txid_spend, 32)) have_spender = 1;
      ck("A's txids name the SPENDING tx too (TOUCH record)", nt == 2 && have_spender); }
    u8 keyB[32]; memset(keyB, 0, 32); memset(keyB, 0xBB, 20);
    nt = axt_read_address(AXF_P2WPKH, keyB, &bal, &rcv, &nu, txids, 64);
    ck("B: balance=140 (50 cb + 90 received) utxos=2", bal == 140 && rcv == 140 && nu == 2 && nt == 2);
    ck("probe agrees with writer", axt_probe_covered() == 2);

    printf("\n== 3: torn tail truncates onto the grid ==\n");
    { FILE* f = fopen(AXF_TAIL_FILE, "ab");
      fwrite("torn", 1, 4, f); fclose(f);
      /* a fresh boot must truncate the 4 orphan bytes and keep coverage */
      axt_boot(store);   /* second boot re-opens; harmless for the test */
      struct { long dummy; } _; (void)_;
      ck("re-boot after torn append keeps covered=2", axt_probe_covered() == 2); }

    printf("\n== 4: reorg truncation by height ==\n");
    { /* pretend the store tip rolled back to 1: every h=2 record must go */
      *(int*)(store + 24) = 1;
      axt_on_truncate(store);
      ck("covered rolled back to 1", axt_covered() == 1 && axt_probe_covered() == 1);
      nt = axt_read_address(AXF_P2WPKH, keyB, &bal, &rcv, &nu, txids, 64);
      ck("B's h2 records are gone", bal == 0 && nu == 0 && nt == 0);
      nt = axt_read_address(AXF_P2PKH, keyA, &bal, &rcv, &nu, txids, 64);
      ck("A's h1 coinbase is unspent again", bal == 100 && nu == 1); }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
