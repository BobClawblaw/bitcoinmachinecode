/* test_addr_hist.c -- the address history index: the builder over a fixture
 * archive (standard-script outputs, a spend chain), read back through the
 * real reader; and the reader's sparse search over a synthetic file with
 * more keys than one sparse stride. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../daemon/addr_hist_fmt.h"
#include "test_tmpdir.h"
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void store_rd_init(void* st);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; printf("%s %s\n", c ? "ok  :" : "FAIL:", w); if (!c) fails++; }
static u8 store_buf[4096];
/* tx: version | nin inputs (prevout, empty scriptSig, seq) | nout outputs (value, P2WPKH to `who`) | locktime */
static long mk_tx(u8* p, int tag, const u8* prev_txid, unsigned prev_vout, int nout, const u8* who, u64 value0){
    u8* s = p; *p++ = 1; *p++ = 0; *p++ = 0; *p++ = (u8)tag; *p++ = 1;
    if (prev_txid){ memcpy(p, prev_txid, 32); p += 32; *p++ = (u8)prev_vout; *p++ = (u8)(prev_vout >> 8); *p++ = 0; *p++ = 0; }
    else { memset(p, 0, 32); p += 32; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff; }
    *p++ = 0; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff; *p++ = 0xff;
    *p++ = (u8)nout;
    for (int i = 0; i < nout; i++){ u64 v = value0 / (u64)(i + 1); memcpy(p, &v, 8); p += 8; *p++ = 22; *p++ = 0x00; *p++ = 0x14; memcpy(p, who, 20); p[0] = (u8)(who[0] + i); p += 20; }
    *p++ = 0; *p++ = 0; *p++ = 0; *p++ = 0; return p - s;
}
int main(void){
    char tool[4096]; if (!getcwd(tool, sizeof tool - 40)) return 1; strcat(tool, "/daemon/bmc_build_addr_hist");
    tt_isolate();
    memset(store_buf, 0, sizeof store_buf);
    ck("store_init", store_init(store_buf) == 1);
    /* A = 0x11.. (20 bytes), B = 0x22.. ; block 0: coinbase pays A 50 (one output);
     * block 1: coinbase pays B; tx1 spends A's coin -> two outputs to A (A+0, A+1: the second is a different address);
     * block 2: coinbase pays B; tx spends tx1:0 -> B */
    static u8 blk[3][4096]; long blen[3]; u8 txid[4][32]; u8 hash[3][32]; static u8 scratch[8192];
    u8 A[20], B[20]; memset(A, 0x11, 20); memset(B, 0x22, 20);
    for (int h = 0; h < 3; h++){ memset(blk[h], 0xA0 + h, 80); memset(hash[h], 0xB0 + h, 32); }
    blk[0][80] = 1; long l0 = mk_tx(blk[0] + 81, 0, NULL, 0, 1, A, 5000000000ULL); blen[0] = 81 + l0; tx_txid(txid[0], blk[0] + 81, l0, scratch, sizeof scratch);
    blk[1][80] = 2; long l1a = mk_tx(blk[1] + 81, 1, NULL, 0, 1, B, 5000000000ULL); long l1b = mk_tx(blk[1] + 81 + l1a, 2, txid[0], 0, 2, A, 4000000000ULL); blen[1] = 81 + l1a + l1b;
    tx_txid(txid[1], blk[1] + 81, l1a, scratch, sizeof scratch); tx_txid(txid[2], blk[1] + 81 + l1a, l1b, scratch, sizeof scratch);
    blk[2][80] = 2; long l2a = mk_tx(blk[2] + 81, 3, NULL, 0, 1, B, 5000000000ULL); long l2b = mk_tx(blk[2] + 81 + l2a, 4, txid[2], 0, 1, B, 3900000000ULL); blen[2] = 81 + l2a + l2b;
    tx_txid(txid[3], blk[2] + 81 + l2a, l2b, scratch, sizeof scratch);
    for (int h = 0; h < 3; h++) ck("store_append", store_append(store_buf, hash[h], blk[h], blen[h]) == h);
    store_rd_init(store_buf);
    { u8 k32[32]; memset(k32, 0, 32); memcpy(k32, A, 20); const ah_event* e0; ck("no index yet: ah_available false, ah_lookup -1", !ah_available() && ah_lookup(2, k32, &e0) == -1); }
    { char cmd[4300]; snprintf(cmd, sizeof cmd, "%s . 2>/dev/null", tool); ck("builder ran to the tip", system(cmd) == 0); }
    ck("index available, to_height 2", ah_available() && ah_to_height() == 2);
    u8 keyA[32], keyA1[32], keyB[32]; memset(keyA, 0, 32); memcpy(keyA, A, 20); memset(keyA1, 0, 32); memcpy(keyA1, A, 20); keyA1[0] = 0x12; memset(keyB, 0, 32); memcpy(keyB, B, 20);
    const ah_event* ev; long n = ah_lookup(2, keyA, &ev);
    ck("A: 4 events (fund h0; fund h1 and spend h1 by tx1; spend h2 of tx1's output)", n == 4);
    if (n == 4){
        ah_event e[4]; for (int i = 0; i < 4; i++) memcpy(&e[i], (const u8*)ev + i * AH_EVENT_BYTES, sizeof e[i]);
        ck("A e0: FUND at height 0, txpos 0, vout 0, 50 BTC", e[0].kind == AH_FUND && e[0].height == 0 && e[0].txpos == 0 && e[0].idx == 0 && e[0].value == 5000000000ULL);
        ck("A e1: FUND at height 1, txpos 1 (tx1's output 0), 40 BTC", e[1].kind == AH_FUND && e[1].height == 1 && e[1].txpos == 1 && e[1].idx == 0 && e[1].value == 4000000000ULL);
        ck("A e2: SPEND at height 1, txpos 1, vin 0, value = the spent 50 BTC", e[2].kind == AH_SPEND && e[2].height == 1 && e[2].txpos == 1 && e[2].idx == 0 && e[2].value == 5000000000ULL);
        ck("A e3: SPEND at height 2, txpos 1, vin 0, value = the spent 40 BTC (sorted by height, txpos, kind)", e[3].kind == AH_SPEND && e[3].height == 2 && e[3].txpos == 1 && e[3].idx == 0 && e[3].value == 4000000000ULL);
    }
    n = ah_lookup(2, keyA1, &ev); ck("A+1 (tx1's second output, a different address): 1 FUND of 20 BTC", n == 1 && ((const ah_event*)ev)->value == 2000000000ULL);
    n = ah_lookup(2, keyB, &ev);
    ck("B: 3 events (coinbase h1, coinbase h2, fund from tx at h2)", n == 3);
    if (n == 3){ ah_event e; memcpy(&e, (const u8*)ev + 2 * AH_EVENT_BYTES, sizeof e); ck("B's last event: FUND at height 2, txpos 1, 39 BTC", e.kind == AH_FUND && e.height == 2 && e.txpos == 1 && e.value == 3900000000ULL); }
    { u8 none[32]; memset(none, 0x99, 32); ck("an unknown address: 0 events", ah_lookup(2, none, &ev) == 0); }
    ck("the A key at the wrong type: 0 events", ah_lookup(1, keyA, &ev) == 0);
    unlink(AH_FILE);

    /* the sparse search: 700 keys (> 2 strides), every key found, gaps not */
    { FILE* f = fopen(AH_FILE, "wb"); ah_header hd; memset(&hd, 0, sizeof hd); hd.magic = AH_MAGIC; hd.version = AH_VERSION; hd.to_height = 7; hd.body_off = AH_HDR_BYTES;
      u8 zero[AH_HDR_BYTES] = {0}; fwrite(zero, 1, AH_HDR_BYTES, f); u64 body = 0; ah_sparse sp[8]; int nsp = 0;
      for (int k = 0; k < 700; k++){ ah_group_hdr g; g.type = 3; memset(g.hash, 0, 32); g.hash[0] = (u8)(k / 256); g.hash[1] = (u8)(k % 256); g.hash[2] = 1; g.n = 1;
          if (k % AH_SPARSE_STRIDE == 0){ sp[nsp].type = 3; memcpy(sp[nsp].hash, g.hash, 32); sp[nsp].off = body; nsp++; }
          fwrite(&g, 1, AH_GROUP_HDR, f); body += AH_GROUP_HDR; ah_event e = { AH_FUND, (u32)k, 0, 0, (u64)k * 1000 }; fwrite(&e, 1, AH_EVENT_BYTES, f); body += AH_EVENT_BYTES; }
      hd.n_keys = 700; hd.n_events = 700; hd.body_len = body; hd.sparse_off = AH_HDR_BYTES + body; hd.sparse_n = (u64)nsp;
      fwrite(sp, AH_SPARSE_BYTES, (size_t)nsp, f); fseek(f, 0, SEEK_SET); fwrite(&hd, 1, sizeof hd, f); fclose(f);
      int all = 1; for (int k = 0; k < 700; k++){ u8 h[32]; memset(h, 0, 32); h[0] = (u8)(k / 256); h[1] = (u8)(k % 256); h[2] = 1; long c = ah_lookup(3, h, &ev); if (c != 1 || ((const ah_event*)ev)->value != (u64)k * 1000) all = 0; }
      ck("synthetic 700-key file (3 sparse entries): every key found with its own event", all);
      { u8 h[32]; memset(h, 0, 32); h[2] = 2; ck("a key between two present keys: 0", ah_lookup(3, h, &ev) == 0); }
      { u8 h[32]; memset(h, 0xff, 32); ck("a key above the last: 0", ah_lookup(3, h, &ev) == 0); }
      { u8 h[32]; memset(h, 0, 32); ck("a key below the first: 0", ah_lookup(3, h, &ev) == 0); }
      ck("a rebuilt file is picked up (to_height changed 2 -> 7)", ah_to_height() == 7);
      unlink(AH_FILE); }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
