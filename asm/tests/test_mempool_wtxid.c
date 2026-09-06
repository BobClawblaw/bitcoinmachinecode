/* tests/test_mempool_wtxid.c -- 2026-09-06: every mempool slot caches its
 * entry's wtxid.
 *
 * bitcoin_mempool.asm's slot is 80 bytes: [len][txid 32][blob_off][wtxid 32].
 * mpool_put computes sha256d over the stored tx bytes once (BIP152's wtxid;
 * the txid itself for a non-witness tx) and stores it at +48, so the compact
 * block reconstructor (daemon/cmpct_recv.c) reads it through
 * mpool_wtxid_at_slot instead of hashing every pool entry for every block.
 *
 * Asserted here, against the asm object the daemon links:
 *   - mpool_struct_size reflects the 80-byte stride;
 *   - the cached wtxid equals tx_wtxid recomputed, for a non-witness tx
 *     (== txid) and for a witness tx (!= txid: the witness is hashed);
 *   - it sits at slot+48, behind the txid, in the slot mpool_put chose;
 *   - the accessor answers 0 for an empty slot and for i > mask;
 *   - after del/put churn (backward-shift deletion moves whole records) every
 *     live slot's cache still equals tx_wtxid over the bytes mpool_get returns.
 * Watched failing first with the sha256d call removed from mpool_put (the
 * cache then holds whatever the slot held before). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mempool_slot.h"
extern unsigned long mpool_struct_size(unsigned long slots);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern long mpool_put(void* mp, const unsigned char txid[32], const unsigned char* tx, unsigned long txlen);
extern const unsigned char* mpool_get(void* mp, const unsigned char txid[32], unsigned long* out_len);
extern long mpool_del(void* mp, const unsigned char txid[32]);
extern long mpool_count(void* mp);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
extern void tx_wtxid(unsigned char out[32], const unsigned char* tx, unsigned long txlen);   /* bitcoin_cmpct.asm */

static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }

/* version 1 | 1 input (prevout = tag, empty scriptSig, seq ff) | 1 output
 * (value = tag, script OP_TRUE) | locktime 0. With `witness`, the BIP144
 * marker/flag and a one-item witness stack (the tag byte) are included. */
static unsigned long mktx(unsigned char* t, unsigned tag, int witness){
    unsigned long o = 0; t[o++]=1; t[o++]=0; t[o++]=0; t[o++]=0;
    if (witness){ t[o++]=0; t[o++]=1; }
    t[o++]=1; memset(t+o, 0, 32); t[o]=(unsigned char)tag; t[o+1]=(unsigned char)(tag>>8); t[o+2]=(unsigned char)(tag>>16); o += 32;
    memset(t+o, 0, 4); o += 4; t[o++]=0; memset(t+o, 0xff, 4); o += 4;
    t[o++]=1; memset(t+o, 0, 8); t[o]=(unsigned char)tag; o += 8; t[o++]=1; t[o++]=0x51;
    if (witness){ t[o++]=1; t[o++]=1; t[o++]=(unsigned char)(tag ^ 0x5a); }
    memset(t+o, 0, 4); o += 4; return o;
}
/* the slot holding txid, found by scanning (not by assuming a probe position) */
static unsigned char* find_slot(unsigned char* mp, unsigned long slots, const unsigned char txid[32]){
    for (unsigned long i = 0; i < slots; i++){
        unsigned char* s = MPOOL_SLOT_AT(mp, i); unsigned long long len; memcpy(&len, s, 8);
        if (len != MPOOL_SLOT_EMPTY && !memcmp(s + MPOOL_SLOT_TXID, txid, 32)) return s;
    }
    return 0;
}
static unsigned long slot_index(unsigned char* mp, unsigned char* s){ return (unsigned long)(s - mp - MPOOL_HDR_BYTES) / MPOOL_SLOT_BYTES; }

int main(void){
    printf("== the stride: mpool_struct_size is 40 + slots*80 + 8 ==\n");
    ok(mpool_struct_size(0) == 48, "mpool_struct_size(0) == 48 (header + guard)");
    ok(mpool_struct_size(1) - mpool_struct_size(0) == 80, "one slot is 80 bytes");
    ok(mpool_struct_size(4096) == MPOOL_AREA_BYTES(4096), "mpool_struct_size(4096) == MPOOL_AREA_BYTES(4096) (asm and mempool_slot.h agree)");
    ok(MPOOL_SLOT_WTXID + 32 == MPOOL_SLOT_BYTES, "the wtxid is the last 32 bytes of the slot");

    unsigned long slots = 256; unsigned char* mp = calloc(1, mpool_struct_size(slots));
    static unsigned char blob[1 << 20]; mpool_init(mp, slots, blob, sizeof blob);

    printf("== a non-witness tx: the cache equals tx_wtxid, which equals the txid ==\n");
    static unsigned char t0[256]; unsigned long l0 = mktx(t0, 1, 0);
    unsigned char id0[32], w0[32]; sha256d(id0, t0, l0); tx_wtxid(w0, t0, l0);
    ok(!memcmp(id0, w0, 32), "sanity: for a non-witness tx, tx_wtxid == txid");
    ok(mpool_put(mp, id0, t0, l0) == 1, "put");
    unsigned char* s0 = find_slot(mp, slots, id0); ok(s0 != 0, "its slot was found by txid");
    ok(s0 && !memcmp(s0 + MPOOL_SLOT_WTXID, w0, 32), "slot+48 holds tx_wtxid(tx)");
    { const unsigned char* c = s0 ? mpool_wtxid_at_slot(mp, slot_index(mp, s0)) : 0;
      ok(c && !memcmp(c, w0, 32), "mpool_wtxid_at_slot returns the same 32 bytes");
      ok(c == s0 + MPOOL_SLOT_WTXID, "and it aliases the slot (no copy)"); }

    printf("== a witness tx: the cache equals tx_wtxid over the stored bytes and differs from the txid ==\n");
    static unsigned char t1[256], t1s[256]; unsigned long l1 = mktx(t1, 2, 1), l1s = mktx(t1s, 2, 0);
    unsigned char id1[32], w1[32], w1x[32]; sha256d(id1, t1s, l1s); tx_wtxid(w1, t1, l1); sha256d(w1x, t1, l1);
    ok(!memcmp(w1, w1x, 32) && memcmp(w1, id1, 32) != 0, "sanity: tx_wtxid == sha256d(with witness) != sha256d(stripped) == txid");
    ok(mpool_put(mp, id1, t1, l1) == 1, "put under its (stripped) txid");
    unsigned char* s1 = find_slot(mp, slots, id1); ok(s1 != 0, "its slot was found by txid");
    ok(s1 && !memcmp(s1 + MPOOL_SLOT_WTXID, w1, 32), "slot+48 holds the WITNESS hash");
    ok(s1 && memcmp(s1 + MPOOL_SLOT_WTXID, id1, 32) != 0, "not the txid");
    { unsigned long gl = 0; const unsigned char* g = mpool_get(mp, id1, &gl);
      unsigned char r[32]; if (g) tx_wtxid(r, g, gl);
      ok(g && gl == l1 && s1 && !memcmp(r, s1 + MPOOL_SLOT_WTXID, 32), "tx_wtxid recomputed over mpool_get's bytes equals the cache"); }

    printf("== the accessor refuses what is not an entry ==\n");
    ok(mpool_wtxid_at_slot(mp, slots) == 0, "i == mask+1 -> 0");
    ok(mpool_wtxid_at_slot(mp, ~0UL) == 0, "i == ~0 -> 0");
    { unsigned long empties = 0, e = 0; for (unsigned long i = 0; i < slots; i++){ unsigned char* s = MPOOL_SLOT_AT(mp, i); unsigned long long len; memcpy(&len, s, 8);
        if (len == MPOOL_SLOT_EMPTY){ empties++; if (mpool_wtxid_at_slot(mp, i) == 0) e++; } }
      ok(empties == slots - 2 && e == empties, "every empty slot -> 0"); }
    ok(mpool_put(mp, id1, t1, l1) == 0 && s1 && !memcmp(s1 + MPOOL_SLOT_WTXID, w1, 32), "a duplicate put leaves the cache alone");

    printf("== churn: del/put with backward-shift moves keeps every live cache right ==\n");
    /* 200 more entries into 256 slots (collisions and shifts guaranteed), delete
     * every third, add 60 more, then audit every live slot against a recompute */
    enum { N = 260 }; static unsigned char txs[N][256]; static unsigned long lens[N]; static unsigned char ids[N][32]; static int live[N];
    int nput = 0;
    for (int i = 0; i < 200; i++){ lens[i] = mktx(txs[i], 100 + (unsigned)i, i & 1); sha256d(ids[i], txs[i], lens[i]); /* key: any 32 bytes distinct per tx */
        if (mpool_put(mp, ids[i], txs[i], lens[i]) == 1){ live[i] = 1; nput++; } }
    ok(nput == 200, "200 puts");
    int ndel = 0; for (int i = 0; i < 200; i += 3){ if (mpool_del(mp, ids[i]) == 1){ live[i] = 0; ndel++; } }
    ok(ndel == 67, "67 deletes");
    for (int i = 200; i < N; i++){ lens[i] = mktx(txs[i], 100 + (unsigned)i, i & 1); sha256d(ids[i], txs[i], lens[i]);
        if (mpool_put(mp, ids[i], txs[i], lens[i]) == 1){ live[i] = 1; nput++; } }
    ok(mpool_count(mp) == 2 + 200 - 67 + 60, "count = 2 + 200 - 67 + 60");
    { int bad = 0, seen = 0;
      for (int i = 0; i < N; i++){ if (!live[i]) continue; seen++;
          unsigned char* s = find_slot(mp, slots, ids[i]); if (!s){ bad++; continue; }
          unsigned long gl = 0; const unsigned char* g = mpool_get(mp, ids[i], &gl); if (!g || gl != lens[i]){ bad++; continue; }
          unsigned char r[32]; tx_wtxid(r, g, gl);
          const unsigned char* c = mpool_wtxid_at_slot(mp, slot_index(mp, s));
          if (!c || memcmp(c, r, 32) || memcmp(s + MPOOL_SLOT_WTXID, r, 32)) bad++; }
      ok(seen == 193 && bad == 0, "every live entry (193): cache at slot+48 == tx_wtxid(recomputed over mpool_get bytes)");
      bad = 0; for (int i = 0; i < 200; i += 3){ if (find_slot(mp, slots, ids[i])) bad++; }
      ok(bad == 0, "no deleted entry is still findable"); }
    { /* and the slot-walk view: every non-empty slot's cache matches its own bytes */
      unsigned char* b; memcpy(&b, mp + 16, 8); int bad = 0, n = 0;
      for (unsigned long i = 0; i < slots; i++){ unsigned char* s = MPOOL_SLOT_AT(mp, i); unsigned long long len, off; memcpy(&len, s, 8);
          if (len == MPOOL_SLOT_EMPTY) continue;
          n++; memcpy(&off, s + MPOOL_SLOT_OFF, 8);
          unsigned char r[32]; tx_wtxid(r, b + off, (unsigned long)len);
          const unsigned char* c = mpool_wtxid_at_slot(mp, i); if (!c || memcmp(c, r, 32)) bad++; }
      ok(n == 195 && bad == 0, "slot walk: 195 live slots, each cache == tx_wtxid(blob bytes)"); }

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails); return fails?1:0;
}
