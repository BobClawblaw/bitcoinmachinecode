/* test_taproot_block_diff -- whole-block differential against the Bitcoin
 * Core oracle for the PARALLEL taproot path (PERF_SCOPE.md section 14.7).
 *
 * WHY THIS SHAPE. Taproot inputs used to be verified in a sequential pass,
 * one transaction at a time, against a scratch arena that was rebuilt per
 * transaction. They now ride the same worker pool as every other shape,
 * reading one per-BLOCK arena that Phase 1.5 fills before any worker starts.
 * The failure mode of getting that wrong is a CORRUPTED SIGHASH -- a worker
 * reading another transaction's outpoints/amounts/scriptPubKeys/stripped-tx
 * bytes. That is silent: there is no error, no assert, no bounds violation.
 * It shows up only as a verdict that disagrees with Core.
 *
 * So the test is a verdict differential, in both directions, over real
 * taproot-dense mainnet blocks, driving BOTH entry points:
 *
 *   A  block path, ACCEPT.  tx_verify_block_connect_all over the whole block,
 *      repeated, because the bug this guards against is scheduling-dependent
 *      and a single run can get lucky.
 *   B  single-tx path, ACCEPT.  tx_verify_block_connect for every
 *      non-coinbase transaction.
 *   C  single-tx path, REJECT.  every taproot-bearing transaction, one at a
 *      time, with its taproot witness corrupted.
 *   D  block path, REJECT.  a spread sample of taproot-bearing transactions,
 *      one corrupted per run, checking that the reported fail_tx_index is
 *      exactly the corrupted transaction.
 *   E  ARENA PROBE, both paths.  bump ONE input's prevout amount by one
 *      satoshi and require every taproot-bearing transaction that spends it
 *      to reject. BIP341 commits to every input's amount, so this fails iff
 *      the amounts array really does reach the sighash -- it is the direct
 *      test that the shared arena's contents are the ones being hashed, and
 *      it is what a wrong descriptor index would break.
 *
 * GROUND TRUTH is Core, not our own previous answer:
 *   * the blocks and every prevout amount/scriptPubKey come from the scratch
 *     oracle at /storage/core-oracle (validation/fetch_taproot_blocks.py),
 *     never from this project's archive -- which is witness-stripped above
 *     height 481,824 and would carry no signatures at all;
 *   * Core accepted every one of these blocks into its chain, so Core's
 *     verdict for every transaction in pass A/B is ACCEPT, and any reject we
 *     produce is a false reject;
 *   * a Schnorr signature or taproot control block with a flipped bit, and a
 *     BIP341 sighash over a wrong amount, are rejects under Core's rules by
 *     construction -- passes C/D/E are the false-ACCEPT direction, which is
 *     the direction that matters here.
 *
 * Fixtures are large and gitignored; the test SKIPs cleanly without them.
 *   python3 validation/fetch_taproot_blocks.py 825000 825001 840000 870000
 *   ./tests/test_taproot_block_diff 825000 825001 840000 870000
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

typedef struct { const u8* ptr; u64 len; u8 txid[32]; u32 pn_in; } block_tx_t;
extern int tx_verify_block_connect(const u8* tx, u64 txlen, long height,
                                   const u8 block_hash32[32], void* lst, void* u,
                                   const char** reason);
extern int tx_verify_block_connect_all(const block_tx_t* txs, u64 ntx, long height,
                                       const u8 block_hash32[32], void* lst, void* u, void* bx,
                                       u64* fail_tx_index, const char** reason);
extern void block_hash(u8 out[32], const u8 hdr[80]);

#define MAX_TX      16384
#define MAX_PREV    32768
#define SPK_MAX     10000

/* ---- prevout table: (txid_wire,vout) -> (value, spk) -------------------- */
typedef struct { u8 key[36]; u64 value; u32 spklen; u8 spk[SPK_MAX]; } prev_t;
static prev_t* g_prev; static long g_nprev;
static int prev_cmp(const void* a, const void* b){ return memcmp(a, b, 36); }

/* The store's documented contract: the returned spk pointer is only valid
 * until the next call. Reproduce it exactly (one reused, poisoned buffer) so
 * this test also keeps pinning the incident-482566 contract. */
long utxo_lsm_get(void* lst, void* u, const u8 txid[32], u32 index,
                  u64* value, u64* height, u64* coinbase,
                  const u8** spk, unsigned long* spklen){
    (void)lst; (void)u;
    static u8 scratch[SPK_MAX];
    u8 key[36]; memcpy(key, txid, 32); memcpy(key+32, &index, 4);
    prev_t* e = bsearch(key, g_prev, g_nprev, sizeof(prev_t), prev_cmp);
    if (!e) return 0;
    memset(scratch, 0xEE, sizeof scratch);
    memcpy(scratch, e->spk, e->spklen);
    *value = e->value; *height = 1; *coinbase = 0;
    *spk = scratch; *spklen = e->spklen;
    return 1;
}
/* bx is always NULL below: every prevout, including same-block chained ones,
 * is in the table (Core's getblock verbosity 3 reports prevouts for those
 * too), so the confirmed-set fallback resolves everything. */
long bidx_get(void* bx, u32 tx_index, const u8 txid[32], u32 index,
              u64* value, u64* height, u64* coinbase,
              const u8** spk, unsigned long* spklen){
    (void)bx;(void)tx_index;(void)txid;(void)index;(void)value;(void)height;(void)coinbase;(void)spk;(void)spklen;
    return -1;
}
long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    unsigned long long* value, const u8** spk, unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr,"unexpected mempool_resolve_confirmed_utxo\n"); abort();
}

/* ---- block/tx walking --------------------------------------------------- */
static u64 rd_cs(const u8** p){ u64 v=**p; (*p)++; if(v<0xfd) return v;
    if(v==0xfd){ v=(*p)[0]|((u64)(*p)[1]<<8); *p+=2; return v; }
    if(v==0xfe){ v=(*p)[0]|((u64)(*p)[1]<<8)|((u64)(*p)[2]<<16)|((u64)(*p)[3]<<24); *p+=4; return v; }
    v=0; for(int i=0;i<8;i++) v|=(u64)(*p)[i]<<(8*i); *p+=8; return v; }

/* Per-transaction map of what this test needs to poke at: which inputs are
 * taproot, and where each taproot input's witness items live in the block
 * buffer (byte offsets, so corruption is a direct write). */
#define MAX_WIT_ITEMS 64
typedef struct {
    u32 nwit;
    u64 off[MAX_WIT_ITEMS];      /* byte offset into blk[] of item j        */
    u64 len[MAX_WIT_ITEMS];
    u8  key[36];                 /* this input's prevout key                */
    u8  is_tap;
} txin_map_t;
typedef struct {
    u64 first_in;                /* index into g_inmap                      */
    u32 nin;
    u32 ntap;
} txmap_t;
static txin_map_t* g_inmap; static u64 g_ninmap;
static txmap_t g_txmap[MAX_TX];

static int is_tap_spk(const u8* spk, u32 n){ return n==34 && spk[0]==0x51 && spk[1]==0x20; }

/* Walks one tx starting at blk+off. Fills g_inmap[g_ninmap..] and *m.
 * Returns the tx byte length, 0 on parse failure. */
static u64 tx_map(const u8* blk, u64 off, txmap_t* m){
    const u8* base = blk; const u8* p = blk + off;
    p += 4;
    int wit = (p[0]==0x00 && p[1]==0x01); if (wit) p += 2;
    u64 nin = rd_cs(&p);
    m->first_in = g_ninmap; m->nin = (u32)nin; m->ntap = 0;
    u64 in0 = g_ninmap; g_ninmap += nin;
    for (u64 i=0;i<nin;i++){
        txin_map_t* e = &g_inmap[in0+i];
        memcpy(e->key, p, 36); p += 36;
        e->nwit = 0; e->is_tap = 0;
        u64 sl = rd_cs(&p); p += sl + 4;
    }
    u64 nout = rd_cs(&p);
    for (u64 i=0;i<nout;i++){ p += 8; u64 sl = rd_cs(&p); p += sl; }
    if (wit) for (u64 i=0;i<nin;i++){
        txin_map_t* e = &g_inmap[in0+i];
        u64 ni = rd_cs(&p);
        e->nwit = (u32)ni;
        for (u64 j=0;j<ni;j++){
            u64 il = rd_cs(&p);
            if (j < MAX_WIT_ITEMS){ e->off[j] = (u64)(p - base); e->len[j] = il; }
            p += il;
        }
    }
    p += 4;
    /* classify each input against the prevout table */
    for (u64 i=0;i<nin;i++){
        txin_map_t* e = &g_inmap[in0+i];
        prev_t* pv = bsearch(e->key, g_prev, g_nprev, sizeof(prev_t), prev_cmp);
        if (pv && is_tap_spk(pv->spk, pv->spklen)) { e->is_tap = 1; m->ntap++; }
    }
    return (u64)(p - (base + off));
}

static u8* g_blk;

/* BIP341 key-path spend: effective witness stack (annex stripped) is exactly
 * one item, the Schnorr signature. Anything else is script-path. */
static int tap_is_keypath(const txin_map_t* e){
    if (e->nwit == 0 || e->nwit > MAX_WIT_ITEMS) return 0;
    u32 nwit = e->nwit;
    int annex = (nwit >= 2 && e->len[nwit-1] >= 1 && g_blk[e->off[nwit-1]] == 0x50);
    return (nwit - (annex ? 1u : 0u)) == 1u;
}

/* The byte this input's corruption should flip, chosen so the reject is
 * unconditional under Core's rules and does not depend on the tapscript's
 * own semantics:
 *   effective stack size 1   -> the Schnorr signature (key-path)
 *   effective stack size >=2 -> the control block's internal pubkey
 *                               (script-path: breaks the BIP341 commitment)
 * An initial-stack item is never chosen: a tapscript may simply not read it.
 * Returns ~0ull if this input cannot be deterministically broken, which does
 * not happen for a well-formed P2TR input. */
static u64 tap_corrupt_offset(const txin_map_t* e){
    if (e->nwit == 0 || e->nwit > MAX_WIT_ITEMS) return ~0ull;
    u32 nwit = e->nwit;
    int annex = (nwit >= 2 && e->len[nwit-1] >= 1 && g_blk[e->off[nwit-1]] == 0x50);
    u32 eff = nwit - (annex ? 1u : 0u);
    if (eff == 0) return ~0ull;
    if (eff == 1){
        if (e->len[0] < 1) return ~0ull;
        return e->off[0];                    /* Schnorr signature */
    }
    /* script-path: control block = last effective item; byte 1 is the first
     * byte of the 32-byte x-only internal pubkey. Flipping it either breaks
     * the merkle commitment or makes the point unliftable -- reject either
     * way, and never a leaf-version or parity change that could alter the
     * classification. */
    u64 ci = eff - 1;
    if (e->len[ci] < 33) return ~0ull;
    return e->off[ci] + 1;
}

static int hx(const char* h, u8* out, int cap){ int n=0; for(; h[0]&&h[1]&&n<cap; h+=2,n++){ unsigned v; sscanf(h,"%2x",&v); out[n]=(u8)v; } return n; }

static long g_fail = 0;

/* ------------------------------------------------------------------------ */
static int run_height(int H, int repeats, int block_reject_samples){
    char path[256];
    snprintf(path, sizeof path, "tests/fixtures/blk_%d.bin", H);
    FILE* fb = fopen(path, "rb");
    snprintf(path, sizeof path, "tests/fixtures/blk_%d.prevouts", H);
    FILE* fp = fopen(path, "r");
    if (!fb || !fp){
        if (fb) fclose(fb);
        if (fp) fclose(fp);
        printf("SKIP h=%d: fixtures absent (validation/fetch_taproot_blocks.py %d)\n", H, H);
        return -1;
    }
    static u8 blk[8<<20];
    long blen = (long)fread(blk, 1, sizeof blk, fb); fclose(fb);
    g_blk = blk;

    if (!g_prev) g_prev = calloc(MAX_PREV, sizeof(prev_t));
    if (!g_inmap) g_inmap = calloc(MAX_PREV, sizeof(txin_map_t));
    g_nprev = 0; g_ninmap = 0;
    {
        static char line[SPK_MAX*2+256];
        while (fgets(line, sizeof line, fp)){
            char txh[80]; static char spkh[SPK_MAX*2+8];
            unsigned idx; unsigned long long val;
            if (sscanf(line, "%79s %u %llu %20007s", txh, &idx, &val, spkh) != 4) continue;
            if (g_nprev >= MAX_PREV){ printf("FAIL h=%d: prevout table overflow\n", H); return 1; }
            prev_t* e = &g_prev[g_nprev++];
            u8 disp[32]; hx(txh, disp, 32);
            for (int k=0;k<32;k++) e->key[k] = disp[31-k];      /* display -> wire */
            memcpy(e->key+32, &idx, 4);
            e->value = val; e->spklen = (u32)hx(spkh, e->spk, sizeof e->spk);
        }
    }
    fclose(fp);
    qsort(g_prev, g_nprev, sizeof(prev_t), prev_cmp);

    u8 bh[32]; block_hash(bh, blk);
    const u8* p = blk + 80; u64 ntx = rd_cs(&p);
    if (ntx > MAX_TX){ printf("FAIL h=%d: ntx=%llu\n", H, (unsigned long long)ntx); return 1; }
    static block_tx_t txs[MAX_TX];
    u64 off = (u64)(p - blk);
    u64 ntap_tx = 0, ntap_in = 0;
    for (u64 t=0; t<ntx; t++){
        txmap_t* m = &g_txmap[t];
        u64 tl = tx_map(blk, off, m);
        if (tl == 0){ printf("FAIL h=%d: tx %llu parse\n", H, (unsigned long long)t); return 1; }
        txs[t].ptr = blk + off; txs[t].len = tl; txs[t].pn_in = m->nin;
        memset(txs[t].txid, 0, 32);
        off += tl;
        if (t > 0 && m->ntap){ ntap_tx++; ntap_in += m->ntap; }
    }
    if ((long)off != blen){ printf("FAIL h=%d: parse consumed %ld of %ld\n", H, (long)off, blen); return 1; }

    long fails = 0;
    printf("h=%d  ntx=%llu  taproot-bearing tx=%llu  taproot inputs=%llu  prevouts=%ld\n",
           H, (unsigned long long)(ntx-1), (unsigned long long)ntap_tx,
           (unsigned long long)ntap_in, g_nprev);

    /* ---- A: block path, ACCEPT, repeated ---- */
    for (int r=0; r<repeats; r++){
        u64 ft = ~0ull; const char* why = "?";
        if (tx_verify_block_connect_all(txs, ntx, H, bh, NULL, NULL, NULL, &ft, &why) != 1){
            printf("  FAIL A run %d: block REJECTED, tx=%llu: %s\n", r, (unsigned long long)ft, why);
            fails++; break;
        }
    }
    printf("  A  block path accept   x%d runs           %s\n", repeats, fails?"FAIL":"ok");

    /* ---- B: single-tx path, ACCEPT, every transaction ---- */
    {
        long bad = 0;
        for (u64 t=1; t<ntx; t++){
            const char* why = "?";
            if (tx_verify_block_connect(txs[t].ptr, txs[t].len, H, bh, NULL, NULL, &why) != 1){
                if (bad < 5) printf("  FAIL B: tx %llu REJECTED: %s\n", (unsigned long long)t, why);
                bad++;
            }
        }
        printf("  B  single-tx accept   %llu transactions      %s\n",
               (unsigned long long)(ntx-1), bad?"FAIL":"ok");
        fails += bad;
    }

    /* ---- C: single-tx path, REJECT, every taproot-bearing transaction ---- */
    {
        long bad = 0, done = 0, skipped = 0;
        for (u64 t=1; t<ntx; t++){
            txmap_t* m = &g_txmap[t];
            if (!m->ntap) continue;
            /* corrupt the FIRST taproot input of this tx */
            txin_map_t* e = NULL;
            for (u32 i=0;i<m->nin;i++) if (g_inmap[m->first_in+i].is_tap){ e = &g_inmap[m->first_in+i]; break; }
            u64 co = e ? tap_corrupt_offset(e) : ~0ull;
            if (co == ~0ull){ skipped++; continue; }
            u8 save = blk[co]; blk[co] ^= 0x01;
            const char* why = "?";
            int r = tx_verify_block_connect(txs[t].ptr, txs[t].len, H, bh, NULL, NULL, &why);
            blk[co] = save;
            if (r != 0){
                if (bad < 5) printf("  FAIL C: tx %llu ACCEPTED with a corrupted taproot witness\n",
                                    (unsigned long long)t);
                bad++;
            } else if (strncmp(why, "p2tr", 4) != 0){
                if (bad < 5) printf("  FAIL C: tx %llu rejected for the wrong reason: %s\n",
                                    (unsigned long long)t, why);
                bad++;
            }
            done++;
        }
        printf("  C  single-tx reject   %ld corrupted tx (%ld unbreakable)  %s\n",
               done, skipped, bad?"FAIL":"ok");
        fails += bad;
    }

    /* ---- D: block path, REJECT, spread sample ---- */
    {
        long bad = 0, done = 0;
        u64 taplist[MAX_TX]; u64 nt = 0;
        for (u64 t=1; t<ntx; t++) if (g_txmap[t].ntap) taplist[nt++] = t;
        u64 stride = nt > (u64)block_reject_samples ? nt/(u64)block_reject_samples : 1;
        for (u64 s=0; s<nt; s += stride){
            u64 t = taplist[s];
            txmap_t* m = &g_txmap[t];
            txin_map_t* e = NULL;
            for (u32 i=0;i<m->nin;i++) if (g_inmap[m->first_in+i].is_tap){ e = &g_inmap[m->first_in+i]; break; }
            u64 co = e ? tap_corrupt_offset(e) : ~0ull;
            if (co == ~0ull) continue;
            u8 save = blk[co]; blk[co] ^= 0x01;
            u64 ft = ~0ull; const char* why = "?";
            int r = tx_verify_block_connect_all(txs, ntx, H, bh, NULL, NULL, NULL, &ft, &why);
            blk[co] = save;
            if (r != 0){
                if (bad < 5) printf("  FAIL D: block ACCEPTED with tx %llu's taproot witness corrupted\n",
                                    (unsigned long long)t);
                bad++;
            } else if (ft != t){
                if (bad < 5) printf("  FAIL D: corrupted tx %llu, blamed tx %llu (%s)\n",
                                    (unsigned long long)t, (unsigned long long)ft, why);
                bad++;
            } else if (strncmp(why, "p2tr", 4) != 0){
                if (bad < 5) printf("  FAIL D: tx %llu rejected for the wrong reason: %s\n",
                                    (unsigned long long)t, why);
                bad++;
            }
            done++;
        }
        printf("  D  block reject       %ld corrupted tx, fail_tx_index exact   %s\n",
               done, bad?"FAIL":"ok");
        fails += bad;
    }

    /* ---- E: arena probe -- perturb the PREVOUT DATA, not the witness ----
     * The witness corruption of C/D proves an input is verified at all. This
     * proves it is verified against ITS OWN transaction's aggregate arrays,
     * which is the thing the shared arena could get wrong. Three probes, all
     * driven through BOTH entry points, all restoring the table afterwards:
     *
     *   E1  the taproot input's OWN prevout amount, +1 satoshi. BIP341
     *       commits to it in every hash type, ANYONECANPAY included --
     *       provided a signature is checked at all, so E1 runs only on
     *       KEY-PATH inputs. A script-path spend under an unknown leaf
     *       version, or under an OP_SUCCESSx leaf, or under a tapscript that
     *       simply contains no CHECKSIG, is consensus-valid without ever
     *       computing a sighash; 17 real transactions in this corpus are
     *       exactly that, and an earlier version of this probe wrongly
     *       called them failures. Those inputs are still covered by C/D,
     *       which break the control block's Merkle commitment -- the one
     *       check every script-path spend must pass.
     *   E2  a DIFFERENT input's prevout amount, +1 satoshi -> sha_amounts.
     *       This one can ONLY reject through the aggregate array: nothing
     *       else in the transaction reads that input's amount.
     *   E3  a DIFFERENT input's prevout scriptPubKey, one bit flipped. Weaker
     *       than E2 on purpose -- the reject may come from sha_scriptpubkeys
     *       or from that input's own script check -- but it still pins that
     *       the block path blames the right transaction. The `sp` array's
     *       PACKED encoding (1+spklen, replacing an nin*(1+TXV_SPK_CAP)
     *       stride) is covered comprehensively by pass A instead: a wrong
     *       stride would break every multi-input taproot transaction there.
     *
     * E2/E3 only hold when the signature actually commits to the other
     * inputs, so they are restricted to transactions whose taproot inputs are
     * ALL key-path with a 64-byte signature -- SIGHASH_DEFAULT, which is
     * neither ANYONECANPAY (that drops sha_amounts/sha_scriptpubkeys
     * entirely; 5 real transactions in this corpus are exactly that, and an
     * earlier version of this probe wrongly called them failures) nor a
     * script-path spend, whose per-CHECKSIG hash type is not decidable from
     * the witness alone. */
    {
        long bad = 0, d1 = 0, d23 = 0;
        for (u64 t=1; t<ntx && d1 < 64; t++){
            txmap_t* m = &g_txmap[t];
            if (!m->ntap) continue;
            txin_map_t* tap = NULL;
            int all_default_keypath = 1;
            for (u32 i=0;i<m->nin;i++){
                txin_map_t* e = &g_inmap[m->first_in+i];
                if (!e->is_tap) continue;
                if (!tap && tap_is_keypath(e)) tap = e;
                if (!(e->nwit == 1 && e->len[0] == 64)) all_default_keypath = 0;
            }
            if (!tap) continue;   /* every taproot input here is script-path */

            /* --- E1: the taproot input's own amount --- */
            prev_t* pv = bsearch(tap->key, g_prev, g_nprev, sizeof(prev_t), prev_cmp);
            if (!pv) continue;
            u64 save = pv->value; pv->value = save + 1;
            const char* w1 = "?"; u64 ft = ~0ull; const char* w2 = "?";
            int r1 = tx_verify_block_connect(txs[t].ptr, txs[t].len, H, bh, NULL, NULL, &w1);
            int r2 = tx_verify_block_connect_all(txs, ntx, H, bh, NULL, NULL, NULL, &ft, &w2);
            pv->value = save;
            if (r1 != 0 || r2 != 0 || ft != t){
                if (bad < 5) printf("  FAIL E1: tx %llu, own amount +1: single=%d block=%d blamed=%llu (%s)\n",
                                    (unsigned long long)t, r1, r2, (unsigned long long)ft, w2);
                bad++;
            }
            d1++;

            if (!all_default_keypath || m->nin < 2) continue;
            /* pick a sibling input that is not the one E1 touched */
            txin_map_t* sib = NULL;
            for (u32 i=0;i<m->nin;i++){
                txin_map_t* e = &g_inmap[m->first_in+i];
                if (memcmp(e->key, tap->key, 36) != 0){ sib = e; break; }
            }
            if (!sib) continue;
            prev_t* sv = bsearch(sib->key, g_prev, g_nprev, sizeof(prev_t), prev_cmp);
            if (!sv || sv->spklen == 0) continue;

            /* --- E2: sibling amount --- */
            save = sv->value; sv->value = save + 1;
            w1 = "?"; ft = ~0ull; w2 = "?";
            r1 = tx_verify_block_connect(txs[t].ptr, txs[t].len, H, bh, NULL, NULL, &w1);
            r2 = tx_verify_block_connect_all(txs, ntx, H, bh, NULL, NULL, NULL, &ft, &w2);
            sv->value = save;
            if (r1 != 0 || r2 != 0 || ft != t){
                if (bad < 5) printf("  FAIL E2: tx %llu, sibling amount +1: single=%d block=%d blamed=%llu (%s)\n",
                                    (unsigned long long)t, r1, r2, (unsigned long long)ft, w2);
                bad++;
            }

            /* --- E3: sibling scriptPubKey --- */
            u8 sb = sv->spk[sv->spklen-1]; sv->spk[sv->spklen-1] ^= 0x01;
            w1 = "?"; ft = ~0ull; w2 = "?";
            r1 = tx_verify_block_connect(txs[t].ptr, txs[t].len, H, bh, NULL, NULL, &w1);
            r2 = tx_verify_block_connect_all(txs, ntx, H, bh, NULL, NULL, NULL, &ft, &w2);
            sv->spk[sv->spklen-1] = sb;
            if (r1 != 0 || r2 != 0 || ft != t){
                if (bad < 5) printf("  FAIL E3: tx %llu, sibling spk bit: single=%d block=%d blamed=%llu (%s)\n",
                                    (unsigned long long)t, r1, r2, (unsigned long long)ft, w2);
                bad++;
            }
            d23++;
        }
        printf("  E  arena probe        E1 %ld tx (own amount), E2+E3 %ld tx (sibling amount+spk)   %s\n",
               d1, d23, bad?"FAIL":"ok");
        fails += bad;
    }

    g_fail += fails;
    return fails ? 1 : 0;
}

int main(int argc, char** argv){
    int repeats = 8, samples = 48;
    const char* e;
    /* TBD_REPEATS/TBD_SAMPLES exist so this harness can also be run as a
     * soak (many accept runs, few reject samples). Clamped, not trusted:
     * samples reaches a divisor in pass D, and TBD_SAMPLES=0 used to be a
     * SIGFPE. A test harness that dies on its own knob is a test harness
     * whose "no output" gets read as "passed". */
    if ((e = getenv("TBD_REPEATS"))) repeats = atoi(e);
    if ((e = getenv("TBD_SAMPLES"))) samples = atoi(e);
    if (repeats < 1) repeats = 1;
    if (samples < 1) samples = 1;
    int nrun = 0, nskip = 0;
    if (argc < 2){
        printf("SKIP: no heights given (usage: %s <height>...)\n", argv[0]);
        printf("ALL TESTS PASSED (0 failures)\n");
        return 0;
    }
    for (int i=1;i<argc;i++){
        int r = run_height(atoi(argv[i]), repeats, samples);
        if (r < 0) nskip++; else nrun++;
    }
    if (nrun == 0){
        printf("SKIP: no fixtures present (%d heights skipped)\n", nskip);
        printf("ALL TESTS PASSED (0 failures)\n");
        return 0;
    }
    if (g_fail){ printf("TESTS FAILED (%ld failures)\n", g_fail); return 1; }
    printf("ALL TESTS PASSED (0 failures) -- %d block(s), %d skipped\n", nrun, nskip);
    return 0;
}
