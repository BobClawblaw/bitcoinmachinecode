/* test_wallet_scan.c -- the wallet rescan (asm/wallet_scan.c).
 *
 * Hermetic: blocks are served to the scanner from an in-memory array through
 * its read_block hook, so this exercises the scanner itself rather than the
 * archive underneath it. Four blocks cover the cases that actually decide
 * whether the record file can be trusted:
 *
 *   h1  coinbase paying our receive key 0 (P2WPKH)          -> receive
 *   h2  a tx spending it, paying our change key 0 and a
 *       stranger                                            -> spend + receive
 *   h3  a tx paying our receive key 1 as P2PKH              -> receive
 *       (the same key getnewaddress renders as bech32 -- a payer who used
 *        its P2PKH address is still paying this wallet)
 *   h4  a SEGWIT tx paying our receive key 2                -> receive
 *       (the recorded txid must be the STRIPPED serialization, not the
 *        witness one, or nothing downstream can look the tx up)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "../wallet_scan.h"

extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
extern void hash160(unsigned char out[20], const void* in, long long len);
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);
extern int  bip32_derive_path(unsigned char k[32], unsigned char c[32],
                              const unsigned char* seed, long seedlen,
                              const unsigned* indexes, long n);

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

/* ---- block fixture ------------------------------------------------------ */
#define NB 5
static unsigned char g_blk[NB][4096];
static long g_blklen[NB];
static int  g_fail_at = -1;         /* height whose read should fail */

static long fixture_read_block(long h, unsigned char* buf, long cap){
    if (h == g_fail_at) return -3;
    if (h < 0 || h >= NB || g_blklen[h] <= 0) return -3;
    if (g_blklen[h] > cap) return -1;
    memcpy(buf, g_blk[h], (size_t)g_blklen[h]);
    return g_blklen[h];
}

static long put_vi(unsigned char* o, unsigned long v){
    if (v < 0xfd){ o[0] = (unsigned char)v; return 1; }
    o[0] = 0xfd; o[1] = (unsigned char)v; o[2] = (unsigned char)(v >> 8); return 3;
}
static long put_u32(unsigned char* o, unsigned int v){
    for (int i = 0; i < 4; i++) o[i] = (unsigned char)(v >> (8*i)); return 4;
}
static long put_u64(unsigned char* o, unsigned long long v){
    for (int i = 0; i < 8; i++) o[i] = (unsigned char)(v >> (8*i)); return 8;
}

/* ---- key set ------------------------------------------------------------ */
static unsigned char SEED[64];
#define NKEY 8
static wscan_key KEYS[NKEY];

static void derive_h160(unsigned idx, int branch, unsigned char h[20]){
    unsigned path[5] = {0x80000000u|84u, 0x80000000u, 0x80000000u, idx, (unsigned)branch};
    unsigned char k[32], c[32], pub[33];
    if (bip32_derive_path(k, c, SEED, 64, path, 5) != 1){ memset(h, 0, 20); return; }
    scalar_to_pubkey(pub, k);
    hash160(h, pub, 33);
}

/* Build a transaction. `spend` (may be NULL) is a 36-byte outpoint to spend;
 * outs[] are (value, scriptPubKey) pairs. Returns the length. */
typedef struct { unsigned long long val; const unsigned char* spk; unsigned long spklen; } tout;

static long build_tx(unsigned char* o, const unsigned char* spend36,
                     const tout* outs, int nout, int segwit){
    long p = 0;
    p += put_u32(o + p, 2);
    if (segwit){ o[p++] = 0x00; o[p++] = 0x01; }
    p += put_vi(o + p, 1);                                  /* one input */
    if (spend36) { memcpy(o + p, spend36, 36); p += 36; }
    else { memset(o + p, 0, 32); p += 32; p += put_u32(o + p, 0xffffffffu); }
    p += put_vi(o + p, 0);                                  /* empty scriptSig */
    p += put_u32(o + p, 0xfffffffdu);                       /* sequence */
    p += put_vi(o + p, (unsigned long)nout);
    for (int i = 0; i < nout; i++){
        p += put_u64(o + p, outs[i].val);
        p += put_vi(o + p, outs[i].spklen);
        memcpy(o + p, outs[i].spk, outs[i].spklen); p += (long)outs[i].spklen;
    }
    if (segwit){
        o[p++] = 0x02;                                      /* 2 witness items */
        o[p++] = 0x04; memcpy(o + p, "\xde\xad\xbe\xef", 4); p += 4;
        o[p++] = 0x02; o[p++] = 0x11; o[p++] = 0x22;
    }
    p += put_u32(o + p, 0);                                 /* locktime */
    return p;
}

/* The STRIPPED serialization of a tx built by build_tx with segwit=1: the
 * same bytes with the marker/flag and witness section removed. Computed here
 * independently so the test is comparing against its own construction, not
 * against the scanner's. */
static long strip_tx(unsigned char* o, const unsigned char* tx, long len){
    long p = 0;
    memcpy(o, tx, 4); p = 4;
    /* the body runs from just after the marker/flag to just before the
     * witness section; locate the witness start by re-walking */
    long q = 6, cc;
    unsigned long n_in = tx[q]; q += 1;
    for (unsigned long i = 0; i < n_in; i++){
        q += 36;
        unsigned long sl = tx[q]; q += 1 + (long)sl;
        q += 4;
    }
    unsigned long n_out = tx[q]; q += 1;
    for (unsigned long i = 0; i < n_out; i++){
        q += 8;
        unsigned long sl = tx[q]; q += 1 + (long)sl;
    }
    cc = q;                                   /* end of outputs */
    memcpy(o + p, tx + 6, (size_t)(cc - 6)); p += cc - 6;
    memcpy(o + p, tx + len - 4, 4); p += 4;
    return p;
}

static long build_block(unsigned char* o, const unsigned char* const* txs,
                        const long* txlens, int ntx){
    memset(o, 0, 80);
    long p = 80;
    p += put_vi(o + p, (unsigned long)ntx);
    for (int i = 0; i < ntx; i++){ memcpy(o + p, txs[i], (size_t)txlens[i]); p += txlens[i]; }
    return p;
}

int main(void){
    tt_isolate();
    for (int i = 0; i < 64; i++) SEED[i] = (unsigned char)(0x11 * (i + 1));

    /* key window: indexes 0..3 across both branches */
    int nk = 0;
    for (unsigned i = 0; i < 4; i++)
        for (int b = 0; b <= 1; b++){
            derive_h160(i, b, KEYS[nk].h160);
            KEYS[nk].keyidx = i; KEYS[nk].branch = (unsigned char)b; nk++;
        }
    unsigned char r0[20], c0[20], r1[20], r2[20];
    derive_h160(0, 0, r0); derive_h160(0, 1, c0);
    derive_h160(1, 0, r1); derive_h160(2, 0, r2);
    qsort(KEYS, (size_t)nk, sizeof KEYS[0], wscan_key_cmp);
    ck("key window built and sorted", nk == NKEY);

    unsigned char p2wpkh_r0[22] = {0x00,0x14}; memcpy(p2wpkh_r0+2, r0, 20);
    unsigned char p2wpkh_c0[22] = {0x00,0x14}; memcpy(p2wpkh_c0+2, c0, 20);
    unsigned char p2wpkh_r2[22] = {0x00,0x14}; memcpy(p2wpkh_r2+2, r2, 20);
    unsigned char p2pkh_r1[25]  = {0x76,0xa9,0x14};
    memcpy(p2pkh_r1+3, r1, 20); p2pkh_r1[23] = 0x88; p2pkh_r1[24] = 0xac;
    unsigned char stranger[22]  = {0x00,0x14};
    for (int i = 0; i < 20; i++) stranger[2+i] = (unsigned char)(0xC0 + i);

    /* h0: an empty-ish block with a coinbase paying nobody we know */
    static unsigned char tx0[1024]; long l0;
    { tout o[1] = {{ 5000000000ULL, stranger, 22 }};
      l0 = build_tx(tx0, NULL, o, 1, 0); }
    { const unsigned char* t[1] = {tx0}; long L[1] = {l0};
      g_blklen[0] = build_block(g_blk[0], t, L, 1); }

    /* h1: coinbase paying our receive key 0, 50 BTC */
    static unsigned char tx1[1024]; long l1;
    { tout o[1] = {{ 5000000000ULL, p2wpkh_r0, 22 }};
      l1 = build_tx(tx1, NULL, o, 1, 0); }
    unsigned char tx1id[32]; sha256d(tx1id, tx1, (unsigned long)l1);
    { const unsigned char* t[1] = {tx1}; long L[1] = {l1};
      g_blklen[1] = build_block(g_blk[1], t, L, 1); }

    /* h2: spend tx1:0, pay 10 BTC to our change key 0 and the rest away */
    static unsigned char tx2[1024]; long l2;
    { unsigned char op[36]; memcpy(op, tx1id, 32); put_u32(op+32, 0);
      tout o[2] = {{ 1000000000ULL, p2wpkh_c0, 22 }, { 3999000000ULL, stranger, 22 }};
      l2 = build_tx(tx2, op, o, 2, 0); }
    unsigned char tx2id[32]; sha256d(tx2id, tx2, (unsigned long)l2);
    { const unsigned char* t[1] = {tx2}; long L[1] = {l2};
      g_blklen[2] = build_block(g_blk[2], t, L, 1); }

    /* h3: pay our receive key 1 at its P2PKH rendering */
    static unsigned char tx3[1024]; long l3;
    { unsigned char op[36]; memset(op, 0x77, 32); put_u32(op+32, 3);
      tout o[1] = {{ 250000000ULL, p2pkh_r1, 25 }};
      l3 = build_tx(tx3, op, o, 1, 0); }
    { const unsigned char* t[1] = {tx3}; long L[1] = {l3};
      g_blklen[3] = build_block(g_blk[3], t, L, 1); }

    /* h4: a SEGWIT tx paying our receive key 2 */
    static unsigned char tx4[1024]; long l4;
    { unsigned char op[36]; memset(op, 0x88, 32); put_u32(op+32, 1);
      tout o[1] = {{ 700000000ULL, p2wpkh_r2, 22 }};
      l4 = build_tx(tx4, op, o, 1, 1); }
    unsigned char tx4strip[1024]; long l4s = strip_tx(tx4strip, tx4, l4);
    unsigned char tx4id[32]; sha256d(tx4id, tx4strip, (unsigned long)l4s);
    unsigned char tx4wit[32]; sha256d(tx4wit, tx4, (unsigned long)l4);
    ck("the segwit fixture really has a witness (txid != wtxid)",
       memcmp(tx4id, tx4wit, 32) != 0);
    { const unsigned char* t[1] = {tx4}; long L[1] = {l4};
      g_blklen[4] = build_block(g_blk[4], t, L, 1); }

    /* ---- run ------------------------------------------------------------ */
    static unsigned char blockbuf[1 << 20];
    char err[256];
    long n = wscan_run(0, 4, KEYS, nk, fixture_read_block, blockbuf, sizeof blockbuf,
                       "walletscan.dat", 1024, NULL, NULL, err, sizeof err);
    if (n < 0) printf("      (scan error: %s)\n", err);
    ck("scan completed", n >= 0);
    ck("five wallet events found (4 receives + 1 spend across h1..h4)", n == 5);

    wscan_rec rec[16]; long tip = -1;
    long got = wscan_read("walletscan.dat", rec, 16, &tip);
    ck("records read back", got == n);
    ck("the file records the height it covered", tip == 4);

    /* order and content */
    ck("record 0 is the h1 receive of 50 BTC to receive key 0",
       got > 0 && rec[0].height == 1 && rec[0].kind == 0 &&
       rec[0].value == 5000000000ULL && rec[0].keyidx == 0 && rec[0].branch == 0 &&
       !memcmp(rec[0].txid, tx1id, 32) && rec[0].vout == 0);
    /* the spend must be recorded before the receive within the same block,
     * and must carry the value of the output SPENT (50 BTC), not the output
     * created -- getting that backwards silently halves every balance */
    ck("record 1 is the h2 SPEND, carrying the 50 BTC that left",
       got > 1 && rec[1].height == 2 && rec[1].kind == 1 &&
       rec[1].value == 5000000000ULL && rec[1].vout == 0 &&
       !memcmp(rec[1].txid, tx2id, 32));
    ck("the spend is attributed to the key that owned the output",
       got > 1 && rec[1].keyidx == 0 && rec[1].branch == 0);
    ck("record 2 is the h2 receive of 10 BTC to CHANGE key 0",
       got > 2 && rec[2].height == 2 && rec[2].kind == 0 &&
       rec[2].value == 1000000000ULL && rec[2].keyidx == 0 && rec[2].branch == 1 &&
       rec[2].vout == 0);
    ck("record 3 is the h3 P2PKH receive to key 1 (same key, legacy form)",
       got > 3 && rec[3].height == 3 && rec[3].kind == 0 &&
       rec[3].value == 250000000ULL && rec[3].keyidx == 1 && rec[3].branch == 0);
    ck("record 4 is the h4 segwit receive to key 2",
       got > 4 && rec[4].height == 4 && rec[4].kind == 0 &&
       rec[4].value == 700000000ULL && rec[4].keyidx == 2 && rec[4].branch == 0);
    { int ordered = 1;
      for (long i = 1; i < got; i++) if (rec[i].height < rec[i-1].height) ordered = 0;
      ck("records are in ascending height order", ordered); }

    /* the stranger's outputs must NOT appear */
    { int strangers = 0;
      for (long i = 0; i < got; i++)
          if (rec[i].value == 3999000000ULL || rec[i].value == 5000000000ULL * 0) strangers++;
      ck("outputs paying a stranger are not recorded", strangers == 0); }

    /* ---- the segwit txid ------------------------------------------------ */
    { /* widen the window to include key 2's block only */
      long n2 = wscan_run(4, 4, KEYS, nk, fixture_read_block, blockbuf, sizeof blockbuf,
                          "wsegwit.dat", 1024, NULL, NULL, err, sizeof err);
      ck("segwit-only scan completed", n2 == 1);
      wscan_rec r2[4]; long t2;
      long g2 = wscan_read("wsegwit.dat", r2, 4, &t2);
      ck("the segwit receive was found", g2 == 1 && r2[0].value == 700000000ULL);
      ck("the recorded txid is the STRIPPED one, not the witness hash",
         g2 == 1 && !memcmp(r2[0].txid, tx4id, 32));
      ck("...and is definitely not the wtxid",
         g2 == 1 && memcmp(r2[0].txid, tx4wit, 32) != 0); }

    /* ---- an unreadable height ABANDONS, and leaves the old file alone ---- */
    { struct stat before, after;
      stat("walletscan.dat", &before);
      g_fail_at = 2;
      long bad = wscan_run(0, 4, KEYS, nk, fixture_read_block, blockbuf, sizeof blockbuf,
                           "walletscan.dat", 1024, NULL, NULL, err, sizeof err);
      g_fail_at = -1;
      ck("a height that cannot be read fails the scan", bad == -1);
      ck("...and says which height and why",
         strstr(err, "block 2") && strstr(err, "incomplete"));
      ck("the previous record file is untouched",
         stat("walletscan.dat", &after) == 0 && after.st_size == before.st_size);
      ck("no .tmp is left behind", stat("walletscan.dat.tmp", &after) != 0);
      /* and it must still read back as the COMPLETE earlier scan */
      wscan_rec again[16]; long t3;
      ck("the old scan still reads back whole",
         wscan_read("walletscan.dat", again, 16, &t3) == 5 && t3 == 4); }

    /* ---- an owned-set too small ABANDONS rather than missing spends ---- */
    { char e2[256];
      long bad = wscan_run(0, 4, KEYS, nk, fixture_read_block, blockbuf, sizeof blockbuf,
                           "tiny.dat", 2, NULL, NULL, e2, sizeof e2);
      ck("a full owned-outpoint set fails the scan rather than dropping spends",
         bad == -1 && strstr(e2, "owned-outpoint set filled"));
      struct stat st;
      ck("...and writes no output file", stat("tiny.dat", &st) != 0); }

    /* ---- an absent file is 'no scan has completed', not an error ---- */
    { wscan_rec r[4]; long t = 99;
      ck("reading an absent file yields 0 records and tip -1",
         wscan_read("nosuchfile.dat", r, 4, &t) == 0 && t == -1); }

    /* ---- a truncated file is treated as absent, never as partial data ---- */
    { FILE* f = fopen("torn.dat", "wb"); fwrite("BMCWSCN1", 1, 4, f); fclose(f);
      wscan_rec r[4]; long t = 99;
      ck("a short file reads as absent, not as a partial scan",
         wscan_read("torn.dat", r, 4, &t) == 0 && t == -1); }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
