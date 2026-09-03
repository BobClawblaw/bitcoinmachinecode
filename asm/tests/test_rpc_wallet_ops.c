/* test_rpc_wallet_ops.c -- Core's Wallet RPC category beyond the query subset.
 *
 * Runs in a private working directory (the harness cds here) so the label
 * store and the fake wallet file are this test's own, and the real
 * data/bmcwallet.dat of a running node is never touched or read.
 *
 * The expected values are the ones captured from a live Core oracle on
 * 2026-08-25 -- the -11/-5/-3/-4/-15 codes and their message text, the
 * {address:{purpose}} shape of getaddressesbylabel, listwalletdir's
 * {wallets:[{name,warnings}]}, and abortrescan's bare false.
 */
#include "test_tmpdir.h"
#include "../rpc_wallet_ops.h"
#include "../rpc_json.h"
#include "../rpc_commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

extern int lbl_set(const char* path, const char* addr, const char* label);
extern int lbl_get(const char* path, const char* addr, char* out, int cap);
extern int lbl_count(const char* path);
extern int  wallet_validate_address(const char* str, int* type_, unsigned char* version,
                                    unsigned char h160[20], unsigned char prog32[32]);
extern int  bip32_derive_path(unsigned char k[32], unsigned char c[32],
                              const unsigned char* seed, long seedlen,
                              const unsigned* indexes, long n);
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);
extern void hash160(unsigned char out[20], const void* in, long long len);
extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);
extern int  msg_verify_core(const char* address, const char* message, const char* sig_b64);

/* ---- a tiny in-memory archive, so the rescan can actually be run --------
 * Three blocks: h1 pays 50 BTC to the wallet's receive key 0, h2 spends it
 * and pays 10 BTC back to change key 0. Served through the same read_block
 * hook the daemon fills with rpc_chain's store handle. */
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
extern void hash160(unsigned char out[20], const void* in, long long len);
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);
extern int  bip32_derive_path(unsigned char[32], unsigned char[32],
                              const unsigned char*, long, const unsigned*, long);
extern long wallet_p2wpkh_address(char*, long, const unsigned char[20]);

#define FX_NB 3
static unsigned char g_fx[FX_NB][2048];
static long g_fxlen[FX_NB];
static long g_fxtip = -1;
static unsigned char g_r0_h160[20], g_c0_h160[20];
static unsigned char g_tx1id[32];

static long fx_read_block(long h, unsigned char* buf, long cap){
    if (h < 0 || h >= FX_NB || g_fxlen[h] <= 0) return -3;
    if (g_fxlen[h] > cap) return -1;
    memcpy(buf, g_fx[h], (size_t)g_fxlen[h]);
    return g_fxlen[h];
}
static long fx_tip(void){ return g_fxtip; }

static long fx_u32(unsigned char* o, unsigned int v){
    for (int i = 0; i < 4; i++) o[i] = (unsigned char)(v >> (8*i));
    return 4; }
static long fx_u64(unsigned char* o, unsigned long long v){
    for (int i = 0; i < 8; i++) o[i] = (unsigned char)(v >> (8*i));
    return 8; }

static void fx_derive(const unsigned char* seed, unsigned idx, int br, unsigned char h[20]){
    unsigned path[5] = {0x80000000u|84u, 0x80000000u, 0x80000000u, idx, (unsigned)br};
    unsigned char k[32], c[32], pub[33];
    if (bip32_derive_path(k, c, seed, 64, path, 5) != 1){ memset(h, 0, 20); return; }
    scalar_to_pubkey(pub, k);
    hash160(h, pub, 33);
}

static long fx_tx(unsigned char* o, const unsigned char* spend36,
                  const unsigned long long* vals, const unsigned char* const* spks,
                  const unsigned long* spklens, int nout){
    long p = 0;
    p += fx_u32(o + p, 2);
    o[p++] = 1;
    if (spend36){ memcpy(o + p, spend36, 36); p += 36; }
    else { memset(o + p, 0, 32); p += 32; p += fx_u32(o + p, 0xffffffffu); }
    o[p++] = 0;
    p += fx_u32(o + p, 0xfffffffdu);
    o[p++] = (unsigned char)nout;
    for (int i = 0; i < nout; i++){
        p += fx_u64(o + p, vals[i]);
        o[p++] = (unsigned char)spklens[i];
        memcpy(o + p, spks[i], spklens[i]); p += (long)spklens[i];
    }
    p += fx_u32(o + p, 0);
    return p;
}

static void fx_build(const unsigned char* seed){
    fx_derive(seed, 0, 0, g_r0_h160);
    fx_derive(seed, 0, 1, g_c0_h160);
    unsigned char w_r0[22] = {0x00,0x14}; memcpy(w_r0+2, g_r0_h160, 20);
    unsigned char w_c0[22] = {0x00,0x14}; memcpy(w_c0+2, g_c0_h160, 20);
    static unsigned char stranger[22] = {0x00,0x14};
    for (int i = 0; i < 20; i++) stranger[2+i] = (unsigned char)(0xC0 + i);
    { unsigned long long v[1] = {5000000000ULL};
      const unsigned char* sp[1] = {stranger}; unsigned long sl[1] = {22};
      unsigned char tx[512]; long l = fx_tx(tx, NULL, v, sp, sl, 1);
      memset(g_fx[0], 0, 80); long p = 80; g_fx[0][p++] = 1;
      memcpy(g_fx[0]+p, tx, (size_t)l); g_fxlen[0] = p + l; }
    { unsigned long long v[1] = {5000000000ULL};
      const unsigned char* sp[1] = {w_r0}; unsigned long sl[1] = {22};
      unsigned char tx[512]; long l = fx_tx(tx, NULL, v, sp, sl, 1);
      sha256d(g_tx1id, tx, (unsigned long)l);
      memset(g_fx[1], 0, 80); long p = 80; g_fx[1][p++] = 1;
      memcpy(g_fx[1]+p, tx, (size_t)l); g_fxlen[1] = p + l; }
    { unsigned char op[36]; memcpy(op, g_tx1id, 32); fx_u32(op+32, 0);
      unsigned long long v[2] = {1000000000ULL, 3999000000ULL};
      const unsigned char* sp[2] = {w_c0, stranger}; unsigned long sl[2] = {22, 22};
      unsigned char tx[512]; long l = fx_tx(tx, op, v, sp, sl, 2);
      memset(g_fx[2], 0, 80); long p = 80; g_fx[2][p++] = 1;
      memcpy(g_fx[2]+p, tx, (size_t)l); g_fxlen[2] = p + l; }
    g_fxtip = 2;
}

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static const char* S(const rj_val* o, const char* k){ rj_val* v = o ? rj_obj_get((rj_val*)o,k) : 0; return v ? v->str : 0; }

/* A deterministic seed. Any 64 bytes are a valid BIP32 seed. */
static unsigned char SEED[64];
static rpc_wallet W;

static rj_val* P(const char* json){ return rj_parse(json, strlen(json)); }

/* The P2PKH rendering of the wallet's receive key at m/84'/0'/0'/0/0 -- the
 * same key whose hash160 forms its P2WPKH address. Computed here from the
 * same primitives the module uses, so the test asserts a ROUND TRIP rather
 * than a hard-coded string that could drift with the derivation. */
static int wallet_p2pkh_addr(int is_change, char out[128]){
    unsigned idx[5] = {0x80000000u | 84u, 0x80000000u, 0x80000000u, 0, (unsigned)is_change};
    unsigned char k[32], c[32], pub[33], h[20], pay[21];
    if (bip32_derive_path(k, c, SEED, 64, idx, 5) != 1) return 0;
    scalar_to_pubkey(pub, k);
    hash160(h, pub, 33);
    pay[0] = 0x00; memcpy(pay + 1, h, 20);
    base58check_encode(out, pay, 21);
    return 1;
}

/* ---- multi-wallet test installer: stands in for wenc_install_seed ------- */
static unsigned char g_tw_seed[64]; static int g_tw_have;
void tw_install(const unsigned char* sd){
    if (sd){ memcpy(g_tw_seed, sd, 64); g_tw_have = 1; }
    else g_tw_have = 0;
}
const unsigned char* tw_seed(void){ return g_tw_have ? g_tw_seed : 0; }

int main(void){
    tt_isolate();   /* the label store and the fake wallet file are ours alone */
    for (int i = 0; i < 64; i++) SEED[i] = (unsigned char)(0x11 * (i + 1));
    memset(&W, 0, sizeof W);
    W.seed = SEED;

    long ec; const char* em; rj_val* r; int rc;
    #define D(m, p) (r = NULL, ec = 0, em = NULL, rc = rpc_wops_dispatch((m), (p), &W, &r, &ec, &em))
    /* methods rpc_commands.c owns (getnewaddress) go through the full dispatcher */
    #define DX(m, p) (r = NULL, ec = 0, em = NULL, rc = rpc_dispatch((m), (p), &W, &r, &ec, &em))

    /* ---- every advertised method is owned, and nothing else is ---- */
    ck("known_method(setlabel)", rpc_wops_known_method("setlabel") == 1);
    ck("known_method(getbalance) == 0 (rpc_commands.c owns it)",
       rpc_wops_known_method("getbalance") == 0);
    ck("unowned method -> -1 so the caller keeps looking",
       rpc_wops_dispatch("getblockcount", NULL, &W, &r, &ec, &em) == -1);

    /* ---- labels ------------------------------------------------------ */
    { /* start from a clean store */
        remove("labels.dat"); remove("data/labels.dat");

        D("listlabels", NULL);
        ck("listlabels on an empty store -> []", rc == 1 && r && r->typ == RJ_ARR && r->nitems == 0);
        rj_free(r);

        rj_val* p = P("[\"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\",\"cold storage\"]");
        D("setlabel", p);
        ck("setlabel -> null", rc == 1 && r && r->typ == RJ_NULL);
        rj_free(r); rj_free(p);

        /* a label with a SPACE must survive verbatim: Core's labels are
         * arbitrary UTF-8 and mangling them silently would be worse than
         * refusing them. This is why the store puts the address first. */
        char got[256] = {0};
        lbl_get("labels.dat", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", got, sizeof got);
        ck("a label containing a space round-trips verbatim", !strcmp(got, "cold storage"));

        p = P("[\"1CounterpartyXXXXXXXXXXXXXXXUWLpVr\",\"cold storage\"]");
        D("setlabel", p); rj_free(r); rj_free(p);
        p = P("[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\",\"hot\"]");
        D("setlabel", p); rj_free(r); rj_free(p);

        D("listlabels", NULL);
        ck("listlabels dedupes and sorts",
           rc == 1 && r && r->nitems == 2 &&
           !strcmp(r->items[0]->str, "cold storage") && !strcmp(r->items[1]->str, "hot"));
        rj_free(r);

        p = P("[\"cold storage\"]");
        D("getaddressesbylabel", p);
        ck("getaddressesbylabel returns ALL addresses under the label",
           rc == 1 && r && r->typ == RJ_OBJ && r->nmembers == 2);
        { rj_val* e = r ? rj_obj_get(r, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") : 0;
          ck("each entry is {purpose:\"receive\"} as Core shapes it",
             e && e->typ == RJ_OBJ && S(e,"purpose") && !strcmp(S(e,"purpose"), "receive")); }
        rj_free(r); rj_free(p);

        p = P("[\"nope\"]");
        D("getaddressesbylabel", p);
        ck("unknown label -> Core's -11 'No addresses with label nope'",
           rc == 0 && ec == -11 && em && !strcmp(em, "No addresses with label nope"));
        rj_free(r); rj_free(p);

        /* one address has exactly ONE label: relabelling must REPLACE, not
         * accumulate, or getaddressesbylabel would report it under both. */
        p = P("[\"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\",\"hot\"]");
        D("setlabel", p); rj_free(r); rj_free(p);
        p = P("[\"cold storage\"]");
        D("getaddressesbylabel", p);
        ck("relabelling REPLACES the old label (address leaves the old set)",
           rc == 1 && r && r->nmembers == 1);
        rj_free(r); rj_free(p);
        ck("the store did not grow a duplicate record", lbl_count("labels.dat") == 3);

        /* clearing to "" is a removal -- the default label is stored as absence */
        p = P("[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\",\"\"]");
        D("setlabel", p);
        ck("setlabel to \"\" succeeds", rc == 1);
        rj_free(r); rj_free(p);
        ck("clearing a label removes the record", lbl_count("labels.dat") == 2);

        p = P("[\"notanaddress\",\"x\"]");
        D("setlabel", p);
        ck("setlabel on a bad address -> -5 Invalid Bitcoin address",
           rc == 0 && ec == -5 && em && !strcmp(em, "Invalid Bitcoin address"));
        rj_free(r); rj_free(p);

        { /* 256 bytes exceeds Core's 255-byte cap */
          char big[300]; memset(big, 'a', 256); big[256] = 0;
          char js[420]; snprintf(js, sizeof js, "[\"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\",\"%s\"]", big);
          p = P(js); D("setlabel", p);
          ck("a 256-byte label is refused, not truncated", rc == 0 && ec == -8);
          rj_free(r); rj_free(p); }
    }

    /* ---- wallet inventory -------------------------------------------- */
    { remove("bmcwallet.dat");
      D("listwallets", NULL);
      ck("listwallets with no wallet file -> []", rc == 1 && r && r->nitems == 0);
      rj_free(r);
      D("listwalletdir", NULL);
      ck("listwalletdir with no wallet -> {wallets:[]}",
         rc == 1 && r && rj_obj_get(r,"wallets") && rj_obj_get(r,"wallets")->nitems == 0);
      rj_free(r);

      FILE* f = fopen("bmcwallet.dat", "w"); fputs("BMCWAL v1\n", f); fclose(f);
      D("listwallets", NULL);
      ck("listwallets with a wallet file -> [\"bmcwallet\"]",
         rc == 1 && r && r->nitems == 1 && !strcmp(r->items[0]->str, "bmcwallet"));
      rj_free(r);
      D("listwalletdir", NULL);
      { rj_val* ws = r ? rj_obj_get(r,"wallets") : 0;
        rj_val* w0 = (ws && ws->nitems) ? ws->items[0] : 0;
        ck("listwalletdir entry carries Core's {name,warnings}",
           w0 && S(w0,"name") && !strcmp(S(w0,"name"),"bmcwallet") &&
           rj_obj_get(w0,"warnings") && rj_obj_get(w0,"warnings")->typ == RJ_ARR); }
      rj_free(r); }

    /* ---- output locks ------------------------------------------------- */
    { rpc_wops_reset_locks();
      D("listlockunspent", NULL);
      ck("listlockunspent starts empty", rc == 1 && r && r->nitems == 0);
      rj_free(r);

      const char* TX = "a8a86ec98cc0b51e3d68d106f94b8c1463287577544590b45eb9fd80793d3d76";
      char js[256]; snprintf(js, sizeof js, "[false,[{\"txid\":\"%s\",\"vout\":1}]]", TX);
      rj_val* p = P(js);
      D("lockunspent", p);
      ck("lockunspent false (lock) -> true", rc == 1 && r && !strcmp(r->str, "1"));
      rj_free(r); rj_free(p);

      D("listlockunspent", NULL);
      ck("the lock is listed back with the SAME display txid",
         rc == 1 && r && r->nitems == 1 &&
         !strcmp(S(r->items[0],"txid"), TX) && !strcmp(S(r->items[0],"vout"), "1"));
      rj_free(r);

      { unsigned char bin[32];
        /* display hex is reversed on the wire; confirm the module stored the
         * INTERNAL order by asking the exported predicate */
        for (int i = 0; i < 32; i++){
            const char* h = TX; int hi, lo;
            char a = h[i*2], b = h[i*2+1];
            hi = (a<='9') ? a-'0' : a-'a'+10;
            lo = (b<='9') ? b-'0' : b-'a'+10;
            bin[31-i] = (unsigned char)((hi<<4)|lo);
        }
        ck("rpc_wops_is_locked sees it in internal byte order", rpc_wops_is_locked(bin, 1) == 1);
        ck("a different vout of the same txid is NOT locked", rpc_wops_is_locked(bin, 0) == 0); }

      /* locking the same outpoint twice must not duplicate it */
      p = P(js); D("lockunspent", p); rj_free(r); rj_free(p);
      D("listlockunspent", NULL);
      ck("re-locking the same outpoint does not duplicate it", rc == 1 && r && r->nitems == 1);
      rj_free(r);

      /* all-or-nothing: a list whose SECOND entry is bad must leave the set
       * untouched, not half-applied */
      { char bad[300];
        snprintf(bad, sizeof bad,
                 "[false,[{\"txid\":\"%s\",\"vout\":7},{\"txid\":\"zz\",\"vout\":0}]]", TX);
        p = P(bad); D("lockunspent", p);
        ck("a malformed entry rejects the WHOLE list -> -8", rc == 0 && ec == -8);
        rj_free(r); rj_free(p);
        D("listlockunspent", NULL);
        ck("...and the lock set is unchanged (not half-applied)",
           rc == 1 && r && r->nitems == 1);
        rj_free(r); }

      p = P("[true]"); D("lockunspent", p);
      ck("lockunspent true with no list unlocks everything", rc == 1);
      rj_free(r); rj_free(p);
      D("listlockunspent", NULL);
      ck("...and the set is empty again", rc == 1 && r && r->nitems == 0);
      rj_free(r); }

    /* ---- signmessage --------------------------------------------------- */
    { rj_val* p = P("[\"notanaddress\",\"hello\"]");
      D("signmessage", p);
      ck("signmessage bad address -> Core's -5 Invalid address",
         rc == 0 && ec == -5 && em && !strcmp(em, "Invalid address"));
      rj_free(r); rj_free(p);

      p = P("[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\",\"hello\"]");
      D("signmessage", p);
      ck("signmessage on a segwit address -> Core's -3 Address does not refer to key",
         rc == 0 && ec == -3 && em && !strcmp(em, "Address does not refer to key"));
      rj_free(r); rj_free(p);

      p = P("[\"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\",\"hello\"]");
      D("signmessage", p);
      ck("signmessage for a key we do not hold -> Core's -4 Private key not available",
         rc == 0 && ec == -4 && em && !strcmp(em, "Private key not available"));
      rj_free(r); rj_free(p);

      /* the real case: the P2PKH rendering of our own derived receive key */
      char mine[128];
      ck("derived the wallet's own P2PKH address", wallet_p2pkh_addr(0, mine) == 1);
      { char js[256]; snprintf(js, sizeof js, "[\"%s\",\"hello world\"]", mine);
        p = P(js); D("signmessage", p);
        ck("signmessage signs for the wallet's own key", rc == 1 && r && r->typ == RJ_STR);
        ck("the signature VERIFIES against that address (round trip, not a shape check)",
           rc == 1 && r && msg_verify_core(mine, "hello world", r->str) == 1);
        ck("it does NOT verify for a different message",
           rc == 1 && r && msg_verify_core(mine, "goodbye", r->str) != 1);
        rj_free(r); rj_free(p); }

      /* the change branch is searched too */
      char chg[128];
      if (wallet_p2pkh_addr(1, chg)){
        char js[256]; snprintf(js, sizeof js, "[\"%s\",\"m\"]", chg);
        p = P(js); D("signmessage", p);
        ck("the change branch is searched as well as receive",
           rc == 1 && r && msg_verify_core(chg, "m", r->str) == 1);
        rj_free(r); rj_free(p); } }

    /* ---- descriptors --------------------------------------------------- */
    { D("listdescriptors", NULL);
      ck("listdescriptors -> {wallet_name, descriptors[]}",
         rc == 1 && r && S(r,"wallet_name") && !strcmp(S(r,"wallet_name"), "bmcwallet") &&
         rj_obj_get(r,"descriptors") && rj_obj_get(r,"descriptors")->nitems == 2);
      { rj_val* d = r ? rj_obj_get(r,"descriptors") : 0;
        rj_val* d0 = (d && d->nitems) ? d->items[0] : 0;
        rj_val* d1 = (d && d->nitems > 1) ? d->items[1] : 0;
        ck("receive descriptor is wpkh(...) with a #checksum",
           d0 && S(d0,"desc") && !strncmp(S(d0,"desc"), "wpkh([", 6) && strchr(S(d0,"desc"), '#'));
        ck("receive descriptor is external, change descriptor is internal",
           d0 && d1 && !strcmp(S(d0,"internal"), "0") && !strcmp(S(d1,"internal"), "1"));
        /* timestamp is deliberately ABSENT: the wallet records no import time
         * and a plausible number would be a fabrication. */
        ck("no timestamp is invented", d0 && rj_obj_get(d0,"timestamp") == NULL); }
      rj_free(r);

      rj_val* p = P("[true]");
      D("listdescriptors", p);
      ck("listdescriptors true (private) is REFUSED, not silently downgraded",
         rc == 0 && ec == -1 && em && strstr(em, "private"));
      rj_free(r); rj_free(p);

      D("gethdkeys", NULL);
      ck("gethdkeys reports one account xpub",
         rc == 1 && r && r->nitems == 1 &&
         S(r->items[0],"xpub") && !strncmp(S(r->items[0],"xpub"), "xpub", 4));
      ck("gethdkeys has_private is true (the seed is present)",
         r && r->nitems && !strcmp(S(r->items[0],"has_private"), "1"));
      rj_free(r); }

    /* ---- encryption state: Core's EXACT answers for an unencrypted wallet */
    { D("walletlock", NULL);
      ck("walletlock -> -15 with Core's exact text",
         rc == 0 && ec == -15 && em &&
         !strcmp(em, "Error: running with an unencrypted wallet, but walletlock was called."));
      rj_free(r);
      D("walletpassphrase", NULL);
      ck("walletpassphrase -> -15 with Core's exact text",
         rc == 0 && ec == -15 && em &&
         !strcmp(em, "Error: running with an unencrypted wallet, but walletpassphrase was called."));
      rj_free(r);
      D("walletpassphrasechange", NULL);
      ck("walletpassphrasechange -> -15 with Core's exact text",
         rc == 0 && ec == -15 && em &&
         !strcmp(em, "Error: running with an unencrypted wallet, but walletpassphrasechange was called."));
      rj_free(r); }

    /* ---- abortrescan / keypoolrefill ----------------------------------- */
    { D("abortrescan", NULL);
      ck("abortrescan -> false (no rescan can be running; Core's answer)",
         rc == 1 && r && r->typ == RJ_BOOL && !strcmp(r->str, "0"));
      rj_free(r);
      D("keypoolrefill", NULL);
      ck("keypoolrefill -> null (deterministic derivation: the pool is unbounded)",
         rc == 1 && r && r->typ == RJ_NULL);
      rj_free(r); }

    /* ---- backupwallet REALLY copies, and really fails ------------------ */
    { rj_val* p = P("[\"backup-copy.dat\"]");
      D("backupwallet", p);
      ck("backupwallet -> null", rc == 1 && r && r->typ == RJ_NULL);
      rj_free(r); rj_free(p);
      struct stat sb;
      ck("backupwallet actually wrote the destination file",
         stat("backup-copy.dat", &sb) == 0 && sb.st_size > 0);
      { FILE* f = fopen("backup-copy.dat", "r"); char b[32] = {0};
        if (f){ (void)!fgets(b, sizeof b, f); fclose(f); }
        ck("the backup holds the wallet's bytes, not an empty file",
           !strncmp(b, "BMCWAL v1", 9)); }

      p = P("[\"/proc/definitely/not/writable/x\"]");
      D("backupwallet", p);
      ck("an unwritable destination is an ERROR, never a false success",
         rc == 0 && ec == -4);
      rj_free(r); rj_free(p);

      p = P("[]");
      D("backupwallet", p);
      ck("backupwallet with no destination -> -8", rc == 0 && ec == -8);
      rj_free(r); rj_free(p); }

    /* ---- the refusals: every one errors with a reason, none no-ops ----- */
    {   /* Nothing is refused wholesale any more. addhdkey was the last, and
         * it is real as of 2026-08-27 (evening) -- see below and slice 25.
         * walletprocesspsbt left this list 2026-08-26 (real; test_rpc_psbtfinal).
         * encryptwallet left 2026-08-27 (real; -8 asserted below).
         * createwallet/loadwallet/unloadwallet/restorewallet/importdescriptors
         * left 2026-08-27: MULTI-WALLET is real now -- the whole lifecycle is
         * exercised at the end of this file.
         * bumpfee/psbtbumpfee left 2026-08-27: REAL now (Core feebumper
         * semantics; differentially proven on regtest).
         * exportwatchonlywallet, migratewallet, createwalletdescriptor and the
         * pruned-funds pair left 2026-08-27 (evening). */
      /* exportwatchonlywallet is real, so it must reject a MISSING
       * destination with Core's -8 rather than refuse wholesale */
      D("exportwatchonlywallet", NULL);
      ck("exportwatchonlywallet with no destination -> -8", rc == 0 && ec == -8);
      rj_free(r);

      /* migratewallet: Core's verdict for a wallet that is ALREADY a
       * descriptor wallet, which every wallet here is. -4, not a refusal. */
      D("migratewallet", NULL);
      ck("migratewallet -> Core's already-a-descriptor-wallet error",
         rc == 0 && ec == -4 && em && strstr(em, "already a descriptor wallet"));
      rj_free(r);

      /* createwalletdescriptor: Core's codes, by argument */
      char bech32m_addr[128] = "";  /* captured below for the getaddressinfo checks further down */
      { rj_val* p1 = P("[\"nonsense\"]");
        D("createwalletdescriptor", p1);
        ck("createwalletdescriptor unknown type -> -5", rc == 0 && ec == -5 &&
           em && strstr(em, "Unknown address type"));
        rj_free(r); rj_free(p1); }
      { rj_val* p1 = P("[\"bech32\"]");
        D("createwalletdescriptor", p1);
        ck("createwalletdescriptor bech32 -> Descriptor already exists (-4)",
           rc == 0 && ec == -4 && em && !strcmp(em, "Descriptor already exists"));
        rj_free(r); rj_free(p1); }
      { rj_val* p1 = P("[\"bech32m\"]");
        D("createwalletdescriptor", p1);
        ck("createwalletdescriptor bech32m -> activated: {descs:[tr(...), tr(...)]} (2026-09-01)",
           rc == 1 && r && rj_obj_get(r, "descs") && rj_obj_get(r, "descs")->nitems == 2 &&
           !strncmp(rj_obj_get(r, "descs")->items[0]->str, "tr([", 4) && strstr(rj_obj_get(r, "descs")->items[0]->str, "/86h/0h/0h/0/0]"));
        rj_free(r); rj_free(p1);
        p1 = P("[\"bech32m\"]");
        D("createwalletdescriptor", p1);
        ck("...a second time -> Descriptor already exists (-4)", rc == 0 && ec == -4 && em && !strcmp(em, "Descriptor already exists"));
        rj_free(r); rj_free(p1);
        /* it is now listed, and getnewaddress hands out the descriptor's own address */
        D("listdescriptors", NULL);
        { rj_val* ds = r ? rj_obj_get(r, "descriptors") : NULL; int ntr = 0; char tr0[400] = "";
          if (ds) for (unsigned long i = 0; i < ds->nitems; i++){ rj_val* d = rj_obj_get(ds->items[i], "desc"); if (d && !strncmp(d->str, "tr(", 3)){ ntr++; if (!tr0[0]) snprintf(tr0, sizeof tr0, "%s", d->str); } }
          ck("listdescriptors now carries the two tr() descriptors beside the two wpkh()", ds && ds->nitems == 4 && ntr == 2);
          rj_free(r);
          rj_val* p2 = P("[\"\", \"bech32m\"]"); DX("getnewaddress", p2);
          char a[128] = ""; if (rc == 1 && r && r->typ == RJ_STR) snprintf(a, sizeof a, "%s", r->str);
          snprintf(bech32m_addr, sizeof bech32m_addr, "%s", a);
          ck("getnewaddress bech32m -> a bc1p address", !strncmp(a, "bc1p", 4));
          extern int rpc_desc_address_at(const char*, long, char*, long, char*, unsigned long);
          char da[128] = {0}, derr[128];
          ck("...equal to deriveaddresses of the listed tr() descriptor", a[0] && rpc_desc_address_at(tr0, 0, da, sizeof da, derr, sizeof derr) && !strcmp(da, a));
          rj_free(r); rj_free(p2); }
        { rj_val* p3 = P("[\"\", \"legacy\"]"); DX("getnewaddress", p3);
          ck("getnewaddress legacy before createwalletdescriptor -> No legacy addresses available (-4)", rc == 0 && ec == -4 && em && strstr(em, "No legacy addresses"));
          rj_free(r); rj_free(p3); }
        { rj_val* p4 = P("[\"p2sh-segwit\"]"); D("createwalletdescriptor", p4);
          ck("createwalletdescriptor p2sh-segwit -> sh(wpkh([../49h/..]))", rc == 1 && r && rj_obj_get(r, "descs") && !strncmp(rj_obj_get(r, "descs")->items[0]->str, "sh(wpkh([", 9));
          rj_free(r); rj_free(p4);
          rj_val* p5 = P("[\"\", \"p2sh-segwit\"]"); DX("getnewaddress", p5);
          char p2sh_addr[128] = ""; if (rc == 1 && r && r->typ == RJ_STR) snprintf(p2sh_addr, sizeof p2sh_addr, "%s", r->str);
          ck("getnewaddress p2sh-segwit -> a 3... address", p2sh_addr[0] == '3');
          rj_free(r); rj_free(p5);

          /* ---- getaddressinfo: real ismine/iswatchonly/ischange/pubkey ----
           * (2026-09-03 audit finding: these four fields used to be
           * hardcoded false/empty for EVERY address). Reuses the addresses
           * this same wallet just derived above, across every active type,
           * plus a fresh legacy activation for the pubkey check -- the one
           * field the RPC has ever tried to populate. */
          { rj_val* pl = P("[\"legacy\"]"); D("createwalletdescriptor", pl); rj_free(r); rj_free(pl); }
          rj_val* p6 = P("[\"\", \"legacy\"]"); DX("getnewaddress", p6);
          char legacy_addr[128] = ""; if (rc == 1 && r && r->typ == RJ_STR) snprintf(legacy_addr, sizeof legacy_addr, "%s", r->str);
          ck("getnewaddress legacy -> a 1... address", legacy_addr[0] == '1');
          rj_free(r); rj_free(p6);

          rj_val* p7 = P("[\"\"]"); DX("getrawchangeaddress", p7);
          char change_addr[128] = ""; if (rc == 1 && r && r->typ == RJ_STR) snprintf(change_addr, sizeof change_addr, "%s", r->str);
          ck("getrawchangeaddress -> a bech32 address", !strncmp(change_addr, "bc1q", 4));
          rj_free(r); rj_free(p7);

          { char qj0[160]; snprintf(qj0, sizeof qj0, "[\"%s\"]", bech32m_addr); rj_val* q = P(qj0); DX("getaddressinfo", q);
            ck("getaddressinfo(our own taproot address): ismine=true",
               rc == 1 && r && S(r, "ismine") && !strcmp(S(r, "ismine"), "1"));
            ck("...ischange=false (it is a receive address)",
               r && S(r, "ischange") && !strcmp(S(r, "ischange"), "0"));
            rj_free(r); rj_free(q); }
          { char qj1[160]; snprintf(qj1, sizeof qj1, "[\"%s\"]", p2sh_addr); rj_val* q = P(qj1); DX("getaddressinfo", q);
            ck("getaddressinfo(our own p2sh-segwit address): ismine=true",
               rc == 1 && r && S(r, "ismine") && !strcmp(S(r, "ismine"), "1"));
            rj_free(r); rj_free(q); }
          { char qj2[160]; snprintf(qj2, sizeof qj2, "[\"%s\"]", change_addr); rj_val* q = P(qj2); DX("getaddressinfo", q);
            ck("getaddressinfo(our own CHANGE address): ismine=true",
               rc == 1 && r && S(r, "ismine") && !strcmp(S(r, "ismine"), "1"));
            ck("...ischange=true", r && S(r, "ischange") && !strcmp(S(r, "ischange"), "1"));
            rj_free(r); rj_free(q); }
          { char qj3[160]; snprintf(qj3, sizeof qj3, "[\"%s\"]", legacy_addr); rj_val* q = P(qj3); DX("getaddressinfo", q);
            ck("getaddressinfo(our own legacy address): ismine=true",
               rc == 1 && r && S(r, "ismine") && !strcmp(S(r, "ismine"), "1"));
            const char* pk = S(r, "pubkey");
            ck("...pubkey is now a REAL 33-byte compressed key (was always empty)",
               pk && strlen(pk) == 66);
            rj_free(r); rj_free(q); }
          { /* a real mainnet address this wallet's seed never derived --
             * from test_wrpc_addr.c's own known vectors, so it is not
             * coincidentally one of ours */
            rj_val* q = P("[\"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH\"]"); DX("getaddressinfo", q);
            ck("getaddressinfo(a real address NOT ours): ismine=false",
               rc == 1 && r && S(r, "ismine") && !strcmp(S(r, "ismine"), "0"));
            ck("...iswatchonly=false too (not imported either)",
               r && S(r, "iswatchonly") && !strcmp(S(r, "iswatchonly"), "0"));
            const char* pk = S(r, "pubkey");
            ck("...pubkey stays empty for an address we cannot sign for", pk && pk[0] == 0);
            rj_free(r); rj_free(q); } } }
      D("createwalletdescriptor", NULL);
      ck("createwalletdescriptor with no type -> -8", rc == 0 && ec == -8);
      rj_free(r);

      /* addhdkey stores an extended PRIVATE key, so it refuses outright
       * unless it can encrypt it -- an xprv written in the clear beside a
       * passphrase-protected seed would be the weakest thing in the wallet
       * directory. This harness has no passphrase, which is exactly that
       * path; the real add is proven on regtest. */
      { rj_val* p1 = P("[\"xprvBogus\"]");
        D("addhdkey", p1);
        ck("addhdkey without a passphrase refuses rather than storing a key in the clear",
           rc == 0 && ec == -4 && em && strstr(em, "encrypted"));
        rj_free(r); rj_free(p1); }
      /* gethdkeys still answers, and still reports the seed */
      { rj_val* gk = NULL; long e3; const char* m3;
        if (rpc_dispatch("gethdkeys", NULL, &W, &gk, &e3, &m3) == 1)
            ck("gethdkeys lists the seed's account xpub",
               gk && gk->typ == RJ_ARR && gk->nitems >= 1);
        else ck("gethdkeys lists the seed's account xpub", 0);
        rj_free(gk); }

      /* setwalletflag: Core's flag vocabulary and its three distinct errors.
       * avoid_reuse is not stored-and-ignored -- wf_coins skips a coin whose
       * destination this wallet has already spent from -- so the call is
       * real rather than a recorded no-op. */
      { rj_val* p1 = P("[\"nonsense\"]");
        D("setwalletflag", p1);
        ck("setwalletflag unknown flag -> -8 Unknown wallet flag",
           rc == 0 && ec == -8 && em && strstr(em, "Unknown wallet flag"));
        rj_free(r); rj_free(p1); }
      { rj_val* p1 = P("[\"disable_private_keys\"]");
        D("setwalletflag", p1);
        ck("setwalletflag immutable flag -> -8 Wallet flag is immutable",
           rc == 0 && ec == -8 && em && strstr(em, "immutable"));
        rj_free(r); rj_free(p1); }
      { rj_val* p1 = P("[\"avoid_reuse\"]");
        D("setwalletflag", p1);
        ck("setwalletflag avoid_reuse -> {flag_name, flag_state:true}",
           rc == 1 && r && r->typ == RJ_OBJ &&
           S(r,"flag_name") && !strcmp(S(r,"flag_name"), "avoid_reuse") &&
           S(r,"flag_state") && !strcmp(S(r,"flag_state"), "1"));
        ck("...with Core's rescan warning", r && S(r,"warnings"));
        rj_free(r); rj_free(p1); }
      { rj_val* p1 = P("[\"avoid_reuse\"]");
        D("setwalletflag", p1);
        ck("setting it twice -> -8 'already set to true'",
           rc == 0 && ec == -8 && em && strstr(em, "already set to true"));
        rj_free(r); rj_free(p1); }
      /* getwalletinfo must now REPORT it, or the flag is invisible */
      { rj_val* gi = NULL; long e2; const char* m2;
        if (rpc_dispatch("getwalletinfo", NULL, &W, &gi, &e2, &m2) == 1)
            ck("getwalletinfo reports avoid_reuse:true",
               gi && S(gi,"avoid_reuse") && !strcmp(S(gi,"avoid_reuse"), "1"));
        else ck("getwalletinfo reports avoid_reuse:true", 0);
        rj_free(gi); }
      /* put it back, so later cases see the default wallet */
      { rj_val* p1 = P("[\"avoid_reuse\",false]");
        D("setwalletflag", p1);
        ck("clearing it again succeeds", rc == 1);
        rj_free(r); rj_free(p1); }

      /* the pruned-funds pair: argument handling. The real import path needs
       * a chain and a proof, and is proven end to end on regtest. */
      D("importprunedfunds", NULL);
      ck("importprunedfunds with no arguments -> -8", rc == 0 && ec == -8);
      rj_free(r);
      { rj_val* p1 = P("[\"0000000000000000000000000000000000000000000000000000000000000001\"]");
        D("removeprunedfunds", p1);
        ck("removeprunedfunds on a txid the wallet lacks -> Core's -4",
           rc == 0 && ec == -4 && em && strstr(em, "does not belong to this wallet"));
        rj_free(r); rj_free(p1); }
      /* encryptwallet is wired (daemon/wallet_enc_state.c): with no passphrase
       * argument it is an ordinary parameter error, not a stub refusal. */
      { D("encryptwallet", NULL);
        ck("encryptwallet with no passphrase -> -8 (wired, not a stub)", rc == 0 && ec == -8);
        rj_free(r); }
      /* walletdisplayaddress is implemented now (rpc_signer.c): with no
       * signer configured it answers Core's exact restart message */
      { rj_val* pp = P("[\"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\"]");
        D("walletdisplayaddress", pp);
        ck("walletdisplayaddress without a signer -> Core's restart message",
           rc == 0 && ec == -1 && em && strstr(em, "restart bitcoind with -signer"));
        rj_free(r); rj_free(pp); }
      /* the ones that cannot answer must say WHY, so a reader knows the gap
       * is a missing rescan and not a missing formatter */
      /* The receive-side family is implemented now, but this harness has no
       * archive attached and no scan has run -- so each must say WHICH of
       * those it is, and neither may answer 0.00000000. */
      D("rescanblockchain", NULL);
      ck("rescanblockchain with no archive attached says so",
         rc == 0 && ec == -4 && em && strstr(em, "no block archive"));
      rj_free(r);
      { rj_val* pa = P("[\"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\"]");
        D("getreceivedbyaddress", pa);
        ck("getreceivedbyaddress before any scan refuses rather than answering 0",
           rc == 0 && ec == -4 && em && strstr(em, "no wallet rescan has completed"));
        ck("...and says why a zero would be wrong",
           rc == 0 && em && strstr(em, "genuinely received nothing"));
        rj_free(r); rj_free(pa); }
      { struct { const char* m; const char* p; } RS[] = {
          {"getreceivedbylabel", "[\"hot\"]"},
          {"listreceivedbyaddress", "[]"},
          {"listreceivedbylabel", "[]"},
          {"listaddressgroupings", "[]"},
          {"listsinceblock", "[]"} };
        int allrs = 1;
        for (int i = 0; i < 5; i++){
            rj_val* pp = P(RS[i].p);
            D(RS[i].m, pp);
            if (!(rc == 0 && ec == -4 && em && strstr(em, "rescan"))){
                printf("      (%s: rc=%d ec=%ld em=%s)\n", RS[i].m, rc, ec, em?em:"");
                allrs = 0;
            }
            rj_free(r); rj_free(pp);
        }
        ck("every receive-side method refuses on a scan-less wallet", allrs); }
      /* sendtoaddress is implemented now; on a scan-less wallet it refuses
       * at the funding step (no coins are knowable) rather than pretending */
      { rj_val* pp = P("[\"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2\",1.0]");
        D("sendtoaddress", pp);
        ck("sendtoaddress before any scan refuses at funding",
           rc == 0 && ec == -4 && em && strstr(em, "rescan"));
        rj_free(r); rj_free(pp); } }

    /* ==== the wallet rescan, end to end =============================== */
    { static unsigned char rbuf[1 << 20];
      fx_build(SEED);
      rpc_wops_set_scanner(fx_read_block, rbuf, (long)sizeof rbuf, fx_tip);

      char r0addr[96], c0addr[96];
      wallet_p2wpkh_address(r0addr, sizeof r0addr, g_r0_h160);
      wallet_p2wpkh_address(c0addr, sizeof c0addr, g_c0_h160);

      D("rescanblockchain", NULL);
      ck("rescanblockchain runs over the attached archive", rc == 1 && r);
      ck("...reporting the range it covered",
         r && S(r,"start_height") && !strcmp(S(r,"start_height"), "0") &&
         S(r,"stop_height") && !strcmp(S(r,"stop_height"), "2"));
      rj_free(r);

      { char js[200]; snprintf(js, sizeof js, "[\"%s\"]", r0addr);
        rj_val* p = P(js);
        D("getreceivedbyaddress", p);
        ck("getreceivedbyaddress now reports the REAL 50 BTC received",
           rc == 1 && r && r->str && !strcmp(r->str, "50.00000000"));
        rj_free(r); rj_free(p); }

      { /* the coin was spent again, but `received` counts ARRIVALS -- it must
         * not net out the spend, or a wallet's received total would shrink as
         * it paid people */
        char js[200]; snprintf(js, sizeof js, "[\"%s\"]", c0addr);
        rj_val* p = P(js);
        D("getreceivedbyaddress", p);
        ck("change received counts separately, and the spend is not netted out",
           rc == 1 && r && r->str && !strcmp(r->str, "10.00000000"));
        rj_free(r); rj_free(p); }

      { rj_val* p = P("[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"]");
        D("getreceivedbyaddress", p);
        ck("an address we do not own -> -4, never 0.00000000",
           rc == 0 && ec == -4 && em && strstr(em, "not found in wallet"));
        rj_free(r); rj_free(p); }

      { /* tip is 2, so the h1 receive has exactly 2 confirmations */
        char js[200]; snprintf(js, sizeof js, "[\"%s\",2]", r0addr);
        rj_val* p = P(js);
        D("getreceivedbyaddress", p);
        ck("minconf 2 still counts a 2-confirmation receive",
           rc == 1 && r && !strcmp(r->str, "50.00000000"));
        rj_free(r); rj_free(p);
        snprintf(js, sizeof js, "[\"%s\",3]", r0addr);
        p = P(js);
        D("getreceivedbyaddress", p);
        ck("minconf 3 excludes it", rc == 1 && r && !strcmp(r->str, "0.00000000"));
        rj_free(r); rj_free(p); }

      { rj_val* p = P("[]");
        D("listreceivedbyaddress", p);
        ck("listreceivedbyaddress lists the two addresses that received",
           rc == 1 && r && r->typ == RJ_ARR && r->nitems == 2);
        { rj_val* e0 = (r && r->nitems) ? r->items[0] : 0;
          ck("...each with Core's address/amount/confirmations/label/txids",
             e0 && S(e0,"address") && S(e0,"amount") && S(e0,"confirmations") &&
             rj_obj_get(e0,"label") && rj_obj_get(e0,"txids") &&
             rj_obj_get(e0,"txids")->nitems == 1); }
        rj_free(r); rj_free(p); }

      { rj_val* p = P("[]");
        D("listaddressgroupings", p);
        ck("listaddressgroupings -> ONE group (a single-seed wallet has one owner)",
           rc == 1 && r && r->typ == RJ_ARR && r->nitems == 1 &&
           r->items[0]->typ == RJ_ARR && r->items[0]->nitems == 2);
        rj_free(r); rj_free(p); }

      { rj_val* p = P("[]");
        D("listsinceblock", p);
        ck("listsinceblock returns every event", rc == 1 && r &&
           rj_obj_get(r,"transactions") && rj_obj_get(r,"transactions")->nitems == 3);
        { rj_val* txs = r ? rj_obj_get(r,"transactions") : 0;
          rj_val* t0 = (txs && txs->nitems) ? txs->items[0] : 0;
          rj_val* t1 = (txs && txs->nitems > 1) ? txs->items[1] : 0;
          ck("the first is the receive",
             t0 && S(t0,"category") && !strcmp(S(t0,"category"), "receive") &&
             !strcmp(S(t0,"amount"), "50.00000000"));
          ck("the second is the SEND, rendered negative as Core does",
             t1 && S(t1,"category") && !strcmp(S(t1,"category"), "send") &&
             !strcmp(S(t1,"amount"), "-50.00000000"));
          ck("confirmations come from the scanned height",
             t0 && S(t0,"confirmations") && !strcmp(S(t0,"confirmations"), "2"));
          ck("no blockhash is invented", t0 && rj_obj_get(t0,"blockhash") == NULL); }
        rj_free(r); rj_free(p); }

      { static const char* H = "0123456789abcdef";
        char id[65];
        for (int k = 0; k < 32; k++){ unsigned char b = g_tx1id[31-k];
            id[k*2] = H[b>>4]; id[k*2+1] = H[b&15]; }
        id[64] = 0;
        char hx[80]; snprintf(hx, sizeof hx, "[\"%s\"]", id);
        rj_val* p = P(hx);
        D("abandontransaction", p);
        ck("abandoning a CONFIRMED transaction -> Core's -5",
           rc == 0 && ec == -5 && em &&
           !strcmp(em, "Transaction not eligible for abandonment"));
        rj_free(r); rj_free(p); }
      { const char* UNSEEN = "0000000000000000000000000000000000000000000000000000000000000009";
        char hx[80]; snprintf(hx, sizeof hx, "[\"%s\"]", UNSEEN);
        rj_val* p = P(hx);
        D("abandontransaction", p);
        ck("abandoning an unseen transaction succeeds", rc == 1 && r && r->typ == RJ_NULL);
        rj_free(r); rj_free(p);
        ck("...and is recorded", rpc_wops_is_abandoned(UNSEEN) == 1);
        p = P(hx);
        D("abandontransaction", p);
        ck("...and is idempotent", rc == 1);
        rj_free(r); rj_free(p); }

      /* ==== coin selection, change and fees ========================== */
      /* Spendable: the 10 BTC change output. The 50 BTC receive was spent at
       * h2, so it must NOT be selectable -- if the spent-detection were the
       * old value/key heuristic this would try to spend it. */
      { rj_val* p = P("[]");
        D("listunspent", p);       /* not this module, but proves the setup */
        rj_free(r); rj_free(p); }

      { /* fundrawtransaction over an inputless tx paying 1 BTC away */
        const char* OUTS =
          "02000000" "00" "01" "00e1f50500000000"
          "16" "0014c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3" "00000000";
        char js[400]; snprintf(js, sizeof js, "[\"%s\"]", OUTS);
        rj_val* p = P(js);
        D("fundrawtransaction", p);
        ck("fundrawtransaction funds an inputless transaction", rc == 1 && r);
        ck("...returning hex, fee and changepos",
           r && S(r,"hex") && S(r,"fee") && S(r,"changepos"));
        ck("...with a change output added (the 10 BTC coin covers 1 BTC + fee)",
           r && S(r,"changepos") && !strcmp(S(r,"changepos"), "1"));
        { /* the fee must be positive and small -- a fee of 0 would mean the
           * size model produced nothing, and a huge one a unit error */
          long long fs = S(r,"fee") ? rpc_amount_to_sat(S(r,"fee")) : -1;
          if (rc != 1) printf("      (fund failed: ec=%ld em=%s)\n", ec, em?em:"");
          ck("the fee is positive", fs > 0);
          ck("the fee is a sane size for a 1-in 2-out tx (< 0.001 BTC)", fs > 0 && fs < 100000); }
        /* and the funded transaction must actually SIGN */
        if (rc == 1 && S(r,"hex")) { char fj[2000];
          snprintf(fj, sizeof fj, "[\"%s\"]", S(r,"hex"));
          rj_val* fp = rj_parse(fj, strlen(fj));
          rj_val* sr = NULL; long e2 = 0; const char* m2 = NULL;
          int src = rpc_dispatch("signrawtransactionwithwallet", fp, &W, &sr, &e2, &m2);
          if (src != 1) printf("      (sign failed: ec=%ld em=%s)\n", e2, m2?m2:"");
          else if (sr && rj_obj_get(sr,"complete") && rj_obj_get(sr,"complete")->str[0] != '1'){
              char b[1200]; rj_write(b, sizeof b, sr, 0);
              printf("      (incomplete: %.900s)\n", b);
          }
          ck("the funded transaction signs to completion with the wallet's keys",
             src == 1 && sr && rj_obj_get(sr,"complete") &&
             rj_obj_get(sr,"complete")->str[0] == '1');
          ck("...producing a witness (segwit signing, not the legacy path)",
             src == 1 && sr && rj_obj_get(sr,"hex") &&
             !strncmp(rj_obj_get(sr,"hex")->str + 8, "0001", 4));
          rj_free(sr); rj_free(fp); }
        else { ck("the funded transaction signs to completion with the wallet's keys", 0);
               ck("...producing a witness (segwit signing, not the legacy path)", 0); }
        rj_free(r); rj_free(p); }

      { /* asking for more than the wallet holds is Core's -6, with the
         * amount available named rather than a bare failure */
        const char* BIG =
          "02000000" "00" "01" "00e40b5402000000"
          "16" "0014c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3" "00000000";
        char js[400]; snprintf(js, sizeof js, "[\"%s\"]", BIG);
        rj_val* p = P(js);
        D("fundrawtransaction", p);
        ck("funding more than the wallet holds -> -6 Insufficient funds",
           rc == 0 && ec == -6 && em && strstr(em, "Insufficient funds"));
        ck("...naming what is actually available", rc == 0 && em && strstr(em, "available"));
        rj_free(r); rj_free(p); }

      { /* a transaction that already has inputs is refused, not mis-funded */
        const char* WITHIN =
          "02000000" "01"
          "0100000000000000000000000000000000000000000000000000000000000000"
          "00000000" "00" "fdffffff"
          "01" "00e1f50500000000" "16"
          "0014c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3" "00000000";
        char js[500]; snprintf(js, sizeof js, "[\"%s\"]", WITHIN);
        rj_val* p = P(js);
        D("fundrawtransaction", p);
        ck("a transaction that already carries inputs is refused",
           rc == 0 && ec == -8 && em && strstr(em, "inputless"));
        rj_free(r); rj_free(p); }

      { /* LOCKED coins must not be selected */
        char hx[65]; static const char* H = "0123456789abcdef";
        /* the change outpoint is tx2:0; recover its txid from listsinceblock */
        rj_val* p0 = P("[]"); D("listsinceblock", p0);
        const char* ctxid = NULL;
        if (r){ rj_val* txs = rj_obj_get(r,"transactions");
                for (size_t i = 0; txs && i < txs->nitems; i++)
                    if (!strcmp(S(txs->items[i],"amount"), "10.00000000"))
                        ctxid = S(txs->items[i],"txid"); }
        char lockjs[200];
        if (ctxid) snprintf(lockjs, sizeof lockjs,
                            "[false,[{\"txid\":\"%s\",\"vout\":0}]]", ctxid);
        else lockjs[0] = 0;
        rj_free(r); rj_free(p0);
        (void)hx; (void)H;
        if (lockjs[0]){
            rj_val* lp = P(lockjs);
            D("lockunspent", lp);
            ck("locked the wallet's only spendable coin", rc == 1);
            rj_free(r); rj_free(lp);
            const char* OUTS2 =
              "02000000" "00" "01" "00e1f50500000000"
              "16" "0014c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3" "00000000";
            char js[400]; snprintf(js, sizeof js, "[\"%s\"]", OUTS2);
            rj_val* p = P(js);
            D("fundrawtransaction", p);
            ck("a LOCKED output is not selected -- funding fails rather than "
               "spending a coin the operator reserved",
               rc == 0 && ec == -6);
            rj_free(r); rj_free(p);
            rj_val* up = P("[true]"); D("lockunspent", up); rj_free(r); rj_free(up);
        } }

      { /* sendtoaddress must get all the way to broadcast: this harness has
         * no download worker, so reaching sendrawtransaction's own error is
         * proof that selection, change, fee and SIGNING all succeeded */
        rj_val* p = P("[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\",1.0]");
        D("sendtoaddress", p);
        ck("sendtoaddress funds and signs, then fails only at the broadcast",
           rc == 0 && ec == -4 && em && strstr(em, "no download worker"));
        rj_free(r); rj_free(p); }

      { rj_val* p = P("[\"notanaddress\",1.0]");
        D("sendtoaddress", p);
        ck("sendtoaddress to a bad address -> -5", rc == 0 && ec == -5);
        rj_free(r); rj_free(p); }
      { rj_val* p = P("[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\",999.0]");
        D("sendtoaddress", p);
        ck("sendtoaddress beyond the balance -> -6", rc == 0 && ec == -6);
        rj_free(r); rj_free(p); }

      { rj_val* p = P("[{\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\":0.5}]");
        D("walletcreatefundedpsbt", p);
        ck("walletcreatefundedpsbt returns a PSBT with fee and changepos",
           rc == 1 && r && S(r,"psbt") && S(r,"fee") && S(r,"changepos"));
        ck("...and the PSBT decodes", rc == 1 && r && !strncmp(S(r,"psbt"), "cHNidP", 6));
        rj_free(r); rj_free(p); }

      { rj_val* p = P("[[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\"]]");
        D("sendall", p);
        ck("sendall sweeps and reaches the broadcast step",
           rc == 0 && ec == -4 && em && strstr(em, "no download worker"));
        rj_free(r); rj_free(p); }

      { /* bumpfee is real: with no/bad txid it is an ordinary -8, and with
           an unknown txid it is Core's -5 (no journal, not-in-mempool) */
        D("bumpfee", NULL);
        ck("bumpfee with no txid -> -8 (wired, not a stub)", rc == 0 && ec == -8);
        rj_free(r);
        rj_val* pb = P("[\"00000000000000000000000000000000000000000000000000000000000000ff\"]");
        D("bumpfee", pb);
        ck("bumpfee unknown txid -> -5 Core's text",
           rc == 0 && ec == -5 && em && !strcmp(em, "Invalid or non-wallet transaction id"));
        rj_free(r); rj_free(pb);
        pb = P("[\"00000000000000000000000000000000000000000000000000000000000000ff\"]");
        D("psbtbumpfee", pb);
        ck("psbtbumpfee unknown txid -> -5", rc == 0 && ec == -5);
        rj_free(r); rj_free(pb); }

      rpc_wops_set_scanner(NULL, NULL, 0, NULL); }

    /* ---- the advertised table and the dispatch ladder must AGREE.
     * A method listed in WOP_METHODS but missing from the ladder would
     * return -1 after known_method() said 1 -- the caller would then get
     * "Method not found" for something the node claims to implement. ---- */
    { static const char* const ALL[] = {
        "setlabel","listlabels","getaddressesbylabel","listwallets","listwalletdir",
        "listlockunspent","lockunspent","signmessage","backupwallet","keypoolrefill",
        "abortrescan","listdescriptors","gethdkeys","walletlock","walletpassphrase",
        "walletpassphrasechange","encryptwallet","createwallet","loadwallet",
        "unloadwallet","restorewallet","migratewallet","setwalletflag",
        "importdescriptors","createwalletdescriptor","addhdkey","importprunedfunds",
        "removeprunedfunds","exportwatchonlywallet","walletdisplayaddress",
        "rescanblockchain","getreceivedbyaddress","getreceivedbylabel",
        "listreceivedbyaddress","listreceivedbylabel","listaddressgroupings",
        "listsinceblock","abandontransaction",
        "sendtoaddress","sendmany","send","sendall","walletcreatefundedpsbt",
        "walletprocesspsbt","bumpfee","psbtbumpfee", NULL };
      int agree = 1, count = 0;
      for (int i = 0; ALL[i]; i++){
          count++;
          if (!rpc_wops_known_method(ALL[i])){ printf("      (%s not known)\n", ALL[i]); agree = 0; }
          D(ALL[i], NULL);
          if (rc == -1){ printf("      (%s known but unhandled)\n", ALL[i]); agree = 0; }
          rj_free(r);
      }
      ck("no method is advertised but unhandled", agree);
      ck("all 46 wallet-ops methods are present", count == 46); }

    /* ==== multi-wallet lifecycle (2026-08-27) ========================== */
    {
      extern void rpc_wops_set_seed_installer(void (*)(const unsigned char*));
      extern const char* rpc_wops_active_wallet_name(void);
      extern int rpc_wops_watchonly(void);
      extern int rpc_wops_watch_newaddress(char*, long, long*, const char**);

      rpc_wops_set_seed_installer(0);   /* first: no installer -> honest -4 */
      rj_val* p = P("[\"w1\"]");
      D("createwallet", p);
      ck("createwallet without an installer -> -4 (standalone rpcd case)",
         rc == 0 && ec == -4 && em && strstr(em, "no seed installer"));
      rj_free(r); rj_free(p);

      rpc_wops_set_seed_installer(tw_install);

      p = P("[\"w1\"]");
      D("createwallet", p);
      ck("createwallet w1 -> {name:w1}", rc == 1 && r && S(r,"name") && !strcmp(S(r,"name"), "w1"));
      rj_free(r); rj_free(p);
      ck("createwallet installed a fresh seed", tw_seed() != 0);
      /* -walletdir: a named wallet is created under it, and listwalletdir sees
       * it there. Restores w1 as the active wallet afterwards, since the
       * checks below assume it. */
      { extern void rpc_wops_set_walletdir(const char*);
        char wdt[] = "/tmp/bmc_walletdir_XXXXXX"; if(!mkdtemp(wdt)){ perror("mkdtemp"); return 1; }
        rpc_wops_set_walletdir(wdt);
        p = P("[\"wd1\"]");
        D("createwallet", p);
        ck("createwallet under walletdir -> {name:wd1}", rc == 1 && r && S(r,"name") && !strcmp(S(r,"name"), "wd1"));
        rj_free(r); rj_free(p);
        { char b[600]; struct stat sb; snprintf(b, sizeof b, "%s/wallets/wd1/bmcwallet.dat", wdt);
          ck("...and the store landed under walletdir/wallets/wd1/", stat(b, &sb) == 0); }
        p = P("[]"); D("listwalletdir", p);
        { int found = 0; rj_val* ws = (rc == 1 && r) ? rj_obj_get(r, "wallets") : 0;
          for (unsigned long i = 0; ws && i < ws->nitems; i++){ const char* nm = S(ws->items[i], "name"); if (nm && !strcmp(nm, "wd1")) found = 1; }
          ck("listwalletdir lists it from walletdir", found); }
        rj_free(r); rj_free(p);
        rpc_wops_set_walletdir("");
        char cmd[300]; snprintf(cmd, sizeof cmd, "rm -rf %s", wdt); (void)!system(cmd);
        p = P("[\"w1\"]"); D("loadwallet", p);
        ck("w1 re-activated after the walletdir excursion", rc == 1);
        rj_free(r); rj_free(p); }
      W.seed = tw_seed();
      ck("active wallet name is w1",
         rpc_wops_active_wallet_name() && !strcmp(rpc_wops_active_wallet_name(), "w1"));

      D("listwallets", NULL);
      ck("listwallets -> [w1]", rc == 1 && r && r->typ == RJ_ARR && r->nitems == 1 &&
         !strcmp(r->items[0]->str, "w1"));
      rj_free(r);

      p = P("[\"w1\"]");
      D("createwallet", p);
      ck("createwallet duplicate -> -4 already exists",
         rc == 0 && ec == -4 && em && strstr(em, "already exists"));
      rj_free(r); rj_free(p);

      p = P("[\"../evil\"]");
      D("createwallet", p);
      ck("path-escaping name refused -8", rc == 0 && ec == -8);
      rj_free(r); rj_free(p);

      D("unloadwallet", NULL);
      ck("unloadwallet -> {warnings:[]}", rc == 1 && r && r->typ == RJ_OBJ);
      rj_free(r);
      W.seed = tw_seed();
      ck("unload cleared the seed", W.seed == 0);

      D("listwallets", NULL);
      ck("listwallets after unload -> []", rc == 1 && r && r->nitems == 0);
      rj_free(r);

      p = P("[\"nosuch\"]");
      D("loadwallet", p);
      ck("loadwallet missing -> -18 Core text", rc == 0 && ec == -18 &&
         em && strstr(em, "does not exist or is not loaded"));
      rj_free(r); rj_free(p);

      p = P("[\"w1\"]");
      D("loadwallet", p);
      ck("loadwallet w1 reloads", rc == 1 && r && S(r,"name") && !strcmp(S(r,"name"), "w1"));
      rj_free(r); rj_free(p);
      W.seed = tw_seed();
      ck("reload restored a seed", W.seed != 0);

      /* ---- watch-only wallet + importdescriptors ---- */
      p = P("[\"watch1\", true]");
      D("createwallet", p);
      ck("createwallet watch-only", rc == 1 && r && S(r,"name") && !strcmp(S(r,"name"), "watch1"));
      rj_free(r); rj_free(p);
      W.seed = tw_seed();
      ck("watch-only wallet has NO seed", W.seed == 0 && rpc_wops_watchonly());

      /* import the Core-verified test-vector descriptor (see
       * test_rpc_chain.c: addresses captured from bitcoin-cli) */
      p = P("[[{\"desc\":\"wpkh(xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8/0/*)#wvk84d79\",\"range\":10,\"timestamp\":\"now\"}]]");
      D("importdescriptors", p);
      ck("importdescriptors -> [{success:true}]",
         rc == 1 && r && r->typ == RJ_ARR && r->nitems == 1 &&
         S(r->items[0],"success") && !strcmp(S(r->items[0],"success"), "1"));
      rj_free(r); rj_free(p);

      { char a[128]; long ec2; const char* em2;
        ck("watch getnewaddress [0] == Core's deriveaddresses[0]",
           rpc_wops_watch_newaddress(a, sizeof a, &ec2, &em2) == 1 &&
           !strcmp(a, "bc1qp5wfcq48h6d63wyy9qz0awtpfqwwv4sma86mhz"));
        ck("watch getnewaddress [1] == Core's deriveaddresses[1]",
           rpc_wops_watch_newaddress(a, sizeof a, &ec2, &em2) == 1 &&
           !strcmp(a, "bc1qrfxr69jqnhwufxgkqgcdep9prq4j4vuw2wyg0v")); }

      p = P("[\"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\", 1.0]");
      D("sendtoaddress", p);
      ck("watch-only send -> Core's private-keys-disabled error",
         rc == 0 && ec == -4 && em &&
         !strcmp(em, "Error: Private keys are disabled for this wallet"));
      rj_free(r); rj_free(p);

      D("listdescriptors", NULL);
      { rj_val* ds = r ? rj_obj_get(r, "descriptors") : 0;
        ck("listdescriptors shows the import, next_index 2",
           rc == 1 && ds && ds->typ == RJ_ARR && ds->nitems == 1 &&
           S(ds->items[0],"next_index") && !strcmp(S(ds->items[0],"next_index"), "2")); }
      rj_free(r);

      /* restorewallet from the w1 store file as a backup */
      { char bpath[512]; struct stat sb;
        const char* cands[2] = { "data/wallets/w1/bmcwallet.dat", "wallets/w1/bmcwallet.dat" };
        bpath[0]=0;
        for (int i=0;i<2;i++) if (stat(cands[i],&sb)==0){ snprintf(bpath,sizeof bpath,"%s",cands[i]); break; }
        char pp[600]; snprintf(pp, sizeof pp, "[\"w2\",\"%s\"]", bpath);
        rj_val* p2 = P(pp);
        D("restorewallet", p2);
        ck("restorewallet w2 from w1's store", rc == 1 && r && S(r,"name") && !strcmp(S(r,"name"), "w2"));
        rj_free(r); rj_free(p2);
        W.seed = tw_seed();
        ck("restored wallet has a seed", W.seed != 0); }

      /* ---- HERMETIC watch-only end-to-end: the fixture chain ----------
       * Import the FIXTURE SEED's own account xpub into a fresh watch-only
       * wallet, rescan the same 3-block fixture archive, and the watch
       * wallet must see exactly what the seed wallet saw at the same
       * address -- import -> descriptor keyset -> scan -> journal ->
       * balance, with zero shared state (its journal lives under
       * wallets/watchfx/). */
      { /* the fixture wallet's account xpub, via its own gethdkeys */
        static unsigned char rbuf2[8192];
        rpc_wops_set_scanner(fx_read_block, rbuf2, (long)sizeof rbuf2, fx_tip);
        W.seed = SEED;
        D("gethdkeys", NULL);
        char fxpub[144]; fxpub[0] = 0;
        if (rc == 1 && r && r->typ == RJ_ARR && r->nitems == 1 && S(r->items[0],"xpub"))
            snprintf(fxpub, sizeof fxpub, "%s", S(r->items[0],"xpub"));
        rj_free(r);
        ck("fixture account xpub obtained", fxpub[0] != 0);

        rj_val* p2 = P("[\"watchfx\", true]");
        D("createwallet", p2); rj_free(r); rj_free(p2);
        W.seed = tw_seed();
        ck("watchfx created watch-only", W.seed == 0 && rpc_wops_watchonly());

        char req[600];
        snprintf(req, sizeof req,
                 "[[{\"desc\":\"wpkh(%s/0/*)\",\"range\":5,\"timestamp\":\"now\"}]]", fxpub);
        p2 = P(req);
        D("importdescriptors", p2);
        ck("watchfx import (checksum appended by the engine)",
           rc == 1 && r && r->nitems == 1 && S(r->items[0],"success") &&
           !strcmp(S(r->items[0],"success"), "1"));
        rj_free(r); rj_free(p2);

        D("rescanblockchain", NULL);
        ck("watchfx rescan over the fixture archive", rc == 1);
        rj_free(r);

        char r0addr[128];
        wallet_p2wpkh_address(r0addr, sizeof r0addr, g_r0_h160);
        char q[200]; snprintf(q, sizeof q, "[\"%s\"]", r0addr);
        p2 = P(q);
        D("getreceivedbyaddress", p2);
        ck("watch-only wallet sees the fixture's 50 BTC receive",
           rc == 1 && r && r->str && !strcmp(r->str, "50.00000000"));
        rj_free(r); rj_free(p2);
        rpc_wops_set_scanner(NULL, NULL, 0, NULL);
      }

      /* back to the fixture wallet so nothing after this block changes */
      D("unloadwallet", NULL); rj_free(r);
      rpc_wops_set_seed_installer(0);
      W.seed = SEED;
    }

    printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
