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

int main(void){
    tt_isolate();   /* the label store and the fake wallet file are ours alone */
    for (int i = 0; i < 64; i++) SEED[i] = (unsigned char)(0x11 * (i + 1));
    memset(&W, 0, sizeof W);
    W.seed = SEED;

    long ec; const char* em; rj_val* r; int rc;
    #define D(m, p) (r = NULL, ec = 0, em = NULL, rc = rpc_wops_dispatch((m), (p), &W, &r, &ec, &em))

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
    { static const char* REFUSE[] = {
        "encryptwallet","createwallet","loadwallet","unloadwallet","restorewallet",
        "migratewallet","setwalletflag","importdescriptors","createwalletdescriptor",
        "addhdkey","importprunedfunds","removeprunedfunds","exportwatchonlywallet",
        "walletdisplayaddress","rescanblockchain","getreceivedbyaddress",
        "getreceivedbylabel","listreceivedbyaddress","listreceivedbylabel",
        "listaddressgroupings","listsinceblock","abandontransaction" };
      int n = (int)(sizeof REFUSE / sizeof *REFUSE), allbad = 1;
      for (int i = 0; i < n; i++){
          D(REFUSE[i], NULL);
          if (!(rc == 0 && ec == -1 && em && strlen(em) > 30)){
              printf("      (%s returned rc=%d ec=%ld)\n", REFUSE[i], rc, ec);
              allbad = 0;
          }
          rj_free(r);
      }
      ck("every unsupported wallet method errors with a substantive reason", allbad);
      /* the ones that cannot answer must say WHY, so a reader knows the gap
       * is a missing rescan and not a missing formatter */
      D("getreceivedbyaddress", NULL);
      ck("the receive-side methods name the missing rescan",
         rc == 0 && em && strstr(em, "rescan"));
      rj_free(r); }

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
        "listsinceblock","abandontransaction", NULL };
      int agree = 1, count = 0;
      for (int i = 0; ALL[i]; i++){
          count++;
          if (!rpc_wops_known_method(ALL[i])){ printf("      (%s not known)\n", ALL[i]); agree = 0; }
          D(ALL[i], NULL);
          if (rc == -1){ printf("      (%s known but unhandled)\n", ALL[i]); agree = 0; }
          rj_free(r);
      }
      ck("no method is advertised but unhandled", agree);
      ck("all 38 wallet-ops methods are present", count == 38); }

    printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
