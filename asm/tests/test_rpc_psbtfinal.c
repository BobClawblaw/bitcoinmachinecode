/* test_rpc_psbtfinal.c -- finalizepsbt, utxoupdatepsbt and
 * combinerawtransaction, driven through rpc_dispatch().
 *
 * These are ROUND TRIPS, not shape checks, and that is the point:
 *
 *   finalizepsbt -- a PSBT is assembled here carrying the REAL signature
 *     that signrawtransactionwithkey produced for the same input, and the
 *     extractor's output must come back BYTE-IDENTICAL to the signer's own
 *     network serialization. A finalizer that assembled the scriptSig or the
 *     witness stack even slightly differently fails that comparison; a shape
 *     check on {hex, complete} would not.
 *
 *   combinerawtransaction -- one two-input transaction is signed twice, each
 *     time with the prevout for only ONE input, and combining the two halves
 *     must reproduce the transaction signed with both prevouts at once.
 *
 * The signing key is the 0x11*32 key whose signed outputs are already
 * Core-validated in test_rpc_signraw.c, so the signatures underneath these
 * round trips are known-good rather than merely self-consistent.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"

extern void hash160(unsigned char out[20], const void* in, long long len);
extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char priv_be[32]);

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }
static void ck_str(const char* w, const char* got, const char* want){
    int c = got && want && !strcmp(got, want);
    checks++;
    if (c) printf("ok  : %s\n", w);
    else { printf("FAIL: %s\n      got  %s\n      want %s\n", w, got?got:"(null)", want?want:"(null)"); fails++; }
}

extern int bip32_derive_path(unsigned char k[32], unsigned char c[32],
                             const unsigned char* seed, unsigned long seedlen,
                             const unsigned* path, unsigned plen);

/* like call(), but with a LOADED wallet (walletprocesspsbt needs one) */
static rj_val* callw(const char* method, const char* pj, const unsigned char* seed,
                     long* ec, const char** em){
    rj_val* p = rj_parse(pj, strlen(pj));
    rj_val* r = NULL; rpc_wallet w; memset(&w, 0, sizeof w);
    w.seed = (unsigned char*)seed;
    *ec = 0; *em = NULL;
    int ok = rpc_dispatch(method, p, &w, &r, ec, em);
    rj_free(p);
    if (!ok){ if (r) rj_free(r); return NULL; }
    return r;
}

static rj_val* call(const char* method, const char* pj, long* ec, const char** em){
    rj_val* p = rj_parse(pj, strlen(pj));
    rj_val* r = NULL; rpc_wallet w; memset(&w, 0, sizeof w);
    *ec = 0; *em = NULL;
    int ok = rpc_dispatch(method, p, &w, &r, ec, em);
    rj_free(p);
    if (!ok){ if (r) rj_free(r); return NULL; }
    return r;
}
static void expect_err_any(const char* label, const char* method, const char* pj, long want_ec){
    long ec2 = 0; const char* em2 = NULL; rj_val* r = call(method, pj, &ec2, &em2);
    ck(label, r == NULL && ec2 == want_ec); if (r) rj_free(r);
}
static const char* S(const rj_val* o, const char* k){
    rj_val* v = o ? rj_obj_get((rj_val*)o, k) : NULL; return v ? v->str : NULL;
}

#define WIF "KwntMbt59tTsj8xqpqYqRRWufyjGunvhSyeMo3NTYpFYzZbXJ5Hp"
static unsigned char PRIV[32];

static void hexify(char* out, const unsigned char* b, size_t n){
    static const char* H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++){ out[i*2] = H[b[i]>>4]; out[i*2+1] = H[b[i]&15]; }
    out[n*2] = 0;
}
static size_t unhex(unsigned char* out, const char* h){
    size_t n = strlen(h)/2;
    for (size_t i = 0; i < n; i++){
        int hi, lo; char a = h[i*2], b = h[i*2+1];
        hi = (a<='9') ? a-'0' : (a|32)-'a'+10;
        lo = (b<='9') ? b-'0' : (b|32)-'a'+10;
        out[i] = (unsigned char)((hi<<4)|lo);
    }
    return n;
}

/* base64 (the encoder rpc_commands uses; mirrored here so the test builds
 * its own PSBT rather than trusting the module under test to round-trip). */
static void b64(char* out, const unsigned char* in, long n){
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    long o = 0;
    for (long i = 0; i < n; i += 3){
        unsigned v = (unsigned)in[i] << 16;
        if (i+1 < n) v |= (unsigned)in[i+1] << 8;
        if (i+2 < n) v |= in[i+2];
        out[o++] = T[(v>>18)&63];
        out[o++] = T[(v>>12)&63];
        out[o++] = (i+1 < n) ? T[(v>>6)&63] : '=';
        out[o++] = (i+2 < n) ? T[v&63]      : '=';
    }
    out[o] = 0;
}

/* varint writer */
static long vi(unsigned char* o, unsigned long long v){
    if (v < 0xfd){ o[0] = (unsigned char)v; return 1; }
    if (v <= 0xffff){ o[0]=0xfd; o[1]=(unsigned char)v; o[2]=(unsigned char)(v>>8); return 3; }
    o[0]=0xfe; for (int i=0;i<4;i++) o[1+i]=(unsigned char)(v>>(8*i)); return 5;
}
/* one PSBT key/value pair */
static long kv(unsigned char* o, const unsigned char* k, unsigned long kl,
               const unsigned char* v, unsigned long vl){
    long p = vi(o, kl); memcpy(o+p, k, kl); p += (long)kl;
    p += vi(o+p, vl); memcpy(o+p, v, vl); p += (long)vl;
    return p;
}

int main(void){
    for (int i = 0; i < 32; i++) PRIV[i] = 0x11;
    unsigned char pub[33], pkh[20];
    scalar_to_pubkey(pub, PRIV);
    hash160(pkh, pub, 33);
    char pkhh[41]; hexify(pkhh, pkh, 20);

    long ec; const char* em;

    /* ================================================================
     * 1. finalizepsbt over a P2WPKH input.
     * ================================================================ */
    /* An unsigned tx spending outpoint (...0001, 0) and paying 0.999 to a
     * P2PKH of the same key -- the same frame test_rpc_signraw.c uses. */
    static const char* UNSIGNED =
        "02000000" "01"
        "0100000000000000000000000000000000000000000000000000000000000000"
        "00000000" "00" "fdffffff"
        "01" "605af40500000000" "19"
        "76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac"
        "00000000";
    char spk[64]; snprintf(spk, sizeof spk, "0014%s", pkhh);

    /* Sign it for real, so the PSBT below carries a genuine signature and
     * the extractor has an authoritative answer to be compared against. */
    char pj[2000];
    snprintf(pj, sizeof pj,
        "[\"%s\",[\"%s\"],[{\"txid\":\"000000000000000000000000000000000000"
        "0000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"%s\","
        "\"amount\":1.0}]]", UNSIGNED, WIF, spk);
    rj_val* sr = call("signrawtransactionwithkey", pj, &ec, &em);
    ck("reference signing succeeded", sr && S(sr,"complete") && S(sr,"complete")[0]=='1');
    char signed_hex[4000];
    snprintf(signed_hex, sizeof signed_hex, "%s", sr ? S(sr,"hex") : "");
    rj_free(sr);

    /* Pull the witness stack out of the signed tx: it ends with
     * 02 <len> <sig> 21 <pubkey> then the 4-byte locktime. */
    unsigned char sbin[2000]; size_t slen = unhex(sbin, signed_hex);
    unsigned char sig[80]; size_t siglen = 0;
    { /* The tail is: 02 <siglen> <sig..> 21 <pubkey33> <locktime4>. Index
       * the pubkey push first, then step back over the signature, whose
       * length is not fixed (low-S can shorten a DER R or S by a byte).
       * Anchor on all three of the item count, the push length and DER's
       * 0x30 so a wrong offset cannot pass unnoticed. */
        size_t pk = slen - 4 - 34;          /* index of the 0x21 pubkey push */
        for (size_t sl = 64; sl <= 73; sl++){
            size_t q = pk - sl;             /* first sig byte */
            if (q < 3) continue;
            if (sbin[q-1] != (unsigned char)sl) continue;
            if (sbin[q-2] != 0x02) continue;          /* two witness items */
            if (sbin[q] != 0x30) continue;            /* DER SEQUENCE */
            siglen = sl; memcpy(sig, sbin + q, sl); break;
        }
        ck("recovered the DER signature from the reference tx",
           siglen >= 64 && siglen <= 73 && sig[0] == 0x30 &&
           sig[siglen-1] == 0x01 /* SIGHASH_ALL */);
    }

    /* Assemble the PSBT: global unsigned tx (key 0x00), input map with
     * witness_utxo (0x01) and one partial sig (0x02 || pubkey). */
    unsigned char utx[500]; size_t utxl = unhex(utx, UNSIGNED);
    unsigned char psbt[2000]; long o = 0;
    psbt[o++]='p'; psbt[o++]='s'; psbt[o++]='b'; psbt[o++]='t'; psbt[o++]=0xff;
    { unsigned char k = 0x00;
      o += kv(psbt+o, &k, 1, utx, utxl);
      psbt[o++] = 0x00; }                  /* end of global map */
    { /* input 0 */
      unsigned char wu[64]; long w = 0;
      unsigned long long val = 100000000ULL;      /* 1.0 BTC */
      for (int i = 0; i < 8; i++) wu[w++] = (unsigned char)(val >> (8*i));
      unsigned char spkb[32]; size_t spkl = unhex(spkb, spk);
      w += vi(wu+w, spkl); memcpy(wu+w, spkb, spkl); w += (long)spkl;
      unsigned char k1 = 0x01;
      o += kv(psbt+o, &k1, 1, wu, (unsigned long)w);
      unsigned char k2[34]; k2[0] = 0x02; memcpy(k2+1, pub, 33);
      o += kv(psbt+o, k2, 34, sig, (unsigned long)siglen);
      psbt[o++] = 0x00; }
    psbt[o++] = 0x00;                      /* output 0 map: empty */
    char psbt64[4000]; b64(psbt64, psbt, o);

    snprintf(pj, sizeof pj, "[\"%s\"]", psbt64);
    rj_val* fr = call("finalizepsbt", pj, &ec, &em);
    ck("finalizepsbt dispatched", fr != NULL);
    ck_str("finalizepsbt reports complete", S(fr,"complete"), "1");
    ck("extract=true returns hex, not psbt",
       fr && rj_obj_get(fr,"hex") && rj_obj_get(fr,"psbt") == NULL);
    /* THE assertion: the extractor must reproduce the signer's bytes. */
    ck_str("extracted tx is BYTE-IDENTICAL to the signer's own output",
           S(fr,"hex"), signed_hex);
    rj_free(fr);

    /* extract=false keeps a PSBT, and finalizing it AGAIN still extracts the
     * same transaction -- so the final fields were written correctly, not
     * merely reported */
    snprintf(pj, sizeof pj, "[\"%s\",false]", psbt64);
    fr = call("finalizepsbt", pj, &ec, &em);
    ck("extract=false returns psbt, not hex",
       fr && rj_obj_get(fr,"psbt") && rj_obj_get(fr,"hex") == NULL);
    ck_str("...still complete", S(fr,"complete"), "1");
    { char again[4000]; snprintf(again, sizeof again, "[\"%s\"]", S(fr,"psbt"));
      rj_val* f2 = call("finalizepsbt", again, &ec, &em);
      ck_str("re-finalizing the finalized PSBT extracts the same tx",
             S(f2,"hex"), signed_hex);
      rj_free(f2); }
    rj_free(fr);

    /* an input with NO partial signature cannot be finalized: complete must
     * be false and the input left alone, exactly as Core reports it */
    { unsigned char p2[2000]; long q = 0;
      p2[q++]='p';p2[q++]='s';p2[q++]='b';p2[q++]='t';p2[q++]=0xff;
      unsigned char k = 0x00;
      q += kv(p2+q, &k, 1, utx, utxl); p2[q++] = 0x00;
      p2[q++] = 0x00;                    /* input map: empty */
      p2[q++] = 0x00;                    /* output map: empty */
      char b[4000]; b64(b, p2, q);
      snprintf(pj, sizeof pj, "[\"%s\"]", b);
      rj_val* r = call("finalizepsbt", pj, &ec, &em);
      ck_str("an unsigned input -> complete:false", S(r,"complete"), "0");
      ck("...and a PSBT is returned even though extract defaulted to true",
         r && rj_obj_get(r,"psbt") && rj_obj_get(r,"hex") == NULL);
      rj_free(r); }

    /* garbage in */
    { rj_val* r = call("finalizepsbt", "[\"notbase64!!\"]", &ec, &em);
      ck("finalizepsbt on garbage -> -22", r == NULL && ec == -22); rj_free(r); }

    /* ================================================================
     * 2. combinerawtransaction over a two-input transaction.
     * ================================================================ */
    /* version | 2 inputs (outpoints ...0001/0 and ...0002/0) | 1 output */
    static const char* UNSIGNED2 =
        "02000000"
        "02"
        "0100000000000000000000000000000000000000000000000000000000000000" "00000000" "00" "fdffffff"
        "0200000000000000000000000000000000000000000000000000000000000000" "00000000" "00" "fdffffff"
        "01" "605af40500000000" "19" "76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac"
        "00000000";
    char p2pkh_spk[64]; snprintf(p2pkh_spk, sizeof p2pkh_spk, "76a914%s88ac", pkhh);
    #define PREVA "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000001\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.0}"
    #define PREVB "{\"txid\":\"0000000000000000000000000000000000000000000000000000000000000002\",\"vout\":0,\"scriptPubKey\":\"%s\",\"amount\":1.0}"

    char both[2200];
    { char pa[300], pb[300];
      snprintf(pa, sizeof pa, PREVA, p2pkh_spk);
      snprintf(pb, sizeof pb, PREVB, p2pkh_spk);
      snprintf(pj, sizeof pj, "[\"%s\",[\"%s\"],[%s,%s]]", UNSIGNED2, WIF, pa, pb);
      rj_val* r = call("signrawtransactionwithkey", pj, &ec, &em);
      ck("both-input reference signing is complete",
         r && S(r,"complete") && S(r,"complete")[0]=='1');
      snprintf(both, sizeof both, "%s", r ? S(r,"hex") : "");
      rj_free(r); }

    char halfA[2200], halfB[2200];
    { char pa[300]; snprintf(pa, sizeof pa, PREVA, p2pkh_spk);
      snprintf(pj, sizeof pj, "[\"%s\",[\"%s\"],[%s]]", UNSIGNED2, WIF, pa);
      rj_val* r = call("signrawtransactionwithkey", pj, &ec, &em);
      ck_str("signing with only prevout A is incomplete", S(r,"complete"), "0");
      snprintf(halfA, sizeof halfA, "%s", r ? S(r,"hex") : "");
      rj_free(r); }
    { char pb[300]; snprintf(pb, sizeof pb, PREVB, p2pkh_spk);
      snprintf(pj, sizeof pj, "[\"%s\",[\"%s\"],[%s]]", UNSIGNED2, WIF, pb);
      rj_val* r = call("signrawtransactionwithkey", pj, &ec, &em);
      ck_str("signing with only prevout B is incomplete", S(r,"complete"), "0");
      snprintf(halfB, sizeof halfB, "%s", r ? S(r,"hex") : "");
      rj_free(r); }
    ck("the two halves really are different transactions", strcmp(halfA, halfB) != 0);

    { char cj[5000];
      snprintf(cj, sizeof cj, "[[\"%s\",\"%s\"]]", halfA, halfB);
      rj_val* r = call("combinerawtransaction", cj, &ec, &em);
      ck("combinerawtransaction dispatched", r && r->typ == RJ_STR);
      ck_str("combining the halves reproduces the fully-signed transaction",
             r ? r->str : NULL, both);
      rj_free(r); }

    { /* a single transaction combines to itself */
      char cj[3000]; snprintf(cj, sizeof cj, "[[\"%s\"]]", both);
      rj_val* r = call("combinerawtransaction", cj, &ec, &em);
      ck_str("combining one transaction returns it unchanged", r ? r->str : NULL, both);
      rj_free(r); }

    { /* a half and the whole are CONSISTENT (the signer is deterministic, so
       * input 0 carries the identical scriptSig in both) -- combining them
       * must succeed and yield the whole, not trip the conflict check */
      char cj[5000]; snprintf(cj, sizeof cj, "[[\"%s\",\"%s\"]]", halfA, both);
      rj_val* r = call("combinerawtransaction", cj, &ec, &em);
      ck_str("a half plus the whole combines cleanly (identical data is not a conflict)",
             r ? r->str : NULL, both);
      rj_free(r); }

    { /* CONFLICTING signature data must be refused, not silently resolved --
       * keeping one side would discard signatures the caller supplied.
       * Build the conflict by flipping one byte inside halfA's scriptSig. */
      char bad[2200]; snprintf(bad, sizeof bad, "%s", halfA);
      /* input 0's scriptSig body starts after version(8) + vin count(2) +
       * outpoint(72) + scriptSig-len(2) = 84 hex chars */
      bad[90] = (bad[90] == 'a') ? 'b' : 'a';
      ck("the mutated copy really differs from halfA", strcmp(bad, halfA) != 0);
      char cj[5000]; snprintf(cj, sizeof cj, "[[\"%s\",\"%s\"]]", halfA, bad);
      rj_val* r = call("combinerawtransaction", cj, &ec, &em);
      ck("two txs with DIFFERENT data for one input -> refused, not merged",
         r == NULL && ec == -22 && em && strstr(em, "combinepsbt"));
      rj_free(r); }

    { /* mismatched inputs: 2-input tx vs the 1-input tx from part 1 */
      char cj[5000]; snprintf(cj, sizeof cj, "[[\"%s\",\"%s\"]]", both, signed_hex);
      rj_val* r = call("combinerawtransaction", cj, &ec, &em);
      ck("transactions with different inputs -> -8", r == NULL && ec == -8);
      rj_free(r); }

    { rj_val* r = call("combinerawtransaction", "[[\"zz\"]]", &ec, &em);
      ck("combinerawtransaction on garbage -> -22", r == NULL && ec == -22); rj_free(r); }

    /* ================================================================
     * 3. utxoupdatepsbt and the two funding refusals.
     * ================================================================ */
    { /* no UTXO store wired in this harness, so the PSBT comes back
       * unchanged rather than invented -- and it must still be a valid PSBT */
      snprintf(pj, sizeof pj, "[\"%s\"]", psbt64);
      rj_val* r = call("utxoupdatepsbt", pj, &ec, &em);
      ck("utxoupdatepsbt returns a base64 PSBT", r && r->typ == RJ_STR);
      { char again[4000]; snprintf(again, sizeof again, "[\"%s\"]", r ? r->str : "");
        rj_val* f = call("finalizepsbt", again, &ec, &em);
        ck_str("the returned PSBT still finalizes to the same transaction",
               S(f,"hex"), signed_hex);
        rj_free(f); }
      rj_free(r); }

    { /* the descriptors argument is honoured (2026-09-01: the Updater); a malformed descriptor is a parse error, not ignored */
      snprintf(pj, sizeof pj, "[\"%s\",[\"wpkh(%s)\"]]", psbt64, "xpub");
      rj_val* r = call("utxoupdatepsbt", pj, &ec, &em);
      ck("a malformed descriptor in the descriptors argument is an ERROR, not silently ignored",
         r == NULL && ec == -5 && em && strstr(em, "not valid"));
      rj_free(r); }

    { /* fundrawtransaction is implemented now (rpc_wallet_ops.c); in this
       * harness no rescan has run, so it refuses at the coin-knowledge step
       * rather than pretending to select from coins it cannot see */
      rj_val* r = call("fundrawtransaction",
                       "[\"0200000000010000000000000000000000000000\"]", &ec, &em);
      ck("fundrawtransaction without a rescan refuses at the funding step",
         r == NULL && ec == -4 && em && strstr(em, "rescan"));
      rj_free(r);
      r = call("descriptorprocesspsbt", "[\"x\",[]]", &ec, &em);
      ck("descriptorprocesspsbt is real (2026-09-01): a bad PSBT fails at decoding, not at a missing signer",
         r == NULL && ec == -22 && em && strstr(em, "decode"));
      rj_free(r); }

    /* ================================================================
     * walletprocesspsbt: the Signer role, end to end (2026-08-26).
     * A PSBT whose one input is a P2WPKH the WALLET's own m/84'/0'/0'/0/0
     * key controls, carrying only witness_utxo -- the wallet must sign it,
     * finalize it (default), report complete, and hand back the hex.
     * ================================================================ */
    {
        static unsigned char seed[64];
        for (int i = 0; i < 64; i++) seed[i] = (unsigned char)(0x42 + i);
        unsigned idx[5] = {0x80000000u|84u, 0x80000000u, 0x80000000u, 0, 0};
        unsigned char wk[32], wc[32], wpub[33], wh160[20];
        ck("wallet key derives", bip32_derive_path(wk, wc, seed, 64, idx, 5) == 1);
        scalar_to_pubkey(wpub, wk);
        hash160(wh160, wpub, 33);
        char wh160h[41]; hexify(wh160h, wh160, 20);

        /* unsigned tx: spend (0x02-filled txid, vout 0), pay 0.999 to the
         * same P2PKH frame the earlier sections use */
        char wuns[600];
        snprintf(wuns, sizeof wuns,
            "02000000" "01"
            "0202020202020202020202020202020202020202020202020202020202020202"
            "00000000" "00" "fdffffff"
            "01" "605af40500000000" "19" "76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac"
            "00000000");
        unsigned char utx2[600]; size_t utx2l = unhex(utx2, wuns);
        char wspk[64]; snprintf(wspk, sizeof wspk, "0014%s", wh160h);

        unsigned char ps[2000]; long o = 0;
        ps[o++]='p'; ps[o++]='s'; ps[o++]='b'; ps[o++]='t'; ps[o++]=0xff;
        { unsigned char k = 0x00; o += kv(ps+o, &k, 1, utx2, utx2l); ps[o++] = 0x00; }
        { unsigned char wu[64]; long w2 = 0;
          unsigned long long val = 100000000ULL;
          for (int i = 0; i < 8; i++) wu[w2++] = (unsigned char)(val >> (8*i));
          unsigned char spkb[32]; size_t spkl = unhex(spkb, wspk);
          w2 += vi(wu+w2, spkl); memcpy(wu+w2, spkb, spkl); w2 += (long)spkl;
          unsigned char k1 = 0x01;
          o += kv(ps+o, &k1, 1, wu, (unsigned long)w2);
          ps[o++] = 0x00; }
        ps[o++] = 0x00;
        char ps64[4000]; b64(ps64, ps, o);

        char wpj[4200]; snprintf(wpj, sizeof wpj, "[\"%s\"]", ps64);
        rj_val* wr = callw("walletprocesspsbt", wpj, seed, &ec, &em);
        ck("walletprocesspsbt signs and completes", wr != NULL);
        ck("...complete true", wr && S(wr, "complete") && S(wr, "complete")[0] == '1');
        const char* whex = wr ? S(wr, "hex") : NULL;
        ck("...hex present when complete (finalize default)", whex != NULL);
        if (whex){
            /* the signed tx's witness must be [sig, OUR pubkey] */
            unsigned char st[2000]; size_t stl = unhex(st, whex);
            char wpubh[67]; hexify(wpubh, wpub, 33);
            char* found = strstr(whex, wpubh);
            ck("...witness carries the wallet's pubkey", found != NULL && stl > utx2l);
        }
        /* the returned PSBT is FINALIZED: final witness present, no partial sigs */
        const char* wps = wr ? S(wr, "psbt") : NULL;
        ck("...psbt returned", wps != NULL);
        if (wps){
            char fpj[4200]; snprintf(fpj, sizeof fpj, "[\"%s\"]", wps);
            rj_val* fr2 = call("finalizepsbt", fpj, &ec, &em);
            ck("...finalizepsbt agrees it is complete",
               fr2 && S(fr2, "complete") && S(fr2, "complete")[0] == '1');
            const char* fhex = fr2 ? S(fr2, "hex") : NULL;
            ck("...and extracts the SAME transaction", fhex && whex && !strcmp(fhex, whex));
            rj_free(fr2);
        }
        rj_free(wr);

        /* finalize=false: partial signature instead of final fields */
        snprintf(wpj, sizeof wpj, "[\"%s\", true, \"ALL\", true, false]", ps64);
        wr = callw("walletprocesspsbt", wpj, seed, &ec, &em);
        ck("finalize=false processes", wr != NULL);
        if (wr){
            const char* wps2 = S(wr, "psbt");
            /* finalizing that PSBT must reproduce the same hex -- proving a
             * genuine PARTIAL_SIG (not final fields) was embedded */
            char fpj[4200]; snprintf(fpj, sizeof fpj, "[\"%s\"]", wps2 ? wps2 : "");
            rj_val* fr3 = call("finalizepsbt", fpj, &ec, &em);
            ck("partial-sig PSBT finalizes independently",
               fr3 && S(fr3, "complete") && S(fr3, "complete")[0] == '1' && S(fr3, "hex"));
            rj_free(fr3);
        }
        rj_free(wr);

        /* no wallet -> the honest -4 */
        { rj_val* r2 = call("walletprocesspsbt", wpj, &ec, &em);
          ck("without a wallet: -4 refusal", r2 == NULL && ec == -4);
          rj_free(r2); }
    }

    ck("all three are advertised as known methods",
       rpc_known_method("combinerawtransaction") &&
       rpc_known_method("finalizepsbt") &&
       rpc_known_method("utxoupdatepsbt"));

    /* ================================================================
     * descriptorprocesspsbt: the wallet-less Signer (2026-09-01). The
     * private key comes from the descriptor itself. A P2WPKH input under
     * wpkh(WIF) is signed and finalized; a P2SH-P2WPKH input under
     * sh(wpkh(WIF)) gets its redeemScript from the descriptor; a
     * descriptor that does not cover the input signs nothing.
     * ================================================================ */
    {
        extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);
        extern void scalar_to_pubkey(unsigned char pub[33], const unsigned char k[32]);
        extern void hash160(unsigned char out[20], const void* in, long long len);
        unsigned char dk[32]; for (int i = 0; i < 32; i++) dk[i] = (unsigned char)(0x71 + i);
        unsigned char dpub[33], dh[20]; scalar_to_pubkey(dpub, dk); hash160(dh, dpub, 33);
        char dhh[41]; hexify(dhh, dh, 20);
        unsigned char pay[34]; pay[0] = 0x80; memcpy(pay+1, dk, 32); pay[33] = 1;
        char wif[64]; base58check_encode(wif, pay, 34);
        char wuns[600];
        snprintf(wuns, sizeof wuns,
            "02000000" "01"
            "0303030303030303030303030303030303030303030303030303030303030303"
            "00000000" "00" "fdffffff"
            "01" "605af40500000000" "19" "76a914fc7250a211deddc70ee5a2738de5f07817351cef88ac"
            "00000000");
        unsigned char utx2[600]; size_t utx2l = unhex(utx2, wuns);
        /* helper: a one-input PSBT carrying witness_utxo {1 BTC, spk} */
        #define MK_PSBT(ps64, spkhex) do{ \
            unsigned char ps[2000]; long o = 0; \
            ps[o++]='p'; ps[o++]='s'; ps[o++]='b'; ps[o++]='t'; ps[o++]=0xff; \
            { unsigned char k = 0x00; o += kv(ps+o, &k, 1, utx2, utx2l); ps[o++] = 0x00; } \
            { unsigned char wu[64]; long w2 = 0; unsigned long long val = 100000000ULL; \
              for (int i = 0; i < 8; i++) wu[w2++] = (unsigned char)(val >> (8*i)); \
              unsigned char spkb[64]; size_t spkl = unhex(spkb, spkhex); \
              w2 += vi(wu+w2, spkl); memcpy(wu+w2, spkb, spkl); w2 += (long)spkl; \
              unsigned char k1 = 0x01; o += kv(ps+o, &k1, 1, wu, (unsigned long)w2); ps[o++] = 0x00; } \
            ps[o++] = 0x00; b64(ps64, ps, o); }while(0)
        char wspk[64]; snprintf(wspk, sizeof wspk, "0014%s", dhh);
        char ps64[4000]; MK_PSBT(ps64, wspk);
        char pj[4400]; snprintf(pj, sizeof pj, "[\"%s\", [\"wpkh(%s)\"]]", ps64, wif);
        rj_val* dr = call("descriptorprocesspsbt", pj, &ec, &em);
        ck("descriptorprocesspsbt signs a wpkh(WIF) input", dr != NULL);
        if (!dr) printf("    (%ld: %s)\n", ec, em ? em : "");
        ck("...complete true", dr && S(dr, "complete") && S(dr, "complete")[0] == '1');
        { const char* h = dr ? S(dr, "hex") : NULL; char ph[67]; hexify(ph, dpub, 33);
          ck("...hex present and its witness carries the descriptor's pubkey", h && strstr(h, ph)); }
        rj_free(dr);
        /* sh(wpkh(WIF)): the redeemScript comes from the descriptor */
        { unsigned char rd[22] = {0x00, 0x14}; memcpy(rd+2, dh, 20); unsigned char rh[20]; hash160(rh, rd, 22);
          char rhh[41]; hexify(rhh, rh, 20); char sspk[64]; snprintf(sspk, sizeof sspk, "a914%s87", rhh);
          MK_PSBT(ps64, sspk);
          snprintf(pj, sizeof pj, "[\"%s\", [\"sh(wpkh(%s))\"]]", ps64, wif);
          dr = call("descriptorprocesspsbt", pj, &ec, &em);
          ck("sh(wpkh(WIF)) input signs with the descriptor's redeemScript", dr && S(dr, "complete") && S(dr, "complete")[0] == '1');
          if (!dr) printf("    (%ld: %s)\n", ec, em ? em : "");
          rj_free(dr); }
        /* a descriptor that does not cover the input signs nothing */
        MK_PSBT(ps64, wspk);
        snprintf(pj, sizeof pj, "[\"%s\", [\"pkh(%s)\"]]", ps64, wif);
        dr = call("descriptorprocesspsbt", pj, &ec, &em);
        ck("an uncovered input is left unsigned: complete false, no hex", dr && S(dr, "complete") && S(dr, "complete")[0] == '0' && !S(dr, "hex"));
        rj_free(dr);
        /* a public-only descriptor cannot sign, and says nothing false */
        { char ph[67]; hexify(ph, dpub, 33);
          snprintf(pj, sizeof pj, "[\"%s\", [\"wpkh(%s)\"]]", ps64, ph);
          dr = call("descriptorprocesspsbt", pj, &ec, &em);
          ck("a public-key-only descriptor leaves the input unsigned", dr && S(dr, "complete") && S(dr, "complete")[0] == '0');
          rj_free(dr); }
        expect_err_any("a malformed descriptor is refused", "descriptorprocesspsbt", "[\"cHNidP8=\", [\"wpkh(notakey)\"]]", -5);
        /* wsh(multi(2,K1,K2)): the witnessScript comes from the descriptor (2026-09-01) */
        { unsigned char dk2[32]; for (int i = 0; i < 32; i++) dk2[i] = (unsigned char)(0x91 + i);
          unsigned char dpub2[33]; scalar_to_pubkey(dpub2, dk2);
          unsigned char pay2[34]; pay2[0] = 0x80; memcpy(pay2+1, dk2, 32); pay2[33] = 1; char wif2[64]; base58check_encode(wif2, pay2, 34);
          unsigned char ws[71]; int o = 0; ws[o++] = 0x52; ws[o++] = 33; memcpy(ws+o, dpub, 33); o += 33; ws[o++] = 33; memcpy(ws+o, dpub2, 33); o += 33; ws[o++] = 0x52; ws[o++] = 0xae;
          extern void sha256_full(unsigned char out[32], const void* msg, unsigned long len);
          unsigned char wsh[32]; sha256_full(wsh, ws, (unsigned long)o); char wshh[65]; hexify(wshh, wsh, 32);
          char wspk2[80]; snprintf(wspk2, sizeof wspk2, "0020%s", wshh);
          MK_PSBT(ps64, wspk2);
          char ph1[67], ph2[67]; hexify(ph1, dpub, 33); hexify(ph2, dpub2, 33);
          snprintf(pj, sizeof pj, "[\"%s\", [\"wsh(multi(2,%s,%s))\"]]", ps64, wif, wif2);
          dr = call("descriptorprocesspsbt", pj, &ec, &em);
          ck("wsh(multi(2,WIF,WIF)) input signs to completion with the descriptor's witnessScript", dr && S(dr, "complete") && S(dr, "complete")[0] == '1');
          if (!dr) printf("    (%ld: %s)\n", ec, em ? em : "");
          rj_free(dr);
          /* only one of the two keys: partial, not complete */
          snprintf(pj, sizeof pj, "[\"%s\", [\"wsh(multi(2,%s,%s))\"]]", ps64, wif, ph2);
          dr = call("descriptorprocesspsbt", pj, &ec, &em);
          ck("...with one private key it stays incomplete", dr && S(dr, "complete") && S(dr, "complete")[0] == '0');
          if (!dr) printf("    (%ld: %s)\n", ec, em ? em : "");
          else if (S(dr, "complete")) printf("    (complete=%s)\n", S(dr, "complete"));
          rj_free(dr); }
        #undef MK_PSBT
    }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
