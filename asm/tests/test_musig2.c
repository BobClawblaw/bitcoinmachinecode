/* tests/test_musig2.c -- BIP327 MuSig2 against libsecp256k1's copy of the
 * BIP's vectors (tests/musig2_vectors.h): key aggregation (+ tweak
 * errors), nonce generation, nonce aggregation (+ invalid pubnonces),
 * sign/verify (valid, signing errors, verification failures/errors), tweaked
 * signing, and signature aggregation -- every case, including the failing
 * ones, with the same expectations libsecp256k1's own test suite checks.
 * The aggregated signatures are additionally verified by the node's
 * consensus schnorr_verify. */
#include <stdio.h>
#include <string.h>
#include "../musig2.h"
#include "musig2_vectors.h"
typedef unsigned char u8;
extern int schnorr_verify(const u8* sig, const u8* pk, const u8* msg, int msglen);
static int fails = 0, checks = 0;
static void ck(const char* l, int c){ checks++; if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void hexs(char* o, const u8* b, int n){ for (int i=0;i<n;i++) sprintf(o+2*i,"%02x",b[i]); o[2*n]=0; }

/* keyagg over key_indices, then the tweaks in order; mirrors libsecp256k1's
 * musig_vectors_keyagg_and_tweak. Returns 1 ok, 0 with *err = MUSIG_PUBKEY /
 * MUSIG_TWEAK. */
static int keyagg_and_tweak(enum MUSIG_ERROR* err, musig2_keyagg_t* ka, const unsigned char (*pubkeys)[33],
                            const unsigned char (*tweaks)[32], size_t nk, const size_t* ki,
                            size_t nt, const size_t* ti, const int* xonly){
    unsigned char pks[8][33];
    for (size_t i = 0; i < nk; i++) memcpy(pks[i], pubkeys[ki[i]], 33);
    if (!musig2_key_agg(ka, pks, (int)nk)){ *err = MUSIG_PUBKEY; return 0; }
    for (size_t i = 0; i < nt; i++) if (!musig2_tweak(ka, tweaks[ti[i]], xonly[i])){ *err = MUSIG_TWEAK; return 0; }
    return 1;
}
#define ARRLEN(a) (sizeof(a)/sizeof((a)[0]))
int main(void){
    char lab[200];
    printf("== KeyAgg ==\n");
    { const struct musig_key_agg_vector* v = &musig_key_agg_vector;
      for (size_t i = 0; i < ARRLEN(v->valid_case); i++){
          const struct musig_key_agg_valid_test_case* c = &v->valid_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e; u8 x[32];
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, v->tweaks, c->key_indices_len, c->key_indices, 0, NULL, NULL);
          if (ok) musig2_agg_xonly(x, &ka);
          snprintf(lab, sizeof lab, "key_agg valid %zu: aggregate x-only key matches", i);
          ck(lab, ok && !memcmp(x, c->expected, 32));
          if (ok && memcmp(x, c->expected, 32)){ char a[65], b[65]; hexs(a, x, 32); hexs(b, c->expected, 32); printf("    got  %s\n    want %s\n", a, b); }
      }
      for (size_t i = 0; i < ARRLEN(v->error_case); i++){
          const struct musig_key_agg_error_test_case* c = &v->error_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e = MUSIG_OTHER;
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, v->tweaks, c->key_indices_len, c->key_indices, c->tweak_indices_len, c->tweak_indices, c->is_xonly);
          snprintf(lab, sizeof lab, "key_agg error %zu: rejected with %s", i, c->error == MUSIG_PUBKEY ? "invalid pubkey" : "invalid tweak");
          ck(lab, !ok && e == c->error);
      }
    }
    printf("== NonceGen ==\n");
    { const struct musig_nonce_gen_vector* v = &musig_nonce_gen_vector;
      for (size_t i = 0; i < ARRLEN(v->test_case); i++){
          const struct musig_nonce_gen_test_case* c = &v->test_case[i];
          u8 sec[97], pub[66];
          int ok = musig2_nonce_gen(sec, pub, c->rand_, c->has_sk ? c->sk : NULL, c->pk, c->has_aggpk ? c->aggpk : NULL,
                                    c->has_msg ? c->msg : NULL, 32, c->has_extra_in ? c->extra_in : NULL, c->has_extra_in ? 32 : 0);
          snprintf(lab, sizeof lab, "nonce_gen %zu: secnonce (k1||k2||pk) matches", i);
          ck(lab, ok && !memcmp(sec, c->expected_secnonce, 97));
          if (ok && memcmp(sec, c->expected_secnonce, 97)){ char a[200], b[200]; hexs(a, sec, 97); hexs(b, c->expected_secnonce, 97); printf("    got  %s\n    want %s\n", a, b); }
          snprintf(lab, sizeof lab, "nonce_gen %zu: pubnonce matches", i);
          ck(lab, ok && !memcmp(pub, c->expected_pubnonce, 66));
      }
    }
    printf("== NonceAgg ==\n");
    { const struct musig_nonce_agg_vector* v = &musig_nonce_agg_vector;
      for (size_t i = 0; i < ARRLEN(v->valid_case); i++){
          const struct musig_nonce_agg_test_case* c = &v->valid_case[i];
          u8 pns[2][66]; for (int j = 0; j < 2; j++) memcpy(pns[j], v->pnonces[c->pnonce_indices[j]], 66);
          u8 agg[66]; int ok = musig2_nonce_agg(agg, pns, 2);
          snprintf(lab, sizeof lab, "nonce_agg valid %zu: aggnonce matches%s", i, i == 1 ? " (a point at infinity encodes as zeros)" : "");
          ck(lab, ok && !memcmp(agg, c->expected, 66));
      }
      for (size_t i = 0; i < ARRLEN(v->error_case); i++){
          const struct musig_nonce_agg_test_case* c = &v->error_case[i];
          int all = 1;
          for (int j = 0; j < 2; j++){ int expect = c->invalid_nonce_idx != j; if (musig2_pubnonce_valid(v->pnonces[c->pnonce_indices[j]]) != expect) all = 0; }
          u8 pns[2][66], agg[66]; for (int j = 0; j < 2; j++) memcpy(pns[j], v->pnonces[c->pnonce_indices[j]], 66);
          snprintf(lab, sizeof lab, "nonce_agg error %zu: the invalid pubnonce is rejected", i);
          ck(lab, all && !musig2_nonce_agg(agg, pns, 2));
      }
    }
    printf("== Sign / PartialSigVerify ==\n");
    { const struct musig_sign_verify_vector* v = &musig_sign_verify_vector;
      for (size_t i = 0; i < ARRLEN(v->valid_case); i++){
          const struct musig_valid_case* c = &v->valid_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e; musig2_session_t s; u8 sec[97], psig[32];
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, NULL, c->key_indices_len, c->key_indices, 0, NULL, NULL);
          ok = ok && musig2_session(&s, &ka, v->aggnonces[c->aggnonce_index], v->msgs[c->msg_index], 32);
          memcpy(sec, v->secnonces[0], 64); memcpy(sec + 64, v->pubkeys[0], 33);
          ok = ok && musig2_partial_sign(psig, sec, v->sk, &ka, &s);
          snprintf(lab, sizeof lab, "sign valid %zu: partial signature matches", i);
          ck(lab, ok && !memcmp(psig, c->expected, 32));
          if (ok && memcmp(psig, c->expected, 32)){ char a[65], b[65]; hexs(a, psig, 32); hexs(b, c->expected, 32); printf("    got  %s\n    want %s\n", a, b); }
          snprintf(lab, sizeof lab, "sign valid %zu: partial signature verifies against pubnonce/pubkey", i);
          ck(lab, ok && musig2_partial_sig_verify(psig, v->pubnonces[0], v->pubkeys[0], &ka, &s));
      }
      for (size_t i = 0; i < ARRLEN(v->sign_error_case); i++){
          const struct musig_sign_error_case* c = &v->sign_error_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e = MUSIG_OTHER; musig2_session_t s; u8 sec[97], psig[32];
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, NULL, c->key_indices_len, c->key_indices, 0, NULL, NULL);
          /* the BIP files "signing key is not a participant" under MUSIG_PUBKEY
           * too (case 0: valid keys, but the signer's is not among them);
           * libsecp256k1 skips it, this implementation rejects it at Sign */
          if (c->error == MUSIG_PUBKEY && !ok){ snprintf(lab, sizeof lab, "sign error %zu: invalid participant pubkey rejected", i); ck(lab, e == MUSIG_PUBKEY); continue; }
          if (!ok){ snprintf(lab, sizeof lab, "sign error %zu: key aggregation unexpectedly failed", i); ck(lab, 0); continue; }
          int sess = musig2_session(&s, &ka, v->aggnonces[c->aggnonce_index], v->msgs[c->msg_index], 32);
          if (c->error == MUSIG_AGGNONCE){ snprintf(lab, sizeof lab, "sign error %zu: invalid aggnonce rejected", i); ck(lab, !sess); continue; }
          memcpy(sec, v->secnonces[c->secnonce_index], 64); memcpy(sec + 64, v->pubkeys[0], 33);
          int signed_ok = sess && musig2_partial_sign(psig, sec, v->sk, &ka, &s);
          snprintf(lab, sizeof lab, "sign error %zu: %s", i, c->error == MUSIG_SECNONCE ? "zero secnonce rejected" : "signing key that is not a participant rejected");
          ck(lab, !signed_ok);
      }
      for (size_t i = 0; i < ARRLEN(v->verify_fail_case); i++){
          const struct musig_verify_fail_error_case* c = &v->verify_fail_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e; musig2_session_t s; u8 pns[3][66], agg[66];
          for (size_t j = 0; j < c->nonce_indices_len; j++) memcpy(pns[j], v->pubnonces[c->nonce_indices[j]], 66);
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, NULL, c->key_indices_len, c->key_indices, 0, NULL, NULL);
          ok = ok && musig2_nonce_agg(agg, pns, (int)c->nonce_indices_len) && musig2_session(&s, &ka, agg, v->msgs[c->msg_index], 32);
          snprintf(lab, sizeof lab, "verify fail %zu: %s", i, c->error == MUSIG_SIG ? "partial sig out of range rejected" : "wrong partial sig rejected");
          ck(lab, ok && !musig2_partial_sig_verify(c->sig, pns[c->signer_index], v->pubkeys[c->signer_index], &ka, &s));
      }
      for (size_t i = 0; i < ARRLEN(v->verify_error_case); i++){
          const struct musig_verify_fail_error_case* c = &v->verify_error_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e = MUSIG_OTHER;
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, NULL, c->key_indices_len, c->key_indices, 0, NULL, NULL);
          if (c->error == MUSIG_PUBKEY){ snprintf(lab, sizeof lab, "verify error %zu: invalid pubkey rejected", i); ck(lab, !ok && e == MUSIG_PUBKEY); }
          else { snprintf(lab, sizeof lab, "verify error %zu: invalid pubnonce rejected", i); ck(lab, ok && !musig2_pubnonce_valid(v->pubnonces[c->nonce_indices[c->signer_index]])); }
      }
    }
    printf("== Tweaked signing ==\n");
    { const struct musig_tweak_vector* v = &musig_tweak_vector;
      for (size_t i = 0; i < ARRLEN(v->valid_case); i++){
          const struct musig_tweak_case* c = &v->valid_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e; musig2_session_t s; u8 sec[97], psig[32];
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, v->tweaks, c->key_indices_len, c->key_indices, c->tweak_indices_len, c->tweak_indices, c->is_xonly);
          ok = ok && musig2_session(&s, &ka, v->aggnonce, v->msg, 32);
          memcpy(sec, v->secnonce, 64); memcpy(sec + 64, v->pubkeys[0], 33);
          ok = ok && musig2_partial_sign(psig, sec, v->sk, &ka, &s);
          snprintf(lab, sizeof lab, "tweak valid %zu (%zu tweak(s)): partial signature matches", i, c->tweak_indices_len);
          ck(lab, ok && !memcmp(psig, c->expected, 32));
          if (ok && memcmp(psig, c->expected, 32)){ char a[65], b[65]; hexs(a, psig, 32); hexs(b, c->expected, 32); printf("    got  %s\n    want %s\n", a, b); }
          snprintf(lab, sizeof lab, "tweak valid %zu: verifies", i);
          ck(lab, ok && musig2_partial_sig_verify(psig, v->pubnonces[c->nonce_indices[c->signer_index]], v->pubkeys[0], &ka, &s));
      }
      for (size_t i = 0; i < ARRLEN(v->error_case); i++){
          const struct musig_tweak_case* c = &v->error_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e = MUSIG_OTHER;
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, v->tweaks, c->key_indices_len, c->key_indices, c->tweak_indices_len, c->tweak_indices, c->is_xonly);
          snprintf(lab, sizeof lab, "tweak error %zu: out-of-range tweak rejected", i);
          ck(lab, !ok && e == MUSIG_TWEAK);
      }
    }
    printf("== PartialSigAgg ==\n");
    { const struct musig_sig_agg_vector* v = &musig_sig_agg_vector;
      for (size_t i = 0; i < ARRLEN(v->valid_case); i++){
          const struct musig_sig_agg_case* c = &v->valid_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e; musig2_session_t s; u8 ps[4][32], sig[64], x[32];
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, v->tweaks, c->key_indices_len, c->key_indices, c->tweak_indices_len, c->tweak_indices, c->is_xonly);
          ok = ok && musig2_session(&s, &ka, c->aggnonce, v->msg, 32);
          for (size_t j = 0; j < c->psig_indices_len; j++) memcpy(ps[j], v->psigs[c->psig_indices[j]], 32);
          ok = ok && musig2_partial_sig_agg(sig, &s, &ka, ps, (int)c->psig_indices_len);
          snprintf(lab, sizeof lab, "sig_agg valid %zu: aggregated signature matches", i);
          ck(lab, ok && !memcmp(sig, c->expected, 64));
          if (ok && memcmp(sig, c->expected, 64)){ char a[129], b[129]; hexs(a, sig, 64); hexs(b, c->expected, 64); printf("    got  %s\n    want %s\n", a, b); }
          musig2_agg_xonly(x, &ka);
          snprintf(lab, sizeof lab, "sig_agg valid %zu: the consensus verifier accepts it for the (tweaked) aggregate key", i);
          ck(lab, ok && schnorr_verify(sig, x, v->msg, 32) == 1);
      }
      for (size_t i = 0; i < ARRLEN(v->error_case); i++){
          const struct musig_sig_agg_case* c = &v->error_case[i];
          musig2_keyagg_t ka; enum MUSIG_ERROR e; musig2_session_t s; u8 ps[4][32], sig[64];
          int ok = keyagg_and_tweak(&e, &ka, v->pubkeys, v->tweaks, c->key_indices_len, c->key_indices, c->tweak_indices_len, c->tweak_indices, c->is_xonly);
          ok = ok && musig2_session(&s, &ka, c->aggnonce, v->msg, 32);
          for (size_t j = 0; j < c->psig_indices_len; j++) memcpy(ps[j], v->psigs[c->psig_indices[j]], 32);
          snprintf(lab, sizeof lab, "sig_agg error %zu: out-of-range partial signature rejected", i);
          ck(lab, ok && !musig2_partial_sig_agg(sig, &s, &ka, ps, (int)c->psig_indices_len));
      }
    }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
