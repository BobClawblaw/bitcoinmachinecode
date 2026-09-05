/* test_taproot_verify_diff.c -- bitcoin_taproot_verify.asm vs
 * bitcoin_taproot_sighash.c's taproot_verify_input.
 *
 * Phase 2 slice 13a: the consensus fork for every taproot spend. Both
 * sides call the same leaves, so the differential isolates the
 * orchestration: annex detection, path classification, control-block size
 * rules, the merkle commitment (which must run at EVERY leaf version), the
 * unknown-leaf-version early accept, Core's prologue ordering (OP_SUCCESSx
 * before the stack limits), the BIP342 weight budget, and the interpreter
 * marshal. rc and the exact reason string are compared on every case.
 *
 * A real script-path ACCEPT is constructed here (leaf = OP_TRUE, control
 * block built from the real internal key so the commitment verifies
 * against a scriptPubKey this test derives with the same asm primitives) --
 * slice 11's lesson: a reject-only crypto differential is weaker than it
 * looks.
 *
 * Usage: ./test_taproot_verify_diff
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long u64;

extern int  taproot_verify_input(const u8* spk, const u8* const* wit, const u32* witlen,
                                 u32 nwit, const u8* tx, int64_t txlen, int64_t n_in,
                                 const u8* prevouts, const u8* amounts, const u8* spks,
                                 int64_t num_inputs, const char** reason);
extern long taproot_verify_input_asm(const u8* spk, const u8* const* wit, const u32* witlen,
                                     u32 nwit, const u8* tx, int64_t txlen, int64_t n_in,
                                     const u8* prevouts, const u8* amounts, const u8* spks,
                                     int64_t num_inputs, const char** reason);
extern int  tap_leaf_hash(u8 out[32], u32 leafver, const u8* script, u64 slen);
extern int  tap_merkle_root(u8 out[32], const u8* leaf, u32 have, const u8* control, u64 clen);
extern int  taproot_tweak_pubkey(u8 out[32], const u8* ipk, const u8* merkle);
extern void scalar_to_pubkey(u8 out33[33], const u8 priv[32]);

long mempool_resolve_confirmed_utxo(void* u, const u8 t[32], unsigned long i,
                                    unsigned long long* v, const u8** s, unsigned long* l){
    (void)u;(void)t;(void)i;(void)v;(void)s;(void)l; abort(); }

static long fails = 0, compared = 0;
static u8 txb[256]; static u64 txl;
static u8 prevouts[36*2], amounts[8*2], spks[2*35];

static void diff(const char* nm, const u8* spk, const u8* const* wit, const u32* wl,
                 u32 nwit, int64_t n_in, int64_t nin_total){
    const char *rc_ = "", *ra_ = "";
    int  c = taproot_verify_input(spk, wit, wl, nwit, txb, (int64_t)txl, n_in,
                                  prevouts, amounts, spks, nin_total, &rc_);
    long a = taproot_verify_input_asm(spk, wit, wl, nwit, txb, (int64_t)txl, n_in,
                                      prevouts, amounts, spks, nin_total, &ra_);
    compared++;
    if (c != (int)a){ if (fails<25) printf("FAIL %s: rc %d vs %ld\n", nm, c, a); fails++; return; }
    if (!c && strcmp(rc_, ra_)){ if (fails<25) printf("FAIL %s: '%s' vs '%s'\n", nm, rc_, ra_); fails++; }
}

static u64 mk_tx(u8* o){
    u64 n = 0;
    o[n++]=2;o[n++]=0;o[n++]=0;o[n++]=0;
    o[n++]=1; for (int k=0;k<36;k++) o[n++]=(u8)(k+9);
    o[n++]=0; o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    o[n++]=1; for (int k=0;k<8;k++) o[n++]=0; o[n++]=1; o[n++]=0x51;
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
    return n;
}


/* both twins must return `want` (used where the verdict itself is the point) */
static void expect(const char* nm, const u8* spk, const u8* const* wit, const u32* wl, u32 nwit,
                   int want, const char* want_reason){
    const char *rc_ = "", *ra_ = "";
    int  c = taproot_verify_input(spk, wit, wl, nwit, txb, (int64_t)txl, 0, prevouts, amounts, spks, 1, &rc_);
    long a = taproot_verify_input_asm(spk, wit, wl, nwit, txb, (int64_t)txl, 0, prevouts, amounts, spks, 1, &ra_);
    compared++;
    /* a rejection for the WRONG reason is a failure: the first draft of the
     * empty-pubkey vector was "rejected" for control-block parity and looked
     * green while testing nothing of what it claimed. */
    int ok = (c == want) && (a == (long)want) &&
             (want || (!strcmp(rc_, want_reason) && !strcmp(ra_, want_reason)));
    if (ok) printf("ok: %s -> %d%s%s\n", nm, want, want ? "" : " ", want ? "" : rc_);
    else { printf("FAIL %s: want %d '%s', C=%d ('%s') asm=%ld ('%s')\n", nm, want, want_reason?want_reason:"", c, rc_, a, ra_); fails++; }
}

int main(void){
    txl = mk_tx(txb);
    memset(prevouts, 0x31, sizeof prevouts);
    memset(amounts, 0, sizeof amounts);
    for (int i=0;i<2;i++) spks[i*35] = 34;          /* packed len-prefixed */
    static u8 priv[32]; for (int i=0;i<32;i++) priv[i]=(u8)(i+7);
    static u8 pub33[33]; scalar_to_pubkey(pub33, priv);
    const u8* ipk = pub33 + 1;                       /* x-only internal key */

    /* ---- a REAL script-path accept: leaf OP_TRUE, 33-byte control ---- */
    static u8 leaf[1] = {0x51};
    static u8 ctrl[33]; ctrl[0] = 0xc0; memcpy(ctrl+1, ipk, 32);
    u8 lh[32], mr[32], q[32];
    static u8 spk_ok[34];
    int have_real = 0;
    if (tap_leaf_hash(lh, 0xc0, leaf, 1) == 1 &&
        tap_merkle_root(mr, lh, 1, ctrl, 33) == 1 &&
        taproot_tweak_pubkey(q, ipk, mr) >= 1){
        spk_ok[0]=0x51; spk_ok[1]=0x20; memcpy(spk_ok+2, q, 32);
        memcpy(spks+1, spk_ok, 34); memcpy(spks+36, spk_ok, 34);
        have_real = 1;
        const u8* w[2] = { leaf, ctrl }; u32 wl[2] = { 1, 33 };
        diff("script-path OP_TRUE accept", spk_ok, w, wl, 2, 0, 1);
        /* same, with an annex appended */
        static u8 annex[4] = {0x50, 1, 2, 3};
        const u8* w3[3] = { leaf, ctrl, annex }; u32 wl3[3] = { 1, 33, 4 };
        diff("script-path accept + annex", spk_ok, w3, wl3, 3, 0, 1);
        /* commitment mismatch: flip one spk byte */
        static u8 spk_bad[34]; memcpy(spk_bad, spk_ok, 34); spk_bad[5] ^= 1;
        diff("commitment mismatch", spk_bad, w, wl, 2, 0, 1);
        /* unknown leaf version: control[0] with a different version, and a
         * scriptPubKey rebuilt to commit to THAT leaf -> accept without exec */
        static u8 ctrl2[33]; memcpy(ctrl2, ctrl, 33); ctrl2[0] = 0xc2;
        u8 lh2[32], mr2[32], q2[32]; static u8 spk2[34];
        if (tap_leaf_hash(lh2, 0xc2, leaf, 1) == 1 &&
            tap_merkle_root(mr2, lh2, 1, ctrl2, 33) == 1 &&
            taproot_tweak_pubkey(q2, ipk, mr2) >= 1){
            spk2[0]=0x51; spk2[1]=0x20; memcpy(spk2+2, q2, 32);
            const u8* wu[2] = { leaf, ctrl2 }; u32 wlu[2] = { 1, 33 };
            diff("unknown leaf version accept", spk2, wu, wlu, 2, 0, 1);
        }
        /* OP_SUCCESSx leaf (0x50 is OP_SUCCESS80): accepts before any limit */
        static u8 leafs[1] = {0x50};
        static u8 ctrls[33]; memcpy(ctrls, ctrl, 33);
        u8 lh3[32], mr3[32], q3[32]; static u8 spk3[34];
        if (tap_leaf_hash(lh3, 0xc0, leafs, 1) == 1 &&
            tap_merkle_root(mr3, lh3, 1, ctrls, 33) == 1 &&
            taproot_tweak_pubkey(q3, ipk, mr3) >= 1){
            spk3[0]=0x51; spk3[1]=0x20; memcpy(spk3+2, q3, 32);
            const u8* ws[2] = { leafs, ctrls }; u32 wls[2] = { 1, 33 };
            diff("OP_SUCCESSx leaf accept", spk3, ws, wls, 2, 0, 1);
            /* OP_SUCCESSx overrides the element-size limit: oversized item */
            static u8 big[600]; memset(big, 0xaa, sizeof big);
            const u8* wb[3] = { big, leafs, ctrls }; u32 wlb[3] = { 600, 1, 33 };
            diff("OP_SUCCESSx with oversized item", spk3, wb, wlb, 3, 0, 1);
            /* without OP_SUCCESS, the same oversized item must be rejected */
            const u8* wb2[3] = { big, leaf, ctrl }; u32 wlb2[3] = { 600, 1, 33 };
            diff("oversized initial-stack item", spk_ok, wb2, wlb2, 3, 0, 1);
        }
        /* script that fails: OP_0 leaf, commitment rebuilt to match */
        static u8 leaff[1] = {0x00};
        u8 lh4[32], mr4[32], q4[32]; static u8 spk4[34];
        if (tap_leaf_hash(lh4, 0xc0, leaff, 1) == 1 &&
            tap_merkle_root(mr4, lh4, 1, ctrl, 33) == 1 &&
            taproot_tweak_pubkey(q4, ipk, mr4) >= 1){
            spk4[0]=0x51; spk4[1]=0x20; memcpy(spk4+2, q4, 32);
            const u8* wf[2] = { leaff, ctrl }; u32 wlf[2] = { 1, 33 };
            diff("tapscript evaluates false", spk4, wf, wlf, 2, 0, 1);
        }
        /* ---- IR-3 (INTERP_REVIEW_2026-09-05): the asm twin never read
         * taproot_checksig_ctx.hard_fail after script_eval (and sized a
         * 96-byte frame slot for a 104-byte ctx, so hard_fail landed in the
         * dead err slot). Core's EvalChecksigTapscript FAILS THE SCRIPT for an
         * invalid non-empty signature or an empty pubkey; only an empty sig
         * with a non-empty pubkey pushes false. With an OP_NOT tail the stack
         * ends truthy, so only the hard_fail read separates accept from
         * reject. The C twin rejects; the asm twin accepted. */
        {
            /* leaf A: <32B x-only pk> OP_CHECKSIG OP_NOT, witness [bad sig64] */
            static u8 leafA[35]; leafA[0]=0x20; memcpy(leafA+1, ipk, 32); leafA[33]=0xac; leafA[34]=0x91;
            u8 lhA[32], mrA[32], qA[32]; static u8 spkA[34]; long twA;
            static u8 ctrlA[33]; memcpy(ctrlA, ctrl, 33);
            if (tap_leaf_hash(lhA, 0xc0, leafA, 35) == 1 &&
                tap_merkle_root(mrA, lhA, 1, ctrlA, 33) == 1 &&
                (twA = taproot_tweak_pubkey(qA, ipk, mrA)) >= 1){
                ctrlA[0] = 0xc0 | (twA == 2);            /* BIP341 parity bit */
                spkA[0]=0x51; spkA[1]=0x20; memcpy(spkA+2, qA, 32);
                memcpy(spks+1, spkA, 34); memcpy(spks+36, spkA, 34);
                static u8 badsig[64]; memset(badsig, 0x01, 64);
                const u8* wA[3] = { badsig, leafA, ctrlA }; u32 wlA[3] = { 64, 35, 33 };
                expect("IR-3 invalid sig + OP_NOT (hard fail, truthy stack)", spkA, wA, wlA, 3, 0, "p2tr tapscript checksig invalid");
                /* control: EMPTY sig, same pubkey -> Core pushes false, OP_NOT
                 * makes it true -> ACCEPT. Both twins must accept. */
                const u8* wC[3] = { badsig, leafA, ctrlA }; u32 wlC[3] = { 0, 35, 33 };
                expect("IR-3 control: empty sig + OP_NOT accepts", spkA, wC, wlC, 3, 1, NULL);
            } else { printf("FAIL: IR-3 fixture A\n"); fails++; }
            /* leaf B: OP_0 OP_0 OP_CHECKSIG OP_NOT -> empty pubkey is a hard
             * fail in Core regardless of the signature. NOT an IR-3 vector,
             * though the review listed it as one: the INTERPRETER refuses an
             * empty tapscript pubkey itself (SCR-3, audit 2026-09-03), so
             * script_eval returns 0 and the callback's hard_fail is never the
             * deciding read. Kept as a control: both twins reject, and for
             * the same reason. */
            static u8 leafB[4] = {0x00, 0x00, 0xac, 0x91};
            u8 lhB[32], mrB[32], qB[32]; static u8 spkB[34]; long twB;
            static u8 ctrlB[33]; memcpy(ctrlB, ctrl, 33);
            if (tap_leaf_hash(lhB, 0xc0, leafB, 4) == 1 &&
                tap_merkle_root(mrB, lhB, 1, ctrlB, 33) == 1 &&
                (twB = taproot_tweak_pubkey(qB, ipk, mrB)) >= 1){
                ctrlB[0] = 0xc0 | (twB == 2);            /* BIP341 parity bit */
                spkB[0]=0x51; spkB[1]=0x20; memcpy(spkB+2, qB, 32);
                memcpy(spks+1, spkB, 34); memcpy(spks+36, spkB, 34);
                const u8* wB[2] = { leafB, ctrlB }; u32 wlB[2] = { 4, 33 };
                expect("IR-3 control: empty pubkey + OP_NOT rejected in the interpreter (SCR-3)", spkB, wB, wlB, 2, 0, "p2tr tapscript execution failed");
            } else { printf("FAIL: IR-3 fixture B\n"); fails++; }
            memcpy(spks+1, spk_ok, 34); memcpy(spks+36, spk_ok, 34);
        }
    } else { printf("FAIL: could not build the real taproot fixture\n"); fails++; }

    if (!have_real) memset(spks+1, 0, 34);
    static u8 spk_any[34]; spk_any[0]=0x51; spk_any[1]=0x20; memset(spk_any+2, 0x5c, 32);

    /* ---- empty / annex-only witnesses ---- */
    { const u8* w[1] = { (const u8*)"" }; u32 wl[1] = { 0 };
      diff("empty witness (nwit=0)", spk_any, w, wl, 0, 0, 1);
      static u8 annex[2] = {0x50, 9};
      const u8* wa[2] = { annex, annex }; u32 wla[2] = { 2, 2 };
      /* nwit=2, last is annex -> eff=1 -> key path with wit[0]=annex bytes */
      diff("annex + one item (key path)", spk_any, wa, wla, 2, 0, 1); }

    /* ---- key-path rejects at several signature lengths ---- */
    { static u8 sig[65]; memset(sig, 0x77, sizeof sig);
      u32 lens[] = { 0, 1, 63, 64, 65, 66 };
      for (unsigned i = 0; i < sizeof lens/sizeof lens[0]; i++){
          const u8* w[1] = { sig }; u32 wl[1] = { lens[i] };
          diff("key-path bad sig", spk_any, w, wl, 1, 0, 1);
      } }

    /* ---- control-block size rules ---- */
    { static u8 leafx[1] = {0x51};
      static u8 c[4200]; memset(c, 0xc0, sizeof c);
      u32 clens[] = { 0, 1, 32, 33, 34, 64, 65, 4129, 4130 };
      for (unsigned i = 0; i < sizeof clens/sizeof clens[0]; i++){
          const u8* w[2] = { leafx, c }; u32 wl[2] = { 1, clens[i] };
          diff("control block size", spk_any, w, wl, 2, 0, 1);
      } }

    /* ---- initial-stack count limit ---- */
    { enum { N = 1003 };
      static const u8* w[N]; static u32 wl[N];
      static u8 tiny[1] = {1};
      static u8 leafx[1] = {0x51};
      static u8 ctrlx[33]; memset(ctrlx, 0xc0, 33);
      for (int i = 0; i < N-2; i++){ w[i] = tiny; wl[i] = 1; }
      w[N-2] = leafx; wl[N-2] = 1;
      w[N-1] = ctrlx; wl[N-1] = 33;
      diff("1001 initial items (over limit)", spk_any, w, wl, N, 0, 1);
      diff("1000 initial items", spk_any, w, wl, N-1, 0, 1); }

    printf("compared %ld taproot-verify cases; %ld mismatch(es)\n", compared, fails);
    printf("%s (%ld failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
