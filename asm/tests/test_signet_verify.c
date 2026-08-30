/* tests/test_signet_verify.c -- BIP325 block-solution verification end to end.
 *
 * This is the layer that makes signet's consensus rule REAL: on signet the
 * block signature stands in for meaningful proof of work, so a node that got
 * this wrong in the permissive direction would accept anything.
 *
 * The positive cases are the strong ones. Each runs a REAL signet block's
 * REAL signature through this node's OWN script interpreter and secp256k1 --
 * a completely separate implementation from the Python that proved the layer
 * 2 vectors. Two independent paths can only agree on the sighash if the
 * modified merkle root, both synthetic transactions and the txid linking them
 * are all right; a single wrong byte anywhere makes the signature fail.
 *
 * The negative cases matter just as much. A verifier that returns 1
 * unconditionally passes every positive test in this file.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../daemon/signet.h"
#include "signet_txs_vectors.h"
#include "signet_custom_vectors.h"

extern void sha256_full(unsigned char out[32], const unsigned char* msg, long long len);

/* bitcoin_txval_modern.c is on the link line for the verifier stack but is
 * never entered from here: signet's to_sign spends a SYNTHETIC output whose
 * value and scriptPubKey are handed to the interpreter directly, so nothing
 * resolves a UTXO. Aborting rather than stubbing a return value makes that a
 * checked claim instead of a comment -- if this fires, the dispatch went
 * somewhere it should not. */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32],
                                    unsigned long index,
                                    unsigned long long* value,
                                    const unsigned char** spk,
                                    unsigned long* spklen){
    (void)u;(void)txid;(void)index;(void)value;(void)spk;(void)spklen;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int fails = 0;
static void ok(int cond, const char* what){
    printf("  %s %s\n", cond ? "ok " : "FAIL", what);
    if (!cond) fails++;
}

static unsigned long unhex(const char* h, unsigned char* out, unsigned long cap){
    unsigned long n = strlen(h) / 2;
    if (n > cap){ fprintf(stderr, "unhex overflow\n"); exit(2); }
    for (unsigned long i = 0; i < n; i++){
        unsigned v = 0;
        for (int k = 0; k < 2; k++){
            char c = h[i*2+k]; v <<= 4;
            v |= (c >= '0' && c <= '9') ? (unsigned)(c-'0')
               : (c >= 'a' && c <= 'f') ? (unsigned)(c-'a'+10)
               : (c >= 'A' && c <= 'F') ? (unsigned)(c-'A'+10) : 16u;
        }
        out[i] = (unsigned char)v;
    }
    return n;
}

static unsigned char work[1 << 21];

/* Verify one vector, optionally with a field corrupted. */
static int run(const signet_txs_vec_t* V, const unsigned char* sol,
               unsigned long sollen, const unsigned char* mrk,
               unsigned int ntime, int nversion,
               const unsigned char* chal, unsigned long chalen){
    unsigned char prev[32];
    unhex(V->prev_block, prev, sizeof prev);
    return signet_check_solution(nversion, prev, ntime, mrk, sol, sollen,
                                 chal, chalen, work, sizeof work);
}

int main(void){
    static unsigned char sol[1<<16], chal[4096], mrk[32];

    printf("== REAL signet blocks verify through this node's own interpreter ==\n");
    int good = 0;
    for (int v = 0; v < SIGNET_TXS_NVEC; v++){
        const signet_txs_vec_t* V = &SIGNET_TXS_VEC[v];
        unsigned long sollen = unhex(V->solution, sol, sizeof sol);
        unsigned long chalen = unhex(V->challenge, chal, sizeof chal);
        unhex(V->signet_merkle, mrk, sizeof mrk);
        int r = run(V, sol, sollen, mrk, V->ntime, V->nversion, chal, chalen);
        if (r == 1) good++;
        else printf("  FAIL height %d: signet_check_solution returned %d\n",
                    V->height, r);
    }
    {
        char msg[160];
        snprintf(msg, sizeof msg, "%d/%d real signet blocks accepted "
                 "(real signatures, real secp256k1, real interpreter)",
                 good, SIGNET_TXS_NVEC);
        ok(good == SIGNET_TXS_NVEC, msg);
    }

    printf("== and a tampered block does NOT verify ==\n");
    {
        const signet_txs_vec_t* V = &SIGNET_TXS_VEC[0];
        unsigned long sollen = unhex(V->solution, sol, sizeof sol);
        unsigned long chalen = unhex(V->challenge, chal, sizeof chal);
        unhex(V->signet_merkle, mrk, sizeof mrk);

        unsigned char bad[32]; memcpy(bad, mrk, 32); bad[7] ^= 0x40;
        ok(run(V, sol, sollen, bad, V->ntime, V->nversion, chal, chalen) == 0,
           "a block whose transactions changed (merkle root) is rejected");

        ok(run(V, sol, sollen, mrk, V->ntime + 1, V->nversion, chal, chalen) == 0,
           "a block whose timestamp changed by one second is rejected");

        ok(run(V, sol, sollen, mrk, V->ntime, V->nversion ^ 4, chal, chalen) == 0,
           "a block whose version changed is rejected");

        unsigned char pv[32]; unhex(V->prev_block, pv, sizeof pv); pv[0] ^= 1;
        ok(signet_check_solution(V->nversion, pv, V->ntime, mrk, sol, sollen,
                                 chal, chalen, work, sizeof work) == 0,
           "a block built on a different parent is rejected");

        /* Flip a bit inside the DER signature, not the surrounding script. */
        unsigned char t[1<<16]; memcpy(t, sol, sollen);
        t[sollen - 8] ^= 0x10;
        ok(run(V, t, sollen, mrk, V->ntime, V->nversion, chal, chalen) == 0,
           "a block whose signature was altered is rejected");

        /* A different network's challenge must not accept this block. */
        unsigned char other[4096]; memcpy(other, chal, chalen);
        other[3] ^= 0x08;                      /* one bit of the first pubkey */
        ok(run(V, sol, sollen, mrk, V->ntime, V->nversion, other, chalen) == 0,
           "the same block under a different challenge is rejected");

        ok(run(V, NULL, 0, mrk, V->ntime, V->nversion, chal, chalen) == 0,
           "a block with NO solution is rejected under a signing challenge");
    }

    printf("== the WITNESS_UNEXPECTED rule sv_verify_script cannot see ==\n");
    {
        /* The default challenge is a bare CHECKMULTISIG -- not a witness
         * program -- so Core's VerifyScript ends in WITNESS_UNEXPECTED if the
         * solution carries any witness data. Re-encode the real solution with
         * a one-item witness stack appended; everything else is untouched and
         * the signature is still correct, so ONLY that rule can reject it. */
        const signet_txs_vec_t* V = &SIGNET_TXS_VEC[0];
        unsigned long sollen = unhex(V->solution, sol, sizeof sol);
        unsigned long chalen = unhex(V->challenge, chal, sizeof chal);
        unhex(V->signet_merkle, mrk, sizeof mrk);

        ok(sol[sollen-1] == 0x00, "the real solution ends with an empty witness stack");
        unsigned char t[1<<16];
        memcpy(t, sol, sollen - 1);
        t[sollen-1] = 0x01; t[sollen] = 0x01; t[sollen+1] = 0xaa;  /* 1 item */
        ok(run(V, t, sollen + 2, mrk, V->ntime, V->nversion, chal, chalen) == 0,
           "an otherwise-valid block carrying witness data is rejected");
    }

    /* Everything above uses the DEFAULT challenge, a bare CHECKMULTISIG, so
     * every outcome is ultimately decided by a signature. That hides any rule
     * whose removal merely corrupts the digest -- the block still gets
     * rejected, for the wrong reason, and the test cannot tell. Mutation
     * testing found exactly that: deleting the WITNESS_UNEXPECTED check and
     * the native-witness scriptSig check both left the suite green.
     *
     * These cases use TRIVIAL challenges instead. With no signature in play
     * the digest cannot mask anything, so each rule is the only thing that
     * can decide the outcome. */
    printf("== trivial challenges: rules a signature would have masked ==\n");
    {
        unsigned char prev[32];
        unhex(SIGNET_TXS_VEC[0].prev_block, prev, sizeof prev);
        unhex(SIGNET_TXS_VEC[0].signet_merkle, mrk, sizeof mrk);
        const unsigned int T = 1700000000u;

        /* --- OP_TRUE: valid with no solution at all (Core allows this). --- */
        unsigned char op_true[1] = { 0x51 };
        ok(signet_check_solution(1, prev, T, mrk, NULL, 0, op_true, 1,
                                 work, sizeof work) == 1,
           "OP_TRUE challenge with no solution is valid (the trivial signet)");

        /* --- same challenge, solution carrying witness data: Core ends in
         * WITNESS_UNEXPECTED. Nothing else here can reject it: OP_TRUE
         * succeeds whatever the transaction bytes are. --- */
        unsigned char wsol[] = { 0x00, 0x01, 0x01, 0xaa };  /* ss="" wit=[aa] */
        ok(signet_check_solution(1, prev, T, mrk, wsol, sizeof wsol,
                                 op_true, 1, work, sizeof work) == 0,
           "OP_TRUE challenge with unexpected witness data is rejected");

        /* --- P2WSH over an OP_TRUE witnessScript: exercises the witness
         * branch end to end, again without a signature. --- */
        unsigned char inner[1] = { 0x51 };
        unsigned char prog[34]; prog[0] = 0x00; prog[1] = 0x20;
        sha256_full(prog + 2, inner, 1);
        unsigned char wsh[] = { 0x00, 0x01, 0x01, 0x51 };   /* ss="" wit=[51] */
        ok(signet_check_solution(1, prev, T, mrk, wsh, sizeof wsh,
                                 prog, 34, work, sizeof work) == 1,
           "a P2WSH challenge satisfied by its witnessScript is valid");

        /* A native witness program requires an EMPTY scriptSig, or witness
         * malleability returns. Same witness, one byte of scriptSig. */
        unsigned char wsh_ss[] = { 0x01, 0x51, 0x01, 0x01, 0x51 };
        ok(signet_check_solution(1, prev, T, mrk, wsh_ss, sizeof wsh_ss,
                                 prog, 34, work, sizeof work) == 0,
           "a native witness program with a non-empty scriptSig is rejected");

        /* Wrong witnessScript: sha256 does not match the program. */
        unsigned char bad_wsh[] = { 0x00, 0x01, 0x01, 0x52 };  /* OP_2 */
        ok(signet_check_solution(1, prev, T, mrk, bad_wsh, sizeof bad_wsh,
                                 prog, 34, work, sizeof work) == 0,
           "a P2WSH challenge with the wrong witnessScript is rejected");

        /* A witnessScript that evaluates FALSE. */
        unsigned char f_inner[1] = { 0x00 };                   /* OP_0 */
        unsigned char f_prog[34]; f_prog[0] = 0x00; f_prog[1] = 0x20;
        sha256_full(f_prog + 2, f_inner, 1);
        unsigned char f_wsh[] = { 0x00, 0x01, 0x01, 0x00 };
        ok(signet_check_solution(1, prev, T, mrk, f_wsh, sizeof f_wsh,
                                 f_prog, 34, work, sizeof work) == 0,
           "a P2WSH witnessScript evaluating false is rejected");

        /* An UNKNOWN witness version is anyone-can-spend under Core's
         * BLOCK_SCRIPT_VERIFY_FLAGS, which omit
         * DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM. Accepting is FAITHFUL, not
         * lax: rejecting would false-reject a chain Core follows. A signet
         * using such a challenge is trivially forgeable, but that is the
         * network operator's mistake, not a divergence for us to invent. */
        unsigned char v1[34]; memcpy(v1, prog, 34); v1[0] = 0x51;  /* OP_1 */
        ok(signet_check_solution(1, prev, T, mrk, wsh, sizeof wsh,
                                 v1, 34, work, sizeof work) == 1,
           "an unknown witness version is accepted, as Core does (not rejected)");
    }

    /* A custom signet with a P2WSH challenge, signed for real. The trivial
     * challenges above prove the witness branch is wired; only a real
     * signature proves it VERIFIES, and only the NULLDUMMY pair proves the
     * flags reach the interpreter at all. Mutation testing found that gap:
     * passing flags=0 to sv_verify_witness_v0 left the OP_TRUE fixtures
     * green, because OP_TRUE succeeds under any flags. */
    printf("== a signed custom-signet P2WSH challenge ==\n");
    {
        unsigned char prev[32], mk[32], ch[64], sg[1024];
        unhex(SC_PREV, prev, sizeof prev);
        unhex(SC_MERKLE, mk, sizeof mk);
        unsigned long chl = unhex(SC_CHALLENGE, ch, sizeof ch);

        unsigned long n = unhex(SC_SOL_GOOD, sg, sizeof sg);
        ok(signet_check_solution(SC_NVERSION, prev, SC_NTIME, mk, sg, n,
                                 ch, chl, work, sizeof work) == 1,
           "a real signature over a P2WSH challenge verifies");

        n = unhex(SC_SOL_BADSIG, sg, sizeof sg);
        ok(signet_check_solution(SC_NVERSION, prev, SC_NTIME, mk, sg, n,
                                 ch, chl, work, sizeof work) == 0,
           "the same block with one bit flipped in the signature is rejected");

        /* Identical, correct signature; only the CHECKMULTISIG dummy differs.
         * NULLDUMMY is the ONLY rule that can reject this, so it fails if the
         * verification flags are not actually being applied. */
        n = unhex(SC_SOL_DUMMY1, sg, sizeof sg);
        ok(signet_check_solution(SC_NVERSION, prev, SC_NTIME, mk, sg, n,
                                 ch, chl, work, sizeof work) == 0,
           "a non-null CHECKMULTISIG dummy is rejected (NULLDUMMY is applied)");

        n = unhex(SC_SOL_GOOD, sg, sizeof sg);
        ok(signet_check_solution(SC_NVERSION, prev, SC_NTIME + 1, mk, sg, n,
                                 ch, chl, work, sizeof work) == 0,
           "and the signature does not carry to a block with a different time");
    }

    /* The LEGACY arm. Everything the real network exercises decides here, yet
     * no real block can tell whether the flags are applied on this path: real
     * solutions all carry a null dummy and canonical DER, so dropping the
     * flags changes none of their outcomes. Mutation testing confirmed it --
     * passing 0 for flags to sv_verify_script left the whole suite green.
     * This pair fixes that the same way the P2WSH pair did. */
    printf("== a signed bare-CHECKMULTISIG challenge (the default signet's shape) ==\n");
    {
        unsigned char prev[32], mk[32], ch[128], sg[1024];
        unhex(SC_PREV, prev, sizeof prev);
        unhex(SC_MERKLE, mk, sizeof mk);
        unsigned long chl = unhex(SC_LCHALLENGE, ch, sizeof ch);

        unsigned long n = unhex(SC_LSOL_GOOD, sg, sizeof sg);
        ok(signet_check_solution(SC_NVERSION, prev, SC_NTIME, mk, sg, n,
                                 ch, chl, work, sizeof work) == 1,
           "a real signature over a bare CHECKMULTISIG challenge verifies");

        n = unhex(SC_LSOL_BADSIG, sg, sizeof sg);
        ok(signet_check_solution(SC_NVERSION, prev, SC_NTIME, mk, sg, n,
                                 ch, chl, work, sizeof work) == 0,
           "with one bit flipped in that signature it is rejected");

        n = unhex(SC_LSOL_DUMMY1, sg, sizeof sg);
        ok(signet_check_solution(SC_NVERSION, prev, SC_NTIME, mk, sg, n,
                                 ch, chl, work, sizeof work) == 0,
           "a non-null dummy is rejected (NULLDUMMY reaches the legacy path)");
    }

    printf("== malformed solutions are invalid blocks, not crashes ==\n");
    {
        const signet_txs_vec_t* V = &SIGNET_TXS_VEC[0];
        unsigned long sollen = unhex(V->solution, sol, sizeof sol);
        unsigned long chalen = unhex(V->challenge, chal, sizeof chal);
        unhex(V->signet_merkle, mrk, sizeof mrk);
        unsigned char t[1<<16];
        int all0 = 1;
        for (unsigned long cut = 1; cut < sollen; cut++){
            memcpy(t, sol, cut);
            if (run(V, t, cut, mrk, V->ntime, V->nversion, chal, chalen) != 0){
                printf("  FAIL a solution truncated to %lu bytes was accepted\n", cut);
                all0 = 0; break;
            }
        }
        ok(all0, "every truncation of a real solution is rejected");

        int trail0 = 1;
        memcpy(t, sol, sollen); t[sollen] = 0x00;
        if (run(V, t, sollen + 1, mrk, V->ntime, V->nversion, chal, chalen) != 0)
            trail0 = 0;
        ok(trail0, "a valid solution with one trailing byte is rejected");
    }

    printf("== the caller's scratch is checked, not assumed ==\n");
    {
        const signet_txs_vec_t* V = &SIGNET_TXS_VEC[0];
        unsigned long sollen = unhex(V->solution, sol, sizeof sol);
        unsigned long chalen = unhex(V->challenge, chal, sizeof chal);
        unhex(V->signet_merkle, mrk, sizeof mrk);
        unsigned char prev[32]; unhex(V->prev_block, prev, sizeof prev);
        ok(signet_check_solution(V->nversion, prev, V->ntime, mrk, sol, sollen,
                                 chal, chalen, work, 4096) == -1,
           "too little scratch is reported as -1, distinct from an invalid block");
        ok(signet_check_solution(V->nversion, prev, V->ntime, mrk, sol, sollen,
                                 chal, chalen, NULL, 0) == -1,
           "a NULL scratch is refused rather than dereferenced");
    }

    printf("\n%s (%d failure%s)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
