/* tests/test_signet_txs.c -- BIP325 SignetTxs::Create (signet.c layer 2).
 *
 * The expectations come from validation/gen_signet_txs_vectors.py, an
 * independent Python implementation run over REAL signet blocks. That
 * generator refuses to emit a vector unless the block's OWN signature
 * verifies against the sighash it derived, so the vectors are anchored to
 * secp256k1 signatures the signet miner made over Core's construction --
 * not to a second opinion that could be wrong in the same way.
 *
 * The default signet challenge is a BARE 1-of-2 CHECKMULTISIG, so every real
 * solution has a scriptSig and an EMPTY witness stack. The witness path is
 * therefore unreachable from mainnet-signet blocks and is covered by
 * hand-built fixtures below; a custom signet with a P2WSH challenge would
 * reach it.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../daemon/signet.h"
#include "signet_txs_vectors.h"

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
            v |= (c >= '0' && c <= '9') ? (unsigned)(c - '0')
               : (c >= 'a' && c <= 'f') ? (unsigned)(c - 'a' + 10)
               : (c >= 'A' && c <= 'F') ? (unsigned)(c - 'A' + 10) : 16u;
        }
        out[i] = (unsigned char)v;
    }
    return n;
}

int main(void){
    static unsigned char buf[1 << 20], leaves[1 << 16], scratch[1 << 16];
    static unsigned char sol[1 << 16], chal[1 << 16], prev[32], want_mrk[32];
    static signet_solution_t s;

    printf("== REAL signet blocks: the whole BIP325 construction ==\n");
    int perfect = 0;
    for (int v = 0; v < SIGNET_TXS_NVEC; v++){
        const signet_txs_vec_t* V = &SIGNET_TXS_VEC[v];
        int good = 1;

        /* layer 1 -> layer 2 chained: carve the solution out of the real
         * scriptPubKey rather than trusting the vector's copy of it. */
        unsigned char spk[4096], carved[4096], stripped[4096];
        unsigned long spklen = unhex(V->commit_spk, spk, sizeof spk);
        unsigned long clen = 0, stlen = 0;
        int found = signet_extract_solution(spk, spklen, carved, &clen,
                                            stripped, &stlen, sizeof carved);
        unsigned long solen = unhex(V->solution, sol, sizeof sol);
        good &= (found == 1 && clen == solen && memcmp(carved, sol, solen) == 0);

        good &= (signet_parse_solution(sol, solen, &s) == 0);

        unsigned long nl = unhex(V->leaves, leaves, sizeof leaves);
        if (nl != (unsigned long)V->ntx * 32){
            printf("  FAIL h=%d leaf list is %lu bytes, not ntx*32\n", V->height, nl);
            fails++; continue;
        }
        memcpy(scratch, leaves, nl);            /* merkle_root destroys it */
        unsigned char mrk[32];
        signet_merkle_root(mrk, scratch, (unsigned long)V->ntx);
        unhex(V->signet_merkle, want_mrk, sizeof want_mrk);
        good &= (memcmp(mrk, want_mrk, 32) == 0);

        unhex(V->prev_block, prev, sizeof prev);
        unsigned long challen = unhex(V->challenge, chal, sizeof chal);
        long n = signet_build_to_spend(buf, sizeof buf, V->nversion, prev, mrk,
                                       V->ntime, chal, challen);
        good &= (n > 0);
        unsigned char want_ts[4096];
        unsigned long wl = unhex(V->to_spend, want_ts, sizeof want_ts);
        good &= (n == (long)wl && memcmp(buf, want_ts, wl) == 0);

        unsigned char tsid[32];
        signet_txid(tsid, buf, (unsigned long)n);
        unsigned char want_tsid[32];
        unhex(V->to_spend_txid, want_tsid, sizeof want_tsid);
        good &= (memcmp(tsid, want_tsid, 32) == 0);

        long m = signet_build_to_sign(buf, sizeof buf, tsid, &s);
        good &= (m > 0);
        unsigned char want_tg[4096];
        unsigned long gl = unhex(V->to_sign, want_tg, sizeof want_tg);
        good &= (m == (long)gl && memcmp(buf, want_tg, gl) == 0);

        if (good) perfect++;
        else printf("  FAIL height %d (ntx=%d)\n", V->height, V->ntx);
    }
    {
        char msg[128];
        snprintf(msg, sizeof msg,
                 "%d/%d real signet blocks: solution, modified merkle root, "
                 "to_spend, txid and to_sign all byte-identical",
                 perfect, SIGNET_TXS_NVEC);
        ok(perfect == SIGNET_TXS_NVEC, msg);
    }

    printf("== the vectors reach the cases that matter ==\n");
    {
        int odd = 0, big = 0, one = 0;
        for (int v = 0; v < SIGNET_TXS_NVEC; v++){
            int n = SIGNET_TXS_VEC[v].ntx;
            if (n == 1) one = 1;
            if (n > 1 && (n & 1)) odd++;
            if (n >= 16) big = 1;
        }
        ok(one, "a single-transaction block (merkle root == the leaf itself)");
        ok(odd >= 3, "odd multi-tx blocks, which force the duplicate-last rule");
        ok(big, "a block deep enough to need several merkle levels");
    }

    printf("== a wrong construction does NOT pass (the test can fail) ==\n");
    {
        const signet_txs_vec_t* V = &SIGNET_TXS_VEC[0];
        unsigned long challen = unhex(V->challenge, chal, sizeof chal);
        unhex(V->prev_block, prev, sizeof prev);
        unhex(V->signet_merkle, want_mrk, sizeof want_mrk);
        unsigned char want_ts[4096];
        unsigned long wl = unhex(V->to_spend, want_ts, sizeof want_ts);

        unsigned char bad[32]; memcpy(bad, want_mrk, 32); bad[0] ^= 0x01;
        long n = signet_build_to_spend(buf, sizeof buf, V->nversion, prev, bad,
                                       V->ntime, chal, challen);
        ok(n == (long)wl && memcmp(buf, want_ts, wl) != 0,
           "one flipped bit in the merkle root changes to_spend");

        n = signet_build_to_spend(buf, sizeof buf, V->nversion, prev, want_mrk,
                                  V->ntime + 1, chal, challen);
        ok(n == (long)wl && memcmp(buf, want_ts, wl) != 0,
           "a one-second change in nTime changes to_spend");

        /* The null outpoint's index is 0xFFFFFFFF, not 0. Getting that wrong
         * is invisible until every signature on the network fails. */
        n = signet_build_to_spend(buf, sizeof buf, V->nversion, prev, want_mrk,
                                  V->ntime, chal, challen);
        ok(n > 36 && buf[5+32] == 0xff && buf[5+33] == 0xff &&
           buf[5+34] == 0xff && buf[5+35] == 0xff,
           "to_spend's input spends outpoint index 0xffffffff (COutPoint())");
        ok(buf[4] == 0x01 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 0,
           "to_spend is version 0 with exactly one input");
    }

    printf("== solution parsing: the witness path real signet never reaches ==\n");
    {
        /* scriptSig 0x51 (OP_1); witness [ 0xaa, 0xbbcc ] */
        unsigned char t[] = { 0x01, 0x51, 0x02, 0x01, 0xaa, 0x02, 0xbb, 0xcc };
        ok(signet_parse_solution(t, sizeof t, &s) == 0, "scriptSig + 2 witness items parses");
        ok(s.script_sig_len == 1 && s.script_sig[0] == 0x51, "scriptSig is OP_1");
        ok(s.nwit == 2 && s.witlen[0] == 1 && s.wit[0][0] == 0xaa &&
           s.witlen[1] == 2 && s.wit[1][0] == 0xbb && s.wit[1][1] == 0xcc,
           "both witness items are located exactly");

        long m = signet_build_to_sign(buf, sizeof buf,
                                      (const unsigned char*)
                                      "\x11\x22\x33\x44\x55\x66\x77\x88"
                                      "\x11\x22\x33\x44\x55\x66\x77\x88"
                                      "\x11\x22\x33\x44\x55\x66\x77\x88"
                                      "\x11\x22\x33\x44\x55\x66\x77\x88", &s);
        ok(m > 0 && buf[4] == 0x00 && buf[5] == 0x01,
           "a non-empty witness stack serialises with the 00 01 marker/flag");
    }
    {
        unsigned char t[] = { 0x00, 0x00 };     /* empty scriptSig, empty stack */
        ok(signet_parse_solution(t, sizeof t, &s) == 0, "an empty solution is valid");
        ok(s.script_sig_len == 0 && s.nwit == 0, "and yields nothing to run");
        long m = signet_build_to_sign(buf, sizeof buf, (const unsigned char*)
                                      "\x00\x00\x00\x00\x00\x00\x00\x00"
                                      "\x00\x00\x00\x00\x00\x00\x00\x00"
                                      "\x00\x00\x00\x00\x00\x00\x00\x00"
                                      "\x00\x00\x00\x00\x00\x00\x00\x00", &s);
        ok(m > 0 && !(buf[4] == 0x00 && buf[5] == 0x01),
           "an empty stack serialises with NO witness marker, as Core does");
    }

    printf("== solution parsing refuses what Core refuses ==\n");
    {
        unsigned char t[] = { 0x01, 0x51, 0x00, 0xff };   /* one byte too many */
        ok(signet_parse_solution(t, sizeof t, &s) == -1,
           "a trailing byte after the witness stack is rejected (Core: !v.empty())");
    }
    {
        unsigned char t[] = { 0x05, 0x51, 0x52 };         /* scriptSig runs past */
        ok(signet_parse_solution(t, sizeof t, &s) == -1, "a truncated scriptSig is rejected");
    }
    {
        unsigned char t[] = { 0x01, 0x51, 0x02, 0x01, 0xaa }; /* item 2 missing */
        ok(signet_parse_solution(t, sizeof t, &s) == -1, "a truncated witness stack is rejected");
    }
    {
        unsigned char t[] = { 0x01, 0x51 };               /* no stack count */
        ok(signet_parse_solution(t, sizeof t, &s) == -1, "a missing witness count is rejected");
    }
    {
        /* 0xfd 0x01 0x00 is "1" spelled in three bytes. */
        unsigned char t[] = { 0xfd, 0x01, 0x00, 0x51, 0x00 };
        ok(signet_parse_solution(t, sizeof t, &s) == -1,
           "a non-canonical CompactSize length is rejected");
    }
    {
        unsigned char t[] = { 0x00, 0xfd, 0xe9, 0x03 };   /* 1001 items */
        ok(signet_parse_solution(t, sizeof t, &s) == -1,
           "a witness stack above the interpreter's 1000-element limit is rejected");
    }
    {
        ok(signet_parse_solution((const unsigned char*)"", 0, &s) == -1,
           "a zero-length solution is rejected (no scriptSig prefix to read)");
    }

    printf("== buffers are bounded, not trusted ==\n");
    {
        unhex(SIGNET_TXS_VEC[0].challenge, chal, sizeof chal);
        unsigned long challen = strlen(SIGNET_TXS_VEC[0].challenge) / 2;
        unhex(SIGNET_TXS_VEC[0].prev_block, prev, sizeof prev);
        int refused_all = 1;
        for (unsigned long cap = 0; cap < 205; cap++){
            if (signet_build_to_spend(buf, cap, 1, prev, prev, 1, chal, challen) != -1){
                printf("  (to_spend accepted a %lu-byte buffer)\n", cap);
                refused_all = 0; break;
            }
        }
        ok(refused_all, "to_spend refuses every buffer smaller than the 205 bytes it needs");
        long n = signet_build_to_spend(buf, 205, 1, prev, prev, 1, chal, challen);
        ok(n == 205, "and writes exactly 205 bytes when given exactly 205");
    }

    printf("\n%s (%d failure%s)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
