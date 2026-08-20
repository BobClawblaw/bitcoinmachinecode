/* test_sig_pushonly_75.c -- sv_push_only's direct-push-opcode boundary must
 * include 0x4b (75) itself, not stop one short of it. Bitcoin's push
 * opcodes 0x01..0x4b (INCLUSIVE) each push that many literal data bytes --
 * 0x4b is the maximum representable by a one-byte length, pushing exactly
 * 75 bytes. `if (op < 0x4b)` excluded op==0x4b from the direct-push branch,
 * so a push of EXACTLY 75 bytes fell through to the OP_PUSHDATA4 branch and
 * read four bytes of the push's own DATA as a length -- desyncing the rest
 * of the scan (landing on a byte that usually isn't a valid opcode at all,
 * or producing a huge bogus "length") and wrongly rejecting an otherwise
 * valid push-only scriptSig with SCRIPT_ERR_SIG_PUSHONLY.
 *
 * Real mainnet regression: height 349617, tx 1 -- the well-known 2015
 * "Kaspersky blockchain malware warning" transaction, which embeds an ASCII
 * news article across many small scriptSig pushes (a P2SH multi-input
 * spend). Two of its six inputs happen to contain a push of exactly 75
 * bytes and were rejected; the other four, whose pushes never happened to
 * land on exactly 75 bytes, passed -- confirming the bug is specific to
 * that one boundary value, not the construction in general. Root-caused
 * with sv_verify_script run directly against each input's real scriptSig
 * and its real prevout scriptPubKey (fetched via a read-only query of the
 * live archive's own UTXO records for these outpoints -- no production
 * data touched or mutated).
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern int sv_verify_script(const unsigned char* ss, unsigned long ssl,
                            const unsigned char* spk, unsigned long spl,
                            uint64_t flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);

#define SV_SIGPUSHONLY (1ULL<<5)

static int fails = 0;

static void check(const char* label, int got, int want){
    if (got == want) printf("ok  : %s -> %d\n", label, got);
    else { printf("FAIL: %s -> got %d (SCRIPT_ERR code), want %d\n", label, got, want); fails++; }
}

int main(void){
    /* Minimal, direct regression: a scriptSig whose ENTIRE content is a
     * single push of exactly 75 bytes (0x4b, the boundary value itself)
     * must be accepted as push-only. flags=SV_SIGPUSHONLY exercises the
     * exact function under test (sv_push_only) with the least possible
     * surrounding machinery -- a trivial always-true scriptPubKey (OP_1),
     * no P2SH involved. */
    static unsigned char work[1<<20];
    unsigned char dummytx[13] = {1,0,0,0, 0, 0,0,0,0, 0,0,0,0};
    unsigned char ssig[76];
    ssig[0] = 0x4b; /* direct-push, len=75 */
    for (int i = 0; i < 75; i++) ssig[1+i] = (unsigned char)i;
    unsigned char spk[1] = {0x51}; /* OP_1 */
    int r = sv_verify_script(ssig, sizeof ssig, spk, 1, SV_SIGPUSHONLY, 0,
                             dummytx, sizeof dummytx, work, sizeof work);
    check("scriptSig = single exact-75-byte push -> push-only accepted", r, 0);

    /* Negative control: a push-only scriptSig with ONE real (non-push)
     * opcode appended after a 75-byte push must still be correctly
     * rejected -- proving the boundary fix didn't also start accepting
     * genuinely non-push content. */
    {
        unsigned char ss2[77];
        memcpy(ss2, ssig, sizeof ssig);
        ss2[76] = 0xac; /* OP_CHECKSIG: a real opcode, not a push */
        int rr = sv_verify_script(ss2, sizeof ss2, spk, 1, SV_SIGPUSHONLY, 0,
                                  dummytx, sizeof dummytx, work, sizeof work);
        check("75-byte push + a real (non-push) opcode -> still rejected", rr, 26 /* SCRIPT_ERR_SIG_PUSHONLY */);
    }

    /* Boundary neighbors: 74 and 76 bytes must also work (74 was already
     * correct before the fix; 76 requires PUSHDATA1 and was also already
     * correct -- both are sanity companions, not the regression itself). */
    {
        unsigned char ss74[75];
        ss74[0] = 0x4a; /* len=74 */
        for (int i = 0; i < 74; i++) ss74[1+i] = (unsigned char)i;
        int r74 = sv_verify_script(ss74, sizeof ss74, spk, 1, SV_SIGPUSHONLY, 0,
                                   dummytx, sizeof dummytx, work, sizeof work);
        check("scriptSig = single exact-74-byte push -> push-only accepted", r74, 0);

        unsigned char ss76[78];
        ss76[0] = 0x4c; ss76[1] = 76; /* PUSHDATA1, len=76 */
        for (int i = 0; i < 76; i++) ss76[2+i] = (unsigned char)i;
        int r76 = sv_verify_script(ss76, sizeof ss76, spk, 1, SV_SIGPUSHONLY, 0,
                                   dummytx, sizeof dummytx, work, sizeof work);
        check("scriptSig = single exact-76-byte push (PUSHDATA1) -> push-only accepted", r76, 0);
    }

    printf("sig_pushonly_75: 4 check(s), %d failure(s)\n", fails);
    return fails?1:0;
}
