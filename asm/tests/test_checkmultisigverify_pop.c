/* test_checkmultisigverify_pop.c -- OP_CHECKMULTISIGVERIFY must pop-and-fail
 * on a false result, exactly like every other VERIFY opcode (EQUALVERIFY,
 * CHECKSIGVERIFY, NUMEQUALVERIFY). It was a bare dispatch alias for plain
 * OP_CHECKMULTISIG with no additional behavior: interp_checkmultisig always
 * pushes its bool result (correct for CHECKMULTISIG, which is not itself a
 * VERIFY op), but CHECKMULTISIGVERIFY never popped-and-checked it. A script
 * ending in CHECKMULTISIGVERIFY would therefore leave a stray leftover
 * boolean on the stack (silently "succeeding" as CLEANSTACK-violating debris,
 * or worse, corrupting every subsequent opcode's stack-position math if
 * anything ran after it).
 *
 * Real mainnet regression: height 324663, tx 34. A P2SH redeem script
 * chains two multisig checks: `2 pubA pubB 2 CHECKMULTISIGVERIFY
 * 2 pubC pubD 2 CHECKMULTISIG`. Under the bug, CHECKMULTISIGVERIFY's
 * leftover bool became the SECOND check's first "signature" operand,
 * which of course never DER-parses/verifies -- rejecting an otherwise-valid
 * confirmed block. Verified: the real prevout script is P2SH-wrapping this
 * exact redeem script (confirmed via a read-only query of the live archive's
 * UTXO record for this outpoint, no production data touched or mutated).
 */
#include <stdio.h>
#include <stdint.h>

extern int sv_verify_script(const unsigned char* ss, unsigned long ssl,
                            const unsigned char* spk, unsigned long spl,
                            uint64_t flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);

static int fails = 0;

static int hex2bin(const char* h, unsigned char* out, int cap){
    int n=0; while(h[2*n] && h[2*n+1]){ if(n>=cap) return -1; unsigned v; sscanf(h+2*n,"%2x",&v); out[n]=(unsigned char)v; n++; } return n;
}

static void check(const char* label, int got, int want){
    if (got == want) printf("ok  : %s -> %d\n", label, got);
    else { printf("FAIL: %s -> got %d (SCRIPT_ERR code), want %d\n", label, got, want); fails++; }
}

/* Full raw tx (1 input, 1 output), spending the chained-multisig P2SH
 * output. Freshly extracted from the block archive. */
static const char* TX_HEX =
"0100000001d43b57a41c528e1abcb72900c0a94d701d00ee1545afb2fb5e70800f506230a"
"600000000fdb70100483045022100802c9070a1d11ae3713756c9729171effb712f6f9bc"
"cd6fdd1c331bfbc8ee96702202a2ce31260a4913c8579051f70358b1222b55f39aea770d"
"1d211baa672184ac501483045022100a0a0496dde677f8e32ef4c61ebf440fc6e2c6e8c8"
"cf90fe2f1d516b30d367b8d02207a26dba7c430488ced13f82f370f3fb5e8dfa3cdb0b97"
"ea836b90933594118430100493046022100e2838a072768486d1454681d5caaaed85a57"
"789667b2a676167e1a9c0fb6b260022100cd7bcd39afb4e172681030b6dedd89c93e331"
"c6bd111f4719078609f4f82ea6301483045022100fecd6921d18a926d870fe002e9fad3"
"3452b7af036e84d4c09050dbdb0ff7dcae0220476368e8ccf00b1a7a34645401c85d343"
"af4c492d206a1ac4cee8ac42ba48d11014c8e5221022330054cfeda1e19bcb4def91db0"
"eb467beacb7d6811a3264963a4d2b68572822102f187d2441e23c129019d29ede469176"
"15ab574cf93250fbc78262df48cab5ddb52af522103b1db0a6775bb3c97f5512d5a7747"
"d2ae1ff6d15ba6b121241ec9654afcf6759021032f7646b4ee3295fe5c44d6a868a6ddb"
"b7bbd1946f6b95080a49526878a07ab9252aeffffffff010000000000000000016a000"
"00000";
static const char* SPEND_SSIG_HEX =
"00483045022100802c9070a1d11ae3713756c9729171effb712f6f9bccd6fdd1c331bfb"
"c8ee96702202a2ce31260a4913c8579051f70358b1222b55f39aea770d1d211baa67218"
"4ac501483045022100a0a0496dde677f8e32ef4c61ebf440fc6e2c6e8c8cf90fe2f1d51"
"6b30d367b8d02207a26dba7c430488ced13f82f370f3fb5e8dfa3cdb0b97ea836b90933"
"594118430100493046022100e2838a072768486d1454681d5caaaed85a57789667b2a6"
"76167e1a9c0fb6b260022100cd7bcd39afb4e172681030b6dedd89c93e331c6bd111f47"
"19078609f4f82ea6301483045022100fecd6921d18a926d870fe002e9fad33452b7af0"
"36e84d4c09050dbdb0ff7dcae0220476368e8ccf00b1a7a34645401c85d343af4c492d"
"206a1ac4cee8ac42ba48d11014c8e5221022330054cfeda1e19bcb4def91db0eb467be"
"acb7d6811a3264963a4d2b68572822102f187d2441e23c129019d29ede46917615ab57"
"4cf93250fbc78262df48cab5ddb52af522103b1db0a6775bb3c97f5512d5a7747d2ae1"
"ff6d15ba6b121241ec9654afcf6759021032f7646b4ee3295fe5c44d6a868a6ddbb7bb"
"d1946f6b95080a49526878a07ab9252ae";
static const char* PREVOUT_SPK_HEX = "a914901981fbcc74661f34f00ae0934f489eb81213b687";

int main(void){
    static unsigned char work[1<<20];
    unsigned char tx[1024], ssig[512], spk[64];
    int txlen = hex2bin(TX_HEX, tx, sizeof tx);
    int ssl = hex2bin(SPEND_SSIG_HEX, ssig, sizeof ssig);
    int spklen = hex2bin(PREVOUT_SPK_HEX, spk, sizeof spk);

    int r = sv_verify_script(ssig, (unsigned long)ssl, spk, (unsigned long)spklen, 1ULL /* SV_P2SH */, 0,
                             tx, (unsigned long)txlen, work, sizeof work);
    check("real mainnet h=324663 t=34: CHECKMULTISIGVERIFY chained into CHECKMULTISIG", r, 0);

    /* Synthetic companion: a script that is JUST `CHECKMULTISIGVERIFY`
     * (0-of-0, so the underlying multisig check itself trivially succeeds)
     * followed by OP_1 must accept -- proving CHECKMULTISIGVERIFY correctly
     * CONSUMES its bool (if it didn't pop it, this would leave TWO items on
     * the final stack, which is fine for non-CLEANSTACK acceptance since
     * only the top item's truthiness matters -- so this case alone
     * wouldn't catch the bug, which is why the real-tx case above is the
     * primary regression check; this is a simple sanity companion). */
    {
        unsigned char ss[3] = {0x00, 0x00, 0x00}; /* dummy, m=0, n=0 */
        unsigned char sp[2] = {0xaf, 0x51};        /* CHECKMULTISIGVERIFY OP_1 */
        int rr = sv_verify_script(ss, 3, sp, 2, 0, 0, tx, (unsigned long)txlen, work, sizeof work);
        check("0-of-0 CHECKMULTISIGVERIFY then OP_1 -> accepts", rr, 0);
    }

    /* Synthetic companion: a script that is JUST a FAILING CHECKMULTISIGVERIFY
     * (1-of-1 with a signature that can't possibly verify against the given
     * pubkey) must reject with SCRIPT_ERR_CHECKMULTISIGVERIFY specifically,
     * not silently succeed by leaving a false bool unconsumed. */
    {
        /* scriptSig: dummy, a syntactically-valid-but-wrong-key signature */
        unsigned char ss[76];
        int n = 0;
        ss[n++] = 0x00; /* dummy */
        /* a minimal 71-byte DER sig (garbage r/s, won't matter -- it will
         * fail to verify against the pubkey below regardless) + hashtype */
        static const unsigned char sig[] = {
            0x30,0x44,0x02,0x20,
            0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
            0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,0x11,
            0x02,0x20,
            0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
            0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,0x22,
            0x01
        };
        ss[n++] = (unsigned char)sizeof sig; for (unsigned i=0;i<sizeof sig;i++) ss[n++] = sig[i];
        unsigned char sp[40];
        int m = 0;
        sp[m++] = 0x51; /* m=1 */
        static const unsigned char pub[33] = {
            0x02,0x1b,0x84,0xc5,0x56,0x7b,0x12,0x64,0x40,0x99,0x5d,0x3e,0xd5,0xaa,0xba,0x05,
            0x65,0xd7,0x1e,0x18,0x34,0x60,0x48,0x19,0xff,0x9c,0x17,0xf5,0xe9,0xd5,0xdd,0x07,0x8f
        };
        sp[m++] = 0x21; for (unsigned i=0;i<33;i++) sp[m++] = pub[i];
        sp[m++] = 0x51; /* n=1 */
        sp[m++] = 0xaf; /* CHECKMULTISIGVERIFY */
        int rr = sv_verify_script(ss, (unsigned long)n, sp, (unsigned long)m, 0, 0, tx, (unsigned long)txlen, work, sizeof work);
        check("1-of-1 CHECKMULTISIGVERIFY, wrong sig -> SCRIPT_ERR_CHECKMULTISIGVERIFY", rr, 13);
    }

    printf("checkmultisigverify_pop: 3 check(s), %d failure(s)\n", fails);
    return fails?1:0;
}
