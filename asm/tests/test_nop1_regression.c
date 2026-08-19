/* test_nop1_regression.c -- OP_NOP1 and OP_NOP4..OP_NOP10 must be pure
 * no-ops in the legacy/segwit-v0 script interpreter, exactly like plain
 * OP_NOP (only OP_NOP2/OP_NOP3 were ever repurposed, by BIP65/BIP112).
 *
 * Part 1: real mainnet regression. Real mainnet spend, height 212613, the
 * exact transaction/prevout pair that stopped bmc-bitcoind.service's live
 * UTXO catch-up on 2026-08-19 (REJECT "legacy script verification failed").
 * Since block 212613 is real, confirmed, active-chain data, Bitcoin Core
 * accepted it -- so a rejection here is unambiguously a bug in this
 * interpreter, not a genuine chain-data problem. The spent output's
 * scriptPubKey is OP_DUP OP_HASH160 <hash> OP_EQUALVERIFY OP_NOP1 (0x88 0xb0)
 * -- NOT standard P2PKH's ...OP_EQUALVERIFY OP_CHECKSIG (0x88 0xac) -- so the
 * spend never actually checks a signature, only that the revealed data
 * hashes to the expected hash160; OP_NOP1 does nothing and the revealed
 * data (truthy) is left as the final stack top.
 *
 * Part 2: synthetic coverage for OP_NOP4..OP_NOP10, which real chain data
 * for this specific project's archive may or may not exercise.
 */
#include <stdio.h>
#include <stdint.h>

extern int sv_verify_script(const unsigned char* ss, unsigned long ssl,
                            const unsigned char* spk, unsigned long spl,
                            uint64_t flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);
extern unsigned long long script_flags_for_block(unsigned long long height, const unsigned char hash32[32]);

static int fails = 0;

static int hex2bin(const char* h, unsigned char* out, int cap){
    int n=0; while(h[2*n] && h[2*n+1]){ if(n>=cap) return -1; unsigned v; sscanf(h+2*n,"%2x",&v); out[n]=(unsigned char)v; n++; } return n;
}

/* Real spending tx, height 212613, t=112, scriptSig for input 0 (a single
 * 65-byte push -- no signature at all, since the prevout it spends never
 * actually checks one). Extracted read-only from the real archive. */
static const char* SPEND_SSIG_HEX =
"4104e19cb94dab9efa1e4507c17c81d4fdb0fc9d03c01caac970995ca4788f6e3fd3b2eb0"
"efba75a98b1e1a62f9bdcb71430ce066869facb4f1e20b9ee1d1669b356";
/* The exact scriptPubKey of the prevout it spends (0bf0d54e...:0), created
 * at height 165115 -- real chain data, not standard P2PKH: ends 0x88 0xb0
 * (EQUALVERIFY NOP1), not 0x88 0xac (EQUALVERIFY CHECKSIG). */
static const char* PREVOUT_SPK_HEX = "76a91407e761706c63b36e5a328fab1d94e9397f40704d88b0";

static void check(const char* label, int got, int want){
    if (got == want) printf("ok  : %s -> %d\n", label, got);
    else { printf("FAIL: %s -> got %d (SCRIPT_ERR code), want %d\n", label, got, want); fails++; }
}

int main(void){
    static unsigned char work[1<<20];
    unsigned char spk[64], ssig[128];
    int ssl = hex2bin(SPEND_SSIG_HEX, ssig, sizeof ssig);
    int spklen = hex2bin(PREVOUT_SPK_HEX, spk, sizeof spk);
    /* legacy_sighash is never actually reached for this script (it ends in
     * NOP1, not CHECKSIG), so the tx buffer just needs to exist. */
    unsigned char dummytx[13] = {1,0,0,0, 0, 0,0,0,0, 0,0,0,0};

    unsigned char zero32[32] = {0};
    unsigned long long flags = script_flags_for_block(212613, zero32);
    printf("real block-212613 script flags = 0x%llx\n", flags);

    /* sv_verify_script returns SCRIPT_ERR_OK (0) on success, a nonzero
     * SCRIPT_ERR_* code (e.g. 16 = SCRIPT_ERR_BAD_OPCODE) on failure --
     * the same convention as the C reference verify_script it mirrors. */
    int r = sv_verify_script(ssig, (unsigned long)ssl, spk, (unsigned long)spklen, flags, 0,
                             dummytx, sizeof dummytx, work, sizeof work);
    check("real mainnet h=212613 t=112 spend of EQUALVERIFY-NOP1 output", r, 0);

    /* Part 2: OP_NOP4..OP_NOP10 (0xb3..0xb9), synthetic. Each script pushes
     * OP_1 then the NOP-range opcode; final stack top must stay truthy --
     * i.e. the interpreter must accept (SCRIPT_ERR_OK), not reject as a bad
     * opcode. */
    static const unsigned char nop_op[] = {0xb0,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,0xb9};
    static const char* nop_name[] = {"NOP1","NOP4","NOP5","NOP6","NOP7","NOP8","NOP9","NOP10"};
    for (int i=0;i<8;i++){
        unsigned char script[2] = {0x51 /* OP_1 */, nop_op[i]};
        char label[64];
        snprintf(label, sizeof label, "OP_1 %s -> stack top stays truthy", nop_name[i]);
        int rr = sv_verify_script((const unsigned char*)"", 0, script, 2, 0, 0,
                                  dummytx, sizeof dummytx, work, sizeof work);
        check(label, rr, 0);
    }

    printf("nop1_regression: %d check(s), %d failure(s)\n", 1+8, fails);
    return fails?1:0;
}
