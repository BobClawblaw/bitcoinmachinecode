/* test_blk_submit.c -- the submitblock evaluator (daemon/blk_submit.c) on the
 * REAL mainnet genesis block, plus targeted corruptions. Genesis is the one
 * block whose full consensus validity is checkable with no chain context:
 * cons_verify passes it, its PoW meets its own bits, and pre-segwit no
 * witness commitment is required. The corruptions pin the reason strings:
 * nonce tamper -> high-hash; tx-byte tamper -> bad-txnmrklroot; resubmit of
 * the tip -> duplicate; short buffer -> Block decode failed. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* blk_submit now runs the BIP325 check, which links the script verifier, and
 * bitcoin_txval_modern.c wants this symbol. Nothing here reaches it: the
 * signet path hands the interpreter a synthetic output directly and resolves
 * no UTXO, and on a non-signet chain the check returns before doing anything.
 * Aborting makes that a checked claim rather than a comment. */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char t[32],
                                    unsigned long i, unsigned long long* v,
                                    const unsigned char** sp, unsigned long* sl){
    (void)u;(void)t;(void)i;(void)v;(void)sp;(void)sl;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n"); abort();
}
extern long blk_submit_evaluate(const unsigned char*, unsigned long,
                                const unsigned char*, long, char*, unsigned long);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
extern long merkle_root(unsigned char out[32], unsigned char* hashes, unsigned long long n);   /* in place */

static int fails=0;
static void ck(const char* l, int c){ printf("%s %s\n", c?"ok  :":"FAIL:", l); if(!c) fails++; }
static const char* GEN = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

int main(void){
    static unsigned char blk[600]; unsigned long n = strlen(GEN)/2;
    for (unsigned long i=0;i<n;i++){ unsigned v; sscanf(GEN+2*i,"%2x",&v); blk[i]=(unsigned char)v; }
    unsigned char zero32[32]; memset(zero32,0,32);
    char r[64];

    /* genesis extends the null tip: consensus-clean -> 1 */
    ck("genesis vs null-prev tip -> would-accept (1)",
       blk_submit_evaluate(blk, n, zero32, -1, r, sizeof r) == 1);

    /* duplicate: tip IS genesis */
    { unsigned char gh[32]; sha256d(gh, blk, 80);
      ck("resubmit of tip -> duplicate",
         blk_submit_evaluate(blk, n, gh, 0, r, sizeof r) == 0 && !strcmp(r,"duplicate")); }

    /* non-linking tip -> inconclusive (side chain / unknown prev) */
    { unsigned char other[32]; memset(other, 0xAB, 32);
      ck("non-linking prev -> inconclusive",
         blk_submit_evaluate(blk, n, other, 100, r, sizeof r) == 0 && !strcmp(r,"inconclusive")); }

    /* nonce tamper: header hash no longer meets bits -> high-hash */
    { static unsigned char bad[600]; memcpy(bad, blk, n); bad[76] ^= 1;
      ck("nonce tamper -> high-hash",
         blk_submit_evaluate(bad, n, zero32, -1, r, sizeof r) == 0 && !strcmp(r,"high-hash")); }

    /* tx-byte tamper (past the header): PoW fine, merkle wrong */
    { static unsigned char bad[600]; memcpy(bad, blk, n); bad[n-10] ^= 1;
      ck("tx tamper -> bad-txnmrklroot",
         blk_submit_evaluate(bad, n, zero32, -1, r, sizeof r) == 0 && !strcmp(r,"bad-txnmrklroot")); }

    /* short buffer */
    ck("80 bytes -> Block decode failed",
       blk_submit_evaluate(blk, 80, zero32, -1, r, sizeof r) == 0 && !strcmp(r,"Block decode failed"));

    /* CON-14 (audit 2026-10-23): a block of 16,500 minimal (60-byte)
     * transactions is 990 KB stripped, inside Core's bad-blk-length bound;
     * submitblock refused anything over 16,384 transactions as
     * bad-blk-length. 16,666 is the first count Core's rule refuses. */
    {
        static unsigned char big[80 + 3 + 16700 * 60];
        static unsigned char ids[16700 * 32];
        for (int pass = 0; pass < 2; pass++){
            unsigned nt = pass == 0 ? 16500 : 16666;
            unsigned char* q = big + 80;
            *q++ = 0xfd; *q++ = (unsigned char)(nt & 0xff); *q++ = (unsigned char)(nt >> 8);
            for (unsigned t = 0; t < nt; t++){
                unsigned char* tx = q;
                *q++ = 1; *q++ = 0; *q++ = 0; *q++ = 0; *q++ = 1;          /* version 1, one input */
                if (t == 0){ memset(q, 0, 32); q += 32; memset(q, 0xff, 4); q += 4; }   /* coinbase */
                else { memset(q, 0x5c, 32); q[0] = (unsigned char)t; q[1] = (unsigned char)(t >> 8); q += 32; memset(q, 0, 4); q += 4; }
                *q++ = 0; memset(q, 0xff, 4); q += 4;                       /* empty scriptSig, sequence */
                *q++ = 1; memset(q, 0, 8); q += 8; *q++ = 0;                /* one 0-value output, empty script */
                memset(q, 0, 4); q += 4;                                    /* locktime */
                sha256d(ids + (size_t)t * 32, tx, (unsigned long)(q - tx));
            }
            if (pass == 0) ck("CON-14 fixture: a minimal transaction is 60 bytes", (q - (big + 83)) == 60L * nt);
            unsigned long blen = (unsigned long)(q - big);
            memset(big, 0, 80); big[0] = 1;
            unsigned char root[32]; merkle_root(root, ids, nt);
            memcpy(big + 36, root, 32);
            big[72] = 0xff; big[73] = 0xff; big[74] = 0x7f; big[75] = 0x20;   /* 0x207fffff */
            unsigned nonce = 0;
            for (;;){ unsigned char hh[32], be[32]; sha256d(hh, big, 80);
                      for (int i = 0; i < 32; i++) be[i] = hh[31-i];
                      if (be[0] < 0x7f) break;
                      nonce++; memcpy(big + 76, &nonce, 4); }
            long rv = blk_submit_evaluate(big, blen, zero32, -1, r, sizeof r);
            if (pass == 0){
                ck("CON-14 a 16,500-transaction block passes the size rules (would-accept)", rv == 1);
                if (rv != 1) printf("      (reason: %s)\n", r);
            } else {
                ck("CON-14 a 16,666-transaction block is bad-blk-length (stripped > 1,000,000)",
                   rv == 0 && !strcmp(r, "bad-blk-length"));
                if (strcmp(r, "bad-blk-length")) printf("      (reason: %s)\n", r);
            }
        }
    }

    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
