/* test_blk_submit.c -- the submitblock evaluator (daemon/blk_submit.c) on the
 * REAL mainnet genesis block, plus targeted corruptions. Genesis is the one
 * block whose full consensus validity is checkable with no chain context:
 * cons_verify passes it, its PoW meets its own bits, and pre-segwit no
 * witness commitment is required. The corruptions pin the reason strings:
 * nonce tamper -> high-hash; tx-byte tamper -> bad-txnmrklroot; resubmit of
 * the tip -> duplicate; short buffer -> Block decode failed. */
#include <stdio.h>
#include <string.h>
extern long blk_submit_evaluate(const unsigned char*, unsigned long,
                                const unsigned char*, long, char*, unsigned long);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);

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

    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
