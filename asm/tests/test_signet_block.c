/* tests/test_signet_block.c -- BIP325 over WHOLE real signet blocks.
 *
 * The layers below are fed decomposed inputs. This one is fed a block exactly
 * as the node receives it, which is the only way to exercise the parts
 * nothing else touches: finding the commitment among the coinbase's outputs,
 * rebuilding the coinbase's unwitnessed serialisation with the solution
 * stripped, and taking every other transaction's txid.
 *
 * Those steps are all hash inputs, so a mistake in any of them is invisible
 * except as "the signature does not verify" -- which is why the whole file
 * ends in a real signature check rather than in field comparisons.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../daemon/signet.h"
#include "../daemon/signet_block.h"
#include "signet_block_vectors.h"

extern void sha256d(unsigned char out[32], const void* msg, long long len);

long mempool_resolve_confirmed_utxo(void* u, const unsigned char t[32],
                                    unsigned long i, unsigned long long* v,
                                    const unsigned char** s, unsigned long* l){
    (void)u;(void)t;(void)i;(void)v;(void)s;(void)l;
    fprintf(stderr, "unexpected mempool_resolve_confirmed_utxo\n"); abort();
}

static int fails = 0;
static void ok(int c, const char* w){
    printf("  %s %s\n", c ? "ok " : "FAIL", w); if (!c) fails++;
}
static unsigned long unhex(const char* h, unsigned char* o, unsigned long cap){
    unsigned long n = strlen(h)/2;
    if (n > cap){ fprintf(stderr,"overflow\n"); exit(2); }
    for (unsigned long i=0;i<n;i++){
        unsigned v=0;
        for (int k=0;k<2;k++){ char c=h[i*2+k]; v<<=4;
            v |= (c>='0'&&c<='9')?(unsigned)(c-'0'):(c>='a'&&c<='f')?(unsigned)(c-'a'+10):
                 (c>='A'&&c<='F')?(unsigned)(c-'A'+10):16u; }
        o[i]=(unsigned char)v;
    }
    return n;
}

static unsigned char blk[1<<20];
static unsigned char scratch[1<<22];
static signet_txref_t refs[4096];

static long check(const signet_block_vec_t* V, unsigned char* b,
                  const unsigned char* chal, unsigned long chalen,
                  const char** reason){
    for (int t = 0; t < V->ntx; t++){
        refs[t].ptr = b + V->off[t];
        refs[t].len = V->len[t];
    }
    return signet_check_block(refs, (unsigned long)V->ntx, sizeof refs[0],
                              b, chal, chalen, 0, scratch, sizeof scratch, reason);
}

int main(void){
    unsigned char chal[128];
    unsigned long chalen = unhex(SB_CHALLENGE, chal, sizeof chal);
    const char* reason = 0;

    printf("== whole real signet blocks, straight off the wire ==\n");
    int good = 0;
    for (int v = 0; v < SIGNET_BLOCK_NVEC; v++){
        const signet_block_vec_t* V = &SIGNET_BLOCK_VEC[v];
        unhex(V->raw, blk, sizeof blk);
        long r = check(V, blk, chal, chalen, &reason);
        if (r == 1) good++;
        else printf("  FAIL height %d (ntx=%d): returned %ld, reason %s\n",
                    V->height, V->ntx, r, reason ? reason : "(none)");
    }
    { char m[140];
      snprintf(m, sizeof m, "%d/%d whole blocks accepted, coinbase rebuilt and "
               "every txid recomputed from the raw bytes", good, SIGNET_BLOCK_NVEC);
      ok(good == SIGNET_BLOCK_NVEC, m); }

    printf("== tampering with the block body is caught ==\n");
    {
        const signet_block_vec_t* V = &SIGNET_BLOCK_VEC[SIGNET_BLOCK_NVEC-1];
        /* the deepest block: several transactions, so the merkle tree matters */
        unhex(V->raw, blk, sizeof blk);
        ok(V->ntx > 2, "the tampering vector has enough transactions to matter");

        /* Flip a byte inside the LAST transaction's VERSION. Nothing in the
         * header changes, so only the modified merkle root can notice.
         *
         * It has to be a byte the TXID covers. A first attempt flipped one
         * eight from the end of the transaction, which lands in WITNESS data
         * on a segwit transaction -- and the block still verified, correctly:
         * the signet merkle root is taken over txids, not wtxids, so witness
         * bytes are deliberately outside what the block signature commits to.
         * (BIP141's own commitment covers them; that is a different check.)
         * The 6/6 above are what pin the txid-not-wtxid choice: build the
         * leaves from wtxids instead and every real block fails. */
        unsigned long last = V->off[V->ntx-1];
        blk[last] ^= 0x20;
        ok(check(V, blk, chal, chalen, &reason) == 0 &&
           reason && !strcmp(reason, "bad-signet-blksig"),
           "a byte changed in the last transaction invalidates the signature");
        blk[last] ^= 0x20;
        ok(check(V, blk, chal, chalen, &reason) == 1, "and restoring it re-validates");

        /* Header time: the signature commits to it. */
        blk[68] ^= 0x01;
        ok(check(V, blk, chal, chalen, &reason) == 0, "a changed nTime is caught");
        blk[68] ^= 0x01;

        /* Header prev-block. */
        blk[4] ^= 0x01;
        ok(check(V, blk, chal, chalen, &reason) == 0, "a changed prev-block is caught");
        blk[4] ^= 0x01;

        ok(check(V, blk, chal, chalen, &reason) == 1, "the block is intact again");
    }

    printf("== a block with no witness commitment is refused ==\n");
    {
        const signet_block_vec_t* V = &SIGNET_BLOCK_VEC[0];
        unhex(V->raw, blk, sizeof blk);
        /* Break the commitment marker (aa21a9ed) wherever it appears in the
         * coinbase, so no output qualifies. Core: SignetTxs::Create returns
         * nullopt when GetWitnessCommitmentIndex finds nothing. */
        unsigned long n = V->len[0]; unsigned char* cb = blk + V->off[0];
        int hit = 0;
        for (unsigned long i = 0; i + 4 < n; i++)
            if (cb[i]==0xaa && cb[i+1]==0x21 && cb[i+2]==0xa9 && cb[i+3]==0xed){
                cb[i+1] ^= 0xff; hit = 1;
            }
        ok(hit, "the test found a commitment marker to break");
        ok(check(V, blk, chal, chalen, &reason) == 0 &&
           reason && !strcmp(reason, "bad-signet-no-commitment"),
           "a coinbase with no witness commitment is rejected, by that name");
    }

    printf("== the empty block and the bounds ==\n");
    {
        const signet_block_vec_t* V = &SIGNET_BLOCK_VEC[0];
        unhex(V->raw, blk, sizeof blk);
        ok(signet_check_block(refs, 0, sizeof refs[0], blk, chal, chalen, 0,
                              scratch, sizeof scratch, &reason) == 0 &&
           reason && !strcmp(reason, "bad-signet-no-coinbase"),
           "a block with no transactions is rejected");
        ok(check(V, blk, chal, 0, &reason) == -1,
           "no configured challenge is an internal error, not a verdict");
        long r = signet_check_block(refs, 1, sizeof refs[0], blk, chal, chalen, 0,
                                    scratch, 4096, &reason);
        ok(r == -1, "too little scratch is an internal error, not a verdict");
    }

    printf("== the genesis block is exempt, as Core exempts it ==\n");
    {
        /* Core's CheckSignetBlockSolution opens with
         *   if (block.GetHash() == consensusParams.hashGenesisBlock) return true;
         * The signet genesis coinbase predates segwit and carries NO witness
         * commitment, so without the exemption it fails as
         * "bad-signet-no-commitment" and the chain cannot start at all.
         *
         * This was a REAL BUG, found by running a sync rather than by any
         * test: every vector here is a real mid-chain block, and a syncing
         * node seeds genesis directly instead of applying it, so only
         * re-applying from height 0 reaches the case. */
        const signet_block_vec_t* V = &SIGNET_BLOCK_VEC[0];
        unhex(V->raw, blk, sizeof blk);
        for (int t = 0; t < V->ntx; t++){
            refs[t].ptr = blk + V->off[t]; refs[t].len = V->len[t];
        }
        /* Pretend this block's own hash is the genesis hash: the exemption
         * must then accept it whatever its solution says. Using the block's
         * real hash keeps the test honest about WHAT is compared. */
        unsigned char bh[32];
        sha256d(bh, blk, 80);
        ok(signet_check_block(refs, (unsigned long)V->ntx, sizeof refs[0], blk,
                              chal, chalen, bh, scratch, sizeof scratch,
                              &reason) == 1,
           "a block whose hash IS the genesis hash is accepted unconditionally");

        /* And a DIFFERENT genesis hash must not exempt it -- otherwise the
         * comparison is not doing anything. */
        unsigned char other[32]; memcpy(other, bh, 32); other[0] ^= 0x01;
        ok(signet_check_block(refs, (unsigned long)V->ntx, sizeof refs[0], blk,
                              chal, chalen, other, scratch, sizeof scratch,
                              &reason) == 1,
           "a non-genesis block still validates normally (this one is valid)");

        /* The decisive pair: break the commitment so the block CANNOT pass,
         * then show the exemption is the only thing that saves it. */
        unsigned char* cb = blk + V->off[0];
        for (unsigned long i = 0; i + 4 < V->len[0]; i++)
            if (cb[i]==0xaa && cb[i+1]==0x21 && cb[i+2]==0xa9 && cb[i+3]==0xed)
                cb[i+1] ^= 0xff;
        sha256d(bh, blk, 80);   /* header unchanged, so this is the same hash */
        ok(signet_check_block(refs, (unsigned long)V->ntx, sizeof refs[0], blk,
                              chal, chalen, other, scratch, sizeof scratch,
                              &reason) == 0,
           "with no commitment and no exemption it is rejected");
        ok(signet_check_block(refs, (unsigned long)V->ntx, sizeof refs[0], blk,
                              chal, chalen, bh, scratch, sizeof scratch,
                              &reason) == 1,
           "and the SAME block is accepted when its hash is the genesis hash");
    }

    printf("\n%s (%d failure%s)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED",
           fails, fails==1?"":"s");
    return fails ? 1 : 0;
}
