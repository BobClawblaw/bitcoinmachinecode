/* test_txoutproof.c -- known-answer regression for the BIP37 partial merkle
 * tree behind gettxoutproof / verifytxoutproof (rpc_chain.c).
 *
 * No archive, no oracle: block 100,000's four txids and merkle root are a
 * fixed, publicly-checkable vector. We reverse the display hex to wire order
 * (the order the tree hashes in), rebuild the root, and round-trip a proof for
 * each leaf. A byte-for-byte live differential against Bitcoin Core is recorded
 * in the worklog; this locks the algorithm down without external state.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "test_tmpdir.h"

typedef uint8_t u8; typedef uint32_t u32;

/* hooks exported by rpc_chain.c */
int pmt_test_root(const u8 (*leaves)[32], u32 ntx, u8 out[32]);
int pmt_test_roundtrip(const u8 (*leaves)[32], u32 ntx, u32 idx, u8 out_root[32], u8 out_leaf[32]);

static void from_hex(u8* out, const char* h, int n){
    for (int i=0;i<n;i++){ unsigned v; sscanf(h+i*2,"%2x",&v); out[i]=(u8)v; }
}
/* display hex (big-endian) -> 32-byte wire order (little-endian) */
static void disp_to_wire(u8 wire[32], const char* disp){
    u8 tmp[32]; from_hex(tmp, disp, 32);
    for (int i=0;i<32;i++) wire[i]=tmp[31-i];
}

/* block 100,000 (mainnet) */
static const char* TXID_DISP[4] = {
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87", /* coinbase */
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
};
static const char* MERKLEROOT_DISP =
    "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766";

int main(void){
    tt_isolate();   /* private cwd: store_init writes index.dat/blk00000.dat by bare name */
    int fails = 0;
    u8 leaves[4][32];
    for (int i=0;i<4;i++) disp_to_wire(leaves[i], TXID_DISP[i]);

    /* 1. full merkle root matches the known block header value */
    u8 root[32], want[32];
    disp_to_wire(want, MERKLEROOT_DISP);
    if (!pmt_test_root((const u8(*)[32])leaves, 4, root) || memcmp(root, want, 32)){
        printf("FAIL: merkle root mismatch\n"); fails++;
    } else printf("ok: merkle root == block 100000 header value\n");

    /* 2. a single-leaf proof round-trips to that same root and recovers the leaf */
    for (u32 i=0;i<4;i++){
        u8 rroot[32], rleaf[32];
        if (!pmt_test_roundtrip((const u8(*)[32])leaves, 4, i, rroot, rleaf)){
            printf("FAIL: roundtrip build/extract failed for leaf %u\n", i); fails++; continue;
        }
        if (memcmp(rroot, want, 32)){ printf("FAIL: extracted root != header root for leaf %u\n", i); fails++; }
        else if (memcmp(rleaf, leaves[i], 32)){ printf("FAIL: recovered wrong txid for leaf %u\n", i); fails++; }
        else printf("ok: proof round-trip leaf %u\n", i);
    }

    /* 3. a one-tx block: root is just the coinbase txid, proof is trivial */
    u8 rroot[32], rleaf[32];
    if (!pmt_test_root((const u8(*)[32])leaves, 1, rroot) || memcmp(rroot, leaves[0], 32)){
        printf("FAIL: 1-tx root != coinbase txid\n"); fails++;
    } else if (!pmt_test_roundtrip((const u8(*)[32])leaves, 1, 0, rroot, rleaf)
               || memcmp(rleaf, leaves[0], 32)){
        printf("FAIL: 1-tx round-trip\n"); fails++;
    } else printf("ok: 1-tx block (root == coinbase, trivial proof)\n");

    /* 4. an odd tx count (3) exercises the duplicate-last-node path */
    if (!pmt_test_roundtrip((const u8(*)[32])leaves, 3, 2, rroot, rleaf)
        || memcmp(rleaf, leaves[2], 32)){
        printf("FAIL: 3-tx (odd) round-trip\n"); fails++;
    } else printf("ok: 3-tx odd-width round-trip (duplicated last node)\n");

    /* The crafted proofs below need a HEADER whose merkle root matches the
     * 4-leaf tree, or verify would die at the root check before reaching the
     * parse bounds under test. The real block-100,000 root is already in this
     * file's own vectors; export it through the serializer via a global. */
    { extern void pmt_test_set_root(const char* hex64);
      pmt_test_set_root(MERKLEROOT_DISP); }

    /* 5. RPX-1 (audit 2026-09-03): a proof whose nTransactions field exceeds
     * PMT_MAX_TX must be REJECTED before anything derived from it is copied.
     * Before the fix the ntx cap ran AFTER the hash-copy loop (and nhash was
     * only bounded by ntx+64), so a post-auth RPC caller could supply ntx =
     * PMT_MAX_TX+1 with nhash = ntx+64 = one entry past the 100064-entry
     * hashes[] allocation and scribble ~1.3 MB past it with chosen bytes.
     * pmt_test_verify drives cmd_verifytxoutproof directly (see rpc_chain.c);
     * every crafted proof must now come back ec=-8 BEFORE the copy loop.
     * NEGATIVE CONTROL (run with the fix reverted): vector (c) is the
     * overflow shape -- under the buggy code it OVERFLOWS (heap corruption /
     * crash under the gate's malloc), and (c2)/(d) must report an ec other
     * than -8, proving these vectors actually exercise the moved bounds. */
    {
        extern long pmt_test_verify(const char* proof_hex);
        extern int  pmt_test_build_hex(const u8 (*leaves)[32], u32 ntx,
                                       u32 ntx_field, u32 idx, char* out, size_t outcap);
        extern int  pmt_test_build_hex_atk(const u8 (*leaves)[32], u32 ntx,
                                           u32 ntx_field, u32 nhash_field,
                                           u32 nfb_field, u32 idx, char* out, size_t outcap);
        static char ph[2 * (84 + 9 + 64*32 + 9 + 64) + 2];
        /* (a) honest tree, ntx field inflated to PMT_MAX_TX+1: the moved cap
         * must reject it (old code: copied, then failed downstream, ec != -8
         * only because the crafted tree consumed unevenly). */
        if (!pmt_test_build_hex((const u8(*)[32])leaves, 4, 100001, 0, ph, sizeof ph)){
            printf("FAIL: could not build crafted proof\n"); fails++;
        } else {
            long ec = pmt_test_verify(ph);
            if (ec == -8) printf("ok: ntx=100001 proof rejected with -8 (RPX-1)\n");
            else { printf("FAIL: ntx=100001 proof got ec=%ld, want -8\n", ec); fails++; }
        }
        /* (b) ntx field at u32 max: same cap, absurd value */
        if (pmt_test_build_hex((const u8(*)[32])leaves, 4, 0xFFFFFFFFu, 0, ph, sizeof ph)) {
            long ec = pmt_test_verify(ph);
            if (ec == -8) printf("ok: ntx=0xffffffff proof rejected with -8\n");
            else { printf("FAIL: ntx=0xffffffff proof got ec=%ld, want -8\n", ec); fails++; }
        }
        /* (c) THE overflow shape, WITNESSED: ntx = 100001 (over the cap by
         * one) with nhash = 100065 = the hashes[] allocation size + 1.
         * pmt_test_verify_guarded arms a guard page immediately after the
         * copy destination in a forked child: the FIXED code rejects at -8
         * before the copy (child exits normally); the OLD code reaches the
         * copy loop and the write at hashes[100064] faults -- the child dies
         * with SIGSEGV, which this test reports as a FAILURE of the old
         * behavior. Deterministic under both code states: no heap-state luck. */
        {
            extern long pmt_test_verify_guarded(const char* proof_hex, int* sig_out);
            static char ph2[2 * (84 + 9 + 100065*32 + 9 + 12512) + 2];
            if (!pmt_test_build_hex_atk((const u8(*)[32])leaves, 4, 100001,
                                        100065, (100001 + 2*17 + 17 + 7) / 8, 0,
                                        ph2, sizeof ph2)){
                printf("FAIL: could not build the overflow-shape proof\n"); fails++;
            } else {
                int sig = 0;
                long ec = pmt_test_verify_guarded(ph2, &sig);
                if (ec == -8 && sig == 0)
                    printf("ok: overflow-shape proof rejected with -8 before the guarded copy\n");
                else { printf("FAIL: overflow-shape proof ec=%ld sig=%d (want -8, 0 = reject before the copy)\n", ec, sig); fails++; }
            }
        }
        /* (c') THE audit's exact scenario: ntx LARGE (1,000,001 -- a value
         * the old code admitted because its ntx cap sat after the copy) and
         * nhash = ntx+64 scaled so the old nhash bound admits it too. The
         * payload carries the hashes; under the old code the copy runs
         * ~1.3 MB+ past the hashes[] allocation (guard-page SIGSEGV in the
         * canary child); the fix rejects at the pre-read ntx cap. */
        {
            extern long pmt_test_verify_guarded(const char* proof_hex, int* sig_out);
            static char ph2b[2 * (84 + 9 + 1000065*32 + 9 + 125008) + 2];
            if (!pmt_test_build_hex_atk((const u8(*)[32])leaves, 4, 1000001,
                                        1000065, (1000001 + 2*20 + 20 + 7) / 8, 0,
                                        ph2b, sizeof ph2b)){
                printf("FAIL: could not build the large-ntx overflow proof\n"); fails++;
            } else {
                int sig = 0;
                long ec = pmt_test_verify_guarded(ph2b, &sig);
                if (ec == -8 && sig == 0)
                    printf("ok: large-ntx overflow (nhash=ntx+64) rejected with -8 before the copy\n");
                else { printf("FAIL: large-ntx overflow proof ec=%ld sig=%d (want -8, 0 = reject before the copy)\n", ec, sig); fails++; }
            }
        }
        /* (d) ntx = 1 with 4 real hashes: a LEGAL ntx, so only the new
         * nhash <= ntx rule rejects it -- isolating the second half of the
         * fix. Under the old bound (5 hashes <= 1+64) the copy ran. */
        if (!pmt_test_build_hex_atk((const u8(*)[32])leaves, 4, 1, 4, 8, 0, ph, sizeof ph)){
            printf("FAIL: could not build the nhash>ntx proof\n"); fails++;
        } else {
            long ec = pmt_test_verify(ph);
            if (ec == -8) printf("ok: nhash=4 with ntx=1 rejected with -8 (nhash>ntx)\n");
            else { printf("FAIL: nhash>ntx proof got ec=%ld, want -8\n", ec); fails++; }
        }
        /* (f) THE OVERFLOW ITSELF, observable: ntx = 4 (legal ntx), nhash =
         * 256 declared in the 0xfd-padded compactsize (legal encoding; this
         * parser accepts padded CompactSizes -- the canonical-only divergence
         * is SER-3, a separate finding), payload carrying 256 hash slots.
         * The old bound admitted it (256 <= 4+64 is FALSE, so the OLD code
         * rejected at THAT bound -- which is why (c)/(d) with nhash <= ntx+64
         * are the true overflow shapes). The NEW nhash <= ntx bound rejects at
         * -8 BEFORE the copy; under a revert this vector's payload (512 hash
         * slots) is rejected too, so its NEGATIVE CONTROL is (d): legal ntx,
         * nhash 4 <= ntx+64, and it is the ONLY vector whose pre-copy fate
         * flips with the nhash rule alone. */
        { extern int pmt_test_build_hex_pad(const u8 (*leaves)[32], u32 ntx,
                                            u32 ntx_field, u32 nhash_field,
                                            u32 nfb_field, u32 idx, char* out, size_t outcap);
            static char ph4[2*(84 + 9 + 256*32 + 9 + 256) + 2];
            if (!pmt_test_build_hex_pad((const u8(*)[32])leaves, 4, 4, 256, 256, 0, ph4, sizeof ph4)){
                printf("FAIL: could not build the padded-256 proof\n"); fails++;
            } else {
                long ec = pmt_test_verify(ph4);
                if (ec == -8) printf("ok: nhash=256 with ntx=4 rejected with -8\n");
                else { printf("FAIL: padded-256 proof got ec=%ld, want -8\n", ec); fails++; }
            }
        }
        /* (e) the HONEST proof must still not be rejected at the moved
         * bounds. It cannot reach ec == 0 here: with no archive, the final
         * "block must be in our chain" step forces ok == 0, which the tail
         * reports as -5 "Transaction already found". The discriminator is
         * the ERROR MESSAGE -- "Invalid proof" names the parse bounds that
         * were tightened; anything else means the honest shape sailed past
         * them, which is what this vector proves. */
        if (!pmt_test_build_hex((const u8(*)[32])leaves, 4, 0, 2, ph, sizeof ph)){
            printf("FAIL: could not build the honest proof\n"); fails++;
        } else {
            extern const char* pmt_test_verify_msg(const char* proof_hex, long* ec_out);
            long ec = 0;
            const char* msg = pmt_test_verify_msg(ph, &ec);
            if (strcmp(msg, "Invalid proof") != 0)
                printf("ok: honest proof passes the parse bounds (ec=%ld msg=%s)\n", ec, msg);
            else { printf("FAIL: honest proof hit the parse bounds (msg=%s)\n", msg); fails++; }
        }
    }

    printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
