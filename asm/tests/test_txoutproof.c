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

    printf(fails ? "\n%d FAILURE(S)\n" : "\nALL PASS\n", fails);
    return fails ? 1 : 0;
}
