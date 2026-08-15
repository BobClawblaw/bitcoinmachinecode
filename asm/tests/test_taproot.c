/* test_taproot.c -- drive secp256k1_taproot.asm (BIP341 helpers) against
 * reference vectors computed with a Python BIP341 implementation.
 *
 * Covers: tagged_hash256, tap_leaf_hash, tap_branch_hash, tap_merkle_root
 * (script-path merkle tree), and taproot_tweak_pubkey (key-path output key
 * with x-only tweak incl. even-normalization and optional script merkle root).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern void tagged_hash256(uint8_t* out, const char* tag, uint64_t taglen,
                           const uint8_t* msg, uint64_t msglen);
extern void tap_leaf_hash(uint8_t* out, uint8_t ver, const uint8_t* script, uint64_t slen);
extern void tap_branch_hash(uint8_t* out, const uint8_t* a, const uint8_t* b);
extern long tap_merkle_root(uint8_t* out, const uint8_t* leaf_hashes, uint64_t count,
                            const uint8_t* control, uint64_t clen);
extern long taproot_tweak_pubkey(uint8_t* out_x, const uint8_t* internal_x,
                                 const uint8_t* merkle_root);

static int g_fails = 0, g_checks = 0;
static void ck(const char* name, const uint8_t* got, const char* hex){
    g_checks++;
    uint8_t exp[32];
    for(int i=0;i<32;i++){unsigned v;sscanf(hex+2*i,"%2x",&v);exp[i]=(uint8_t)v;}
    if (memcmp(got, exp, 32)==0) { printf("PASS %s\n", name); }
    else {
        g_fails++;
        printf("FAIL %s\n got %02x%02x%02x...\n exp %s\n", name, got[0],got[1],got[2], hex);
    }
}
static void h2b(uint8_t* o, const char* h){ for(int i=0;i<32;i++){unsigned v;sscanf(h+2*i,"%2x",&v);o[i]=(uint8_t)v;} }
static void prx(char* n, const uint8_t* d){ printf("%s=",n); for(int i=0;i<32;i++)printf("%02x",d[i]); printf("\n"); }

int main(void){
    uint8_t out[32], a[32], b[32], scr[1];
    // ---- tagged_hash256: TapTweak over 32 zero bytes ----
    uint8_t z[32]; memset(z,0,32);
    tagged_hash256(out, "TapTweak", 8, z, 32);
    ck("tagged_hash256 TapTweak(32z)", out,
       "38acfd2d72ad71541503bf9521485ed40eb70ad40dd562d29677a32c917d8e61");

    // ---- tap_leaf_hash: TapLeaf(0xc0 || 0x01 || 0x51) ----
    scr[0]=0x51;
    tap_leaf_hash(out, 0xc0, scr, 1);
    ck("tap_leaf_hash ver0xc0 [51]", out,
       "a85b2107f791b26a84e7586c28cec7cb61202ed3d01944d832500f363782d675");

    // ---- tap_branch_hash (BIP341 sorts): a=range(32), b=zeros -> branch(zeros||range) ----
    for(int i=0;i<32;i++) a[i]=(uint8_t)i;
    memset(b,0,32);
    tap_branch_hash(out, a, b);
    ck("tap_branch_hash(range,0)", out,
       "371af43ac798634583a6d71282e78cd72cfa331199af153517691cb8370e5597");

    // ---- tap_merkle_root: 2-leaf (l1=range, l2=zeros) ----
    uint8_t ctrl[128]; ctrl[0]=0xc0; memset(ctrl+1,0,96);
    // leaf_hashes[0] = l1 = range
    tap_merkle_root(out, a, 1, ctrl, 33+32);
    ck("merkle_root 2-leaf", out,
       "371af43ac798634583a6d71282e78cd72cfa331199af153517691cb8370e5597");

    // ---- taproot_tweak_pubkey key-only: BIP341 spec internal key ----
    uint8_t ik[32];
    h2b(ik, "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115");
    long r = taproot_tweak_pubkey(out, ik, NULL);
    ck("tweak key-only (BIP341)", out,
       "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c");
    printf("  (return=%ld)\n", r);

    // ---- taproot_tweak_pubkey with 2-leaf merkle root (script path) ----
    uint8_t mr[32];
    h2b(mr, "371af43ac798634583a6d71282e78cd72cfa331199af153517691cb8370e5597");
    r = taproot_tweak_pubkey(out, ik, mr);
    ck("tweak with 2-leaf mr (BIP341 ik)", out,
       "895c80ce44afcb80b39c5bebdf19ebed39f02eeaddc18c3a96631aafe762dfc0");
    printf("  (return=%ld)\n", r);

    // ---- reject invalid internal keys: x>=p (lift_x must fail) ----
    uint8_t bad[32]; memset(bad,0xFF,32); /* 2^256-1 > p */
    r = taproot_tweak_pubkey(out, bad, NULL);
    printf("  x>p internal return=%ld (%s)\n", r, r==0?"OK":"FAIL");
    if (r!=0) { g_fails++; g_checks++; }
    // ---- reject non-on-curve internal key: x=5 (x^3+7 not a QR) ----
    uint8_t nqr[32]; memset(nqr,0,32); nqr[31]=5; /* x=5, not on curve */
    r = taproot_tweak_pubkey(out, nqr, NULL);
    printf("  non-QR internal return=%ld (%s)\n", r, r==0?"OK":"FAIL");
    if (r!=0) { g_fails++; g_checks++; }

    printf("\n%s (%d checks, %d failures)\n", g_fails?"TESTS FAILED":"ALL PASS", g_checks, g_fails);
    return g_fails ? 1 : 0;
}
