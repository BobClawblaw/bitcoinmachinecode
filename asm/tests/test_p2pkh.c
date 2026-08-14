/* test_p2pkh.c -- end-to-end P2PKH spend validation via asm verify_p2pkh.
 * A real signed P2PKH tx (signature produced by cryptography over the asm
 * sighash), embedded. Expect verify_p2pkh == 1. Also a tampered-sig negative. */
#include <stdio.h>
#include <string.h>

/* extern in bitcoin_script.asm */
extern int verify_p2pkh(const unsigned char* tx, unsigned long txlen,
                        unsigned long input_index,
                        const unsigned char* prevout_script, unsigned long prevout_len,
                        unsigned char* work, unsigned long work_cap);

static int fails=0;
static void ck(const char* l,int got,int exp){
    if(got==exp) printf("ok  : %s\n",l);
    else { printf("FAIL: %s (got %d exp %d)\n",l,got,exp); fails++; }
}

static void hex_in(unsigned char* out, const char* h){
    int n=(int)(strlen(h))/2; for(int i=0;i<n;i++){ unsigned int v; sscanf(h+2*i,"%2x",&v); out[i]=(unsigned char)v; }
}

int main(void){
    /* from mkfull.py -- pure-Python self-verified ECDSA over the asm sighash */
    const char* F= "02000000011111111111111111111111111111111111111111111111111111111111111111010000006a47304402200401546f83a81708c6fe7c377c911bdfb08a60a797597531b37ac1ddc2132e6802200a19109980a117e28405737402efb1d9422f776b0cdaaa036bc7c18e9bfe0fa6012103ba6f2e86a2b485e96242506b576251b7c8038255463401361d248973b654d445feffffff0150c30000000000001976a914333333333333333333333333333333333333333388ac00000000";
    const char* SCPK="76a914444444444444444444444444444444444444444488ac";

    unsigned char full[2048], scp[64], work[4096];
    int fn=(int)(strlen(F))/2;
    hex_in(full,F);
    int sn=(int)(strlen(SCPK))/2;
    hex_in(scp,SCPK);

    int r = verify_p2pkh(full, fn, 0, scp, sn, work, sizeof work);
    ck("valid P2PKH spend verifies -> 1", r, 1);

    /* negative: flip a byte inside the actual DER signature (offset ~50) */
    unsigned char bad[2048];
    memcpy(bad, full, sizeof bad);
    bad[51] ^= 0xff;   /* inside the DER sig r-value -> sig no longer valid */
    int r2 = verify_p2pkh(bad, fn, 0, scp, sn, work, sizeof work);
    ck("tampered signature rejected -> 0", r2, 0);

    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
