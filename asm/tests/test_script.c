/* test_script.c -- verify asm der_parse_sig (with be_to_limbs) against a real
 * DER signature. DER (no trailing hashtype) -> htype==0; append 0x01 -> htype==1. */
#include <stdio.h>
#include <string.h>

extern int der_parse_sig(const unsigned char* sig, unsigned long slen,
                         unsigned long long r[4], unsigned long long s[4],
                         unsigned int* hashtype);

static int fails=0;
static void ck(const char* l,int got,int exp){
    if(got==exp) printf("ok  : %s\n",l);
    else { printf("FAIL: %s (got %d exp %d)\n",l,got,exp); fails++; }
}
static void limbs2be(const unsigned long long l[4], unsigned char be[32]){
    for(int i=0;i<4;i++){ unsigned long long v=l[i]; for(int j=0;j<8;j++){ be[31-(i*8+j)]=(unsigned char)(v&0xff); v>>=8; } }
}
static void ck_limbs(const char* l, const unsigned long long lm[4], const char* hexexp){
    unsigned char got[32], exp[32];
    limbs2be(lm,got);
    for(int i=0;i<32;i++){ unsigned int v; sscanf(hexexp+2*i,"%2x",&v); exp[i]=(unsigned char)v; }
    if(memcmp(got,exp,32)==0) printf("ok  : %s\n",l);
    else { printf("FAIL: %s\n",l); fails++; }
}

int main(void){
    /* real DER sig 70 bytes + trailing SIGHASH byte */
    const char* derhex="30450221009258d7b8a815be913af88d25b756e5db4723f1afb939ed733b967b57efe20f6902206c40715db92a6e08bc41b1c81aa340219e4a20e0762ae2dd7c167bd39fd4bc9c";
    unsigned char der[72]; int n=(int)(strlen(derhex)/2);
    for(int i=0;i<n;i++){ unsigned int v; sscanf(derhex+2*i,"%2x",&v); der[i]=(unsigned char)v; }
    unsigned long long r[4],s[4]; unsigned int htype=99;

    /* without trailing hashtype: parse DER, htype should be 0 */
    int r1 = der_parse_sig(der, n, r, s, &htype);
    ck("der_parse_sig valid (no htype)", r1, 1);
    ck("hashtype absent -> 0", (int)htype, 0);
    ck_limbs("r limbs", r, "9258d7b8a815be913af88d25b756e5db4723f1afb939ed733b967b57efe20f69");
    ck_limbs("s limbs", s, "6c40715db92a6e08bc41b1c81aa340219e4a20e0762ae2dd7c167bd39fd4bc9c");

    /* with trailing 0x01 => SIGHASH_ALL */
    der[n]=1;
    r1 = der_parse_sig(der, n+1, r, s, &htype);
    ck("der_parse_sig valid (with htype)", r1, 1);
    ck("hashtype == 1", (int)htype, 1);

    /* negatives */
    unsigned char bad[16]={0};
    ck("bad prefix rejected", der_parse_sig(bad,16,r,s,&htype), 0);      /* first byte 0x00 != 0x30 */
    bad[0]=0x30; bad[1]=3; bad[2]=0x02; bad[3]=0x00; ck("empty r rejected", der_parse_sig(bad,16,r,s,&htype), 0);
    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
