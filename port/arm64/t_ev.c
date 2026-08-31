/* ARM ecdsa_verify with block2518 tx1 input0 high-S sig vs low-S form, using
 * the KNOWN-CORRECT sighash z = 65226057... verified by independent Python. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int ecdsa_verify(const unsigned long long z[4], const unsigned long long r[4], const unsigned long long s[4], const unsigned long long qx[4], const unsigned long long qy[4]);
extern int be_to_limbs(unsigned long long out[4], const unsigned char* p, int n);
extern int der_parse_sig(const unsigned char* sig, int siglen, unsigned long long r[4], unsigned long long s[4], int* dht);
void hex2b(const char*h,unsigned char*o){ int n=strlen(h)/2; for(int i=0;i<n;i++){unsigned v; sscanf(h+2*i,"%2x",&v); o[i]=v;} }
int main(void){
    /* DER(71) + sighash 0x01 = the 72-byte stack element */
    unsigned char el[72];
    hex2b("304502204464dc3788af495d691d7e89aca897370aa1f65031da6595df603dbe506d78c3022100c85950deefdc003cce2eaf6525cfa6f6016e120031ed0b21a09419cf9910d3fb01", el);
    unsigned long long r[4], s[4]; int dht=0;
    der_parse_sig(el, 72, r, s, &dht);
    printf("r=%016llx%016llx%016llx%016llx\ndht=%d\n", r[3],r[2],r[1],r[0], dht);
    printf("s=%016llx%016llx%016llx%016llx\n", s[3],s[2],s[1],s[0]);
    /* sighash SHA256d little-endian? be_to_limbs takes big-endian bytes. ground truth 65226057...: */
    static const unsigned char zbe[32]={0x65,0x22,0x60,0x57,0x67,0x76,0x54,0xd6,0xcd,0x94,0xeb,0x6c,0xf4,0x41,0xbd,0x5c,0x41,0x08,0x7a,0xd4,0x75,0x93,0xee,0x0c,0x2d,0x52,0x42,0x87,0x5d,0xc2,0x75,0x39};
    unsigned long long z[4]; be_to_limbs(z, zbe, 32);
    /* pubkey qx,qy (65-byte uncompressed), limbs */
    unsigned char pub[65];
    hex2b("045a54932d7c000175ad8e6d4ea6653ade90068e3f5b1471e162e09fe23ce59da925e507510a15086ac647b39f72c772520d32305bfa5e3d7a8fa5b1bf7c8402", pub);
    unsigned long long qx[4], qy[4]; be_to_limbs(qx, pub+1, 32); be_to_limbs(qy, pub+33, 32);
    int v1 = ecdsa_verify(z, r, s, qx, qy);
    printf("ecdsa_verify(high-S): %d\n", v1);
    /* s low = N - s */
    static const unsigned long long N[4]={0xbfd25e8cd0364141ull,0xbaaedce6af48a03bull,0xfffffffffffffffeull,0xffffffffffffffffull};
    unsigned long long sl[4]; unsigned long long borrow=0;
    for(int i=0;i<4;i++){ unsigned long long d=N[i]-s[i]-borrow; sl[i]=d; borrow=(N[i]<s[i]+borrow)?1:0; }
    printf("s_low=%.16llx%.16llx%.16llx%.16llx\n", sl[3],sl[2],sl[1],sl[0]);
    int v2 = ecdsa_verify(z, r, sl, qx, qy);
    printf("ecdsa_verify(low-S):  %d\n", v2);
    return 0;
}
