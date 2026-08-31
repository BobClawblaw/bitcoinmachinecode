/* Test sv_checksig_asm directly with CORRECT block2518 tx1 input0 values, and
 * compare its path to the manual reference. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int sv_checksig_asm(const unsigned char* tx, unsigned long txlen, unsigned long nin, unsigned char* work, unsigned long workcap,
    const unsigned char* sig, unsigned long siglen, const unsigned char* pub, unsigned long publen, const unsigned char* slice, unsigned long sliceLen);
extern int legacy_sighash(unsigned char out32[32], const unsigned char* tx, unsigned long txlen, unsigned long nin, const unsigned char* sc, unsigned long sclen, unsigned long ht, unsigned char* work, unsigned long workcap);
extern long script_push_encode(unsigned char* out, const unsigned char* p, unsigned long n);
extern long script_find_and_delete(unsigned char* sc, unsigned char* sp, unsigned long n, const unsigned char* needle, unsigned long nlen);
extern int der_parse_sig(const unsigned char* sig, int siglen, unsigned long long r[4], unsigned long long s[4], int* dht);
extern int ecdsa_verify(const unsigned long long z[4], const unsigned long long r[4], const unsigned long long s[4], const unsigned long long qx[4], const unsigned long long qy[4]);
extern int be_to_limbs(unsigned long long out[4], const unsigned char* p, int n);
static void hex2b(const char* h, unsigned char* o){ size_t n=strlen(h); for(size_t i=0;i<n;i+=2){ unsigned v; sscanf(h+i,"%2x",&v); o[i/2]=(unsigned char)v; } }
static size_t hx(const char* h){ return strlen(h)/2; }
int main(void){
    FILE*f=fopen("/tmp/tx1_2518.hex","r"); char hex[20000]; if(!f||!fscanf(f,"%s",hex)){printf("no tx\n");return 2;} fclose(f);
    unsigned char* tx=malloc(hx(hex)); hex2b(hex,tx);
    /* sig element = DER + sighash (72 bytes, no 0x48 push) */
    const char* sigh="304502204464dc3788af495d691d7e89aca897370aa1f65031da6595df603dbe506d78c3022100c85950deefdc003cce2eaf6525cfa6f6016e120031ed0b21a09419cf9910d3fb01";
    /* pub = 65 bytes from real spk */
    const char* pubh="045a54932d7c000175ad8e6d4ea6653ade90068e3f5b1471e162e09fe23ce59da925e507510a15086ac647b39f72c772520d32305bfa5e3d7a8fa5b1bf7c840288";
    /* slice = spk (the script where OP_CHECKSIG executes) = 41<pub>ac (67B) */
    const char* spkh="41045a54932d7c000175ad8e6d4ea6653ade90068e3f5b1471e162e09fe23ce59da925e507510a15086ac647b39f72c772520d32305bfa5e3d7a8fa5b1bf7c840288ac";
    unsigned char sig[256], pub[256], spk[256];
    static unsigned char work[8<<20];
    hex2b(sigh,sig); hex2b(pubh,pub); hex2b(spkh,spk);
    int r = sv_checksig_asm(tx, hx(hex), 0, work, 8<<20, sig, hx(sigh), pub, hx(pubh), spk, hx(spkh));
    printf("sv_checksig_asm(input0) = %d\n", r);
    /* manual reference: push_encode sig, find_and_delete from spk, legacy_sighash, ecdsa */
    unsigned char needle[200]; long nlen=script_push_encode(needle, sig, hx(sigh));
    unsigned char scF[300]; memcpy(scF,spk,hx(spkh));
    long sflen=script_find_and_delete(scF, scF, hx(spkh), needle, nlen);
    printf("push_encode nlen=%ld, findanddelete sflen=%ld\n", nlen, sflen);
    unsigned char z[32];
    legacy_sighash(z, tx, hx(hex), 0, scF, sflen, sig[hx(sigh)-1], work, 8<<20);
    unsigned char zh[65]; snprintf(zh,sizeof zh,"%02x%02x%02x%02x%02x%02x%02x%02x..%02x%02x",z[0],z[1],z[2],z[3],z[4],z[5],z[6],z[7],z[30],z[31]);
    printf("svg sighash z = %s... (truth 6522...c27539)\n", zh);
    /* ecdsa verify with this z */
    unsigned char d[80]; hex2b(sigh,d);
    unsigned long long rl[4],sl[4]; int dht=0; der_parse_sig(d, 71, rl, sl, &dht);
    unsigned char zb[32]; memcpy(zb,z,32); unsigned long long zl[4]; be_to_limbs(zl,zb,32);
    unsigned long long qx[4],qy[4]; be_to_limbs(qx,pub+1,32); be_to_limbs(qy,pub+33,32);
    int ev=ecdsa_verify(zl, rl, sl, qx, qy);
    printf("ecdsa_verify(manual z)= %d\n", ev);
    free(tx);
    return 0;
}
