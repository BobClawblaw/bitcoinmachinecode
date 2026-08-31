/* Replicate sv_checksig_asm steps for block2518 tx1 input0 P2PK. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern int  legacy_sighash(unsigned char out32[32], const unsigned char* tx, unsigned long txlen,
                           unsigned long nIn, const unsigned char* scF, unsigned long scflen,
                           unsigned long long ht, unsigned char* preimg, unsigned long cap);
extern int  der_parse_sig(const void*sig, unsigned long siglen, void*r, void*s, void*dht);
extern long script_push_encode(void* needle, unsigned cap, const void*sig, unsigned long siglen);
extern long script_find_and_delete(void* dst, unsigned cap, const void* src, unsigned long srclen,
                                   const void* needle, unsigned long nlen);
extern int  sv_checksig_asm(void* ctx, const unsigned char* sig, unsigned long siglen,
                            const unsigned char* pub, unsigned long publen,
                            const unsigned char* slice[2]);
static void hex2b(const char*h,unsigned char*o){size_t n=strlen(h);for(size_t i=0;i<n;i+=2){unsigned v;sscanf(h+i,"%2x",&v);o[i/2]=(unsigned char)v;}}
int main(void){
    FILE*f=fopen("/tmp/tx1_2518.hex","r"); char hex[20000]; if(!f||!fscanf(f,"%s",hex)){printf("no tx\n");return 2;} fclose(f);
    unsigned char* tx=malloc(strlen(hex)/2); hex2b(hex,tx); unsigned long txlen=strlen(hex)/2;
    unsigned char sig[100], pub[80], spk[100];
    hex2b("48304502204464dc3788af495d691d7e89aca897370aa1f65031da6595df603dbe506d78c3022100c85950deefdc003cce2eaf6525cfa6f6016e120031ed0b21a09419cf9910d3fb01", sig);
    hex2b("045a54932d7c000175ad8e6d4ea6653ade90068e3f5b1471e162e09fe23ce59da925e507510a15086ac647b39f72c772520d32305bfa5e3d7a8fa5b1bf7c84028", pub);
    hex2b("41045a54932d7c000175ad8e6d4ea6653ade90068e3f5b1471e162e09fe23ce59da925e507510a15086ac647b39f72c772520d32305bfa5e3d7a8fa5b1bf7c840288ac", spk);
    static unsigned char work[8<<20];
    struct cctx{ void*tx;unsigned long tl;unsigned long nIn;void*w;unsigned long wc;} ctx={tx,txlen,0,work,sizeof work};
    unsigned char* slice[2]={spk,(unsigned char*)67};
    int r0=sv_checksig_asm(&ctx,sig,72,pub,65,slice);
    printf("sv_checksig_asm(input0,slice=spk)=%d\n", r0);
    /* manual: findanddelete scF */
    unsigned char needle[600]; long nlen=script_push_encode(needle,600,sig,72);
    printf("push_encode nlen=%ld\n", nlen);
    unsigned char scF[20000];
    long scflen=script_find_and_delete(scF,20000,spk,67,needle,nlen);
    printf("findanddelete scflen=%ld (expect 67, unchanged since sig not in spk)\n", scflen);
    unsigned char z[32];
    int lt=legacy_sighash(z,tx,txlen,0, scF, (unsigned long)(scflen>0?scflen:67), 1ULL, work, sizeof work);
    printf("legacy_sighash via scF -> "); for(int i=0;i<32;i++) printf("%02x",z[i]); printf(" (truth 65226057677654d6cd94eb6cf441bd5c41087ad47593ee0c2d5242875dc27539)\n");
    free(tx);
    return 0;
}
