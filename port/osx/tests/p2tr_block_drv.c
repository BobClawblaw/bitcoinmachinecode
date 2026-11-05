/* p2tr_block_drv.c -- per-input taproot verify differential driver (bmc_osx).
 * Reads lines "txidx vinidx stripped-hex prevouts-hex amounts-hex spks-hex
 * nwit wit0 [wit1 ...]" (spks = compactsize-prefixed, prevouts = 36-byte
 * outpoints, txids internal order) and runs taproot_verify_input_flags on
 * each -- the daemon's exact BIP341/342 verify entry (bitcoin_taproot_sighash.c).
 * The companion p2tr_block_123615.txt carries the 88 taproot inputs of
 * testnet4 block 123615 (hash 0000000000000003242f3a455ccc265d470ce99d6da5aa5b7fd9d1a7a8284c88).
 * x86 reference: 88/88 pass; osx twin: 86/88 -- tx#57 vin#0 and tx#62 vin#0
 * (6-item script-path spends, witness {sig,sig,preimage,01,script,control},
 * script = IF HASH256 <h> EQUAL ... ENDIF with 4 initial-stack args) fail
 * with "p2tr tapscript execution failed" on the twin. The scripts contain
 * NO OP_SUCCESSx and the pre-scan is correct on both sides; the divergence
 * is inside script_eval's execution of the multi-arg IF branch (or its
 * CHECKSIG under a 4-deep initial stack). Debug WITH CARE: the driver
 * itself had three context bugs on the way in (num_inputs passed as a byte
 * length, prevouts as 32-byte txids instead of 36-byte outpoints, spks
 * without compactsize prefixes) -- the x86 fails the same way on a wrong
 * context, so ALWAYS cross-check a driver change against .242 before
 * suspecting the twin. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
extern int taproot_verify_input_flags(const u8* spk, const u8* const* wit, const u32* witlen, u32 nwit,
                                      const u8* tx, long long txlen, long long n_in,
                                      const u8* prevouts, const u8* amounts, const u8* spks, long long num_inputs,
                                      const char** reason, unsigned long long flags);
static u8* hexd(const char* h, unsigned* len){
    unsigned n=strlen(h)/2; u8* b=malloc(n?n:1);
    for(unsigned i=0;i<n;i++){ unsigned v; sscanf(h+2*i,"%2x",&v); b[i]=v; }
    *len=n; return b;
}
int main(int argc, char** argv){
    FILE* f=fopen(argv[1],"r");
    char line[1<<21];
    int fails=0, n=0;
    while (fgets(line,sizeof line,f)){
        if (strlen(line)<40) continue;
        static char stripped[800001], pv[262145], am[65537], sp[800001];
        static char wx[8][600001];
        long ti; unsigned vi; unsigned nitems;
        if (sscanf(line,"%ld %u %800000s %262144s %65536s %800000s %u %600000s %600000s %600000s %600000s %600000s %600000s %600000s %600000s",
                   &ti,&vi,stripped,pv,am,sp,&nitems,wx[0],wx[1],wx[2],wx[3],wx[4],wx[5],wx[6],wx[7]) < 8) continue;
        unsigned sl,pl,al,cl;
        u8* s=hexd(stripped,&sl); u8* p=hexd(pv,&pl); u8* m=hexd(am,&al); u8* c=hexd(sp,&cl);
        const u8* wit[8]; u32 wl[8]; u32 nwit = nitems<8?nitems:8;
        u8* xs[8];
        for (u32 k=0;k<nwit;k++){ xs[k]=hexd(wx[k],&wl[k]); wit[k]=xs[k]; }
        /* spks: compactsize-prefix each script; count inputs; spk = vi-th */
        u8* cp=malloc(cl + 4*(cl/32+2) + 64); unsigned cw=0, nin=0;
        u8* spk_nin=NULL; unsigned spk_nin_len=0;
        { u8*q=c; u8*e=c+cl;
          while (q<e){
            u8 b0=*q; unsigned vsz, l2;
            if (b0<0xfd){ vsz=1; l2=b0; }
            else if (b0==0xfd){ vsz=3; l2=q[1]|(q[2]<<8); }
            else if (b0==0xfe){ vsz=5; l2=q[2]|(q[3]<<8)|(q[4]<<16)|(q[5]<<24); }
            else { vsz=9; l2=0; }
            if (q+vsz+l2>e) break;
            if (b0<0xfd){ cp[cw++]=b0; }
            else { cp[cw++]=0xfd; cp[cw++]=l2&0xff; cp[cw++]=(l2>>8)&0xff; }
            if ((long long)nin==vi){ spk_nin=cp+cw; spk_nin_len=l2; }
            memcpy(cp+cw,q+vsz,l2); cw+=l2; q+=vsz+l2; nin++; }
        }
        const char* reason=NULL;
        int r=taproot_verify_input_flags(spk_nin,(const u8* const*)wit,wl,nwit,s,sl,vi,p,m,cp,nin,&reason,0);
        n++;
        if(!r){ printf("FAIL tx#%ld vin#%u nwit=%u: %s\n",ti,vi,nwit,reason?reason:"?"); fails++; }
        free(s);free(p);free(m);free(c); for (u32 k=0;k<nwit;k++) free(xs[k]); free(cp);
    }
    printf("%d/%d passed\n",n-fails,n);
    return fails!=0;
}
