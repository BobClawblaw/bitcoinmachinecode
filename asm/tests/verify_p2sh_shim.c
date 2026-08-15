/* verify_p2sh_shim.c -- stdin drive for the ASM P2SH VerifyScript (bitcoin_verify.c),
 * mirroring validation/core_verify_oracle.cpp's line protocol so the SAME
 * differential harness feeds identical (scriptSig, scriptPubKey, tx, idx, flags)
 * triples to both and compares verdict + error code.
 *
 *   VERIFY <flags_hex> <inputidx> <tx_hex> <scriptSig_hex> <scriptPubKey_hex>
 *   QUIT
 * prints: OK <0|1> <error_code>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int verify_script(const unsigned char* scriptSig, unsigned long ssl,
                         const unsigned char* scriptPubKey, unsigned long spl,
                         unsigned long long flags, unsigned long nIn,
                         const unsigned char* tx, unsigned long txlen,
                         unsigned char* work, unsigned long workcap);

static long hex2b(const char* h, unsigned char* o, long max){
    long n=0; if(!h) return 0;
    for(const char*p=h;p[0]&&p[1];p+=2){ unsigned v; if(sscanf(p,"%2x",&v)!=1) break; o[n++]=(unsigned char)v; if(n>=max) break; }
    return n;
}

int main(void){
    /* heap buffers so the big scratch areas do not sit against the 8MB stack */
    unsigned char* txs = (unsigned char*)malloc(1<<20);
    unsigned char* ss  = (unsigned char*)malloc(1<<16);
    unsigned char* spk = (unsigned char*)malloc(1<<16);
    unsigned char* work= (unsigned char*)malloc(1<<20);
    char* line = (char*)malloc(1<<21);
    if (!txs||!ss||!spk||!work||!line){ fprintf(stderr,"OOM\n"); return 1; }
    char cmd[16];
    while(fgets(line,1<<21,stdin)){
        char* save=NULL; char* tok=strtok_r(line," \t\n",&save);
        if(!tok) continue;
        snprintf(cmd,sizeof cmd,"%s",tok);
        if(!strcmp(cmd,"QUIT")) break;
        if(!strcmp(cmd,"VERIFY")){
            char* fl_h =strtok_r(NULL," \t\n",&save);
            char* idx_h=strtok_r(NULL," \t\n",&save);
            char* tx_h =strtok_r(NULL," \t\n",&save);
            char* ss_h =strtok_r(NULL," \t\n",&save);
            char* spk_h=strtok_r(NULL," \t\n",&save);
            if(!spk_h){ printf("OK 0 1\n"); fflush(stdout); continue; }
            if (strcmp(ss_h,"-")==0) ss_h="";
            if (strcmp(spk_h,"-")==0) spk_h="";
            unsigned long long flags=strtoull(fl_h,0,16);
            unsigned long idx=strtoul(idx_h,0,10);
            long tn=hex2b(tx_h, txs, 1<<20);
            long sn=hex2b(ss_h, ss, 1<<16);
            long pn=hex2b(spk_h, spk, 1<<16);
            int code=verify_script(ss,(unsigned long)sn,spk,(unsigned long)pn,flags,idx,
                                   txs,(unsigned long)tn,work,1<<20);
            printf("OK %d %d\n", code==0?1:0, code);
            fflush(stdout);
        }
    }
    free(txs); free(ss); free(spk); free(work); free(line);
    return 0;
}
