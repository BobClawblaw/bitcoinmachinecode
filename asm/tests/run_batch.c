/* run_batch.c - batch runner for the asm interpreter. Reads lines:
 *   <sigversion> <flags> <ninit> <script_hex> <init0_hex> <init1_hex> ...
 * For each line prints: `RESULT <ok> <errcode>`.
 * stdin-driven so a Python oracle can drive vector suites without a shared lib.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "interp_shim.c"

static int hex2b(const char* h, uint8_t* o){
    int n=0; if(!h) return 0;
    for(const char*p=h;p[0]&&p[1];p+=2){ unsigned v; sscanf(p,"%2x",&v); o[n++]=(uint8_t)v; }
    return n;
}
static int hex2b_args(const char* h, uint8_t* o, size_t* outlen){
    int n=hex2b(h,o); if(outlen)*outlen=n; return n;
}

int main(void){
    char line[65536];
    while(fgets(line,sizeof(line),stdin)){
        /* tokenize by whitespace */
        char* save=NULL;
        char* tok=strtok_r(line," \t\n",&save);
        if(!tok) continue;
        int sigv=atoi(tok);
        tok=strtok_r(NULL," \t\n",&save); uint64_t flags=strtoull(tok,NULL,0);
        tok=strtok_r(NULL," \t\n",&save); int ninit=atoi(tok);
        tok=strtok_r(NULL," \t\n",&save); /* script hex */
        uint8_t script[20000]; size_t slen=hex2b(tok,script);
        static uint8_t buf[520][520];
        static size_t blen[520];
        const uint8_t* datap[520];
        for(int i=0;i<ninit;i++){
            tok=strtok_r(NULL," \t\n",&save);
            blen[i]=hex2b(tok,buf[i]);
            datap[i]=buf[i];
        }
        uint64_t err=0;
        int ok=eval_script_bytes(script,slen,datap,blen,ninit,sigv,flags,&err);
        printf("RESULT %d %llu\n", ok, (unsigned long long)err);
        fflush(stdout);
    }
    return 0;
}
