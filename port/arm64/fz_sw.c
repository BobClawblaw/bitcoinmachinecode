/* fz_sw.c -- driver for strip_witness_asm differential fuzz against a
 * from-scratch Python oracle. Reads "hex cap" lines from stdin, runs
 * strip_witness_asm, prints "rc:OUTHEX". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern long strip_witness_asm(const uint8_t* tx, int64_t txlen, uint8_t* out, long cap);

static int hexv(int c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }

int main(void){
    char line[1<<22];
    uint8_t *buf=malloc(1<<20), *out=malloc(1<<20);
    while(fgets(line,sizeof line,stdin)){
        line[strcspn(line,"\n")]=0;
        char* sp=strchr(line,' ');
        if(!sp) continue;
        *sp=0; long cap=atol(sp+1);
        int hlen=strlen(line); if(hlen%2){ printf("-1\n"); continue; }
        int n=hlen/2;
        for(int i=0;i<n;i++){ int a=hexv(line[2*i]),b=hexv(line[2*i+1]); if(a<0||b<0){n=-1;break;} buf[i]=(a<<4)|b; }
        if(n<0){ printf("-1\n"); continue; }
        memset(out,0xCC,1024);
        long rc=strip_witness_asm(buf,n,out,cap);
        printf("%ld:",rc);
        int span = (rc>0)? (int)rc : ((cap>0&&cap<1024)?(int)cap:0);
        for(int i=0;i<span && i<1024;i++) printf("%02x",out[i]);
        printf("\n");
    }
    free(buf); free(out); return 0;
}
