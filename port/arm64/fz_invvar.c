/* fz_invvar.c -- read a hex a from stdin lines, print sc_inv_var result. */
#include <stdio.h>
#include <stdlib.h>
typedef unsigned long long u64;
extern int sc_inv_var(u64 r[4], const u64 a[4]);
int main(void){
    char line[512];
    while (fgets(line,sizeof line,stdin)){
        char* p=line; while(*p==' '||*p=='\t')p++;
        if(*p=='#'||*p=='\n')continue;
        u64 a[4];
        for(int i=0;i<4;i++){
            char b[20];int j=0;
            while(*p && *p!=' ' && *p!='\n' && j<16)b[j++]=*p++;
            b[j]=0;a[i]=strtoull(b,0,16);
            while(*p==' ')p++;
        }
        u64 r[4];
        int ok=sc_inv_var(r,a);
        printf("%d %016llx %016llx %016llx %016llx\n",ok,r[0],r[1],r[2],r[3]);
    }
    return 0;
}
