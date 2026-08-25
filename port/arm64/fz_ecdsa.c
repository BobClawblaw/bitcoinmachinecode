#include <stdio.h>
#include <stdlib.h>
typedef unsigned long long u64;
extern int ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
                        const u64 Qx[4], const u64 Qy[4]);
static void rd(u64* o,char**p,int n){for(int i=0;i<n;i++){char b[20];int j=0;while(**p&&**p!=' '&&**p!='\n'&&j<16)b[j++]=*(*p)++;b[j]=0;o[i]=strtoull(b,0,16);while(**p==' ')(*p)++;}}
int main(void){
    char line[2048];
    while(fgets(line,sizeof line,stdin)){
        char*p=line; while(*p==' '||*p=='\t')p++;
        if(*p=='#'||*p=='\n')continue;
        u64 z[4],r[4],s[4],Qx[4],Qy[4];
        rd(z,&p,4);rd(r,&p,4);rd(s,&p,4);rd(Qx,&p,4);rd(Qy,&p,4);
        printf("%d\n", ecdsa_verify(z,r,s,Qx,Qy));
    }
    return 0;
}
