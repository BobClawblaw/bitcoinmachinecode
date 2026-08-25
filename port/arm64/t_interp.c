/* t_interp.c -- driver for bitcoin_interp.S pure helpers.
 * "op <n>"      -> is_opsuccess_c(n)   (exhaustive 0..255 done by python)
 * "me <hexa> <hexb>" -> interp_memeq(a,b,len)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
extern long is_opsuccess_c(long);
extern long interp_memeq(const uint8_t*,const uint8_t*,unsigned long);
static int hv(int c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;if(c>='A'&&c<='F')return c-'A'+10;return 0;}
static size_t h2b(const char*h,uint8_t*o,size_t m){size_t n=strlen(h);if(m<n/2)n=m*2;for(size_t i=0;i<n/2;i++)o[i]=(uint8_t)((hv(h[2*i])<<4)|hv(h[2*i+1]));return n/2;}
int main(int ac,char**av){
    (void)ac;(void)av;
    char line[4096]; uint8_t A[1024],B[1024];
    long op;
    if(scanf("op %ld",&op)==1){ printf("%ld\n",is_opsuccess_c(op)); return 0; }
    while(fgets(line,sizeof line,stdin)){
        if(!strncmp(line,"op ",3)){ long o=strtol(line+3,0,10); printf("%ld\n",is_opsuccess_c(o)); }
        else if(!strncmp(line,"me ",3)){
            char*aa=line+3; char*bb=strchr(aa,' '); *bb=0; bb++;
            // trim newline
            char*e=strchr(bb,'\n'); if(e)*e=0;
            size_t na=h2b(aa,A,sizeof A), nb=h2b(bb,B,sizeof B);
            size_t n = na<nb?na:nb;
            printf("%ld\n", interp_memeq(A,B,n));
        }
    }
    return 0;
}
