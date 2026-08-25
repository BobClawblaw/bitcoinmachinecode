/* fz_sigops.c -- differential-fuzz helper for bitcoin_sigops.S (AArch64).
 * Usage:
 *   fz_sigops S <hextx>                      -> tx_legacy_sigops (inaccurate)
 *   fz_sigops A <hexscript>                  -> script_sigops_accurate
 *   fz_sigops I <hexscript>                  -> script_sigops (inaccurate)
 * Prints one result line so a Python oracle can compare.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;

extern long script_sigops(const u8* script, unsigned long len);
extern long script_sigops_accurate(const u8* script, unsigned long len);
extern long tx_legacy_sigops(const u8* tx, unsigned long len);

static int hexval(int c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

int main(int argc, char**argv){
    if(argc<3) return 2;
    char mode=argv[1][0];
    const char*h=argv[2];
    static char bigbuf[1<<25];   /* 32MB hex -> up to 16MB of tx bytes */
    /* '@<file>' : read hex from a file (handles inputs too large for argv) */
    if(h[0]=='@'){
        FILE*f=fopen(h+1,"r");
        if(!f){ fprintf(stderr,"cannot open %s\n",h+1); return 3; }
        size_t got=fread(bigbuf,1,sizeof bigbuf-1,f);
        fclose(f);
        bigbuf[got]=0; h=bigbuf;
    }
    int n=(int)strlen(h)/2;
    unsigned char *b=malloc(n?n:1);
    for(int i=0;i<n;i++) b[i]=(hexval(h[2*i])<<4)|hexval(h[2*i+1]);
    long r=0;
    if(mode=='S')      r=tx_legacy_sigops(b,(unsigned long)n);
    else if(mode=='A') r=script_sigops_accurate(b,(unsigned long)n);
    else               r=script_sigops(b,(unsigned long)n);
    printf("%ld\n", r);
    free(b);
    return 0;
}
