/* fz_tx.c -- differential-fuzz helper: parse a tx passed on argv (hex),
 * print tx_parse txinfo fields + tx_txid result so a Python oracle can
 * compare. Usage: fz_tx <hexstring>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int  u32;
extern int tx_parse(u64 info[8], const void *tx, unsigned long txlen);
extern int tx_txid(u8 out[32], const u8 *tx, unsigned long txlen, u8 *buf, unsigned long buflen);

typedef struct {
    u64 tx_len;
    u32 version, n_in, n_out, locktime;
    u64 in0_script, in0_script_len;
    u64 out0_value, out0_script, out0_script_len;
} txinfo;

static int hexval(int c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return c-'a'+10;
    if(c>='A'&&c<='F') return c-'A'+10;
    return -1;
}

static void puthex(const u8*p,int n){ for(int i=0;i<n;i++) printf("%02x",p[i]); }

int main(int argc, char**argv){
    if(argc<2) return 2;
    const char*h=argv[1];
    int n=(int)strlen(h)/2;
    unsigned char *tx=malloc(n?n:1);
    for(int i=0;i<n;i++) tx[i]=(hexval(h[2*i])<<4)|hexval(h[2*i+1]);
    txinfo ti; memset(&ti,0,sizeof ti);
    int rp=tx_parse((u64*)&ti,tx,n);
    printf("P%d %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
        rp,
        (u64)ti.tx_len,(u64)ti.version,(u64)ti.n_in,(u64)ti.n_out,(u64)ti.locktime,
        ti.in0_script,ti.in0_script_len,ti.out0_value,ti.out0_script,ti.out0_script_len);
    unsigned char out[32]; unsigned char buf[1<<20];
    int rt=tx_txid(out,tx,n,buf,sizeof buf);
    printf("T%d ", rt);
    if(rt) puthex(out,32);
    printf("\n");
    free(tx);
    return 0;
}
