/* test_lsm_tie_order.c -- the utxo_lsm_twin radix sorter's 96-bit tie-break
 * regression (testnet4 h=51859): a txid with enough outputs puts multiple
 * records behind one 12-byte compact prefix; the MSD insertion path's
 * tie-break comparison was direction-inverted and ordered those tie groups
 * DESCENDING, so every point lookup past the inversion missed. Verifies
 * utxo_lsm_sort_desc orders same-txid descriptor groups strictly ascending
 * by the full 36-byte key at scales the 229-record differential cannot
 * reach (its vectors never tie on the compact bits). Usage:
 *   test_lsm_tie_order [N]   (default 465; SORTMODE=1 forces the radix) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned char u8; typedef unsigned long long u64; typedef unsigned int u32;
extern void utxo_lsm_sort_desc(u8 *a, u8 *b, u64 n);
extern void utxo_lsm_set_sort_mode(u64 mode);
static int cmpk(const u8 *p, const u8 *q){
    for (int i=0;i<36;i++){ if(p[i]<q[i]) return -1; if(p[i]>q[i]) return 1; }
    return 0;
}
int main(void){
    /* one txid, 465 outputs, descriptors in CREATION order (index asc), each
     * 64 bytes: key36 + type1 at [36] + slack */
    int N = atoi(getenv("N")?getenv("N"):"465");
    u8 *a = malloc(N*64), *b = malloc(N*64);
    u8 txid[32]; for (int i=0;i<32;i++) txid[i]= (u8)(i*7+1);
    for (int i=0;i<N;i++){
        u8 *d=a+i*64;
        memcpy(d, txid, 32);
        u32 idx=(u32)i;                     /* creation order == index order */
        memcpy(d+32,&idx,4);
        d[36]= (i%3==0)?2:1;                /* mix of PUTs and DELs */
        for (int k=37;k<64;k++) d[k]=0xAA;
    }
    utxo_lsm_set_sort_mode(atoi(getenv("SORTMODE")?getenv("SORTMODE"):"1"));
    utxo_lsm_sort_desc(a,b,N);
    int bad=0; u8 prev[36]; int have=0;
    for (int i=0;i<N;i++){
        if (have && cmpk(prev,a+i*64)>0){
            if(!bad) printf("first inversion at %d: prev idx=%u this idx=%u\n", i,
                            *(u32*)(prev+32), *(u32*)(a+i*64+32));
            bad++;
        }
        memcpy(prev,a+i*64,36); have=1;
    }
    printf("%s: %d inversions of %d same-txid records\n", bad?"FAIL":"PASS", bad, N);
    return bad!=0;
}
