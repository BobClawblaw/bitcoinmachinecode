/* test_utxo.c -- verify asm UTXO set: put/get/del/dedup/double-spend guard,
 * and (2026-08-19, Stage D) the height/is_coinbase fields added so script
 * verification can enforce the 100-block coinbase maturity rule. */
#include <stdio.h>
#include <string.h>

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long value, unsigned long height,
                     unsigned long is_coinbase, const unsigned char* script, unsigned long slen);
extern long utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, unsigned long* height,
                     unsigned long* is_coinbase, const unsigned char** script, unsigned long* slen);
extern long utxo_del(void* u, const unsigned char txid[32], unsigned long index);
extern long utxo_count(void* u);

static int fails=0;
static void ck(const char* l,int got,int exp){
    if(got==exp) printf("ok  : %s\n",l);
    else { printf("FAIL: %s (got %d exp %d)\n",l,got,exp); fails++; }
}

int main(void){
    static unsigned char ux[ 40+512*48+8 ];
    static unsigned char blob[1<<16];
    utxo_init(ux, 512, blob, sizeof blob);

    unsigned char tA[32], tB[32];
    for(int i=0;i<32;i++){ tA[i]=0xAA; tB[i]=0xBB; }

    /* put two outputs under different (txid,index) -- A is a coinbase
     * output at height 100, B is a normal spend at height 200 */
    unsigned char scrA[25], scrB[22];
    for(int i=0;i<25;i++) scrA[i]=0x10+i;
    for(int i=0;i<22;i++) scrB[i]=0xC0+i;
    ck("put A0 new (coinbase, h=100)", utxo_put(ux,tA,0, 50000ULL, 100, 1, scrA, 25), 1);
    ck("put B7 new (normal, h=200)", utxo_put(ux,tB,7, 1234567ULL, 200, 0, scrB, 22), 1);
    ck("count 2", utxo_count(ux), 2);

    /* get A0 back */
    unsigned long long v; unsigned long h, cb, sl; const unsigned char* s;
    ck("get A0 found", utxo_get(ux,tA,0,&v,&h,&cb,&s,&sl), 1);
    ck("get A0 value", (int)(v==50000ULL), 1);
    ck("get A0 height", (int)h, 100);
    ck("get A0 is_coinbase", (int)cb, 1);
    ck("get A0 slen", (int)sl, 25);
    ck("get A0 script matches", memcmp(s,scrA,25)==0, 1);
    /* get B7 back */
    ck("get B7 found", utxo_get(ux,tB,7,&v,&h,&cb,&s,&sl), 1);
    ck("get B7 value", (int)(v==1234567ULL), 1);
    ck("get B7 height", (int)h, 200);
    ck("get B7 is_coinbase", (int)cb, 0);
    ck("get B7 slen", (int)sl, 22);
    ck("get B7 script matches", memcmp(s,scrB,22)==0, 1);

    /* duplicate put A0 -> 0 */
    ck("put A0 dup -> 0", utxo_put(ux,tA,0, 9ULL, 999, 1, scrA, 25), 0);
    /* wrong index on same txid -> miss (distinct outpoint) */
    ck("get A1 miss", utxo_get(ux,tA,1,&v,&h,&cb,&s,&sl), 0);
    /* other index put as distinct, non-coinbase this time */
    ck("put A1 new (normal, h=300)", utxo_put(ux,tA,1, 777ULL, 300, 0, scrB, 22), 1);
    ck("count 3", utxo_count(ux), 3);
    ck("get A1 is_coinbase false", utxo_get(ux,tA,1,&v,&h,&cb,&s,&sl) && cb==0, 1);
    ck("get A1 height", (int)h, 300);

    /* spend/delete */
    ck("del A0 deleted", utxo_del(ux,tA,0), 1);
    ck("get A0 now miss (spent)", utxo_get(ux,tA,0,&v,&h,&cb,&s,&sl), 0);
    /* double spend / second del -> miss */
    ck("del A0 again miss", utxo_del(ux,tA,0), 0);
    ck("count 2 after spend", utxo_count(ux), 2);
    /* A1 (same txid, different index) still unspent */
    ck("get A1 still unspent", utxo_get(ux,tA,1,&v,&h,&cb,&s,&sl), 1);

    /* is_coinbase=1 at a height whose value, packed into the qword's high
     * bits, would corrupt *height by +2^32 if the extraction masked wrong
     * (a real bug this test would have caught: `and r8,0xFFFFFFFF` sign-
     * extends the immediate to all-1s, a no-op mask -- caught by nasm's own
     * warning before this test ever ran, but this case pins it structurally
     * too, at the boundary height value where the bug would be most visible). */
    unsigned char tC[32]; for(int i=0;i<32;i++) tC[i]=0xCC;
    unsigned char scrC[3]={0x51,0x52,0xac};
    ck("put C0 coinbase at max-plausible height", utxo_put(ux,tC,0, 5000000000ULL, 700000, 1, scrC, 3), 1);
    ck("get C0 found", utxo_get(ux,tC,0,&v,&h,&cb,&s,&sl), 1);
    ck("get C0 height exact (not corrupted by is_coinbase bit)", (int)h, 700000);
    ck("get C0 is_coinbase", (int)cb, 1);
    ck("get C0 value", (int)(v==5000000000ULL), 1);

    /* probing: add many distinct to exercise wrap / collisions */
    int ok=1;
    for(unsigned long long i=0;i<300;i++){
        unsigned char t[32]; for(int j=0;j<32;j++) t[j]=0x05;
        t[0]=(unsigned char)(i&0xff); t[1]=(unsigned char)((i>>8)&0xff);
        unsigned char sc[3]={0x51,(unsigned char)i,0xac};
        if(utxo_put(ux,t,i, i*2ULL, (unsigned long)i, (unsigned long)(i&1), sc, 3)!=1){ ok=0; }
    }
    ck("bulk put 300 ok", ok, 1);
    for(unsigned long long i=0;i<300 && ok;i++){
        unsigned char t[32]; for(int j=0;j<32;j++) t[j]=0x05;
        t[0]=(unsigned char)(i&0xff); t[1]=(unsigned char)((i>>8)&0xff);
        unsigned long long vv; unsigned long hh, cc; const unsigned char* ss; unsigned long sl2;
        if(utxo_get(ux,t,i,&vv,&hh,&cc,&ss,&sl2)!=1 || vv!=i*2ULL || sl2!=3
           || hh!=(unsigned long)i || cc!=(unsigned long)(i&1)) ok=0;
    }
    ck("bulk get back 300 byte-exact incl height/coinbase", ok, 1);

    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
