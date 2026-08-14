/* test_utxo.c -- verify asm UTXO set: put/get/del/dedup/double-spend guard. */
#include <stdio.h>
#include <string.h>

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long value, const unsigned char* script, unsigned long slen);
extern long utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script, unsigned long* slen);
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

    /* put two outputs under different (txid,index) */
    unsigned char scrA[25], scrB[22];
    for(int i=0;i<25;i++) scrA[i]=0x10+i;
    for(int i=0;i<22;i++) scrB[i]=0xC0+i;
    ck("put A0 new", utxo_put(ux,tA,0, 50000ULL, scrA, 25), 1);
    ck("put B7 new", utxo_put(ux,tB,7, 1234567ULL, scrB, 22), 1);
    ck("count 2", utxo_count(ux), 2);

    /* get A0 back */
    unsigned long long v; const unsigned char* s; unsigned long sl;
    ck("get A0 found", utxo_get(ux,tA,0,&v,&s,&sl), 1);
    ck("get A0 value", (int)(v==50000ULL), 1);
    ck("get A0 slen", (int)sl, 25);
    ck("get A0 script matches", memcmp(s,scrA,25)==0, 1);
    /* get B7 back */
    ck("get B7 found", utxo_get(ux,tB,7,&v,&s,&sl), 1);
    ck("get B7 value", (int)(v==1234567ULL), 1);
    ck("get B7 slen", (int)sl, 22);
    ck("get B7 script matches", memcmp(s,scrB,22)==0, 1);

    /* duplicate put A0 -> 0 */
    ck("put A0 dup -> 0", utxo_put(ux,tA,0, 9ULL, scrA, 25), 0);
    /* wrong index on same txid -> miss (distinct outpoint) */
    ck("get A1 miss", utxo_get(ux,tA,1,&v,&s,&sl), 0);
    /* other index put as distinct */
    ck("put A1 new", utxo_put(ux,tA,1, 777ULL, scrB, 22), 1);
    ck("count 3", utxo_count(ux), 3);

    /* spend/delete */
    ck("del A0 deleted", utxo_del(ux,tA,0), 1);
    ck("get A0 now miss (spent)", utxo_get(ux,tA,0,&v,&s,&sl), 0);
    /* double spend / second del -> miss */
    ck("del A0 again miss", utxo_del(ux,tA,0), 0);
    ck("count 2 after spend", utxo_count(ux), 2);
    /* A1 (same txid, different index) still unspent */
    ck("get A1 still unspent", utxo_get(ux,tA,1,&v,&s,&sl), 1);

    /* probing: add many distinct to exercise wrap / collisions */
    int ok=1;
    for(unsigned long long i=0;i<300;i++){
        unsigned char t[32]; for(int j=0;j<32;j++) t[j]=0x05;
        t[0]=(unsigned char)(i&0xff); t[1]=(unsigned char)((i>>8)&0xff);
        unsigned char sc[3]={0x51,(unsigned char)i,0xac};
        if(utxo_put(ux,t,i, i*2ULL, sc, 3)!=1){ ok=0; }
    }
    ck("bulk put 300 ok", ok, 1);
    for(unsigned long long i=0;i<300 && ok;i++){
        unsigned char t[32]; for(int j=0;j<32;j++) t[j]=0x05;
        t[0]=(unsigned char)(i&0xff); t[1]=(unsigned char)((i>>8)&0xff);
        unsigned long long vv; const unsigned char* ss; unsigned long sl;
        if(utxo_get(ux,t,i,&vv,&ss,&sl)!=1 || vv!=i*2ULL || sl!=3) ok=0;
    }
    ck("bulk get back 300 byte-exact", ok, 1);

    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
