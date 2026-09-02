/* test_wrpc_sign.c -- verify the wallet-core/RPC signrawtransactionwithkey
 * (card 4). Builds an UNSIGNED 2-in/1-out P2PKH tx with wallet_createrawtx,
 * signs every input with wallet_signrawtx_withkeys using the owning keys, then
 * feeds the signed tx through the whole-tx validator (UTXO presence/double-
 * spend + per-input verify_p2pkh + fee). Negative: wrong key leaves an input
 * un-signed -> validator rejects. Already-signed inputs are left untouched.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* wallet core */
extern long wallet_createrawtx(unsigned char* out_tx, long cap,
    const unsigned char toutid[][32], const unsigned long* tidx,
    const unsigned long long* tval, unsigned long n, const unsigned char to_script[25],
    unsigned long long amount, const unsigned char change_script[25],
    unsigned long long fee, unsigned long locktime);
extern long wallet_signrawtx_withkeys(unsigned char* out_tx, long cap,
    const unsigned char* tx, unsigned long txlen,
    const unsigned char keys[][32], unsigned long nkeys,
    const unsigned char prevout[][25], unsigned long n_in, unsigned char* signed_mask_out);
extern void wallet_make_p2pkh_script(unsigned char script[25], const unsigned char priv_be[32]);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);
extern int  wallet_p2pkh_output_script(unsigned char out[25], const unsigned char h160[20]);

/* asm validator */
extern int  tx_parse(void* info, const unsigned char* tx, unsigned long txlen);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long value, unsigned long height,
                     unsigned long is_coinbase, const unsigned char* script, unsigned long slen);
extern long utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, unsigned long* height,
                     unsigned long* is_coinbase, const unsigned char** script, unsigned long* slen);
extern int  verify_p2pkh(const unsigned char* tx, unsigned long txlen,
                         unsigned long input_index,
                         const unsigned char* prevout_script, unsigned long prevout_len,
                         unsigned char* work, unsigned long cap);

typedef struct { unsigned long long tx_len; unsigned int version,n_in,n_out,locktime;
    unsigned long long a,b,c,d,e; } txinfo;
static unsigned long rd_varint(const unsigned char* p, const unsigned char** adv){
    unsigned long v=*p++;
    if(v<0xfd){*adv=p;return v;}
    if(v==0xfd){v=(unsigned long)p[0]|((unsigned long)p[1]<<8);p+=2;}
    else if(v==0xfe){v=0;for(int i=0;i<4;i++)v|=(unsigned long)p[i]<<(8*i);p+=4;}
    else {v=0;for(int i=0;i<8;i++)v|=(unsigned long)p[i]<<(8*i);p+=8;}
    *adv=p;return v;
}
static int validate_signed_tx(const unsigned char* tx, unsigned long txlen, void* utxo,
                              unsigned char* work, unsigned long workcap){
    txinfo info;
    if(tx_parse(&info,tx,txlen)!=1){printf("  [parse]\n");return 0;}
    if(info.n_in==0||info.n_out==0)return 0;
    unsigned long long total_in=0;
    const unsigned char* scripts[64];
    const unsigned char* p=tx+4;
    unsigned long ni=rd_varint(p,&p);
    for(unsigned int i=0;i<ni&&i<64;i++){
        unsigned char txid[32]; memcpy(txid,p,32);
        unsigned long idx=(unsigned long)p[32]|((unsigned long)p[33]<<8)|((unsigned long)p[34]<<16)|((unsigned long)p[35]<<24);
        p+=36; unsigned long sl=rd_varint(p,&p); p+=sl+4;
        unsigned long long val; const unsigned char* s; unsigned long ssl, h_unused, cb_unused;
        if(utxo_get(utxo,txid,idx,&val,&h_unused,&cb_unused,&s,&ssl)!=1){printf("  [double-spend]\n");return 0;}
        scripts[i]=s; total_in+=val;
    }
    for(unsigned int i=0;i<info.n_in&&i<64;i++)
        if(verify_p2pkh(tx,txlen,i,scripts[i],25,work,workcap)!=1){printf("  [sig] in %u\n",i);return 0;}
    unsigned long long total_out=0;
    { const unsigned char* q=tx+4; (void)rd_varint(q,&q);
      for(unsigned int i=0;i<info.n_in;i++){q+=36;unsigned long sl=rd_varint(q,&q);q+=sl+4;}
      (void)rd_varint(q,&q);
      for(unsigned int i=0;i<info.n_out;i++){unsigned long long v=0;for(int j=0;j<8;j++)v|=(unsigned long long)q[j]<<(8*j);q+=8;unsigned long sl=rd_varint(q,&q);q+=sl;total_out+=v;}
    }
    if(total_out>total_in){printf("  [fee]\n");return 0;}
    return 1;
}

static int fails=0;
static void ck(const char*l,int g,int e){ if(g==e)printf("ok  : %s\n",l); else{printf("FAIL: %s (got %d exp %d)\n",l,g,e);fails++;} }

int main(void){
    /* two distinct owning keys K0, K1 */
    unsigned char K0[32], K1[32];
    for(int i=0;i<32;i++){K0[i]=(unsigned char)(0xaa+i);K1[i]=(unsigned char)(0xbb+i);}
    unsigned char kA[2][32]; memcpy(kA[0],K0,32); memcpy(kA[1],K1,32);
    unsigned char prevB[2][25];
    wallet_make_p2pkh_script(prevB[0],K0);
    wallet_make_p2pkh_script(prevB[1],K1);
    /* a third non-owner key */
    unsigned char KX[32]; for(int i=0;i<32;i++)KX[i]=(unsigned char)(0xcc+i);

    /* two prevouts owned by K0 and K1 */
    unsigned char tA[32],tB[32];
    for(int i=0;i<32;i++){tA[i]=(unsigned char)(0x10+i);tB[i]=(unsigned char)(0x20+i);}
    unsigned long tidx[2]={0,1};
    unsigned long long tval[2]={4000000ULL,3000000ULL}; /* total 7M */
    unsigned char (*tid)[32]=malloc(2*32);
    memcpy(tid[0],tA,32);memcpy(tid[1],tB,32);

    /* destination K1's h160 */
    unsigned char h1[20]; wallet_key_h160(h1,K1);
    unsigned char to_scr[25]; wallet_p2pkh_output_script(to_scr,h1);
    unsigned char chg[25]; wallet_make_p2pkh_script(chg,K0);

    unsigned char raw[1024];
    long rawlen=wallet_createrawtx(raw,sizeof raw,tid,tidx,tval,2,to_scr,900000ULL,chg,1000ULL,0);
    ck("unsigned raw built (2-in/1-out)", rawlen>0,1);

    /* VALID: sign both inputs with the owning keys K0,K1 */
    {
        unsigned char signed_k[1024]; unsigned char mask[8]={0,0,0,0,0,0,0,0};
        long sl=wallet_signrawtx_withkeys(signed_k,sizeof signed_k,raw,(unsigned long)rawlen,
                                          kA,2,prevB,2,mask);
        ck("sign with both keys ok", sl>0,1);
        ck("  input0 signed", mask[0],1);
        ck("  input1 signed", mask[1],1);
        unsigned char ux[40+512*48+8], ublob[1<<16], work[8192];
        utxo_init(ux,512,ublob,sizeof ublob);
        utxo_put(ux,tA,0,tval[0],0,0,prevB[0],25);
        utxo_put(ux,tB,1,tval[1],0,0,prevB[1],25);
        ck("signed tx VALID", sl>0 && validate_signed_tx(signed_k,(unsigned long)sl,ux,work,sizeof work),1);
    }

    /* WRONG KEY: sign with KX only (owns neither) -> no input signed, mask clear */
    {
        unsigned char signed_k[1024]; unsigned char mask[8]={0,0,0,0,0,0,0,0};
        unsigned char kx[1][32]; memcpy(kx[0],KX,32);
        unsigned char prev_wrong[2][25]; wallet_make_p2pkh_script(prev_wrong[0],K0); wallet_make_p2pkh_script(prev_wrong[1],K1);
        long sl=wallet_signrawtx_withkeys(signed_k,sizeof signed_k,raw,(unsigned long)rawlen,
                                          kx,1,prev_wrong,2,mask);
        ck("wrong key: tx returned", sl>0,1);
        ck("  input0 NOT signed", mask[0]==0,1);
        ck("  input1 NOT signed", mask[1]==0,1);
        /* the result should be byte-identical to the unsigned raw */
        ck("  unsigned unchanged", sl==rawlen && memcmp(signed_k,raw,(size_t)rawlen)==0,1);
        unsigned char ux[40+512*48+8], ublob[1<<16], work[8192];
        utxo_init(ux,512,ublob,sizeof ublob);
        utxo_put(ux,tA,0,tval[0],0,0,prevB[0],25);
        utxo_put(ux,tB,1,tval[1],0,0,prevB[1],25);
        ck("wrong-key tx REJECTED (sig fail)", validate_signed_tx(signed_k,(unsigned long)sl,ux,work,sizeof work)==0,1);
    }

    /* PARTIAL: sign only input 0 (only K0 provided) -> input0 signed, input1 blank */
    {
        unsigned char signed_k[1024]; unsigned char mask[8]={0,0,0,0,0,0,0,0};
        unsigned char k0[1][32]; memcpy(k0[0],K0,32);
        long sl=wallet_signrawtx_withkeys(signed_k,sizeof signed_k,raw,(unsigned long)rawlen,
                                          k0,1,prevB,2,mask);
        ck("sign input0 only ok", sl>0,1);
        ck("  input0 signed", mask[0],1);
        ck("  input1 blank", mask[1],0);
        /* still invalid because input1 unsigned */
        unsigned char ux[40+512*48+8], ublob[1<<16], work[8192];
        utxo_init(ux,512,ublob,sizeof ublob);
        utxo_put(ux,tA,0,tval[0],0,0,prevB[0],25);
        utxo_put(ux,tB,1,tval[1],0,0,prevB[1],25);
        ck("partial (in0 only) REJECTED (in1 unsigned)", validate_signed_tx(signed_k,(unsigned long)sl,ux,work,sizeof work)==0,1);
    }

    free(tid);
    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
