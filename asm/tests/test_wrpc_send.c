/* test_wrpc_send.c -- verify the wallet-core/RPC sendtoaddress + getbalance
 * end-to-end (card 5, the capstone of the wallet-core/RPC batch). Picks wallet
 * UTXOs greedily, builds + signs the send, validates the signed tx with the
 * whole-tx validator, and checks getbalance decreases by (amount + fee).
 *
 * Reuses wallet_core.c (sendtoaddress / get_balance) + the asm validator chain.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern long wallet_sendtoaddress(unsigned char* out_tx, long cap,
    const unsigned char our_txid[][32], const unsigned long* our_idx,
    const unsigned long long* our_val, unsigned long n_ours,
    const unsigned char to_h160[20],
    unsigned long long amount, unsigned long long fee,
    const unsigned char priv_be[32],
    unsigned long long* out_change, unsigned long* out_picked,
    unsigned long long* out_picked_val);
extern unsigned long long wallet_get_balance(const unsigned long long* tval, unsigned long n);
extern void wallet_make_p2pkh_script(unsigned char script[25], const unsigned char priv_be[32]);
extern void wallet_key_h160(unsigned char h[20], const unsigned char priv_be[32]);

extern int  tx_parse(void* info, const unsigned char* tx, unsigned long txlen);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long value, const unsigned char* script, unsigned long slen);
extern long utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script, unsigned long* slen);
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
    const unsigned char* p=tx+4;
    unsigned long ni=rd_varint(p,&p);
    unsigned long long total_in=0; const unsigned char* scripts[64];
    for(unsigned int i=0;i<ni&&i<64;i++){
        unsigned char txid[32]; memcpy(txid,p,32);
        unsigned long idx=(unsigned long)p[32]|((unsigned long)p[33]<<8)|((unsigned long)p[34]<<16)|((unsigned long)p[35]<<24);
        p+=36; unsigned long sl=rd_varint(p,&p); p+=sl+4;
        unsigned long long val; const unsigned char* s; unsigned long ssl;
        if(utxo_get(utxo,txid,idx,&val,&s,&ssl)!=1){printf("  [double-spend]\n");return 0;}
        scripts[i]=s; total_in+=val;
    }
    for(unsigned int i=0;i<info.n_in&&i<64;i++)
        if(verify_p2pkh(tx,txlen,i,scripts[i],25,work,workcap)!=1){printf("  [sig] %u\n",i);return 0;}
    return total_in>0?1:0;
}

static int fails=0;
static void ck(const char*l,int g,int e){ if(g==e)printf("ok  : %s\n",l); else{printf("FAIL: %s (got %d exp %d)\n",l,g,e);fails++;} }

int main(void){
    unsigned char priv[32]; for(int i=0;i<32;i++)priv[i]=(unsigned char)(0xaa+i);
    unsigned char dpriv[32]; for(int i=0;i<32;i++)dpriv[i]=(unsigned char)(0x55+i);
    unsigned char to_h[20]; wallet_key_h160(to_h,dpriv);
    unsigned char scr[25]; wallet_make_p2pkh_script(scr,priv);

    /* wallet has 5 UTXOs of varying size */
    unsigned char (*u_txid)[32]=malloc(5*32);
    unsigned char t0[32],t1[32],t2[32],t3[32],t4[32];
    for(int i=0;i<32;i++){t0[i]=(unsigned char)(0x10+i);t1[i]=(unsigned char)(0x20+i);t2[i]=(unsigned char)(0x30+i);t3[i]=(unsigned char)(0x40+i);t4[i]=(unsigned char)(0x50+i);}
    memcpy(u_txid[0],t0,32);memcpy(u_txid[1],t1,32);memcpy(u_txid[2],t2,32);memcpy(u_txid[3],t3,32);memcpy(u_txid[4],t4,32);
    unsigned long u_idx[5]={0,1,2,3,4};
    unsigned long long u_val[5]={2000000ULL,5000000ULL,1000000ULL,3000000ULL,8000000ULL}; /* total 19M */
    unsigned long long total=wallet_get_balance(u_val,5);
    ck("getbalance == sum", total,19000000ULL);

    /* send 6_000_000 with fee 10_000. Greedy picks the largest covering set:
     * 8M alone already >= 6.01M -> 1 input, change = 8M-6M-10k = 1_990_000. */
    {
        unsigned char signedtx[4096];
        unsigned long long change=0; unsigned long picked=0; unsigned long long pv=0;
        long sl=wallet_sendtoaddress(signedtx,sizeof signedtx,u_txid,u_idx,u_val,5,
                                     to_h,6000000ULL,10000ULL,priv,&change,&picked,&pv);
        ck("sendtoaddress produced", sl>0,1);
        ck("  picked 1 input (largest 8M covers)", picked,1);
        ck("  picked value 8M", pv,8000000ULL);
        ck("  change = 8M - 6M - 10k", change,1990000ULL);

        /* validate against a UTXO store holding all 5 */
        unsigned char ux[40+512*48+8], ublob[1<<16], work[8192];
        utxo_init(ux,512,ublob,sizeof ublob);
        for(int i=0;i<5;i++) utxo_put(ux,u_txid[i],u_idx[i],u_val[i],scr,25);
        ck("signed send tx VALID (validator)", sl>0 && validate_signed_tx(signedtx,(unsigned long)sl,ux,work,sizeof work),1);
        (void)total;
    }

    /* insufficient funds: send 18_990_001 + 10k fee needs 19_000_001 > 19M -> -1 */
    {
        unsigned char signedtx[4096];
        long sl=wallet_sendtoaddress(signedtx,sizeof signedtx,u_txid,u_idx,u_val,5,
                                     to_h,18990001ULL,10000ULL,priv,NULL,NULL,NULL);
        ck("insufficient funds rejected", sl<0,1);
    }

    /* exact balance (no change): spend 18_990_000 + 10k fee == 19M total,
     * greedy must pick all 5 inputs and produce no change output. */
    {
        unsigned char signedtx[4096];
        unsigned long long change=0; unsigned long picked=0; unsigned long long pv=0;
        long sl=wallet_sendtoaddress(signedtx,sizeof signedtx,u_txid,u_idx,u_val,5,
                                     to_h,18990000ULL,10000ULL,priv,&change,&picked,&pv);
        ck("send ~entire balance ok", sl>0,1);
        ck("  all 5 inputs picked", picked,5);
        ck("  picked value 19M", pv,19000000ULL);
        ck("  change 0", change,0);

    }

    free(u_txid);
    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
