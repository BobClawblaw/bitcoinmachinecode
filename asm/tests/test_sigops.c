/* test_sigops.c -- sigop accounting (bitcoin_sigops.asm) vs Core semantics.
 *
 * Verifies script_sigops / tx_legacy_sigops against Core's GetSigOpCount /
 * GetLegacySigOpCount rules:
 *   - OP_CHECKSIG/VERIFY = 1 each
 *   - OP_CHECKMULTISIG/VERIFY = DecodeOP_N(previous OP_1..16) when accurate,
 *     20 when inaccurate
 *   - numeric push before a multisig op is remembered only for accurate mode
 *   - tx_legacy_sigops sums every input's scriptSig + every output's
 *     scriptPubKey (inaccurate), skipping the SegWit marker+flag.
 *
 * Builder helpers mirror Core serialization; expected counts are hardcoded
 * from the rules.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern unsigned long long script_sigops(const unsigned char*s, unsigned long long len);
extern unsigned long long script_sigops_accurate(const unsigned char*s, unsigned long long len);
extern unsigned long long tx_legacy_sigops(const unsigned char*tx, unsigned long long len);

static int fails=0;
static void ck(const char*l,unsigned long long g,unsigned long long e){
    if(g==e) printf("ok  : %-46s -> %llu\n",l,g);
    else { printf("FAIL: %-46s got %llu exp %llu\n",l,g,e); fails++; }
}

/* script builders */
static void push_p2pkh(unsigned char*out,int*o){
    out[(*o)++]=0x76; out[(*o)++]=0xa9; out[(*o)++]=0x14;   /* DUP HASH160 push20 */
    memset(out+*o,0,20); *o+=20; out[(*o)++]=0x88; out[(*o)++]=0xac;
}
static void push_mofn(unsigned char*out,int*o,int m,int n){
    out[(*o)++]=0x50+m;
    for(int i=0;i<n;i++){ out[(*o)++]=0x21; memset(out+*o,i+1,33); *o+=33; }
    out[(*o)++]=0x50+n; out[(*o)++]=0xae;                 /* OP_n OP_CHECKMULTISIG */
}
static void push_checksigs(unsigned char*out,int*o,int n){
    for(int i=0;i<n;i++) out[(*o)++]=0xac;
}

/* tx builder: returns txlen, fills out */
static int build_tx(unsigned char*out, int n_in_script_len, const unsigned char*in_script,
                    int n_out, const unsigned char*out_scripts[], int out_lens[],
                    int segwit){

    int o=0, slen;
    out[o++]=1;out[o++]=0;out[o++]=0;out[o++]=0;                 /* version */
    if(segwit){ out[o++]=0x00; out[o++]=0x01; }                 /* marker+flag */
    out[o++]=1;                                                 /* n_in */
    memset(out+o,0x11,32); o+=32;                               /* prevout txid */
    out[o++]=0;out[o++]=0;out[o++]=0;out[o++]=0;                /* index */
    out[o++]=n_in_script_len; memcpy(out+o,in_script,n_in_script_len); o+=n_in_script_len;
    out[o++]=0xff;out[o++]=0xff;out[o++]=0xff;out[o++]=0xff;    /* sequence */
    out[o++]=n_out;
    for(int i=0;i<n_out;i++){
        out[o++]=0;out[o++]=0;out[o++]=0;out[o++]=0;            /* value LE32 (8) */
        out[o++]=0;out[o++]=0;out[o++]=0;out[o++]=0;
        out[o++]=out_lens[i];
        memcpy(out+o,out_scripts[i],out_lens[i]); o+=out_lens[i];
    }
    out[o++]=0;out[o++]=0;out[o++]=0;out[o++]=0;                /* locktime */
    (void)slen;
    return o;
}

int main(void){
    unsigned char s[10000];

    /* --- script_sigops: bare opcodes --- */
    { int o=0; push_checksigs(s,&o,3); ck("3x OP_CHECKSIG (inaccurate)", script_sigops(s,o), 3);
      ck("3x OP_CHECKSIG (accurate)", script_sigops_accurate(s,o), 3); }

    /* --- P2PKH --- */
    { int o=0; push_p2pkh(s,&o); ck("P2PKH script", script_sigops(s,o), 1); }

    /* --- multisig: OP_2 <3pk> OP_3 CHECKMULTISIG --- */
    { int o=0; push_mofn(s,&o,2,3);
      ck("2-of-3 multisig (inaccurate=20)", script_sigops(s,o), 20);
      ck("2-of-3 multisig (accurate=3)", script_sigops_accurate(s,o), 3); }

    /* --- multisig: OP_5 <7pk> OP_7 CHECKMULTISIG --- */
    { int o=0; push_mofn(s,&o,5,7);
      ck("5-of-7 multisig (accurate=7)", script_sigops_accurate(s,o), 7);
      ck("5-of-7 multisig (inaccurate=20)", script_sigops(s,o), 20); }

    /* --- P2PKH + multisig combined --- */
    { int o=0; push_p2pkh(s,&o); push_mofn(s,&o,2,3);
      ck("P2PKH + 2-of-3 (accurate=4)", script_sigops_accurate(s,o), 4);
      ck("P2PKH + 2-of-3 (inaccurate=21)", script_sigops(s,o), 21); }

    /* --- tx_legacy_sigops --- */
    {
        /* tx: 1 in (empty scriptSig), 1 out P2PKH -> 1 */
        unsigned char tx[1000];
        const unsigned char* outs[1]; int lens[1];
        int oo=0; push_p2pkh(s,&oo); outs[0]=s; lens[0]=oo;
        int n=build_tx(tx,0,NULL,1,outs,lens,0);
        ck("legacy tx P2PKH out = 1", tx_legacy_sigops(tx,n), 1);
    }
    {
        /* tx: 1 out 2-of-3 multisig -> 20 (inaccurate) */
        unsigned char tx[1000];
        int oo=0; push_mofn(s,&oo,2,3); const unsigned char* os[1]; int ls[1]={oo}; os[0]=s;
        int n=build_tx(tx,0,NULL,1,os,ls,0);
        ck("legacy tx 2-of-3 out = 20", tx_legacy_sigops(tx,n), 20);
    }
    {
        /* scriptSig = single OP_1 (0 sigops, no sigop opcode), out P2PKH -> 1 */
        unsigned char tx[1000];
        unsigned char sig_data[1]={0x51};
        int oo=0; push_p2pkh(s,&oo); const unsigned char* os[1]; int ls[1]={oo}; os[0]=s;
        int n=build_tx(tx,1,sig_data,1,os,ls,0);
        ck("scriptSig OP_1 not counted, P2PKH out = 1", tx_legacy_sigops(tx,n), 1);
    }
    {
        /* SegWit marker+flag must be skipped: tx marked segwit, 1 P2PKH out -> 1 */
        unsigned char tx[1000];
        int oo=0; push_p2pkh(s,&oo); const unsigned char* os[1]; int ls[1]={oo}; os[0]=s;
        int n=build_tx(tx,0,NULL,1,os,ls,1);
        ck("segwit-flagged tx P2PKH out = 1", tx_legacy_sigops(tx,n), 1);
    }

    printf("\n%s (%d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", fails);
    return fails?1:0;
}
