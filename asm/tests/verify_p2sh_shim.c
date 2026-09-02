/* verify_p2sh_shim.c -- stdin drive for the ASM P2SH VerifyScript (bitcoin_verify.c),
 * mirroring validation/core_verify_oracle.cpp's line protocol so the SAME
 * differential harness feeds identical (scriptSig, scriptPubKey, tx, idx, flags)
 * triples to both and compares verdict + error code.
 *
 *   VERIFY <flags_hex> <inputidx> <tx_hex> <scriptSig_hex> <scriptPubKey_hex>
 *   TAPVERIFY <inputidx> <tx_hex_WITH_witness> <n_prev> <amount_i> <spk_i_hex> ...
 *   WITVERIFY <flags_hex> <inputidx> <tx_hex_WITH_witness> <amount> <spk_hex> [<scriptSig_hex>]
 *   QUIT
 * prints: OK <0|1> <error_code>
 *
 * TAPVERIFY added 2026-08-25 so witness/taproot spends become differentially
 * checkable against Core (validation/spend_corpus_diff.py). Before it, the
 * shim answered only VERIFY, and the corpus had to SKIP every witness spend --
 * a silent hole in exactly the era the chain now lives in. It parses the
 * segwit tx into per-input witness stacks and packs the prevout arrays
 * (outpoints/amounts/spks) BIP341's aggregate sighash needs, then calls the
 * same taproot_verify_input the node uses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PRODUCTION verifier (bitcoin_scriptverify.c's sv_verify_script) -- the one
 * daemon/tx_verify.c actually drives. This shim used bitcoin_verify.c's
 * verify_script until 2026-08-25; that file is the SUPERSEDED standalone P2SH
 * implementation ("bitcoin_scriptverify.c is replacing bitcoin_verify.c's
 * role" -- tests/test_scriptverify_parity.c), and it rejects large legacy
 * transactions the production path accepts. A differential harness must drive
 * the code the node runs, or it measures a program nobody executes. */
extern int sv_verify_script(const unsigned char* scriptSig, unsigned long ssl,
                            const unsigned char* scriptPubKey, unsigned long spl,
                            unsigned long long flags, unsigned long nIn,
                            const unsigned char* tx, unsigned long txlen,
                            unsigned char* work, unsigned long workcap);
extern long strip_witness(const unsigned char* tx, long long txlen,
                          unsigned char* out, long cap);
/* WITVERIFY (2026-08-25): witness v0 (P2WPKH / P2WSH, native or P2SH-wrapped).
 * Core's VerifyWitnessProgram v0 arm; returns a SCRIPT_ERR_* code (0 = ok).
 * Unlike the taproot path this takes the tx AS-IS -- BIP143 builds its own
 * serialization internally (daemon/tx_verify.c passes the raw tx here and the
 * STRIPPED view only to the legacy path; getting that backwards is exactly
 * the bug that made every script-path spend look like a node divergence). */
extern int sv_verify_witness_v0(const unsigned char* prog, unsigned int proglen,
                                const unsigned char* const* wit, const unsigned int* witlen,
                                unsigned int nwit, unsigned long long amount,
                                unsigned long long flags, unsigned long nIn,
                                const unsigned char* tx, unsigned long txlen,
                                unsigned char* work, unsigned long workcap);
extern int taproot_verify_input(const unsigned char* spk,
                                const unsigned char* const* wit, const unsigned int* witlen,
                                unsigned int nwit, const unsigned char* tx, long long txlen,
                                long long n_in, const unsigned char* prevouts,
                                const unsigned char* amounts, const unsigned char* spks,
                                long long num_inputs, const char** reason);

/* --- minimal segwit tx walk: witness stack for input `want`, and the
 * outpoint list, so TAPVERIFY can assemble what BIP341 hashes. Returns 0 on
 * a parse failure (the corpus feeds real chain txs, so a failure here is a
 * shim bug, reported as a reject rather than a crash). --- */
static unsigned long rd_varint(const unsigned char* p, const unsigned char* e, unsigned long* c){
    if(p>=e){ *c=0; return 0; }
    if(p[0]<0xfd){ *c=1; return p[0]; }
    if(p[0]==0xfd){ if(p+3>e){*c=0;return 0;} *c=3; return p[1]|((unsigned long)p[2]<<8); }
    if(p[0]==0xfe){ if(p+5>e){*c=0;return 0;} *c=5;
        return p[1]|((unsigned long)p[2]<<8)|((unsigned long)p[3]<<16)|((unsigned long)p[4]<<24); }
    if(p+9>e){*c=0;return 0;} *c=9;
    unsigned long v=0; for(int i=0;i<8;i++) v|=(unsigned long)p[1+i]<<(8*i); return v;
}
#define TAPW_MAX 64
static int tx_witness_of(const unsigned char* tx, long txlen, unsigned long want,
                         const unsigned char** wit, unsigned int* witlen, unsigned int* nwit,
                         unsigned char* outpoints, unsigned long* n_in_out){
    const unsigned char* e = tx + txlen;
    const unsigned char* q = tx + 4;
    if (txlen < 10 || q[0]!=0x00 || q[1]!=0x01) return 0;     /* segwit marker */
    q += 2;
    unsigned long c, nin = rd_varint(q,e,&c); if(!c) return 0; q += c;
    if (nin == 0 || nin > 10000) return 0;
    *n_in_out = nin;
    for (unsigned long i=0;i<nin;i++){
        if (q+36 > e) return 0;
        if (outpoints) memcpy(outpoints + i*36, q, 36);
        q += 36;
        unsigned long sl = rd_varint(q,e,&c); if(!c) return 0; q += c + sl + 4;
        if (q > e) return 0;
    }
    unsigned long nout = rd_varint(q,e,&c); if(!c) return 0; q += c;
    for (unsigned long i=0;i<nout;i++){
        if (q+8 > e) return 0;
        q += 8;
        unsigned long sl = rd_varint(q,e,&c); if(!c) return 0; q += c + sl;
        if (q > e) return 0;
    }
    /* witness section: one stack per input, in order */
    *nwit = 0;
    for (unsigned long i=0;i<nin;i++){
        unsigned long items = rd_varint(q,e,&c); if(!c) return 0; q += c;
        for (unsigned long k=0;k<items;k++){
            unsigned long il = rd_varint(q,e,&c); if(!c) return 0; q += c;
            if (q + il > e) return 0;
            if (i == want && k < TAPW_MAX){ wit[k] = q; witlen[k] = (unsigned int)il; }
            q += il;
        }
        if (i == want) *nwit = (unsigned int)(items > TAPW_MAX ? TAPW_MAX : items);
    }
    return 1;
}

static long hex2b(const char* h, unsigned char* o, long max){
    long n=0; if(!h) return 0;
    for(const char*p=h;p[0]&&p[1];p+=2){ unsigned v; if(sscanf(p,"%2x",&v)!=1) break; o[n++]=(unsigned char)v; if(n>=max) break; }
    return n;
}

int main(void){
    /* heap buffers so the big scratch areas do not sit against the 8MB stack */
    unsigned char* txs = (unsigned char*)malloc(1<<20);
    unsigned char* ss  = (unsigned char*)malloc(1<<16);
    unsigned char* spk = (unsigned char*)malloc(1<<16);
    unsigned char* work= (unsigned char*)malloc(8<<20);   /* legacy_sighash serializes the WHOLE tx here: a 62KB tx with 400+ inputs needs far more than 1MB once each input is re-serialized (2026-08-25) */
    char* line = (char*)malloc(1<<21);
    if (!txs||!ss||!spk||!work||!line){ fprintf(stderr,"OOM\n"); return 1; }
    char cmd[16];
    while(fgets(line,1<<21,stdin)){
        char* save=NULL; char* tok=strtok_r(line," \t\n",&save);
        if(!tok) continue;
        snprintf(cmd,sizeof cmd,"%s",tok);
        if(!strcmp(cmd,"QUIT")) break;
        if(!strcmp(cmd,"WITVERIFY")){
            char* fl_h  =strtok_r(NULL," \t\n",&save);
            char* idx_h =strtok_r(NULL," \t\n",&save);
            char* tx_h  =strtok_r(NULL," \t\n",&save);
            char* amt_h =strtok_r(NULL," \t\n",&save);
            char* spk_h =strtok_r(NULL," \t\n",&save);
            char* ss_h  =strtok_r(NULL," \t\n",&save);   /* optional: P2SH-wrapped */
            if(!spk_h){ printf("OK 0 1\n"); fflush(stdout); continue; }
            unsigned long long flags=strtoull(fl_h,0,16);
            unsigned long idx=strtoul(idx_h,0,10);
            unsigned long long amount=strtoull(amt_h,0,10);
            long tn=hex2b(tx_h, txs, 1<<20);
            long pn=hex2b(spk_h, spk, 1<<16);
            /* The witness PROGRAM: for a native v0 spk it is the spk's payload
             * (OP_0 <push>); for a P2SH-wrapped spend the redeemScript in the
             * scriptSig IS the program, and the spk is the P2SH wrapper --
             * Core unwraps the same way before entering the v0 arm. */
            const unsigned char* prog=NULL; unsigned int proglen=0;
            if (pn>=4 && spk[0]==0x00 && (spk[1]==0x14 || spk[1]==0x20) && pn==2+spk[1]){
                prog=spk+2; proglen=spk[1];
            } else if (ss_h && strcmp(ss_h,"-")!=0){
                long sn=hex2b(ss_h, ss, 1<<16);
                /* scriptSig is a single push of the redeemScript */
                if (sn>=3 && ss[0]==sn-1 && ss[1]==0x00 && (ss[2]==0x14||ss[2]==0x20) && sn==3+ss[2]){
                    prog=ss+3; proglen=ss[2];
                }
            }
            if(!prog){ printf("OK 0 1\n"); fflush(stdout); continue; }
            /* witness stack for this input, out of the raw tx */
            const unsigned char* wit[TAPW_MAX]; unsigned int witlen[TAPW_MAX], nwit=0;
            unsigned long nin=0;
            if(!tx_witness_of(txs, tn, idx, wit, witlen, &nwit, NULL, &nin)){
                printf("OK 0 1\n"); fflush(stdout); continue; }
            int err = sv_verify_witness_v0(prog, proglen, wit, witlen, nwit, amount,
                                           flags, idx, txs, (unsigned long)tn,
                                           work, 1<<20);
            printf("OK %d %d\n", err==0?1:0, err);
            fflush(stdout);
        }
        else if(!strcmp(cmd,"TAPVERIFY")){
            char* idx_h =strtok_r(NULL," \t\n",&save);
            char* tx_h  =strtok_r(NULL," \t\n",&save);
            char* np_h  =strtok_r(NULL," \t\n",&save);
            if(!np_h){ printf("OK 0 1\n"); fflush(stdout); continue; }
            unsigned long idx=strtoul(idx_h,0,10);
            unsigned long nprev=strtoul(np_h,0,10);
            long tn=hex2b(tx_h, txs, 1<<20);
            static unsigned char amounts[10000*8], spks_packed[1<<20], outpoints[10000*36];
            unsigned long spos=0; int bad=0;
            unsigned long tap_spk_off=0, tap_spk_len=0;
            for(unsigned long i=0;i<nprev && !bad;i++){
                char* amt_h=strtok_r(NULL," \t\n",&save);
                char* spk_h2=strtok_r(NULL," \t\n",&save);
                if(!spk_h2){ bad=1; break; }
                unsigned long long amt=strtoull(amt_h,0,10);
                for(int b=0;b<8;b++) amounts[i*8+b]=(unsigned char)(amt>>(8*b));
                long pl=hex2b(spk_h2, spks_packed+spos+1, (1<<20)-spos-2);
                spks_packed[spos]=(unsigned char)pl;          /* varint-style length prefix */
                if(i==idx){ tap_spk_off=spos+1; tap_spk_len=(unsigned long)pl; }
                spos += 1 + (unsigned long)pl;
            }
            if(bad || idx>=nprev){ printf("OK 0 1\n"); fflush(stdout); continue; }
            const unsigned char* wit[TAPW_MAX]; unsigned int witlen[TAPW_MAX], nwit=0;
            unsigned long nin=0;
            if(!tx_witness_of(txs, tn, idx, wit, witlen, &nwit, outpoints, &nin)){
                printf("OK 0 1\n"); fflush(stdout); continue; }
            /* taproot_verify_input expects the WITNESS-STRIPPED serialization
             * (daemon/tx_verify.c strips before calling: BIP341's SigMsg
             * commits to the tx WITHOUT witness data, and tx_parse reads the
             * input count straight after the version -- a raw segwit tx makes
             * it read the 0x00 marker as nin=0 and fail). Passing the raw tx
             * here made every real script-path spend "fail", which this
             * harness first reported as a node divergence. */
            static unsigned char stripped[1<<20];
            long sn2 = strip_witness(txs, (long long)tn, stripped, (long)tn);
            if (sn2 <= 0){ printf("OK 0 1\n"); fflush(stdout); continue; }
            const char* reason="?";
            int ok = taproot_verify_input(spks_packed+tap_spk_off, wit, witlen, nwit,
                                          stripped, (long long)sn2, (long long)idx,
                                          outpoints, amounts, spks_packed,
                                          (long long)nprev, &reason);
            (void)tap_spk_len;
            printf("OK %d %d\n", ok==1?1:0, ok==1?0:1);
            fflush(stdout);
        }
        else if(!strcmp(cmd,"VERIFY")){
            char* fl_h =strtok_r(NULL," \t\n",&save);
            char* idx_h=strtok_r(NULL," \t\n",&save);
            char* tx_h =strtok_r(NULL," \t\n",&save);
            char* ss_h =strtok_r(NULL," \t\n",&save);
            char* spk_h=strtok_r(NULL," \t\n",&save);
            if(!spk_h){ printf("OK 0 1\n"); fflush(stdout); continue; }
            if (strcmp(ss_h,"-")==0) ss_h="";
            if (strcmp(spk_h,"-")==0) spk_h="";
            unsigned long long flags=strtoull(fl_h,0,16);
            unsigned long idx=strtoul(idx_h,0,10);
            long tn=hex2b(tx_h, txs, 1<<20);
            long sn=hex2b(ss_h, ss, 1<<16);
            long pn=hex2b(spk_h, spk, 1<<16);
            /* LEGACY inputs take the WITNESS-STRIPPED serialization -- Core's
             * legacy SignatureHash serializes the tx without witness data,
             * and daemon/tx_verify.c does exactly this (legacy_tx_view)
             * before calling. A legacy input inside a SEGWIT transaction
             * (7 of 234 inputs carried witnesses in the tx that exposed
             * this) otherwise hashes the wrong bytes and returns EVAL_FALSE
             * on a spend the chain contains. Non-segwit txs are passed
             * through unchanged. */
            const unsigned char* vtx = txs; unsigned long vtn = (unsigned long)tn;
            static unsigned char lstrip[1<<20];
            if (tn > 6 && txs[4]==0x00 && txs[5]==0x01){
                long ln = strip_witness(txs, (long long)tn, lstrip, (long)tn);
                if (ln > 0){ vtx = lstrip; vtn = (unsigned long)ln; }
            }
            int code=sv_verify_script(ss,(unsigned long)sn,spk,(unsigned long)pn,flags,idx,
                                      vtx,vtn,work,8<<20);
            printf("OK %d %d\n", code==0?1:0, code);
            fflush(stdout);
        }
    }
    free(txs); free(ss); free(spk); free(work); free(line);
    return 0;
}
