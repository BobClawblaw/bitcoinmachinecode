/* bip30_shim.c -- chain-context BIP30 differential shim for the asm node.
 *
 * BIP30 (duplicate-txid rule) is a UTXO/chain-context consensus rule: a block
 * is rejected with "bad-txns-BIP30" if it tries to create an outpoint (txid,
 * vout) that already exists as an unspent coin in the chain's UTXO set,
 * UNLESS the block is one of the two historical mainnet duplicate-coinbase
 * blocks (91842 / 91880) that Core grandfathers via IsBIP30Repeat, or BIP34
 * activation has made new duplicates impossible.
 *
 * This shim maintains a persistent in-memory UTXO set (the verified asm
 * bitcoin_utxo.asm table) across CONNECT calls, so a Python oracle can replay a
 * real or constructed chain in order and compare the BIP30 verdict byte-for-
 * byte against real Bitcoin Core. It mirrors validation.cpp's ConnectBlock
 * BIP30 gate exactly:
 *
 *   fEnforceBIP30 = !IsBIP30Repeat(height, blockhash)
 *   if (fEnforceBIP30 || height >= 1983702):
 *       for tx in block, for out o:
 *           if view.HaveCoin(txid, o): reject "bad-txns-BIP30"
 *
 * Line protocol (one record per line, space separated):
 *   RESET                              -> clear the UTXO view (new chain)
 *   CONNECT <hexblock> <height>        -> BIP30 gate + apply block to view
 *        prints:  OK <enforce> <bip30> <ntx> <added>
 *          enforce : was BIP30 enforcement active for this block? (0/1)
 *          bip30   : 1 = BIP30 violation found (reject); 0 = pass
 *          ntx     : transactions parsed
 *          added   : outputs added to the view
 *   QUERY  <txidhex32> <n>             -> 1 found / 0 miss (debug)
 *   QUIT
 *
 * Block-hash (for IsBIP30Repeat) from the asm block_hash; txid from tx_txid.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* asm exports */
extern size_t utxo_struct_size(unsigned long slots);
extern void   utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long   utxo_put(void* u, const unsigned char txid[32], unsigned long index,
                       unsigned long long value, const unsigned char* script, unsigned long slen);
extern long   utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                       unsigned long long* value, const unsigned char** script, unsigned long* slen);
extern long   utxo_del(void* u, const unsigned char txid[32], unsigned long index);

extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  tx_parse(unsigned long long info[8], const void* tx, unsigned long long txlen);
extern int  tx_txid(unsigned char out[32], const void* tx, unsigned long long txlen,
                    void* scratch, unsigned long long cap);

/* ---- Core chainparams + BIP30 constants (kernel/chainparams.cpp, validation.cpp) ---- */
#define BIP34_IMPLIES_BIP30_LIMIT 1983702

static const struct { int h; const char* hash; } BIP30_GRANDFATHER[] = {
    { 91842, "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec" },
    { 91880, "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721" },
};

/* ---- UTXO view (persistent across CONNECT) ---- */
#define UTXO_SLOTS   (1u<<20)
static unsigned char* g_utxo;
static unsigned char* g_blob;
static unsigned char g_scratch[1<<20];       /* tx_txid scratch */

static long hex2b(const char* h, unsigned char* o, long max){
    long n=0; if(!h) return 0;
    for(const char* p=h; p[0]&&p[1]; p+=2){
        unsigned v; if(sscanf(p,"%2x",&v)!=1) break; o[n++]=(unsigned char)v; if(n>=max) break;
    }
    return n;
}

/* display(BE) hex hash -> internal LE bytes (block_hash outputs LE) */
static int hex_be_to_le(const char* h, unsigned char out[32]){
    if(!h || strlen(h) != 64) return 0;
    char tmp[65];
    for(size_t i=0;i<32;i++){ tmp[i*2]=h[(31-i)*2]; tmp[i*2+1]=h[(31-i)*2+1]; }
    tmp[64]=0; hex2b(tmp, out, 64); return 1;
}

static int is_bip30_repeat(int height, const unsigned char hash_le[32]){
    for(size_t i=0;i<sizeof(BIP30_GRANDFATHER)/sizeof(BIP30_GRANDFATHER[0]); i++){
        if(BIP30_GRANDFATHER[i].h != height) continue;
        unsigned char hb[32]; hex_be_to_le(BIP30_GRANDFATHER[i].hash, hb);
        if(memcmp(hash_le, hb, 32)==0) return 1;
    }
    return 0;
}

static void reset_view(void){
    utxo_init(g_utxo, UTXO_SLOTS, g_blob, 1u<<25);
}

/* Read CompactSize; returns bytes consumed or -1 on bounds error. */
static long rd_cs(const unsigned char* p, const unsigned char* end, unsigned long long* v){
    if (p >= end) return -1;
    unsigned char f = *p++;
    if (f < 0xfd) { *v=f; return 1; }
    if (f == 0xfd){ if (p+2>end) return -1; *v=(unsigned)p[0]|((unsigned)p[1]<<8); return 3; }
    if (f == 0xfe){ if (p+4>end) return -1; *v=0; for(int i=0;i<4;i++) *v|=(unsigned long long)p[i]<<(8*i); return 5; }
    if (p+8>end) return -1; *v=0; for(int i=0;i<8;i++) *v|=(unsigned long long)p[i]<<(8*i); return 9;
    return -1;
}

/* Apply one connecting block: run the BIP30 gate then mutate the view. */
static void do_connect(const unsigned char* blk, unsigned long n, int height){
    if (n < 81){ printf("OK 0 0 0 0\n"); return; }

    unsigned char hh[32]; block_hash(hh, blk);

    const unsigned char* p = blk + 80;
    const unsigned char* end = blk + n;
    unsigned long long ntxx=0;
    long c = rd_cs(p, end, &ntxx); if(c<0 || ntxx>200000){ printf("OK 0 0 0 0\n"); return; }
    p += c;
    long ntx = (long)ntxx;

    /* ---- BIP30 enforcement switch (pre-BIP34 chain: enforcement on unless
       the block is one of the two grandfathered mainnet duplicate blocks) ---- */
    int enforce = 1;
    if (is_bip30_repeat(height, hh)) enforce = 0;

    /* ---- BIP30 gate ---- */
    int bip30 = 0;
    if (enforce || height >= BIP34_IMPLIES_BIP30_LIMIT){
        const unsigned char* t = p;
        for (long i=0;i<ntx && t<end;i++){
            unsigned long long info[8];
            if (!tx_parse(info, t, (unsigned long long)(end-t))) break;
            unsigned long long tlen = info[0];
            unsigned char txid[32];
            if (tx_txid(txid, t, tlen, g_scratch, 1u<<20)){
                const unsigned char* q = t;
                /* skip to outputs: version(4) + varint nin + inputs */
                q += 4; unsigned long long nin=0;
                long cc = rd_cs(q, end, &nin); if(cc<0) break; q += cc;
                int ok=1;
                for (unsigned long long k=0;k<nin && ok;k++){
                    if (q+36 > end){ok=0;break;} q += 36;
                    unsigned long long sl=0; cc=rd_cs(q,end,&sl); if(cc<0){ok=0;break;} q+=cc;
                    if(q+sl+4 > end){ok=0;break;} q+=sl+4;
                }
                if(!ok) break;
                unsigned long long nout=0; cc=rd_cs(q,end,&nout); if(cc<0) break;
                for (unsigned long long k=0;k<nout;k++){
                    if (q+8 > end){ok=0;break;} q+=8;
                    unsigned long long sl=0; cc=rd_cs(q,end,&sl); if(cc<0){ok=0;break;} q+=cc;
                    /* BIP30: does (txid,k) already exist as an unspent coin? */
                    unsigned long long v; const unsigned char* sp; unsigned long slen;
                    if (utxo_get(g_utxo, txid, (unsigned long)k, &v, &sp, &slen)==1 && bip30==0){
                        bip30 = 1;
                    }
                    if(q+sl > end){ok=0;break;} q+=sl;
                }
            }
            t += tlen;
        }
    }

    /* ---- apply block to the view (spend inputs, then add outputs) ---- */
    long added = 0;
    {
        const unsigned char* t = p;
        for (long i=0;i<ntx && t<end;i++){
            unsigned long long info[8];
            if (!tx_parse(info, t, (unsigned long long)(end-t))) break;
            unsigned long long tlen = info[0];
            unsigned char txid[32];
            int got = tx_txid(txid, t, tlen, g_scratch, 1u<<20);
            const unsigned char* q = t; q += 4;
            unsigned long long nin=0;
            long cc=rd_cs(q,end,&nin); if(cc<0) break; q+=cc;
            /* walk all inputs; spend prevouts only for non-coinbase txs */
            for (unsigned long long k=0;k<nin;k++){
                if (q+36>end) break;
                const unsigned char* prev = q; q += 36;
                unsigned long long sl=0; cc=rd_cs(q,end,&sl); if(cc<0) break; q+=cc;
                if(q+sl+4>end) break; q+=sl+4;
                if (i>0){
                    unsigned long idx=(unsigned long)(prev[32]|(prev[33]<<8)|(prev[34]<<16)|((uint32_t)prev[35]<<24));
                    utxo_del(g_utxo, prev, idx);
                }
            }
            /* add outputs */
            unsigned long long nout=0; cc=rd_cs(q,end,&nout); if(cc<0) break;
            for (unsigned long long k=0;k<nout;k++){
                if (q+8>end) break;
                unsigned long long val=0; for(int b=0;b<8;b++) val|=(unsigned long long)q[b]<<(8*b); q+=8;
                unsigned long long sl=0; cc=rd_cs(q,end,&sl); if(cc<0) break; q+=cc;
                if(q+sl>end) break;
                if (got){ utxo_put(g_utxo, txid, (unsigned long)k, val, q, (unsigned long)sl); added++; }
                q+=sl;
            }
            t += tlen;
        }
    }

    printf("OK %d %d %ld %ld\n", enforce, bip30, ntx, added);
}

int main(void){
    unsigned long struct_sz = (unsigned long)utxo_struct_size(UTXO_SLOTS);
    g_utxo  = (unsigned char*)malloc(struct_sz + (1u<<25));
    if(!g_utxo) return 1;
    g_blob  = g_utxo + struct_sz;
    reset_view();

    static char line[4<<20];
    static unsigned char buf[8<<20];
    char cmd[16];
    while(fgets(line,sizeof(line),stdin)){
        char* save=NULL; char* tok=strtok_r(line," \t\n",&save);
        if(!tok) continue;
        snprintf(cmd,sizeof cmd,"%s",tok);
        if(!strcmp(cmd,"RESET")){ reset_view(); printf("OK\n"); }
        else if(!strcmp(cmd,"QUIT")){ break; }
        else {
            tok=strtok_r(NULL," \t\n",&save);
            if(!tok) continue;
            long n=hex2b(tok,buf,sizeof buf);
            if(!strcmp(cmd,"CONNECT")){
                char* htok=strtok_r(NULL," \t\n",&save);
                int height = htok ? atoi(htok) : 0;
                do_connect(buf,(unsigned long)n,height);
            } else if(!strcmp(cmd,"QUERY")){
                char* ntok=strtok_r(NULL," \t\n",&save);
                unsigned long idx = ntok ? (unsigned long)strtoul(ntok,NULL,10) : 0;
                unsigned long long v; const unsigned char* sp; unsigned long slen;
                long f=utxo_get(g_utxo, buf, idx, &v, &sp, &slen);
                printf("OK %ld\n", f);
            }
        }
        fflush(stdout);
    }
    return 0;
}
