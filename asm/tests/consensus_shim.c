/* consensus_shim.c - consensus differential harness shim for the asm node.
 *
 * stdin-driven (same pattern as run_batch.c) so a Python oracle can drive the
 * same REAL mainnet block/tx bytes through the ASM consensus stack and compare
 * the verdicts byte-for-byte against Bitcoin Core.
 *
 * Line protocol (one record per line, space separated):
 *   BLOCK  <hex>              -> cons_verify on the whole block
 *        prints:  OK <0|1> <blockhash_le32> <ntx> <nbytes>
 *   HEADER <hex80>            -> pow_check + block_hash on a header
 *        prints:  OK <0|1> <blockhash_le32>
 *   TXID   <hex_tx>           -> tx_parse + tx_txid (BIP141 unwitnessed)
 *        prints:  OK <0|1> <txid_le32> <ntxin> <ntxout>
 *   TARGET <hex4_bits>        -> diff_target(nBits)
 *        prints:  OK 1 <target_le32>
 *   QUIT
 *
 * cons_verify comes straight from asm bitcoin_cons.asm (PoW + merkle +
 * coinbase + bounds + txcount); block_hash/pow_check/diff_target and
 * tx_parse/tx_txid from the same asm objects.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int  cons_verify(const void* block, unsigned long len, void* txid_scratch, unsigned long cap);
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  pow_check(const unsigned char hdr[80]);
extern void diff_target(unsigned char out[32], unsigned bits);
extern int  tx_parse(unsigned long long info[8], const void* tx, unsigned long long txlen);
extern int  tx_txid(unsigned char out[32], const void* tx, unsigned long long txlen,
                    void* scratch, unsigned long long cap);
extern unsigned long long tx_legacy_sigops(const void* tx, unsigned long long txlen);

static long hex2b(const char* h, unsigned char* o, long max){
    long n=0; if(!h) return 0;
    for(const char*p=h;p[0]&&p[1];p+=2){
        unsigned v; if(sscanf(p,"%2x",&v)!=1) break; o[n++]=(unsigned char)v; if(n>=max) break;
    }
    return n;
}
static void put_hex(const unsigned char* b, long n){
    static const char* d="0123456789abcdef";
    for(long i=0;i<n;i++){ putchar(d[b[i]>>4]); putchar(d[b[i]&15]); }
}

int main(void){
    /* Mainnet MAX_BLOCK_SERIALIZED_SIZE = 4,000,000 bytes => hex up to 8,000,000
     * chars. The old 4<<20 line buffer truncated any real block > 2 MB (4MB hex
     * chars), silently decoding a truncated block -> cons_verify/DUPTX/SIGOPS
     * desynchronised on every >2MB mainnet block. Use 8MB line (static, so it
     * lives in BSS not on the 8MB default stack) + 8MB binary buffer. */
    static char line[8<<20];
    static unsigned char buf[8<<20];
    static unsigned char scratch[64<<20];
    static unsigned char tscratch[1<<20];
    char cmd[16];
    while(fgets(line,sizeof(line),stdin)){
        char* save=NULL; char* tok=strtok_r(line," \t\n",&save);
        if(!tok) continue;
        snprintf(cmd,sizeof cmd,"%s",tok);
        tok=strtok_r(NULL," \t\n",&save);
        if(!tok) continue;
        long n=hex2b(tok,buf,sizeof buf);
        if(!strcmp(cmd,"BLOCK")){
            long ok = cons_verify(buf,(unsigned long)n,scratch,(unsigned long)(sizeof scratch/32));
            unsigned char hh[32]; block_hash(hh,buf);
            unsigned long long ntx=0; unsigned char c=buf[80];
            if(c<0xfd) ntx=c;
            else if(c==0xfd) ntx=buf[81]|(buf[82]<<8);
            else if(c==0xfe) ntx=(unsigned)buf[81]|((unsigned)buf[82]<<8)|((unsigned)buf[83]<<16)|((unsigned)buf[84]<<24);
            else { ntx=0; for(int k=0;k<8;k++) ntx|=((unsigned long long)buf[81+k])<<(8*k); }
            printf("OK %ld ",ok); put_hex(hh,32); printf(" %llu %ld\n",ntx,n);
        } else if(!strcmp(cmd,"HEADER")){
            unsigned char hh[32]; block_hash(hh,buf);
            int ok=pow_check(buf);
            printf("OK %d ",ok); put_hex(hh,32); printf("\n");
        } else if(!strcmp(cmd,"TXID")){
            unsigned long long info[8]; memset(info,0,sizeof info);
            int pr=tx_parse(info,buf,(unsigned long long)n);
            unsigned char id[32];
            int tid = tx_txid(id,buf,(unsigned long long)n,tscratch,(unsigned long long)(sizeof tscratch));
            printf("OK %d ",(pr&&tid)?1:0);
            if(tid){ put_hex(id,32); }
            printf(" %llu %llu\n", (unsigned long long)info[0], (unsigned long long)info[1]);
        } else if(!strcmp(cmd,"TARGET")){
            unsigned bits; memcpy(&bits,buf,4);
            unsigned char t[32]; diff_target(t,bits);
            printf("OK 1 "); put_hex(t,32); printf("\n");
        } else if(!strcmp(cmd,"SIGOPS")){
            /* Walk every tx in the block, sum ASM tx_legacy_sigops (matches
             * Core's structurally-computable legacy sigop count). */
            unsigned long long idx=80, total=0;
            unsigned char c=buf[80];
            if(c<0xfd) idx=81;
            else if(c==0xfd) idx=83;
            else if(c==0xfe) idx=85;
            else idx=89;
            int ntx=0; int cap_ok=1;
            while(idx < (unsigned long)n){
                unsigned long long info[8];
                int pr=tx_parse(info,buf+idx,(unsigned long long)(n-idx));
                if(!pr){ cap_ok=0; break; }
                unsigned long long tlen=info[0];
                if(tlen==0 || tlen>(unsigned long long)(n-idx)){ cap_ok=0; break; }
                total += tx_legacy_sigops(buf+idx,tlen);
                idx += tlen; ntx++;
                if(ntx>20000){cap_ok=0;break;}
            }
            printf("OK %lld %d %d\n", total, ntx, cap_ok?1:0);
        } else if(!strcmp(cmd,"DUPTX")){
            /* In-block duplicate-txid detection using ASM tx_txid. Core's
             * CheckBlock rejects a block that contains two txs with the same
             * txid (BIP30 in-block rule). Print:  <dup> <ntx>. */
            static unsigned char dupbuf[20000*32]; /* txids so far */
            unsigned long long idx=80;
            unsigned char c=buf[80];
            if(c<0xfd) idx=81;
            else if(c==0xfd) idx=83;
            else if(c==0xfe) idx=85;
            else idx=89;
            int ntx=0; int dup=0;
            for(int i=0;i<20000 && idx<(unsigned long)n && !dup;i++,ntx++){
                unsigned long long info[8];
                int pr=tx_parse(info,buf+idx,(unsigned long long)(n-idx));
                if(!pr) break;
                unsigned long long tlen=info[0];
                if(tlen==0 || tlen>(unsigned long long)(n-idx)) break;
                unsigned char id[32];
                int tid=tx_txid(id,buf+idx,tlen,tscratch,(unsigned long long)(sizeof tscratch));
                if(tid){
                    for(int j=0;j<i;j++){
                        if(!memcmp(id, dupbuf+j*32, 32)){ dup=1; break; }
                    }
                    if(!dup) memcpy(dupbuf+i*32, id, 32);
                }
                idx += tlen;
            }
            printf("OK %d %d\n", dup, ntx);
        } else if(!strcmp(cmd,"QUIT")){
            break;
        }
        fflush(stdout);
    }
    return 0;
}
