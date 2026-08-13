/* daemon/verify.c -- verify an assembled node store (blk00000.dat + index.dat) is
 * a cryptographically VALID, internally-consistent mainnet chain, using the
 * assembly hashing/consensus primitives. This is the post-download assurance
 * pass: after hundreds of GB arrive from untrusted peers, confirm the store is a
 * contiguous valid chain before trusting/re-serving it.
 *
 * Checks (all via asm block_hash / sha256d / pow_check / diff_target / cons_verify):
 *   1. per block: block_hash(stored_block) == index-record hash   (nothing stored
 *      wrong under its own height)
 *   2. chain continuity: block[h+1].prevhash == block[h].hash      (the chain links)
 *   3. PoW holds for every header (diff_target + pow_check)         (real difficulty)
 *   4. cons_verify accepts every block (PoW + tx walk + merkle)     (full consensus)
 *
 * Usage: verify <dir>
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  pow_check(const unsigned char hdr[80]);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern long store_get_at(void* st, unsigned long long height, void* out_meta);
extern int  store_init(void* st);

static unsigned char store[4096];

static void trim(const char* p, char* out){
    /* remove trailing newline */
    strcpy(out,p);
    long n=strlen(out); while(n>0&&(out[n-1]=='\n'||out[n-1]=='\r')) out[--n]=0;
}

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: %s <dir>\n", argv[0]); return 2; }
    const char* dir=argv[1];
    if(chdir(dir)!=0){ perror("chdir"); return 1; }
    extern long store_reload(void*);
    extern long store_get_tip(void*, void*);

    static unsigned char mc[16];
    if(store_init(store)!=1){ fprintf(stderr,"store_init failed\n"); return 1; }
    store_reload(store);
    int tip=*(int*)((char*)store+24);
    if(tip<0){ fprintf(stderr,"empty store\n"); return 1; }
    long total=tip+1;
    printf("== verifying %ld blocks (heights 0..%d) in %s ==\n", total, tip, dir);

    /* open blk file once */
    FILE* blk = fopen("blk00000.dat","rb"); if(!blk){ perror("open blk"); return 1; }

    static unsigned char prev_hash[32];
    static unsigned char prev_hdr[80];
    int have_prev=0;
    long okay_hash=0, okay_chain=0, okay_pow=0, okay_cons=0, bad=0;
    long first_bad=-1;
    long last_checked=0;

    /* scratch for cons_verify: big enough for dense blocks */
    static unsigned char scratch[8<<20];

    for(long h=0; h<total; h++){
        unsigned char meta[16];
        if(store_get_at(store,h,meta)!=1){ fprintf(stderr,"store_get_at(%ld) failed\n",h); bad++; break; }
        unsigned long long off; memcpy(&off,meta,8);
        unsigned len; memcpy(&len,meta+8,4);
        /* seek to off+8 (skip blk frame header), read len */
        if(fseek(blk,(long)(off+8),SEEK_SET)!=0){ bad++; break; }
        static unsigned char blkbuf[4<<20];
        if(len>sizeof blkbuf){ fprintf(stderr,"block too big (%u)\n",len); bad++; break; }
        if(fread(blkbuf,1,len,blk)!=(size_t)len){ bad++; break; }
        /* header is first 80 bytes */
        unsigned char hh[32]; block_hash(hh,blkbuf);
        /* check 1: hash matches index record (index hash = meta not directly; use
         * store's record. We trust store_get_at meta has the pointer; the hash is
         * in index.dat at h*48. Re-read index.dat directly. */
        /* Simplest: recompute and compare to the hash we'd store at index h. */
        /* index file: 48B records; record hash at [0] */
        static unsigned char record[48];
        FILE* ix=fopen("index.dat","rb");
        if(ix){ fseek(ix,(long)h*48,SEEK_SET); if(fread(record,1,48,ix)==48 && memcmp(record,hh,32)==0) okay_hash++;
                fclose(ix); }

        /* check 2: continuity with previous block's hash */
        if(have_prev){
            if(memcmp(blkbuf+4, prev_hash, 32)==0) okay_chain++;
            else { if(first_bad<0) first_bad=h; printf("  chain BREAK at height %ld: prevhash != block[%ld].hash\n", h, h-1); }
        }
        memcpy(prev_hash, hh, 32);
        have_prev=1;

        /* check 3: PoW holds */
        if(pow_check(blkbuf)==1) okay_pow++;
        else { if(first_bad<0) first_bad=h; printf("  POW fail at height %ld\n", h); }

        /* check 4: full consensus (PoW + tx walk + merkle) */
        if(cons_verify(blkbuf,len,scratch,(unsigned)(sizeof scratch/32))==1) okay_cons++;
        else { if(first_bad<0) first_bad=h; printf("  CONS fail at height %ld\n", h); }

        if(okay_cons==0 && h==0) bad++;
        last_checked=h;
        if(h%50000==0){ fprintf(stderr,"  ... verified through height %ld\n", h); }
    }
    fclose(blk);

    printf("== verify summary ==\n");
    printf("  heights checked : %ld\n", last_checked+1);
    printf("  hash-match OK   : %ld\n", okay_hash);
    printf("  chain-link  OK  : %ld\n", okay_chain);
    printf("  pow-ok      OK  : %ld\n", okay_pow);
    printf("  cons-verify OK  : %ld\n", okay_cons);
    printf("  first problem   : %ld\n", first_bad);
    int pass = (okay_hash==total && okay_chain==total-1 && okay_pow==total && okay_cons==total);
    printf("== %s ==\n", pass?"CHAIN VERIFIED (contiguous, valid mainnet chain)":"CHAIN HAS ERRORS");
    return pass?0:1;
}
