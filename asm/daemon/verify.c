/* daemon/verify.c -- verify an assembled node store (multi-file blk*.dat +
 * index.dat) is a cryptographically VALID, internally-consistent mainnet chain,
 * using the assembly hashing/consensus primitives. After hundreds of GB arrive
 * from untrusted peers, confirm the store is a contiguous valid chain before
 * trusting/re-serving it.
 *
 * Multi-file aware: reads each index record's [hash][file_no][pos][size] and
 * opens blk%05u.dat per record, so it validates the whole unified archive,
 * not just blk00000.dat.
 *
 * Checks (all via asm block_hash / sha256d / pow_check / cons_verify):
 *   1. per block: block_hash(stored_block) == index-record hash
 *   2. chain continuity: block[h+1].prevhash == block[h].hash
 *   3. PoW holds for every header (pow_check)
 *   4. cons_verify accepts every block (PoW + tx walk + merkle)
 *
 * Usage: verify <dir> [start_h] [end_h]
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>

extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  pow_check(const unsigned char hdr[80]);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);

/* simple per-file open cache */
static FILE* open_blk(const char* dir, int fno){
    char nm[80]; snprintf(nm,sizeof nm,"blk%05u.dat",(unsigned)fno);
    char p[640]; snprintf(p,sizeof p,"%s/%s",dir,nm);
    return fopen(p,"rb");
}

int main(int argc,char**argv){
    if(argc<2){ fprintf(stderr,"usage: %s <dir> [start] [end]\n", argv[0]); return 2; }
    const char* dir=argv[1];
    long start_h= argc>2? atol(argv[2]) : 0;
    long end_h  = argc>3? atol(argv[3]) : -1;   /* -1 => to tip */
    /* total blocks = index.dat size / 48 */
    char idxp[640]; snprintf(idxp,sizeof idxp,"%s/index.dat",dir);
    FILE* ix0=fopen(idxp,"rb"); if(!ix0){ perror("open index.dat"); return 1; }
    fseek(ix0,0,SEEK_END); long tot=ftell(ix0)/48; fclose(ix0);
    if(end_h<0 || end_h>tot-1) end_h=tot-1;
    printf("== verifying heights [%ld,%ld] of %ld in %s ==\n", start_h, end_h, tot, dir);

    static unsigned char prev_hash[32];
    int have_prev=0;
    long okay_hash=0, okay_chain=0, okay_pow=0, okay_cons=0, bad=0;
    long first_bad=-1;
    static unsigned char scratch[64<<20];          /* big blocks */
    static unsigned char blkbuf[16<<20];
    int cur_fno=-1; FILE* blk=NULL;

    /* read first record to seed continuity start */
    unsigned char rec[48];
    for(long h=start_h; h<=end_h; h++){
        FILE* ix=fopen(idxp,"rb");
        if(!ix){ bad++; break; }
        if(fseek(ix,(long)h*48,SEEK_SET)!=0 || fread(rec,1,48,ix)!=48){ fclose(ix); bad++; break; }
        fclose(ix);
        unsigned len; memcpy(&len,rec+44,4);
        unsigned long long off; memcpy(&off,rec+36,8);
        int fno; memcpy(&fno,rec+32,4);
        if(len==0 || len> (unsigned)sizeof blkbuf){ if(first_bad<0)first_bad=h; fprintf(stderr,"  bad size h=%ld len=%u\n",h,len); bad++; continue; }
        if(fno!=cur_fno){ if(blk)fclose(blk); blk=open_blk(dir,fno); cur_fno=fno; }
        if(!blk){ if(first_bad<0)first_bad=h; fprintf(stderr,"  no blk file %u at h=%ld\n",fno,h); bad++; continue; }
        if(fseek(blk,(long)(off+8),SEEK_SET)!=0 || (long)fread(blkbuf,1,len,blk)!=(long)len){ if(first_bad<0)first_bad=h; fprintf(stderr,"  read fail h=%ld fno=%u off=%llu\n",h,fno,off); bad++; continue; }

        unsigned char hh[32]; block_hash(hh,blkbuf);
        if(memcmp(rec,hh,32)==0) okay_hash++; else { if(first_bad<0)first_bad=h; fprintf(stderr,"  HASH mismatch h=%ld\n",h); }
        if(have_prev){ if(memcmp(blkbuf+4,prev_hash,32)==0) okay_chain++; else { if(first_bad<0)first_bad=h; fprintf(stderr,"  CHAIN BREAK h=%ld\n",h); } }
        memcpy(prev_hash,hh,32); have_prev=1;

        if(pow_check(blkbuf)==1) okay_pow++; else { if(first_bad<0)first_bad=h; fprintf(stderr,"  POW fail h=%ld\n",h); }
        if(cons_verify(blkbuf,len,scratch,(unsigned)(sizeof scratch/32))==1) okay_cons++; else { if(first_bad<0)first_bad=h; fprintf(stderr,"  CONS fail h=%ld\n",h); }
        if((h-start_h)%50000==0){ fprintf(stderr,"  ... through height %ld\n", h); }
    }
    if(blk)fclose(blk);
    long n=end_h-start_h+1;
    printf("== verify summary (heights %ld..%ld) ==\n", start_h, end_h);
    printf("  hash-match OK : %ld/%ld\n", okay_hash, n);
    printf("  chain-link OK : %ld/%ld\n", okay_chain, n>0?n-1:0);
    printf("  pow-ok     OK : %ld/%ld\n", okay_pow, n);
    printf("  cons-verifyOK : %ld/%ld\n", okay_cons, n);
    printf("  first problem : %ld\n", first_bad);
    int pass = (okay_hash==n && okay_chain==(n>0?n-1:0) && okay_pow==n && okay_cons==n);
    printf("== %s ==\n", pass?"CHAIN VERIFIED (contiguous, valid mainnet blocks)":"CHAIN HAS ERRORS");
    return pass?0:1;
}
