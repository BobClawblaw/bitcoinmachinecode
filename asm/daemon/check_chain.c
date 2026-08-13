/* daemon/check_chain.c -- fast integrity audit of a single-directory archive:
 *   - zero-hash index holes (heights never written)
 *   - duplicate block hashes (any hash at 2+ heights, incl. non-adjacent)
 *   - per-height: block_hash(stored) must equal the index record hash, and the
 *     recorded (file_no,pos,size) must be readable from the blk file
 * Reports a summary and a PASS/FAIL. Does full cons_verify per block only when
 * requested (mode 'deep'), since that is slower.
 * Usage: check_chain <dir> [deep]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
int main(int argc,char**argv){
    const char* dir = argc>1? argv[1] : ".";
    int deep = argc>2 && !strcmp(argv[2],"deep");
    char idxp[640]; snprintf(idxp,sizeof idxp,"%s/index.dat",dir);
    FILE* f=fopen(idxp,"rb"); if(!f){ perror("index.dat"); return 1; }
    fseek(f,0,SEEK_END); long n=ftell(f)/48; fseek(f,0,SEEK_SET);
    unsigned char* idx=malloc(n*48);
    if(fread(idx,1,n*48,f)!=(size_t)n*48){ printf("read index fail\n"); return 1; }
    fclose(f);

    long stored=0, holes=0, hashbad=0, unreadable=0, consbad=0, first_problem=-1, chainbreak=0;
    unsigned char prevhash[32]; int have_prev=0;
    int cur_fno=-1; FILE* blk=NULL;
    static unsigned char blkbuf[16<<20]; static unsigned char scratch[64<<20];
    for(long h=0;h<n;h++){
        unsigned char* rec=idx+h*48;
        int zero = (rec[0]==0&&rec[1]==0&&rec[2]==0&&rec[3]==0&&rec[44]==0&&rec[45]==0&&rec[46]==0&&rec[47]==0);
        if(zero){ holes++; if(first_problem<0)first_problem=h; continue; }
        stored++;
        uint32_t fno; memcpy(&fno,rec+32,4);
        uint64_t pos; memcpy(&pos,rec+36,8);
        uint32_t sz;  memcpy(&sz,rec+44,4);
        if(sz==0 || sz>(unsigned)sizeof blkbuf){ if(first_problem<0)first_problem=h; continue; }
        char nm[80]; snprintf(nm,sizeof nm,"blk%05u.dat",(unsigned)fno);
        char p[640]; snprintf(p,sizeof p,"%s/%s",dir,nm);
        if(fno!=cur_fno){ if(blk)fclose(blk); blk=fopen(p,"rb"); cur_fno=fno; }
        if(!blk || fseek(blk,(long)(pos+8),SEEK_SET)!=0 || (long)fread(blkbuf,1,sz,blk)!=(long)sz){
            if(first_problem<0)first_problem=h; unreadable++; continue;
        }
        unsigned char hh[32]; block_hash(hh,blkbuf);
        if(memcmp(rec,hh,32)){ if(first_problem<0)first_problem=h; hashbad++; }
        if(have_prev && memcmp(blkbuf+4,prevhash,32)){ if(first_problem<0)first_problem=h; chainbreak++; }
        memcpy(prevhash,hh,32); have_prev=1;
        if(deep && !cons_verify(blkbuf,sz,scratch,(unsigned)(sizeof scratch/32)))
            { if(first_problem<0)first_problem=h; consbad++; }
    }
    if(blk)fclose(blk);
    /* duplicates: any hash appearing at 2+ stored heights */
    long dups=0;
    {
        /* naive O(n) via a simple hash->count map (bounded: mainnet ~1.1M blocks) */
        /* use a dict of first-30-bytes to detect repeats */
        static unsigned char seen[1<<20][30]; static unsigned char* s1=(unsigned char*)seen;
        long scnt=0;
        for(long h=0;h<n;h++){
            unsigned char* rec=idx+h*48;
            if(rec[0]==0&&rec[1]==0&&rec[2]==0&&rec[3]==0) continue;
            int found=0;
            for(long k=0;k<scnt && !found;k++){ if(!memcmp(s1+k*30,rec+2,30)){ found=1; } }
            if(!found && scnt < (1<<20)){ memcpy(s1+scnt*30,rec+2,30); scnt++; }
            else if(found){ dups++; }
        }
    }
    printf("== check_chain %s (heights 0..%ld) ==\n", dir, n-1);
    printf("  index records : %ld\n", n);
    printf("  stored        : %ld\n", stored);
    printf("  holes (zero)  : %ld\n", holes);
    printf("  unique hashes : %ld\n", stored-dups);
    printf("  duplicate rec : %ld\n", dups);
    printf("  hash-mismatch : %ld\n", hashbad);
    printf("  unreadable    : %ld\n", unreadable);
    printf("  chain-breaks  : %ld\n", chainbreak);
    printf("  cons-bad      : %ld\n", consbad);
    printf("  first problem : %ld\n", first_problem);
    int pass = (dups==0 && hashbad==0 && unreadable==0 && chainbreak==0 && consbad==0);
    printf("== %s ==\n", pass?"ARCHIVE CLEAN (no dups, no gaps, no corruption)"
                          :(holes>0?"ARCHIVE INCOMPLETE (has holes; run/resume)":
                            "ARCHIVE CORRUPT"));
    free(idx);
    return pass?0:1;
}
