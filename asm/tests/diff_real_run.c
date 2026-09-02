/* tests/diff_real_run.c -- READ-ONLY differential against a REAL production
 * run file.
 *
 * Why this exists: the 2026-08-22 production REJECT (h=318148, "missing/
 * already-spent UTXO", first block after a reload with manifest_n=6) could
 * not be reproduced synthetically. Every constructible shape was tried and
 * matched the assembly exactly -- large/sparse runs, compaction-created runs,
 * reloads, a 180k-get randomized soak, and a full production-scale run
 * (3.5M records, saturated 4MiB bloom, 290MB file, sparse_n=13672).
 *
 * So the trigger is something about the real files. This tool reads an actual
 * utxo_run_NNNNNN.dat, harvests the keys it actually contains by walking its
 * record section, and asks BOTH lookup paths for each one. It opens the file
 * read-only and never writes, so it is safe to point at a live datadir.
 *
 *   ./tests/diff_real_run <dir> <run_no> [max_keys]
 *
 * <dir> must contain utxo_run_<run_no padded to 6>.dat. Run it from anywhere;
 * it chdir()s into <dir> because both lookup paths open the run by relative
 * name.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

/* Driven through the real entry point (utxo_lsm_get) with a synthetic
 * single-run manifest, so this exercises exactly the production call path.
 * mac_run_lookup is a local label and cannot be called directly. */
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index,
                          unsigned long long* value, unsigned long* height,
                          unsigned long* is_coinbase,
                          const unsigned char** script, unsigned long* slen);
extern void lsm_mm_set_enabled(int on);
extern long utxo_lsm_init(void* lst);
extern void utxo_lsm_close(void* lst);

struct LST {
    long log_fd, idx_fd;
    unsigned long long log_len, ckpt_log_off, ckpt_n;
    unsigned long long op_count, op_threshold, fill_threshold;
    void* tomb_buf; unsigned long long tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; unsigned long long manifest_cap, manifest_n;
    void* scratch_buf; unsigned long long scratch_cap;
    unsigned long long next_run_no;
    void* tomb_hash_buf; unsigned long long tomb_hash_mask;
};

#define KEY 36

int main(int argc, char** argv){
    if (argc < 3) { fprintf(stderr,"usage: %s <dir> <run_no> [max_keys]\n",argv[0]); return 2; }
    const char* dir = argv[1];
    unsigned run_no = (unsigned)strtoul(argv[2],NULL,10);
    unsigned long max_keys = (argc>3)? strtoul(argv[3],NULL,10) : 20000;
    if (chdir(dir)!=0){ perror("chdir"); return 2; }

    char path[64]; snprintf(path,sizeof path,"utxo_run_%06u.dat",run_no);
    int fd = open(path,O_RDONLY);
    if (fd<0){ perror(path); return 2; }
    struct stat st; if (fstat(fd,&st)!=0){ perror("fstat"); return 2; }
    const u8* m = mmap(NULL,(size_t)st.st_size,PROT_READ,MAP_SHARED,fd,0);
    if (m==MAP_FAILED){ perror("mmap"); return 2; }

    u32 magic; memcpy(&magic,m,4);
    u64 hdr = (magic==0x4E555255u)?28:44;
    u64 gen,nrec,bbits,soff=0,sn=0;
    memcpy(&gen,m+4,8); memcpy(&nrec,m+12,8); memcpy(&bbits,m+20,8);
    if (hdr==44){ memcpy(&soff,m+28,8); memcpy(&sn,m+36,8); }
    int rec_v2 = (magic==0x33555255u);
    u64 bbytes = bbits>>3, rstart = hdr + bbytes;
    printf("%s: magic=%08x gen=%llu nrec=%llu bloom_bytes=%llu sparse_n=%llu rec_v2=%d size=%lld\n",
           path,magic,(unsigned long long)gen,(unsigned long long)nrec,
           (unsigned long long)bbytes,(unsigned long long)sn,rec_v2,(long long)st.st_size);

    /* harvest keys by walking the record section */
    u8 (*keys)[KEY] = malloc(max_keys*KEY);
    unsigned long nk=0; u64 pos=rstart;
    while (nk<max_keys && pos+37<=(u64)st.st_size){
        memcpy(keys[nk],m+pos,KEY); nk++;
        u8 kind=m[pos+36];
        if (kind!=1){ pos+=37; continue; }
        u64 vp=pos+37, vlen=rec_v2?15:10;
        if (vp+vlen>(u64)st.st_size) break;
        u32 sl=(u32)(m[vp+8] | (m[vp+9]<<8));
        pos = vp+vlen+sl;
    }
    printf("harvested %lu keys from the record section\n",nk);

    /* Build a REAL, fully-initialised LST in a scratch dir (utxo_lsm_init
     * allocates the internals this code needs), then repoint its manifest at
     * the run under test and chdir back -- both lookup paths open the run by
     * relative name. The scratch dir keeps init's own files away from <dir>,
     * so the target directory is never written to. */
    char cwd[4096]; if(!getcwd(cwd,sizeof cwd)){ perror("getcwd"); return 2; }
    char scratchdir[]="/tmp/diffrunXXXXXX";
    if(!mkdtemp(scratchdir)){ perror("mkdtemp"); return 2; }
    if(chdir(scratchdir)!=0){ perror("chdir scratch"); return 2; }

    #define D_TOMB 512
    #define D_MAN  8
    #define D_DESC 64
    #define D_SCRATCH ((unsigned long long)D_DESC*128 + (4u<<20) + 65536)
    void* d_tomb=malloc(D_TOMB*36); void* d_man=malloc(D_MAN*16);
    void* d_scr=malloc(D_SCRATCH); void* blob=malloc(1u<<20);
    void* u=malloc(utxo_struct_size(1024));
    if(!d_tomb||!d_man||!d_scr||!blob||!u){ fprintf(stderr,"alloc\n"); return 2; }
    utxo_init(u,1024,blob,1u<<20);
    struct LST lst; memset(&lst,0,sizeof lst);
    lst.op_threshold=1ULL<<40; lst.fill_threshold=1ULL<<40;
    lst.tomb_buf=d_tomb; lst.tomb_cap=D_TOMB;
    lst.manifest_buf=d_man; lst.manifest_cap=D_MAN;
    lst.scratch_buf=d_scr; lst.scratch_cap=D_SCRATCH;
    if(utxo_lsm_init(&lst)!=1){ fprintf(stderr,"lsm_init failed\n"); return 2; }
    /* point it at the real run and go back to <dir> */
    ((unsigned long long*)d_man)[0]=gen;
    ((unsigned long long*)d_man)[1]=run_no;
    lst.manifest_n=1;
    if(chdir(cwd)!=0){ perror("chdir back"); return 2; }

    unsigned long mism=0, checked=0;
    for (unsigned long i=0;i<nk;i++){
        const u8* t = keys[i];
        u32 idx; memcpy(&idx,t+32,4);
        unsigned long long v1=0,v2=0; unsigned long h1=0,c1=0,h2=0,c2=0;
        const unsigned char *s1=NULL,*s2=NULL; unsigned long l1=0,l2=0;
        lsm_mm_set_enabled(1);
        long r1 = utxo_lsm_get(&lst,u,t,idx,&v1,&h1,&c1,&s1,&l1);
        lsm_mm_set_enabled(0);
        long r2 = utxo_lsm_get(&lst,u,t,idx,&v2,&h2,&c2,&s2,&l2);
        lsm_mm_set_enabled(1);
        checked++;
        if (r1!=r2 || v1!=v2 || h1!=h2 || c1!=c2 || l1!=l2 ||
            (r1==1 && l1 && memcmp(s1,s2,l1)!=0)) {
            if (mism<10)
                printf("MISMATCH key[%lu] idx=%u  mm{r=%ld v=%llu h=%llu cb=%llu sl=%lu}  asm{r=%ld v=%llu h=%llu cb=%llu sl=%lu}\n",
                       i,idx,r1,v1,(unsigned long long)h1,(unsigned long long)c1,l1,
                       r2,v2,(unsigned long long)h2,(unsigned long long)c2,l2);
            mism++;
        }
    }
    printf("\n%lu keys compared, %lu mismatches -> %s\n",checked,mism,
           mism? "FAST PATH DIVERGES":"identical");
    return mism?1:0;
}
