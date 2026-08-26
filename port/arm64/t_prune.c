/* t_prune.c -- behavioral verification of store_prune (AArch64 port).
 *
 * Builds a REAL multi-file store on disk (blk00000.dat..blk00002.dat + index.dat)
 * by hand to the exact store_append on-disk format:
 *   - blk file frame: [u32 len][u32 magic=0xd9b4bef9] + raw
 *   - index record (48B): hash[32] | file_no(u32)@32 | data_pos(u64)@36 | size(u32)@44
 * Then drives store_prune across every branch and verifies the on-disk result
 * and store_get_at behaviour. Mirrors upstream bitcoin_store.asm store_prune.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

extern int  store_init(void* st);
extern int  store_prune(void* st, int h);
extern int  store_get_at(void* st, uint64_t height, uint64_t out_meta[3]);
extern int  store_get_file_fd(void* st, uint32_t file_no);

#define MAGIC 0xd9b4bef9u
#define RAW   64          /* raw bytes per block */
#define FRAME (8+RAW)     /* header + raw */

/* ---- block layout ---- */
typedef struct { int file; uint64_t pos; uint32_t size; uint8_t raw[RAW]; } BINFO;
static BINFO* blocks;
static int total;
static int nfiles;

static unsigned pat[16];
static void init_pattern(void){ for(int i=0;i<16;i++) pat[i]=(unsigned)(0xA5B3C1D7u ^ ((unsigned)i*0x9E3779B1u)); }

static void raw_for(int b, uint8_t* o){
    memset(o,0,RAW);
    memcpy(o, pat, sizeof pat);
    memcpy(o+16, &b, 4);
    o[20]=(uint8_t)(b>>24);
    /* fill distinct bytes so overwrite bugs surface */
    for(int i=24;i<RAW;i++) o[i]=(uint8_t)(b+i);
}

static void build_store(int per[3]){
    unsigned char hdr[8];
    FILE* f[3];
    uint64_t pos[3]={0,0,0};
    int b=0;
    for(int fno=0; fno<3; fno++){
        char nm[32]; snprintf(nm,32,"blk%05d.dat",fno);
        f[fno]=fopen(nm,"wb");
        for(int k=0;k<per[fno];k++,b++){
            int sz=RAW; uint8_t rb[RAW];
            raw_for(b,rb);
            hdr[0]=sz&0xff; hdr[1]=(sz>>8)&0xff; hdr[2]=(sz>>16)&0xff; hdr[3]=(sz>>24)&0xff;
            uint32_t mg=MAGIC;
            memcpy(hdr+4,&mg,4);
            fwrite(hdr,1,8,f[fno]);
            fwrite(rb,1,RAW,f[fno]);
            blocks[b].file=fno; blocks[b].pos=pos[fno]; blocks[b].size=(uint32_t)sz;
            memcpy(blocks[b].raw,rb,RAW);
            pos[fno]+=FRAME;
        }
        fclose(f[fno]);
    }
    /* index.dat */
    FILE* ix=fopen("index.dat","wb");
    unsigned char rec[48];
    for(int b=0;b<total;b++){
        memset(rec,0,48);
        memcpy(rec, pat,16); memcpy(rec+16,&b,4);
        uint32_t fn=blocks[b].file;  memcpy(rec+32,&fn,4);
        uint64_t p=blocks[b].pos;    memcpy(rec+36,&p,8);
        uint32_t sz=blocks[b].size;  memcpy(rec+44,&sz,4);
        fwrite(rec,1,48,ix);
    }
    fclose(ix);
    /* prune.dat absent by default */
}

static void setup_st(uint8_t* st){
    memset(st,0,1024);
    int fd=open("index.dat",O_RDWR);
    if(fd<0){perror("open index");exit(1);}
    *(int64_t*)(st+8)  = fd;          /* idx_fd */
    *(int64_t*)(st+16) = (int64_t)(total*48); /* idx_len */
    *(int32_t*)(st+24) = total-1;     /* tip */
    *(int32_t*)(st+28) = nfiles-1;    /* cur_file_no */
    *(int32_t*)(st+0)  = -1;          /* cur_blk_fd */
    *(int32_t*)(st+32) = 0;
    *(int32_t*)(st+36) = MAGIC;
    *(int32_t*)(st+48) = 0;           /* prune_height */
}

/* read the raw bytes of block b back via get_at + get_file_fd */
static int get_block(uint8_t* st, int b, uint8_t* out){
    uint64_t meta[3];
    int r=store_get_at(st,b,meta);
    if(r==1){
        int fd=store_get_file_fd(st,(uint32_t)meta[2]);
        if(fd<0){printf("  get_block %d: open file %llu failed\n",b,(unsigned long long)meta[2]);return -1;}
        uint8_t tmp[FRAME];
        if(pread(fd,tmp,FRAME,meta[0])!=FRAME){printf("  get_block %d: pread failed\n",b);return -1;}
        memcpy(out,tmp+8,RAW);
        return 0;
    }
    return r; /* -2 / -3 */
}

static int fails=0;
#define CHECK(cond,msg) do{ if(!(cond)){ printf("  FAIL: %s\n", msg); fails++; } }while(0)

/* ---- Case H: large blocks >64KB exercise the multi-chunk compaction copy ---- */
static int test_large_chunk(void){
    int save=fails;
    /* blocks: 0..1 in file0 (small), 2..4 in file1 (boundary) with LARGE sizes that
       cross the 64KB copy-buffer boundary in the in-place compaction loop. */
    const int SZ[5]={40, 40, 0x10000+0x50, 0x60, 0x20000}; /* sizes of blk0..4 */
    const int FNO[5]={0,0,1,1,1};
    uint64_t off[5]={0,0,0,0,0};
    /* build files */
    FILE* f0=fopen("blk00000.dat","wb");
    FILE* f1=fopen("blk00001.dat","wb");
    uint8_t hdr[8], *blk = malloc(0x20000+64);  /* scratch big block */
    FILE* cur=f0; uint64_t pos[2]={0,0};
    for(int b=0;b<5;b++){
        if(FNO[b]==1 && cur==f0){ fclose(cur); cur=f1; }
        for(int i=0;i<SZ[b];i++) blk[i]=(uint8_t)(b+i*7+1);
        uint32_t L=SZ[b], M=MAGIC; memcpy(hdr,&L,4); memcpy(hdr+4,&M,4);
        off[b]=pos[FNO[b]];
        fwrite(hdr,1,8,cur); fwrite(blk,1,SZ[b],cur);
        pos[FNO[b]]+=8+SZ[b];
    }
    fclose(cur);
    /* index.dat: 5 records */
    FILE* ix=fopen("index.dat","wb");
    for(int b=0;b<5;b++){
        unsigned char rec[48]; memset(rec,0,48);
        memcpy(rec,pat,16); memcpy(rec+16,&b,4);
        uint32_t fn=FNO[b]; memcpy(rec+32,&fn,4);
        uint64_t p=off[b];  memcpy(rec+36,&p,8);
        uint32_t s=SZ[b];   memcpy(rec+44,&s,4);
        fwrite(rec,1,48,ix);
    }
    fclose(ix);
    uint8_t st[1024]; memset(st,0,1024);
    int fd=open("index.dat",O_RDWR);
    if(fd<0){perror("open index");exit(1);}
    *(int64_t*)(st+8)  = fd;
    *(int64_t*)(st+16) = 5*48;      /* idx_len = 5 records */
    *(int32_t*)(st+24) = 4;         /* tip = 4 (blocks 0..4) */
    *(int32_t*)(st+28) = 1;         /* cur_file_no = 1 */
    *(int32_t*)(st+0)  = -1;        /* cur_blk_fd */
    *(int32_t*)(st+36) = MAGIC;
    *(int32_t*)(st+48) = 0;
    int rc=store_prune(st,2);     /* eff=2, first_retained_file=1 -> delete f0, compact f1 2..4 */
    printf("%-28s prune(2) LARGE chunks\n","H_large_chunk");
    CHECK(rc==1,"H rc==1");
    CHECK(access("blk00000.dat",F_OK)!=0,"H file0 deleted");
    struct stat sb; stat("blk00001.dat",&sb);
    uint64_t expect = (8+(uint64_t)SZ[2]) + (8+(uint64_t)SZ[3]) + (8+(uint64_t)SZ[4]);
    CHECK(sb.st_size==(off_t)expect,"H file1 compacted size");
    /* read each retained block via get_at + pread, verify stripped of its pruned prefix */
    uint8_t expectpat[0x20000+64];
    int rfd=open("blk00001.dat",O_RDONLY);
    uint64_t newoff=0;
    for(int b=2;b<=4;b++){
        for(int i=0;i<SZ[b];i++) expectpat[i]=(uint8_t)(b+i*7+1);
        uint8_t buf[0x20000+64];
        if(pread(rfd,buf,8+SZ[b],newoff)!= (ssize_t)(8+SZ[b])){ CHECK(0,"H pread fail"); break; }
        if(memcmp(buf+8,expectpat,SZ[b])!=0){ CHECK(0,"H chunk content mismatch"); break; }
        newoff += 8+SZ[b];
    }
    close(rfd);
    free(blk);
    close(*(int*)(st+8));
    return fails-save;
}

/* verify full post-prune state for expected_eff (or -1 meaning 'no prune gate = all served') */
static void verify_post(int eff, int deleted0, int deleted1, uint64_t expect_size[3],
                        uint8_t* st){
    /* prune.dat */
    int pfd=open("prune.dat",O_RDONLY);
    if(eff<0){ CHECK(pfd<0,"prune.dat should NOT exist"); }
    else{
        CHECK(pfd>=0,"prune.dat should exist");
        if(pfd>=0){
            int32_t v; read(pfd,&v,4); close(pfd);
            CHECK(v==eff,"prune.dat value mismatch");
        }
    }
    struct stat sb;
    /* deleted files must be gone */
    const char* names[3]={"blk00000.dat","blk00001.dat","blk00002.dat"};
    CHECK((deleted0? access(names[0],F_OK)!=0 : access(names[0],F_OK)==0),"file0 del state");
    CHECK((deleted1? access(names[1],F_OK)!=0 : access(names[1],F_OK)==0),"file1 del state");
    if(access(names[2],F_OK)==0){ stat(names[2],&sb); CHECK(sb.st_size==(off_t)expect_size[2],"file2 size"); }
    if(access(names[1],F_OK)==0){ stat(names[1],&sb); CHECK(sb.st_size==(off_t)expect_size[1],"file1 size"); }
    /* every block readable / pruned */
    for(int b=0;b<total;b++){
        uint8_t got[RAW];
        int r=get_block(st,b,got);
        if(eff<0 || b>=eff){  /* retained */
            char m[64]; snprintf(m,64,"block %d should be RETAINED (rc=%d)",b,r);
            CHECK(r==0,m);
            if(r==0) CHECK(memcmp(got,blocks[b].raw,RAW)==0,"raw mismatch");
        } else {              /* pruned */
            char m[64]; snprintf(m,64,"block %d should be PRUNED -3 (rc=%d)",b,r);
            CHECK(r==-3,m);
        }
    }
}

static void run_case(const char* name, int h, int exp_eff, int d0, int d1, uint64_t esz[3]){
    printf("%-28s prune(%d)\n", name, h);
    uint8_t st[1024]; setup_st(st);
    int rc=store_prune(st,h);
    char m[64]; snprintf(m,64,"rc==1 (got %d)",rc);
    CHECK(rc==1,m);
    verify_post(exp_eff,d0,d1,esz,st);
    close(*(int*)(st+8));
}

int main(void){
    init_pattern();
    int per[3]={40,40,20};       /* 0..39 f0, 40..79 f1, 80..99 f2 */
    total=100; nfiles=3;
    blocks=calloc(total,sizeof(BINFO));

    fails=0;
    build_store(per);

    /* --- Case A: prune at h=80 (first block of file 2) ---
       eff=80, first_retained_file=2 -> delete f0,f1; compact f2. */
    uint64_t eA[3]={0,0,(uint64_t)(20*FRAME)};
    run_case("A_f2_first @80", 80, 80, 1,1, eA);
    /* verify compacted f2: block 80 data_pos==0, blocks 80-99 re-packed */
    {
        int fx=open("blk00002.dat",O_RDONLY);
        CHECK(fx>=0,"f2 exists after A");
        struct stat sb; fstat(fx,&sb);
        CHECK(sb.st_size==(off_t)(20*FRAME),"f2 compacted size");
        uint8_t tmp[FRAME];
        pread(fx,tmp,FRAME,0); close(fx);
        CHECK(memcmp(tmp+8,blocks[80].raw,RAW)==0,"block80 at offset 0");
    }

    /* rebuild pristine store for next case */
    unlink("blk00000.dat"); unlink("blk00001.dat"); unlink("blk00002.dat");
    unlink("index.dat"); unlink("prune.dat");
    build_store(per);

    /* --- Case B: prune at h=60 (mid file 1) ---
       eff=60, first_retained_file=1 -> delete f0; compact f1 (blocks 60..79), f2 intact. */
    uint64_t eB[3]={0,(uint64_t)(20*FRAME),(uint64_t)(20*FRAME)};
    run_case("B_mid_f1 @60", 60, 60, 1,0, eB);
    {
        int fx=open("blk00001.dat",O_RDONLY);
        struct stat sb; fstat(fx,&sb);
        CHECK(sb.st_size==(off_t)(20*FRAME),"f1 compacted size (B)");
        uint8_t tmp[FRAME]; pread(fx,tmp,FRAME,0); close(fx);
        CHECK(memcmp(tmp+8,blocks[60].raw,RAW)==0,"block60 at offset0 (B)");
    }

    unlink("blk00000.dat"); unlink("blk00001.dat"); unlink("blk00002.dat");
    unlink("index.dat"); unlink("prune.dat");
    build_store(per);

    /* --- Case C: prune at h=0 -> persist_only, nothing deleted --- */
    uint64_t eC[3]={(uint64_t)(40*FRAME),(uint64_t)(40*FRAME),(uint64_t)(20*FRAME)};
    run_case("C_zero @0", 0, 0, 0,0, eC);

    unlink("blk00000.dat"); unlink("blk00001.dat"); unlink("blk00002.dat");
    unlink("index.dat"); unlink("prune.dat");
    build_store(per);

    /* --- Case D: prune at h=100 (tip+1) -> prune_all (delete all 3) --- */
    uint64_t eD[3]={0,0,0};
    run_case("D_all @100", 100, 100, 1,1, eD);

    unlink("blk00000.dat"); unlink("blk00001.dat"); unlink("blk00002.dat");
    unlink("index.dat"); unlink("prune.dat");
    build_store(per);

    /* --- Case E: prune at h=-1 -> clamp to 0 -> persist_only --- */
    uint64_t eE[3]={(uint64_t)(40*FRAME),(uint64_t)(40*FRAME),(uint64_t)(20*FRAME)};
    run_case("E_neg @-1", -1, 0, 0,0, eE);

    unlink("blk00000.dat"); unlink("blk00001.dat"); unlink("blk00002.dat");
    unlink("index.dat"); unlink("prune.dat");
    build_store(per);

    /* --- Case F: prune at h=200 -> clamp to tip+1=100 -> prune_all --- */
    uint64_t eF[3]={0,0,0};
    run_case("F_over @200", 200, 100, 1,1, eF);

    /* --- Case G: empty store (tip=-1) -> .empty -> persists 0 --- */
    unlink("blk00000.dat"); unlink("blk00001.dat"); unlink("blk00002.dat");
    unlink("index.dat"); unlink("prune.dat");
    {
        total=0; nfiles=1;
        FILE* ix=fopen("index.dat","wb"); fclose(ix); /* empty */
        uint8_t st[1024]; setup_st(st);
        *(int32_t*)(st+24)=-1;  /* tip = -1 -> empty */
        int rc=store_prune(st,5);
        printf("%-28s prune(5) on EMPTY\n","G_empty");
        CHECK(rc==1,"G rc==1");
        int pfd=open("prune.dat",O_RDONLY);
        CHECK(pfd>=0,"G prune.dat exists");
        if(pfd>=0){ int32_t v; read(pfd,&v,4); close(pfd); CHECK(v==0,"G prune.dat==0"); }
        close(*(int*)(st+8));
    }

    unlink("index.dat"); unlink("prune.dat");
    /* Case H: large-block multi-chunk compaction (rebuild fresh dir of files) */
    unlink("blk00000.dat"); unlink("blk00001.dat");
    {
        /* need a clean dir: remove leftovers from prior cases */
        int df=test_large_chunk();
        (void)df;
    }

    unlink("index.dat"); unlink("prune.dat"); unlink("blk00000.dat"); unlink("blk00001.dat");
    free(blocks);

    if(fails){ printf("\nRESULT: FAIL (%d)\n",fails); return 1; }
    printf("\nRESULT: ALL PASS\n");
    return 0;
}
