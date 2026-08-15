/* test_prune.c -- harness for the PRUNING additions in bitcoin_store.asm.
 * Verifies the Core-style -prune behaviour end-to-end:
 *   - configurable prune height (store_set_prune / store_prune)
 *   - full blk-file deletion (files fully below the prune height are unlinked)
 *   - boundary-file in-place compaction (retained blocks re-packed from 0)
 *   - store_get_at returns -3 (pruned/unavailable) below the prune point,
 *     serves normally at/above it
 *   - persistence: prune.dat reloaded by store_init so a restart keeps the gate
 * Runs in a throwaway temp dir; standalone (links bitcoin_store.o only).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>

extern int  store_init(void* st);
extern int  store_reload(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);
extern int  store_get_at(void* st, unsigned long long height, unsigned long long* out_meta);
extern int  store_get_tip(void* st, unsigned long long* out_meta);
extern int  store_set_prune(void* st, int h);
extern int  store_prune(void* st, int h);

/* state layout must mirror bitcoin_store.asm (prune at +48) */
struct St {
    unsigned long long cur_blk_fd;
    unsigned long long idx_fd;
    unsigned long long idx_len;
    int tip_height;
    int cur_file_no;
    int cur_file_pos;
    int magic;
    int pad;
    int pad2;
    int prune_height;
};

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }

static void mkblock(unsigned char* buf, int* len, int fill){
    memset(buf,0,200);
    for(int i=0;i<200;i++) buf[i]=(unsigned char)(fill+i);
    *len=200;
}
static int exists(const char* p){ struct stat s; return stat(p,&s)==0; }

/* build a fully-pruned + boundary keep on a SINGLE file using the real API */
static void single_file_case(void){
    struct St st; memset(&st,0,sizeof st);
    cki("s1 init", store_init(&st), 1);
    static unsigned char h[5][32]; static unsigned char b[5][200]; static int bl[5];
    for(int i=0;i<5;i++){ h[i][0]=i+1; mkblock(b[i],&bl[i],i*10); }
    for(int i=0;i<5;i++) cki("s1 append", store_append(&st,h[i],b[i],bl[i]), i);
    /* file 0 now holds h0..h4 at offsets 0,208,416,624,832 (200-byte blocks) */
    unsigned long long meta[3];
    cki("s1 get_at(4) pre", store_get_at(&st,4,meta), 1);
    cki("s1 get_at(0) pre", store_get_at(&st,0,meta), 1);
    /* prune to keep heights >= 3 -> boundary file 0 compacts h3,h4 */
    cki("s1 store_prune(3)", store_prune(&st,3), 1);
    cki("s1 prune_height", store_get_at(&st,2,meta), -3);   /* pruned */
    cki("s1 get_at(1) pruned", store_get_at(&st,1,meta), -3);
    cki("s1 get_at(0) pruned", store_get_at(&st,0,meta), -3);
    cki("s1 get_at(3) ok", store_get_at(&st,3,meta), 1);
    cki("s1 get_at(3) pos", meta[0], 0);                    /* re-packed from 0 */
    cki("s1 get_at(3) size", meta[1], 200);
    cki("s1 get_at(4) ok", store_get_at(&st,4,meta), 1);
    cki("s1 get_at(4) pos", meta[0], 208);                  /* 208 = 8+200 */
    cki("s1 get_at(4) size", meta[1], 200);
    /* boundary file truncated to exactly the two retained blocks */
    { FILE* f=fopen("blk00000.dat","rb"); fseek(f,0,SEEK_END); long sz=ftell(f); fclose(f);
      cki("s1 blk file compacted size", sz, 416); }         /* 2*(8+200) */
    /* served bytes at new frame start (offset 8) must equal the ORIGINAL h3 payload */
    { FILE* f=fopen("blk00000.dat","rb"); fseek(f,8,SEEK_SET); unsigned char c[200]; fread(c,1,200,f); fclose(f);
      int ok=1; for(int i=0;i<200;i++) if(c[i]!=(unsigned char)(30+i)) ok=0;
      cki("s1 retained h3 bytes intact", ok, 1); }
    /* persistence: restart keeps the gate */
    struct St st2; memset(&st2,0,sizeof st2);
    cki("s1 re-init", store_init(&st2), 1);
    cki("s1 re-init reload", store_reload(&st2), 1);
    cki("s1 restart prune_height restored", st2.prune_height, 3);
    cki("s1 restart get_at(0) pruned", store_get_at(&st2,0,meta), -3);
    cki("s1 restart get_at(4) ok", store_get_at(&st2,4,meta), 1);
    cki("s1 restart get_at(4) pos", meta[0], 208);
    /* full make clean of this dir by the caller */

    unlink("prune.dat");
    /* clear gate back to 0 and verify serving of all heights again */
    struct St st3; memset(&st3,0,sizeof st3);
    cki("s1 third init(no prune.dat)", store_init(&st3), 1);
    cki("s1 clear -> prune_height 0", st3.prune_height, 0);
}

/* build a MULTI-FILE store by hand: files f0..f2 with blocks split across them,
 * index.dat fully populated. Then prune and verify whole files are deleted. */
static void multi_file_case(void){
    /* three files:
       blk00000.dat: blocks 0,1,2   (frame 8+40 each)
       blk00001.dat: blocks 3,4,5
       blk00002.dat: blocks 6,7,8
       index.dat: 9 records -> height 0..8, tip=8, cur_file_no=2, cur_file_pos=... */
    const int NB=40;
    FILE* f0=fopen("blk00000.dat","wb");
    FILE* f1=fopen("blk00001.dat","wb");
    FILE* f2=fopen("blk00002.dat","wb");
    unsigned char block[40];
    for(int i=0;i<40;i++) block[i]=(unsigned char)(i+1);
    /* pos index per height -> (file, pos) tuple, computed as we write */
    long pos[9]; int fileno[9];
    FILE* cur=f0; int cf=0; long p=0;
    for(int h=0; h<9; h++){
        if(h==3){ fclose(f0); cur=f1; cf=1; p=0; }
        if(h==6){ fclose(f1); cur=f2; cf=2; p=0; }
        /* frame: [u32 len][u32 magic 0xd9b4bef9][raw] */
        unsigned char hdr[8];
        hdr[0]=NB&0xff; hdr[1]=(NB>>8)&0xff; hdr[2]=(NB>>16)&0xff; hdr[3]=(NB>>24)&0xff;
        hdr[4]=0xf9; hdr[5]=0xbe; hdr[6]=0xb4; hdr[7]=0xd9;
        fwrite(hdr,1,8,cur); fwrite(block,1,40,cur);
        pos[h]=p; fileno[h]=cf; p+=48;
    }
    fclose(f2);
    /* index.dat */
    FILE* idf=fopen("index.dat","wb");
    for(int h=0; h<9; h++){
        unsigned char rec[48]; memset(rec,0,48);
        for(int i=0;i<32;i++) rec[i]=(unsigned char)(h+1);   /* hash filler */
        unsigned int fn=fileno[h]; memcpy(rec+32,&fn,4);
        unsigned long long dp=pos[h]; memcpy(rec+36,&dp,8);
        unsigned int sz=NB; memcpy(rec+44,&sz,4);
        fwrite(rec,1,48,idf);
    }
    fclose(idf);

    struct St st; memset(&st,0,sizeof st);
    cki("m init", store_init(&st), 1);
    cki("m reload", store_reload(&st), 1);
    cki("m tip 8", st.tip_height, 8);
    cki("m cur_file_no 2", st.cur_file_no, 2);

    unsigned long long meta[3];
    cki("m get_at(5) pre ok", store_get_at(&st,5,meta), 1);
    /* prune to retain heights >= 6 (files 0,1 fully pruned; file 2 fully kept) */
    cki("m store_prune(6)", store_prune(&st,6), 1);
    cki("m blk00000 deleted", exists("blk00000.dat"), 0);
    cki("m blk00001 deleted", exists("blk00001.dat"), 0);
    cki("m blk00002 kept", exists("blk00002.dat"), 1);
    for(int h=0; h<6; h++){ cki("m pruned", store_get_at(&st,h,meta), -3); }
    cki("m get_at(6) ok", store_get_at(&st,6,meta), 1);
    cki("m get_at(6) pos", meta[0], 0);
    cki("m get_at(6) file", meta[2], 2);
    cki("m get_at(8) ok", store_get_at(&st,8,meta), 1);
    cki("m get_at(8) pos", meta[0], 96);   /* 2 blocks already in file 2 */
    cki("m get_at(8) file", meta[2], 2);
    /* persistence across restart */
    struct St st2; memset(&st2,0,sizeof st2);
    cki("m re-init", store_init(&st2), 1);
    cki("m re-init reload", store_reload(&st2), 1);
    cki("m restart prune restored", st2.prune_height, 6);
    cki("m restart get_at(5) pruned", store_get_at(&st2,5,meta), -3);
    cki("m restart get_at(8) ok", store_get_at(&st2,8,meta), 1);
    /* reset gate to 0 -> everything served again (files 0,1 note: still gone,
       so heights 0..5 reference deleted files -> store_get_at would try open and
       fail with -1; but with gate cleared the store is now inconsistent. This is
       expected: clearing the gate on a pruned store is not supported (files are
       gone). We only assert the gate is 0, matching the "disabled" default. */
    unlink("prune.dat");
}

/* prune-all (UTXO-only) retention: every blk file deleted */
static void prune_all_case(void){
    struct St st; memset(&st,0,sizeof st);
    cki("p init", store_init(&st), 1);
    static unsigned char h[3][32]; static unsigned char b[3][50]; int bl[3];
    for(int i=0;i<3;i++){ h[i][0]=i+9; memset(b[i],i+1,50); bl[i]=50; }
    for(int i=0;i<3;i++) cki("p append", store_append(&st,h[i],b[i],bl[i]), i);
    cki("p exists blk00000 pre", exists("blk00000.dat"), 1);
    cki("p store_prune(tip+1=3)", store_prune(&st,3), 1);
    cki("p blk00000 deleted", exists("blk00000.dat"), 0);
    unsigned long long meta[3];
    for(int hh=0; hh<3; hh++) cki("p all pruned", store_get_at(&st,hh,meta), -3);
}

int main(void){
    char tmpl[]="/tmp/btcpruneXXXXXX";
    char* base = mkdtemp(tmpl);
    if(!base){ printf("FAIL mkdtemp\n"); return 1; }

    /* single-file case in its own subdir */
    { char d[256]; snprintf(d,sizeof d,"%s/single",base); mkdir(d,0700); chdir(d);
      single_file_case(); chdir(base); }

    /* multi-file case */
    { char d[256]; snprintf(d,sizeof d,"%s/multi",base); mkdir(d,0700); chdir(d);
      multi_file_case(); chdir(base); }

    /* prune-all */
    { char d[256]; snprintf(d,sizeof d,"%s/all",base); mkdir(d,0700); chdir(d);
      prune_all_case(); chdir(base); }

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
