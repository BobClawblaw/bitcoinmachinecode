/* test_headers.c -- 100% AI-generated harness for the assembly bitcoin_headers.asm
 * persistent header-chain store. Runs in a throwaway temp directory; verifies
 * append/get/count/reload, the on-disk 112-byte-positional layout, restart-resume,
 * and that each stored entry's block_hash (computed via the proven block_hash asm)
 * links to the next entry's prevhash -- i.e. the node's chain-linking primitive
 * over real headers works end to end.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>

extern int  hst_init(void* hst);
extern int  hst_reload(void* hst);
extern long hst_append(void* hst, const void* hdr, const void* hash);
extern int  hst_get_at(void* hst, unsigned long long height, void* out);
extern long hst_count(void* hst);
extern void block_hash(void* out, const void* hdr);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void put_u32le(unsigned char*p,unsigned v){p[0]=v;p[1]=v>>8;p[2]=v>>16;p[3]=v>>24;}

/* state struct layout must mirror bitcoin_headers.asm */
struct Hst { unsigned long long fd, count; };

/* build an 80-byte header that chains off `prev` (hash internal order) */
static void mk_hdr(unsigned char* h, const unsigned char* prev){
    put_u32le(h+0, 0x20000000);
    if(prev) memcpy(h+4, prev, 32); else memset(h+4, 0, 32);   /* genesis: prev=0 */
    memset(h+36, 7, 32);          /* merkle root (arbitrary for chaining test) */
    put_u32le(h+68, 1700000000u);
    put_u32le(h+72, 0x1d00ffff);  /* early-difficulty bits */
    put_u32le(h+76, 0);           /* nonce */
}

int main(void){
    char tmpl[]="/tmp/btchdrXXXXXX";
    char* dir = mkdtemp(tmpl);
    if(!dir){ printf("FAIL mkdtemp\n"); return 1; }
    chdir(dir);

    struct Hst hs; memset(&hs,0,sizeof hs);
    cki("hst_init", hst_init(&hs), 1);
    cki("hst empty count", hst_count(&hs), 0);

    /* build a chain of 5 headers: h[i] prevhash = block_hash(h[i-1]) */
    static unsigned char hdr[5][80];
    static unsigned char bh[5][32];
    mk_hdr(hdr[0], NULL);        /* block 0, genesis-style (prev = 0) */
    block_hash(bh[0], hdr[0]);
    for(int i=1;i<5;i++){ mk_hdr(hdr[i], bh[i-1]); block_hash(bh[i], hdr[i]); }

    /* append each with its block_hash -> count advances 1..5 */
    for(int i=0;i<5;i++){
        char lbl[64]; snprintf(lbl,sizeof lbl,"append %d -> count %d", i, i+1);
        long got = hst_append(&hs, hdr[i], bh[i]);
        if(got==i+1) printf("PASS %s (got %ld)\n", lbl, got);
        else { printf("FAIL %s got=%ld exp=%ld\n", lbl, got, (long)(i+1)); failures++; }
    }

    cki("hst count == 5", hst_count(&hs), 5);

    /* get_at returns the (hdr,hash) pair byte-exact */
    static unsigned char rec[112];
    cki("get_at(0) ok", hst_get_at(&hs,0,rec), 1);
    cki("get_at(0) hdr[0]==hdr0", memcmp(rec, hdr[0], 80)==0, 1);
    cki("get_at(0) hash==bh0", memcmp(rec+80, bh[0], 32)==0, 1);
    cki("get_at(3) hdr[3]==hdr3", (hst_get_at(&hs,3,rec)==1 && memcmp(rec, hdr[3], 80)==0), 1);
    cki("get_at out-of-range", hst_get_at(&hs,5,rec), 0);

    /* ---- on-disk layout: entry N at N*112, 112 bytes each ---- */
    FILE* f = fopen("headers.dat","rb");
    fseek(f,0,SEEK_END); long sz=ftell(f); fclose(f);
    cki("headers.dat size = 5*112", sz, 560);
    FILE* f2 = fopen("headers.dat","rb");
    unsigned char e0[112]; fread(e0,1,112,f2); fclose(f2);
    cki("entry0 hdr == hdr0", memcmp(e0, hdr[0], 80)==0, 1);
    cki("entry0 hash == bh0", memcmp(e0+80, bh[0], 32)==0, 1);

    /* ---- chain continuity via the stored hashes (node locator primitive) ----
     * For every entry i>=1, hdr[i].prevhash (rec[4..36]) must equal the stored
     * block_hash of entry i-1. This is exactly what the paged IBD loop checks. */
    int cont=1;
    for(int i=1;i<5;i++){
        unsigned char prev_rec[112], cur_hdr[80];
        hst_get_at(&hs, i-1, prev_rec);
        hst_get_at(&hs, i,   rec);
        memcpy(cur_hdr, rec, 80);
        if(memcmp(cur_hdr+4, prev_rec+80, 32)!=0) cont=0;   /* prevhash == prior hash */
        if(memcmp(cur_hdr+4, bh[i-1], 32)!=0) cont=0;
    }
    cki("chain continuous (prevhash==prior block_hash)", cont, 1);

    /* ---- simulate restart: re-init + reload restores count; get_at still works ---- */
    struct Hst hs2; memset(&hs2,0,sizeof hs2);
    cki("re-init (existing file)", hst_init(&hs2), 1);
    cki("reload ok", hst_reload(&hs2), 1);
    cki("reload count == 5", hst_count(&hs2), 5);
    cki("reload get_at(4) hash==bh4", (hst_get_at(&hs2,4,rec)==1 && memcmp(rec+80, bh[4], 32)==0), 1);

    /* append h5 after reload -> count 6 at offset 5*112=560 */
    static unsigned char hdr5[80], bh5[32];
    mk_hdr(hdr5, bh[4]); block_hash(bh5, hdr5);
    cki("append after reload -> count 6", hst_append(&hs2, hdr5, bh5), 6);
    cki("count 6", hst_count(&hs2), 6);

    unlink("headers.dat"); rmdir(dir);
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
