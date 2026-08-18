/* test_locator.c -- 100% AI-generated harness for Stage A reorg/fork-choice
 * primitive #2: the real multi-hash block locator.
 *   - p2p_getheaders (bitcoin_p2p.asm) extended to accept count>1 locator
 *     hashes, serialized per the Bitcoin wire format.
 *   - locator_build (daemon/locator_build.c) building the doubling-gap
 *     ancestor-height list from a store's on-disk index.
 * Runs in a throwaway temp dir (locator_build/store_* touch relative
 * filenames).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

extern long p2p_getheaders(void* out, const void* locator, long count, const void* stop);

extern int  store_init(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);

#define LOCATOR_MAX 32
extern long locator_build(void* store_buf, unsigned char out_hashes[LOCATOR_MAX*32]);

/* state struct layout must mirror bitcoin_store.asm (see tests/test_store.c) */
struct St {
    unsigned long long cur_blk_fd, idx_fd, idx_len;
    int tip_height, cur_file_no, cur_file_pos, magic, pad, pad2, prune_height;
};

static int failures = 0;
static void cki(const char* l, long g, long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else{printf("FAIL %s got=%ld exp=%ld\n",l,g,e);failures++;} }
static void ckm(const char* l, int cond){ cki(l, cond, 1); }
static void cbyte(const char* l, const unsigned char* g, const unsigned char* e, int n){
    if (memcmp(g,e,n)==0) printf("PASS %s\n", l);
    else { printf("FAIL %s\n  got ", l); for(int i=0;i<n;i++) printf("%02x",g[i]);
           printf("\n  exp "); for(int i=0;i<n;i++) printf("%02x",e[i]); printf("\n"); failures++; }
}

static void fill_hash(unsigned char h[32], int height){
    memset(h, 0, 32);
    h[0] = (unsigned char)(height & 0xff);
    h[1] = (unsigned char)((height>>8) & 0xff);
    h[2] = 0xAB; /* distinguishes real store hashes from stray zero buffers */
}

int main(void){
    char tmpl[]="/tmp/btclocXXXXXX";
    char* dir = mkdtemp(tmpl);
    if(!dir){ printf("FAIL mkdtemp\n"); return 1; }
    chdir(dir);

    /* ============================================================
     * Part 1: p2p_getheaders count>1 wire format
     * ============================================================ */
    {
        unsigned char loc3[3*32];
        for (int i=0;i<3;i++) for (int j=0;j<32;j++) loc3[i*32+j] = (unsigned char)(0x10*(i+1)+j);
        unsigned char stop[32]; for (int j=0;j<32;j++) stop[j] = (unsigned char)(0xC0+j);
        unsigned char out[8+3*32+32+8];
        memset(out, 0xEE, sizeof out);

        long len = p2p_getheaders(out, loc3, 3, stop);
        cki("getheaders count=3 len", len, 5 + 3*32 + 32);

        unsigned char expect[5+3*32+32];
        expect[0]=0x80; expect[1]=0x11; expect[2]=0x01; expect[3]=0x00; /* version 70016 LE */
        expect[4]=0x03; /* locator count varint */
        memcpy(expect+5, loc3, 3*32);
        memcpy(expect+5+3*32, stop, 32);
        cbyte("getheaders count=3 bytes", out, expect, sizeof expect);
    }
    {
        /* count==1 must remain byte-identical to the pre-extension behaviour */
        unsigned char h[32]; for (int j=0;j<32;j++) h[j]=(unsigned char)(0x30+j);
        unsigned char stop[32]={0};
        unsigned char out[69];
        long len = p2p_getheaders(out, h, 1, stop);
        cki("getheaders count=1 len", len, 69);
        unsigned char expect[69];
        expect[0]=0x80; expect[1]=0x11; expect[2]=0x01; expect[3]=0x00; expect[4]=0x01;
        memcpy(expect+5, h, 32);
        memset(expect+37, 0, 32);
        cbyte("getheaders count=1 bytes (unchanged)", out, expect, 69);
    }
    {
        unsigned char loc[32]={0}, stop[32]={0}, out[512];
        cki("getheaders count=0 rejected", p2p_getheaders(out, loc, 0, stop), -1);
        cki("getheaders count=253 rejected", p2p_getheaders(out, loc, 253, stop), -1);
        unsigned char loc252[252*32]; memset(loc252,0,sizeof loc252);
        unsigned char out252[252*32+64];
        cki("getheaders count=252 accepted (varint boundary)", p2p_getheaders(out252, loc252, 252, stop), 5+252*32+32);
    }

    /* ============================================================
     * Part 2: locator_build edge cases (empty store, single block)
     * ============================================================ */
    {
        struct St st; memset(&st, 0, sizeof st);
        cki("store_init (for empty-store locator check)", store_init(&st), 1);
        unsigned char hashes[LOCATOR_MAX*32];
        cki("locator_build on empty store", locator_build(&st, hashes), 0);
        unlink("index.dat");
    }
    {
        struct St st; memset(&st, 0, sizeof st);
        cki("store_init (single-block store)", store_init(&st), 1);
        unsigned char h0[32]; fill_hash(h0, 0);
        unsigned char raw[16]; memset(raw, 0xAB, sizeof raw);
        cki("append genesis", store_append(&st, h0, raw, sizeof raw), 0);
        unsigned char hashes[LOCATOR_MAX*32];
        long n = locator_build(&st, hashes);
        cki("locator_build single-block count", n, 1);
        cbyte("locator_build single-block hash == genesis", hashes, h0, 32);
        unlink("blk00000.dat"); unlink("index.dat");
    }

    /* ============================================================
     * Part 3: locator_build doubling-gap heights on a 50-height chain
     *   tip=49; hand-derived (and independently re-traced) expected
     *   height sequence per the gap rule "1,1,2,4,8,16,... (doubles
     *   starting at the 3rd transition)":
     *     49 -1-> 48 -1-> 47 -2-> 45 -4-> 41 -8-> 33 -16-> 17 -32-> 0
     *   i.e. heights = [49,48,47,45,41,33,17,0], 8 entries total.
     * ============================================================ */
    {
        struct St st; memset(&st, 0, sizeof st);
        cki("store_init (50-height chain)", store_init(&st), 1);
        unsigned char all_hashes[50][32];
        unsigned char raw[8];
        for (int h=0; h<50; h++){
            fill_hash(all_hashes[h], h);
            memset(raw, (unsigned char)h, sizeof raw);
            long r = store_append(&st, all_hashes[h], raw, sizeof raw);
            if (r != h){ printf("FAIL append height %d got %ld\n", h, r); failures++; }
        }

        unsigned char hashes[LOCATOR_MAX*32];
        long n = locator_build(&st, hashes);
        cki("locator_build(tip=49) count", n, 8);

        int expected_heights[8] = {49,48,47,45,41,33,17,0};
        for (int i=0;i<8 && i<n;i++){
            char lbl[64]; snprintf(lbl, sizeof lbl, "locator entry %d == height %d hash", i, expected_heights[i]);
            cbyte(lbl, hashes+i*32, all_hashes[expected_heights[i]], 32);
        }
        ckm("locator_build never exceeds LOCATOR_MAX", n <= LOCATOR_MAX);

        unlink("blk00000.dat"); unlink("index.dat");
    }

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    rmdir(dir);
    return failures?1:0;
}
