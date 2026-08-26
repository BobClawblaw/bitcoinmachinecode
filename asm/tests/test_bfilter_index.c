/* tests/test_bfilter_index.c -- the persistent BIP158 filter index
 * (daemon/bfilter_index.c).
 *
 * The oracle differential (filters + chained headers byte-identical to
 * Core over real blocks) ran at build time; what THIS test pins is the
 * index machinery itself:
 *   1. create/append/get round-trip, with the header chain equal to a
 *      manual bf_header fold;
 *   2. torn-tail reconciliation: a partial idx record AND orphan data
 *      bytes are truncated away, and appends continue on the grid;
 *   3. lazy adoption: denied while the gap to the tip exceeds the undo
 *      window, taken when it closes, gap filled through undo records
 *      (stubbed here), tail appended per block;
 *   4. reorg truncate drops records and the chain re-appends cleanly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "../block_filter.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern int  store_rd_init(void* st);
extern void sha256d(u8 out[32], const void* msg, long long len);

extern long bfi_open(int rw);
extern int  bfi_create(void);
extern int  bfi_append(const u8* filter, unsigned long flen);
extern int  bfi_get(long h, u8* out, unsigned long cap, unsigned long* flen, u8 header[32]);
extern long bfi_count(void);
extern int  bfi_active(void);
extern void bfi_close(void);
extern void bfi_on_block(void* store_buf, long h, const u8* blk, unsigned long blen);
extern void bfi_on_truncate(long new_tip);
extern long bfi_probe_count(void);

/* stub undo_replay: serves one fixed prevout script per height, so the
 * expected filter is computable independently */
static u8 g_stub_spk[25];
long undo_replay(long height,
                 int (*cb)(void*, const u8*, u32, u64, u32, u8, const u8*, unsigned short),
                 void* ctx){
    (void)height;
    static u8 tid[32];
    memset(tid, 0x11, 32);
    cb(ctx, tid, 0, 1000, 1, 0, g_stub_spk, 25);
    return 1;
}

static int failures = 0;
static void ck(const char* l, int cond){
    if (cond) printf("  ok  %s\n", l);
    else { printf("  FAIL %s\n", l); failures++; }
}

static unsigned char store_buf[4096];

/* a parseable block: header + 1 minimal tx with one P2PKH-ish output */
static long mk_block(u8* b, int tag){
    memset(b, (u8)tag, 80);
    b[80] = 1;                                   /* ntx */
    long o = 81;
    b[o++]=1; b[o++]=0; b[o++]=0; b[o++]=0;      /* version */
    b[o++]=1;                                    /* nin */
    memset(b+o, (u8)(0x50+tag), 36); o += 36;    /* outpoint */
    b[o++]=0;                                    /* scriptSig */
    b[o++]=0xff; b[o++]=0xff; b[o++]=0xff; b[o++]=0xff;
    b[o++]=1;                                    /* nout */
    memset(b+o, 1, 8); o += 8;                   /* value */
    b[o++]=25;                                   /* spk len */
    b[o]=0x76; b[o+1]=0xa9; b[o+2]=0x14; memset(b+o+3, 0x60+tag, 20);
    b[o+23]=0x88; b[o+24]=0xac; o += 25;
    b[o++]=0; b[o++]=0; b[o++]=0; b[o++]=0;      /* locktime */
    return o;
}

static long expected_filter(const u8* blk, long blen, u8* out, unsigned long cap){
    u8 hash[32]; sha256d(hash, blk, 80);
    bf_script pv = { g_stub_spk, 25 };
    return bf_basic_build(blk, (unsigned long)blen, hash, &pv, 1, out, cap);
}

extern void bfi_set_undo_replay(long (*)(long, int (*)(void*, const u8*, u32, u64, u32, u8, const u8*, unsigned short), void*));

int main(void){
    tt_isolate();
    bfi_set_undo_replay(undo_replay);
    g_stub_spk[0]=0x76; g_stub_spk[1]=0xa9; g_stub_spk[2]=0x14;
    memset(g_stub_spk+3, 0x99, 20); g_stub_spk[23]=0x88; g_stub_spk[24]=0xac;

    printf("== 1: create / append / get, header chain ==\n");
    ck("create", bfi_create() == 1);
    static u8 f1[64] = {1,2,3,4,5}, f2[64] = {9,8,7};
    ck("append f1", bfi_append(f1, 5) == 1);
    ck("append f2", bfi_append(f2, 3) == 1);
    static u8 got[1<<16]; unsigned long gl; u8 hdr0[32], hdr1[32];
    ck("get 0", bfi_get(0, got, sizeof got, &gl, hdr0) == 1 && gl == 5 && !memcmp(got, f1, 5));
    ck("get 1", bfi_get(1, got, sizeof got, &gl, hdr1) == 1 && gl == 3 && !memcmp(got, f2, 3));
    { u8 z[32] = {0}, e0[32], e1[32];
      bf_header(f1, 5, z, e0);
      bf_header(f2, 3, e0, e1);
      ck("header chain matches a manual fold", !memcmp(hdr0, e0, 32) && !memcmp(hdr1, e1, 32)); }
    ck("probe count 2", bfi_probe_count() == 2);
    bfi_close();

    printf("\n== 2: torn tail reconciles ==\n");
    { int ifd = open("bfilters.idx", O_RDWR); struct stat s; fstat(ifd, &s);
      /* append 20 junk bytes (a torn record) and 7 orphan data bytes */
      pwrite(ifd, "junkjunkjunkjunkjunk", 20, s.st_size); close(ifd);
      int dfd = open("bfilters.dat", O_WRONLY|O_APPEND); (void)!write(dfd, "orphans", 7); close(dfd); }
    ck("reopen reconciles to 2", bfi_open(1) == 2);
    ck("append still works on the grid", bfi_append(f1, 5) == 1 && bfi_count() == 3);
    ck("record 2 reads back", bfi_get(2, got, sizeof got, &gl, hdr0) == 1 && gl == 5);
    bfi_close();
    { unlink("bfilters.idx"); unlink("bfilters.dat"); }

    printf("\n== 3: lazy adoption + undo gap close + tail ==\n");
    memset(store_buf, 0, sizeof store_buf);
    ck("store_init", store_init(store_buf) == 1);
    static u8 blk[8][4096]; long blen[8]; u8 bh[8][32];
    for (int h = 0; h < 6; h++){
        blen[h] = mk_block(blk[h], h);
        memset(bh[h], 0xB0 + h, 32);
        ck("store_append", store_append(store_buf, bh[h], blk[h], blen[h]) == h);
    }
    store_rd_init(store_buf);
    /* no files yet: on_block is a silent no-op */
    bfi_on_block(store_buf, 5, blk[5], (unsigned long)blen[5]);
    ck("no files -> stays inactive", !bfi_active());
    /* builder produces 0..2, then the daemon adopts at tip 5 (gap 3 <= 144)
     * and closes 3..4 from (stubbed) undo before appending 5 */
    ck("builder create", bfi_create() == 1);
    for (int h = 0; h < 3; h++){
        static u8 f[1<<16];
        long fl = expected_filter(blk[h], blen[h], f, sizeof f);
        ck("builder append", fl > 0 && bfi_append(f, (unsigned long)fl) == 1);
    }
    bfi_close();
    bfi_on_block(store_buf, 5, blk[5], (unsigned long)blen[5]);
    ck("adopted", bfi_active());
    ck("gap closed + tip appended: count 6", bfi_count() == 6);
    { static u8 ef[1<<16]; long efl = expected_filter(blk[4], blen[4], ef, sizeof ef);
      ck("gap-closed record 4 content", efl > 0 &&
         bfi_get(4, got, sizeof got, &gl, hdr0) == 1 && (long)gl == efl && !memcmp(got, ef, gl)); }

    printf("\n== 4: reorg truncate + re-append ==\n");
    bfi_on_truncate(3);
    ck("truncated to 4 records", bfi_count() == 4);
    bfi_on_block(store_buf, 5, blk[5], (unsigned long)blen[5]);
    ck("re-closed to 6", bfi_count() == 6);
    { u8 h5a[32], h5b[32];
      ck("record 5 present again", bfi_get(5, got, sizeof got, &gl, h5a) == 1);
      /* header chain re-derives identically */
      static u8 ef[1<<16]; long efl = expected_filter(blk[5], blen[5], ef, sizeof ef);
      u8 h4[32];
      ck("prev record header read", bfi_get(4, got, sizeof got, &gl, h4) == 1);
      bf_header(ef, (unsigned long)efl, h4, h5b);
      ck("chained header identical after the reorg round-trip", !memcmp(h5a, h5b, 32)); }

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
