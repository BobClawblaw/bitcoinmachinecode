/* tests/test_txindex_tail.c -- the txid index's incremental tail
 * (daemon/tx_index_tail.c).
 *
 * The properties that matter, each replayed here:
 *   - boot BACKFILLS the gap between the base index's to_height and the
 *     archive tip (this is also what closes the offline-build -> deploy gap
 *     and catches blocks that arrived while the daemon was down);
 *   - per-block appends are STRICTLY MONOTONIC by height, so a full UTXO
 *     replay revisiting old heights appends nothing (the 29 GB-duplicate
 *     failure shape);
 *   - a height ahead of covered+1 backfills the middle from the archive, so
 *     coverage stays contiguous;
 *   - a torn final record (crash mid-write) is ignored on reboot and its
 *     block is re-appended whole;
 *   - no base txindex.dat => disabled (never backfill-from-genesis into an
 *     unsorted file);
 *   - a base REBUILT past the tail truncates the tail (records folded in).
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "../daemon/txi_format.h"

extern long store_init(void* st);
extern long store_append(void* st, const unsigned char hash[32], const void* raw, long len);
extern int  store_rd_init(void* st);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
extern void txit_boot(void* store_buf);
extern void txit_on_block(void* store_buf, long h, const unsigned char* blk, long blen);

static int failures = 0;
static void ck(const char* l, long long g, long long e){
    if (g==e) printf("PASS %s (got %lld)\n", l, g);
    else { printf("FAIL %s got=%lld exp=%lld\n", l, g, e); failures++; }
}

static unsigned char store_buf[4096];

/* One minimal legacy transaction: version | 1 input (null prevout, empty
 * scriptSig) | 1 output (8B value, 1-byte script) | locktime. 64 bytes.
 * `tag` varies the bytes so every tx has a distinct txid. */
static long mk_tx(unsigned char* p, int tag){
    unsigned char* s = p;
    *p++=1; *p++=0; *p++=0; *p++=(unsigned char)tag;       /* version (tag varies it) */
    *p++=1;                                                /* nin */
    memset(p, (unsigned char)(0x10+tag), 36); p += 36;     /* prevout */
    *p++=0;                                                /* scriptSig len */
    *p++=0xff; *p++=0xff; *p++=0xff; *p++=0xff;            /* sequence */
    *p++=1;                                                /* nout */
    memset(p, (unsigned char)(0x40+tag), 8); p += 8;       /* value */
    *p++=1; *p++=0x51;                                     /* script: OP_TRUE */
    *p++=0; *p++=0; *p++=0; *p++=0;                        /* locktime */
    return p - s;
}

/* A parseable "block": 80-byte header + varint ntx + ntx transactions. */
static long mk_block(unsigned char* b, int height_tag, int ntx){
    memset(b, (unsigned char)height_tag, 80);
    b[80] = (unsigned char)ntx;
    long o = 81;
    for (int t = 0; t < ntx; t++) o += mk_tx(b + o, height_tag*8 + t);
    return o;
}

static long tail_size(void){
    struct stat sb;
    return stat(TXI_TAIL_FILE, &sb) == 0 ? (long)sb.st_size : -1;
}

/* the base index: a VALID header describing zero records covering [0,to].
 * The tail module reads only the header, so this is exactly the contract. */
static void write_base(long to){
    unsigned char h[TXI_HDR]; memset(h, 0, sizeof h);
    memcpy(h, TXI_MAGIC, 8);
    unsigned long long so = TXI_HDR;
    for (int i = 0; i < 8; i++) h[16+i] = (unsigned char)(so >> (8*i));
    for (int i = 0; i < 4; i++) h[36+i] = (unsigned char)((unsigned)to >> (8*i));
    int fd = open("txindex.dat", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (write(fd, h, sizeof h) != (long)sizeof h) _exit(97);
    close(fd);
}

int main(void){
    tt_isolate();
    memset(store_buf, 0, sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);

    static unsigned char blk[8][4096]; long blen[8];
    unsigned char hash[8][32];
    int ntx_at[8] = {1, 2, 3, 2, 1, 2, 0, 0};
    for (int h = 0; h < 6; h++){
        blen[h] = mk_block(blk[h], h, ntx_at[h]);
        memset(hash[h], 0xA0 + h, 32);
    }

    /* archive: h0..h2 stored before "boot" */
    for (int h = 0; h < 3; h++)
        ck("store_append", store_append(store_buf, hash[h], blk[h], blen[h]), h);
    store_rd_init(store_buf);

    /* no base index => disabled: nothing appears no matter what happens */
    txit_boot(store_buf);
    txit_on_block(store_buf, 3, blk[3], blen[3]);
    ck("no base index -> tail disabled, no file growth", tail_size() <= 0, 1);

    /* base covers h0 only; boot must backfill h1..h2 from the archive */
    write_base(0);
    txit_boot(store_buf);
    long expect = (long)(ntx_at[1] + ntx_at[2]) * TXI_REC;
    ck("boot backfilled h1..h2", tail_size(), expect);

    /* the backfilled records carry the real txids, heights and extents */
    {
        unsigned char rec[TXI_REC], want[32], scratch[4096];
        int fd = open(TXI_TAIL_FILE, O_RDONLY);
        ck("tail readable", fd >= 0, 1);
        ck("first record read", read(fd, rec, TXI_REC), TXI_REC);
        /* h1's first tx starts right after the 80B header + 1B count */
        ck("rec offset", (long)(rec[12] | rec[13]<<8), 81);
        unsigned len = rec[16] | rec[17]<<8;
        ck("rec height", (long)(rec[8] | rec[9]<<8), 1);
        ck("txid matches a fresh tx_txid over those bytes",
           tx_txid(want, blk[1] + 81, len, scratch, sizeof scratch) == 1 &&
           memcmp(want, rec, 8) == 0, 1);
        close(fd);
    }

    /* live append: h3 grows the tail; the SAME height again does not (this
     * is what makes a from-genesis UTXO replay harmless) */
    ck("store_append h3", store_append(store_buf, hash[3], blk[3], blen[3]), 3);
    txit_on_block(store_buf, 3, blk[3], blen[3]);
    expect += (long)ntx_at[3] * TXI_REC;
    ck("h3 appended", tail_size(), expect);
    txit_on_block(store_buf, 3, blk[3], blen[3]);
    ck("h3 again -> no growth", tail_size(), expect);
    txit_on_block(store_buf, 1, blk[1], blen[1]);
    ck("old height -> no growth", tail_size(), expect);

    /* a burst: archive advances to h5, but the caller only hands us h5 --
     * h4 must be backfilled from the archive so coverage stays contiguous */
    ck("store_append h4", store_append(store_buf, hash[4], blk[4], blen[4]), 4);
    ck("store_append h5", store_append(store_buf, hash[5], blk[5], blen[5]), 5);
    txit_on_block(store_buf, 5, blk[5], blen[5]);
    expect += (long)(ntx_at[4] + ntx_at[5]) * TXI_REC;
    ck("gap h4 backfilled with h5", tail_size(), expect);

    /* crash shape: the write for h5 was lost entirely and h4's single
     * record was torn 7 bytes short. Reboot must truncate the torn bytes
     * back to the record grid (a partial record mid-file would shift every
     * later record off it), see coverage ending at h3, and backfill h4..h5
     * whole -- landing at exactly the full size again. */
    ck("torn-tail setup",
       truncate(TXI_TAIL_FILE, expect - (long)ntx_at[5] * TXI_REC - 7), 0);
    txit_boot(store_buf);
    ck("torn tail rebooted to full coverage", tail_size(), expect);

    /* a base rebuilt past everything: the tail folds away */
    write_base(5);
    txit_boot(store_buf);
    ck("tail truncated after base rebuild", tail_size(), 0);

    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures ? 1 : 0;
}
