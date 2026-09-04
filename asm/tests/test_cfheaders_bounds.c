/* STO-6 (audit 2026-09-03): BIP157 reply framing and range limits.
 *
 * Three defects lived in daemon/serve_cfilters.c, all reachable from a normal
 * light client:
 *
 *   (a) When the index could not supply the whole requested range, the count
 *       varint was rewritten IN PLACE -- cf_put_varint(out + w, got) -- after
 *       the hashes had already been laid down at the offset the ORIGINAL
 *       varint's width implied. With n >= 253 and got < 253 the replacement is
 *       one byte where three were reserved, so two stale bytes sit between the
 *       count and the first hash and no peer can parse the message.
 *
 *   (b) getcfheaders was clamped to 1000 (Core's MAX_GETCFILTERS_SIZE) rather
 *       than 2000 (MAX_GETCFHEADERS_SIZE), and any clamp keeps the REQUESTED
 *       stop_hash in the reply -- so a compliant client, which checks
 *       count == stop_height - start_height + 1, rejects the message.
 *
 *   (c) A missing filter at start-1 left prev_header all-zero, which is the
 *       legitimate value only at height 0, so the client chained every header
 *       in the range off the wrong root.
 *
 * The fixture is a synthetic filter index written straight to disk in the
 * layout cf_open/cf_read read, so nothing here depends on the indexer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
extern int serve_cfilters(int fd, int kind, const u8* pl, unsigned long plen);
extern void serve_cfilters_set_enabled(int on);

static int failures = 0;
static void ok(int c, const char* what){
    printf("  %s  %s\n", c ? "ok " : "FAIL", what);
    if (!c) failures++;
}

/* ---- stubs the serve path calls out to ---- */
static u8   g_last[1<<20];
static long g_last_len = -1;
static int  g_writes   = 0;
static char g_last_cmd[16];

long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen){
    (void)fd;
    g_writes++;
    memset(g_last_cmd, 0, sizeof g_last_cmd);
    memcpy(g_last_cmd, cmd, cmdlen < 15 ? cmdlen : 15);
    g_last_len = plen;
    if (plen <= sizeof g_last) memcpy(g_last, pl, plen);
    return (long)plen + 24;
}
/* The fixture encodes a height in the first 4 bytes of every block hash. */
long serve_height_of_hash(const u8 h[32]){
    long v = 0;
    for (int i = 0; i < 4; i++) v |= (long)h[i] << (8*i);
    return v;
}

#define BFI_HDR 48
#define BFI_REC 48
#define FLEN     4          /* every synthetic filter is 4 bytes */

static void hash_for(long h, u8 out[32]){
    memset(out, 0, 32);
    for (int i = 0; i < 4; i++) out[i] = (u8)(h >> (8*i));
    out[8] = 0xa5;          /* so it is never all-zero (cf_hash_fd's presence test) */
}

/* Write bfilters.idx / bfilters.dat / index.dat for `count` heights. */
static void build_index(long count){
    unlink("bfilters.idx"); unlink("bfilters.dat"); unlink("index.dat");
    int ifd = open("bfilters.idx", O_RDWR|O_CREAT|O_TRUNC, 0644);
    int dfd = open("bfilters.dat", O_RDWR|O_CREAT|O_TRUNC, 0644);
    int bfd = open("index.dat",    O_RDWR|O_CREAT|O_TRUNC, 0644);
    u8 hdr[BFI_HDR]; memset(hdr, 0, sizeof hdr);
    memcpy(hdr, "BMCBFIX1", 8);
    for (int i = 0; i < 8; i++) hdr[8+i] = (u8)((unsigned long long)count >> (8*i));
    (void)!write(ifd, hdr, BFI_HDR);
    for (long h = 0; h < count; h++){
        u8 f[FLEN]; for (int i = 0; i < FLEN; i++) f[i] = (u8)(h + i);
        long off = (long)h * FLEN;
        (void)!pwrite(dfd, f, FLEN, off);
        u8 rec[BFI_REC]; memset(rec, 0, sizeof rec);
        for (int i = 0; i < 8; i++) rec[i]   = (u8)((unsigned long long)off >> (8*i));
        for (int i = 0; i < 4; i++) rec[8+i] = (u8)((unsigned)FLEN >> (8*i));
        rec[16] = (u8)(h & 0xff); rec[17] = 0x5a;      /* a distinguishable header */
        (void)!pwrite(ifd, rec, BFI_REC, BFI_HDR + h*BFI_REC);
        u8 brec[48]; memset(brec, 0, sizeof brec);
        hash_for(h, brec);
        (void)!pwrite(bfd, brec, 48, h*48);
    }
    close(ifd); close(dfd); close(bfd);
}

/* getcfheaders payload: type(1) start(4) stop_hash(32) */
static unsigned mk_hdr_req(u8* p, unsigned start, long stop){
    p[0] = 0;
    for (int i = 0; i < 4; i++) p[1+i] = (u8)(start >> (8*i));
    hash_for(stop, p+5);
    return 37;
}

/* Read the count varint that follows type(1)+stop(32)+prev(32). */
static unsigned long long reply_count(unsigned* width){
    const u8* q = g_last + 65;
    if (q[0] < 0xfd){ *width = 1; return q[0]; }
    if (q[0] == 0xfd){ *width = 3; return (unsigned long long)q[1] | ((unsigned long long)q[2] << 8); }
    *width = 5;
    unsigned long long v = 0; for (int i = 0; i < 4; i++) v |= (unsigned long long)q[1+i] << (8*i);
    return v;
}

int main(void){
    tt_isolate();
    serve_cfilters_set_enabled(1);
    u8 req[64];

    printf("== a full, in-range request is served and frames correctly ==\n");
    build_index(2500);
    g_writes = 0; g_last_len = -1;
    serve_cfilters(3, 1, req, mk_hdr_req(req, 0, 252));      /* 253 blocks: the 3-byte varint boundary */
    ok(g_writes == 1 && strcmp(g_last_cmd, "cfheaders") == 0, "253-block request answered");
    {
        unsigned w = 0; unsigned long long c = reply_count(&w);
        ok(c == 253 && w == 3, "count is 253 in a 3-byte varint");
        ok(g_last_len == (long)(1 + 32 + 32 + 3 + 253*32),
           "payload length == header + count + exactly 253 hashes (no stale bytes)");
    }

    printf("== (b) 2000 blocks is Core's cfheaders limit, not 1000 ==\n");
    g_writes = 0;
    serve_cfilters(3, 1, req, mk_hdr_req(req, 0, 1999));
    ok(g_writes == 1, "a 2000-block getcfheaders is answered");
    { unsigned w = 0; ok(reply_count(&w) == 2000, "...with all 2000 hashes, not 1000"); }
    g_writes = 0;
    serve_cfilters(3, 1, req, mk_hdr_req(req, 0, 2000));
    ok(g_writes == 0, "a 2001-block getcfheaders is REFUSED, not silently clamped");

    printf("== (a) a range the index cannot cover is refused, not mis-framed ==\n");
    /* 300 filters on disk; ask for 0..299 -- fits -- then shrink the index to
     * 100 and ask again. n = 300 (3-byte varint), got = 100 (1-byte). */
    build_index(300);
    g_writes = 0;
    serve_cfilters(3, 1, req, mk_hdr_req(req, 0, 299));
    ok(g_writes == 1, "0..299 answered while the index holds 300");
    build_index(100);
    g_writes = 0;
    /* index.dat now only has 100 records, so resolve the stop hash by hand:
     * rebuild just that record so serve_height_of_hash still finds height 299. */
    serve_cfilters(3, 1, req, mk_hdr_req(req, 0, 299));
    ok(g_writes == 0, "0..299 against a 100-filter index sends NOTHING (was a mis-framed reply)");

    printf("== (c) an unavailable previous header is refused, not zeroed ==\n");
    build_index(300);
    g_writes = 0;
    serve_cfilters(3, 1, req, mk_hdr_req(req, 10, 20));
    ok(g_writes == 1, "start=10 answered when the filter at 9 exists");
    ok(memcmp(g_last + 33, "\0\0\0\0\0\0\0\0", 8) != 0, "...and prev_header is not all-zero");
    build_index(0);           /* no filters at all, but keep index.dat below */
    {   /* index.dat must still resolve the stop hash */
        int bfd = open("index.dat", O_RDWR|O_CREAT, 0644);
        for (long h = 0; h < 300; h++){ u8 b[48]; memset(b,0,48); hash_for(h,b); (void)!pwrite(bfd,b,48,h*48); }
        close(bfd);
    }
    g_writes = 0;
    serve_cfilters(3, 1, req, mk_hdr_req(req, 10, 20));
    ok(g_writes == 0, "start=10 with no filter at 9 sends NOTHING (was prev_header = 0)");

    printf("== cfcheckpt: a short checkpoint list is refused too ==\n");
    build_index(2500);
    { u8 c[64]; c[0] = 0; hash_for(2400, c+1);
      g_writes = 0;
      serve_cfilters(3, 2, c, 33);
      ok(g_writes == 1 && strcmp(g_last_cmd, "cfcheckpt") == 0, "cfcheckpt to 2400 answered (2 checkpoints)"); }
    build_index(1500);
    {   int bfd = open("index.dat", O_RDWR|O_CREAT, 0644);
        for (long h = 0; h < 2500; h++){ u8 b[48]; memset(b,0,48); hash_for(h,b); (void)!pwrite(bfd,b,48,h*48); }
        close(bfd);
        u8 c[64]; c[0] = 0; hash_for(2400, c+1);
        g_writes = 0;
        serve_cfilters(3, 2, c, 33);
        ok(g_writes == 0, "cfcheckpt to 2400 with only 1500 filters sends NOTHING"); }

    printf("\n%s (%d failures)\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
