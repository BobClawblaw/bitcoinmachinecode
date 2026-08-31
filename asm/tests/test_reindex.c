/* tests/test_reindex.c -- Core -reindex: index.dat, headers.dat and
 * chainwork.dat are rebuilt from the blk*.dat frames alone.
 *
 * The archive under test is deliberately hostile: frames in shuffled order
 * across two files, one block appended twice, an orphan whose parent no
 * frame carries, a stale fork off height 7, a frame whose header fails its
 * own nBits, and garbage after the last frame of the second file. The rebuilt
 * index must contain exactly the twelve best-chain blocks at their heights,
 * every derived file must agree with the frames, the counters must name each
 * kind of junk, and -- the invariant the store's append path depends on --
 * the tip frame must be the physically last frame of the highest file.
 *
 * The one-shot rule (-reindex is a request, not a mode) is the same predicate
 * -reindex-chainstate uses, checked the same way. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "../daemon/archive_reindex.h"

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
extern void sha256d(u8 out[32], const void* p, unsigned long n);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

#define MAGIC 0xdab5bffau                 /* regtest message-start as the store's dword */
#define BITS  0x207fffffu                 /* regtest: every hash passes */
#define NBLK  12
#define BODY  20                          /* fake transaction bytes after the header */

typedef struct { u8 raw[80 + BODY]; u8 hash[32]; } blk_t;

static void mk_block(blk_t* b, const u8 prev[32], u32 nonce, u32 bits){
    /* regtest's target (0x207fffff) still rejects every hash whose top byte
     * is >= 0x80, so blocks must be "mined": bump the nonce until the hash
     * clears it. Blocks carrying a real difficulty are left unmined on
     * purpose -- they are the bad-PoW case. */
  for (;; nonce++){
    memset(b->raw, 0, sizeof b->raw);
    b->raw[0] = 1;                                     /* version */
    memcpy(b->raw + 4, prev, 32);
    memset(b->raw + 36, 0x33, 32);                      /* merkle root */
    b->raw[36] = (u8)nonce;                             /* make every merkle unique */
    b->raw[68] = 0x11; b->raw[69] = 0x22;               /* time */
    memcpy(b->raw + 72, &bits, 4);
    memcpy(b->raw + 76, &nonce, 4);
    memset(b->raw + 80, 0xAB, BODY);
    sha256d(b->hash, b->raw, 80);
    if (bits != BITS || b->hash[31] < 0x80) return;
  }
}
static void put_frame(FILE* f, const blk_t* b, u32 magic){
    u32 len = sizeof b->raw;
    fwrite(&len, 4, 1, f); fwrite(&magic, 4, 1, f); fwrite(b->raw, 1, sizeof b->raw, f);
}
static long fsize(const char* p){ struct stat s; return stat(p, &s) == 0 ? (long)s.st_size : -1; }
static int should_reindex(int flag_set, int marker_present){ return flag_set && !marker_present; }

int main(void){
    char dir[] = "/tmp/bmc_reindex_XXXXXX";
    if (!mkdtemp(dir)){ perror("mkdtemp"); return 1; }
    char p0[4200], p1[4200], px[4200];
    snprintf(p0, sizeof p0, "%s/blk00000.dat", dir);
    snprintf(p1, sizeof p1, "%s/blk00001.dat", dir);

    /* the best chain: 0..11 */
    blk_t c[NBLK]; u8 zero[32] = {0};
    mk_block(&c[0], zero, 0, BITS);
    for (int i = 1; i < NBLK; i++) mk_block(&c[i], c[i-1].hash, (u32)i, BITS);
    blk_t fork; mk_block(&fork, c[7].hash, 777, BITS);          /* stale: height 8, less total work than 11 */
    blk_t orphan; u8 nowhere[32]; memset(nowhere, 0x5a, 32); mk_block(&orphan, nowhere, 999, BITS);
    blk_t badpow; mk_block(&badpow, c[3].hash, 4, 0x1d00ffffu); /* mainnet difficulty: this hash will not clear it */

    printf("== 1. a hostile archive: shuffled, duplicated, forked, orphaned, garbage tail ==\n");
    FILE* f = fopen(p0, "wb");
    int order0[] = { 5, 0, 7, 1, 5 /*dup*/, 3, 2, 9, 4, 6, 8 };
    for (unsigned i = 0; i < sizeof order0 / sizeof *order0; i++) put_frame(f, &c[order0[i]], MAGIC);
    put_frame(f, &orphan, MAGIC);
    put_frame(f, &badpow, MAGIC);
    fclose(f);
    f = fopen(p1, "wb");
    put_frame(f, &c[10], MAGIC);
    put_frame(f, &c[11], MAGIC);
    put_frame(f, &fork, MAGIC);                                 /* the stale fork is the LAST frame on disk */
    fputs("trailing-garbage", f);                                /* no magic: the scanner must stop here, not crash */
    fclose(f);
    long size1_before = fsize(p1);

    archive_reindex_stats st; char err[256] = {0};
    int rc = archive_reindex(dir, c[0].hash, MAGIC, &st, err, sizeof err);
    ck("reindex succeeds", rc == 0);
    if (rc != 0) printf("      error: %s\n", err);
    ck("tip is height 11", st.tip == 11);
    ck("two files scanned", st.files == 2);
    ck("the duplicate was collapsed", st.duplicates == 1);
    ck("the orphan was counted and excluded", st.orphans == 1);
    ck("the stale fork was counted and excluded", st.stale == 1);
    ck("the bad-PoW frame was counted and excluded", st.bad_pow == 1);
    ck("the garbage tail was reported", st.truncated_files == 1);

    printf("== 2. the rebuilt files agree with the frames ==\n");
    snprintf(px, sizeof px, "%s/index.dat", dir);
    ck("index.dat is 12 records", fsize(px) == 12 * 48);
    u8 idx[12 * 48]; int fd = open(px, O_RDONLY); (void)!read(fd, idx, sizeof idx); close(fd);
    int idx_ok = 1;
    for (int h = 0; h < NBLK; h++){
        const u8* r = idx + h * 48;
        if (memcmp(r, c[h].hash, 32)) { idx_ok = 0; printf("      h=%d wrong hash\n", h); continue; }
        u32 fno, size; u64 pos; memcpy(&fno, r + 32, 4); memcpy(&pos, r + 36, 8); memcpy(&size, r + 44, 4);
        char fp[4200]; snprintf(fp, sizeof fp, "%s/blk%05u.dat", dir, fno);
        u8 frame[8 + 80 + BODY]; int ff = open(fp, O_RDONLY); (void)!pread(ff, frame, sizeof frame, (off_t)pos); close(ff);
        if (size != 80 + BODY || memcmp(frame + 8, c[h].raw, 80 + BODY)) { idx_ok = 0; printf("      h=%d record does not point at its frame\n", h); }
    }
    ck("every height's record points at that block's frame", idx_ok);
    snprintf(px, sizeof px, "%s/headers.dat", dir);
    ck("headers.dat is 12 x 112", fsize(px) == 12 * 112);
    u8 hdr[12 * 112]; fd = open(px, O_RDONLY); (void)!read(fd, hdr, sizeof hdr); close(fd);
    int hdr_ok = 1;
    for (int h = 0; h < NBLK; h++) if (memcmp(hdr + h * 112, c[h].raw, 80) || memcmp(hdr + h * 112 + 80, c[h].hash, 32)) hdr_ok = 0;
    ck("each header record is [80-byte header][hash]", hdr_ok);
    snprintf(px, sizeof px, "%s/chainwork.dat", dir);
    ck("chainwork.dat is 12 x 16", fsize(px) == 12 * 16);
    u8 cw[12 * 16]; fd = open(px, O_RDONLY); (void)!read(fd, cw, sizeof cw); close(fd);
    int cw_ok = 1;
    for (int h = 1; h < NBLK; h++){
        int gt = 0; for (int i = 15; i >= 0; i--){ if (cw[h*16+i] > cw[(h-1)*16+i]){ gt = 1; break; } if (cw[h*16+i] < cw[(h-1)*16+i]) break; }
        if (!gt) cw_ok = 0;
    }
    ck("cumulative work strictly increases with height", cw_ok);
    /* regtest work per block is 2 (target 2^255): 12 blocks = 24 */
    ck("work at the tip is 12 x 2 (regtest block work)", cw[11*16] == 24 && cw[11*16+1] == 0);

    printf("== 3. append safety ==\n");
    { const u8* r = idx + 11 * 48; u32 fno, size; u64 pos; memcpy(&fno, r + 32, 4); memcpy(&pos, r + 36, 8); memcpy(&size, r + 44, 4);
      ck("the tip frame was re-appended (it was not physically last)", st.tip_reappended == 1);
      ck("the tip record now points at the end of the highest file", fno == 1 && pos == (u64)size1_before && (long)(pos + 8 + size) == fsize(p1));
      u8 frame[8 + 80 + BODY]; int ff = open(p1, O_RDONLY); (void)!pread(ff, frame, sizeof frame, (off_t)pos); close(ff);
      ck("and the copy is the tip block", !memcmp(frame + 8, c[11].raw, 80 + BODY)); }

    printf("== 4. the originals are kept ==\n");
    snprintf(px, sizeof px, "%s/blk00000.dat", dir);
    ck("blk files are untouched apart from the appended tip copy", fsize(px) == 13 * (8 + 80 + BODY));
    snprintf(px, sizeof px, "%s/index.dat.pre-reindex", dir);
    ck("no index.dat.pre-reindex when there was no index.dat", fsize(px) < 0);
    /* run it again: now index.dat exists, so a .pre-reindex must appear and the result must be identical */
    rc = archive_reindex(dir, c[0].hash, MAGIC, &st, err, sizeof err);
    ck("a second rebuild succeeds", rc == 0);
    ck("...keeps the previous index.dat as index.dat.pre-reindex", fsize(px) == 12 * 48);
    ck("...and is idempotent (tip already last: no second copy)", st.tip == 11 && st.tip_reappended == 0 && fsize(p1) == size1_before + 8 + 80 + BODY);

    printf("== 5. a missing genesis is an error, not a silent empty index ==\n");
    { u8 fake[32]; memset(fake, 0x77, 32); rc = archive_reindex(dir, fake, MAGIC, &st, err, sizeof err);
      ck("refused with a reason", rc == -1 && strstr(err, "genesis") != 0);
      snprintf(px, sizeof px, "%s/index.dat", dir);
      ck("and nothing was replaced", fsize(px) == 12 * 48); }

    printf("== 6. one-shot: a request, not a mode ==\n");
    ck("flag set, no marker: reindex", should_reindex(1, 0) == 1);
    ck("flag set, marker present: do NOT reindex again", should_reindex(1, 1) == 0);
    ck("flag clear: never", should_reindex(0, 0) == 0 && should_reindex(0, 1) == 0);

    char cmd[4300]; snprintf(cmd, sizeof cmd, "rm -rf %s", dir); (void)!system(cmd);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
