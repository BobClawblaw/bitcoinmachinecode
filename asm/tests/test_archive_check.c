/* test_archive_check.c -- boot verification (-checkblocks/-checklevel), hole
 * detection, and the prune budget->height conversion.
 *
 * BUILDS ITS OWN FIXTURE, in its own scratch directory, and never opens
 * anything under the production datadir. The test that missed the ~600GB
 * archive loss on 2026-08-18 pointed at live block files through symlinks and
 * asserted only on index.dat counts; a test for archive integrity that does
 * not own its data is worse than no test at all.
 *
 * The genesis block below is the real mainnet one (same bytes as
 * test_block_genesis.c), so the level-4 pass is a genuine PoW+merkle check
 * against real chain data, not a self-consistent forgery.
 *
 * THE FIXTURE MUST USE THE REAL ON-DISK FORMAT. Every block is written as
 * [u32 len LE][u32 magic 0xd9b4bef9][payload], and index.dat's data_pos points
 * at the FRAME, not the payload (see bitcoin_store.asm's format block). The
 * first version of this test wrote bare payloads at data_pos, which happened
 * to agree with a bug in archive_check -- so both were wrong together and the
 * test went green. A fixture that encodes the implementation's assumption
 * instead of the format tests nothing.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

extern long archive_check(long nblocks, int level);
extern long archive_first_hole(long upto);
extern long archive_prune_height_for_budget(long long budget_bytes);
#include "archive_verify.h"
extern void block_hash(unsigned char out[32], const unsigned char hdr[80]);

static int failures = 0;
static void cki(const char* lbl, long got, long exp){
    if (got==exp) printf("PASS: %s (got %ld)\n", lbl, got);
    else { printf("FAIL: %s got=%ld exp=%ld\n", lbl, got, exp); failures++; }
}

static const unsigned char GEN_HDR[80] = {
    0x01,0x00,0x00,0x00,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
    0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a,
    0x29,0xab,0x5f,0x49, 0xff,0xff,0x00,0x1d, 0x1d,0xac,0x2b,0x7c
};
static const unsigned char GEN_CB[204] = {
    0x01,0x00,0x00,0x00, 0x01,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xff,0xff,0xff,0xff, 0x4d,
    0x04,0xff,0xff,0x00,0x1d,0x01,0x04,0x45,0x54,0x68,0x65,0x20,0x54,0x69,0x6d,0x65,
    0x73,0x20,0x30,0x33,0x2f,0x4a,0x61,0x6e,0x2f,0x32,0x30,0x30,0x39,0x20,0x43,0x68,
    0x61,0x6e,0x63,0x65,0x6c,0x6c,0x6f,0x72,0x20,0x6f,0x6e,0x20,0x62,0x72,0x69,0x6e,
    0x6b,0x20,0x6f,0x66,0x20,0x73,0x65,0x63,0x6f,0x6e,0x64,0x20,0x62,0x61,0x69,0x6c,
    0x6f,0x75,0x74,0x20,0x66,0x6f,0x72,0x20,0x62,0x61,0x6e,0x6b,0x73,
    0xff,0xff,0xff,0xff,
    0x01,
    0x00,0xf2,0x05,0x2a,0x01,0x00,0x00,0x00, 0x43,
    0x41,0x04,0x67,0x8a,0xfd,0xb0,0xfe,0x55,0x48,0x27,0x19,0x67,0xf1,0xa6,0x71,0x30,
    0xb7,0x10,0x5c,0xd6,0xa8,0x28,0xe0,0x39,0x09,0xa6,0x79,0x62,0xe0,0xea,0x1f,0x61,
    0xde,0xb6,0x49,0xf6,0xbc,0x3f,0x4c,0xef,0x38,0xc4,0xf3,0x55,0x04,0xe5,0x1e,0xc1,
    0x12,0xde,0x5c,0x38,0x4d,0xf7,0xba,0x0b,0x8d,0x57,0x8a,0x4c,0x70,0x2b,0x6b,0xf1,
    0x1d,0x5f,0xac,
    0x00,0x00,0x00,0x00
};

/* Corrupt one byte by inverting it, so the change is guaranteed to be real
 * whatever the original value was. Returns 0 on success. */
static int flip_byte(int fd, long off){
    unsigned char b;
    if (pread(fd, &b, 1, off) != 1) return -1;
    b ^= 0xff;
    return (pwrite(fd, &b, 1, off) == 1) ? 0 : -1;
}

#define FRAME_LEN 8
#define MAGIC     0xd9b4bef9u

/* Write one block in the real on-disk framing at `off`; returns bytes written
 * (frame + payload) or -1. */
static long write_framed(int fd, long off, const unsigned char* body, unsigned dsz){
    unsigned char fr[FRAME_LEN];
    unsigned magic = MAGIC;
    memcpy(fr, &dsz, 4);
    memcpy(fr + 4, &magic, 4);
    if (pwrite(fd, fr, FRAME_LEN, off) != FRAME_LEN) return -1;
    if (pwrite(fd, body, dsz, off + FRAME_LEN) != (ssize_t)dsz) return -1;
    return FRAME_LEN + (long)dsz;
}

static void put_rec(unsigned char rec[48], const unsigned char h[32],
                    unsigned fno, unsigned long long pos, unsigned dsz){
    memset(rec,0,48);
    memcpy(rec,h,32);
    memcpy(rec+32,&fno,4);
    memcpy(rec+36,&pos,8);
    memcpy(rec+44,&dsz,4);
}

int main(void){
    printf("---- archive_check ----\n");
    const char* dir = "/storage/bitcoinmachinecode/asm/t_archchk";
    char cmd[512]; snprintf(cmd,sizeof cmd,"rm -rf %s && mkdir -p %s", dir, dir);
    if (system(cmd)!=0){ printf("FAIL: could not create scratch dir\n"); return 1; }
    if (chdir(dir)!=0){ printf("FAIL: chdir scratch\n"); return 1; }

    /* --- fixture: blk00000.dat = [real genesis][synthetic block] --- */
    unsigned char gen[285];
    memcpy(gen, GEN_HDR, 80); gen[80]=1; memcpy(gen+81, GEN_CB, 204);

    /* a synthetic block: a well-formed 80-byte header we hash ourselves, so
     * its index record is CORRECT (level 3 must pass) while its PoW is not
     * real (level 4 must fail). That difference is the only way to prove the
     * two levels actually do different work. */
    unsigned char syn[285];
    memcpy(syn, gen, 285);
    syn[76] ^= 0xff;    /* perturb the nonce -> hash changes, PoW no longer met */

    unsigned char gh[32], sh[32];
    block_hash(gh, gen);
    block_hash(sh, syn);

    int bf = open("blk00000.dat", O_RDWR|O_CREAT|O_TRUNC, 0644);
    if (bf<0){ printf("FAIL: create blk00000.dat\n"); return 1; }
    const long POS0 = 0, POS1 = FRAME_LEN + 285;
    if (write_framed(bf, POS0, gen, 285) < 0 ||
        write_framed(bf, POS1, syn, 285) < 0){ printf("FAIL: write framed bodies\n"); return 1; }
    close(bf);

    unsigned char r0[48], r1[48];
    put_rec(r0, gh, 0, (unsigned long long)POS0, 285);
    put_rec(r1, sh, 0, (unsigned long long)POS1, 285);
    int xf = open("index.dat", O_RDWR|O_CREAT|O_TRUNC, 0644);
    if (write(xf, r0, 48)!=48 || write(xf, r1, 48)!=48){ printf("FAIL: write index\n"); return 1; }
    close(xf);

    /* 1. level 0 does nothing at all */
    cki("checklevel=0 returns clean without reading", archive_check(0,0), 0);

    /* 2. levels 1 and 2 read only index.dat -- both records are well-formed */
    cki("checklevel=1 clean on a well-formed index", archive_check(0,1), 0);
    cki("checklevel=2 clean (layout is monotonic)",  archive_check(0,2), 0);

    /* 3. level 3 reads bodies; both hash to their index records */
    cki("checklevel=3 clean (bodies match the index)", archive_check(0,3), 0);

    /* 4. level 4 adds PoW+merkle: genesis passes, the perturbed block does not.
     *    checkblocks=1 restricts the check to the trailing block only. */
    cki("checklevel=4 on genesis alone is clean", archive_check(0,4)-1, 0);  /* 1 problem: the synthetic block */
    cki("checkblocks=1 checklevel=4 catches the bad PoW", archive_check(1,4), 1);
    cki("checkblocks=1 checklevel=3 passes the same block", archive_check(1,3), 0);

    /* 5. corruption. Two DIFFERENT failures, because they land at different
     *    levels and the distinction is the whole argument for the default.
     *
     *    (a) a corrupted HEADER changes block_hash -> level 3 catches it,
     *        level 1 (index only) cannot.
     *    (b) corrupted TRANSACTION DATA does NOT change block_hash, which
     *        digests only the 80-byte header -> level 3 is blind to it and
     *        only level 4's merkle recomputation notices. */
    /* FLIP the byte, never assign a constant: the first version of this test
     * wrote 0x00 into block 1's prevhash field, which is all zeros (it was
     * copied from genesis) -- so the "corruption" changed nothing and the test
     * reported that level 3 had missed a defect that was never introduced. */
    bf = open("blk00000.dat", O_RDWR);
    if (flip_byte(bf, POS1+FRAME_LEN+10)!=0) printf("FAIL: poison header write\n"); /* block 1's header */
    close(bf);
    cki("checklevel=1 misses a corrupted header (index-only)", archive_check(1,1), 0);
    cki("checklevel=3 catches the corrupted header",          archive_check(1,3), 1);
    bf = open("blk00000.dat", O_RDWR);            /* restore block 1 */
    if (pwrite(bf, syn, 285, POS1+FRAME_LEN)!=285) printf("FAIL: restore block 1\n");
    close(bf);
    cki("checklevel=3 clean again after restore", archive_check(1,3), 0);

    bf = open("blk00000.dat", O_RDWR);
    if (flip_byte(bf, POS0+FRAME_LEN+150)!=0) printf("FAIL: poison tx write\n"); /* genesis coinbase */
    close(bf);
    cki("checklevel=3 is BLIND to corrupted tx data (header-only hash)", archive_check(0,3), 0);
    cki("checklevel=4 catches it via the merkle root", archive_check(0,4), 2);
    bf = open("blk00000.dat", O_RDWR);            /* restore genesis */
    if (pwrite(bf, gen, 285, POS0+FRAME_LEN)!=285) printf("FAIL: restore genesis\n");
    close(bf);

    /* 5c. a corrupted FRAME is caught before the body is even hashed. This is
     *     the check whose absence let a wrong-offset reader mis-read every
     *     block in a healthy archive without noticing. */
    bf = open("blk00000.dat", O_RDWR);
    if (flip_byte(bf, POS1+4)!=0) printf("FAIL: poison magic\n");   /* frame magic */
    close(bf);
    cki("checklevel=3 catches a bad frame magic", archive_check(1,3), 1);
    bf = open("blk00000.dat", O_RDWR);
    if (flip_byte(bf, POS1+4)!=0) printf("FAIL: restore magic\n");
    close(bf);

    { unsigned bogus = 999;                    /* frame length != index size */
      bf = open("blk00000.dat", O_RDWR);
      if (pwrite(bf, &bogus, 4, POS1)!=4) printf("FAIL: poison frame len\n");
      close(bf);
      cki("checklevel=3 catches frame length disagreeing with the index", archive_check(1,3), 1);
      unsigned good = 285;
      bf = open("blk00000.dat", O_RDWR);
      if (pwrite(bf, &good, 4, POS1)!=4) printf("FAIL: restore frame len\n");
      close(bf); }
    cki("checklevel=3 clean after both frame repairs", archive_check(1,3), 0);

    /* 6. a missing blk file is reported, not fatal */
    if (rename("blk00000.dat","blk00000.dat.away")!=0) printf("FAIL: rename\n");
    cki("missing blk file reported at level 3", archive_check(1,3), 1);
    if (rename("blk00000.dat.away","blk00000.dat")!=0) printf("FAIL: rename back\n");

    /* 7. holes: an all-zero record is a height never downloaded */
    cki("no hole in a fully populated index", archive_first_hole(1), -1);
    unsigned char zero[48]; memset(zero,0,48);
    xf = open("index.dat", O_RDWR);
    if (pwrite(xf, zero, 48, 0)!=48) printf("FAIL: zero record\n");
    close(xf);
    cki("hole at height 0 detected", archive_first_hole(1), 0);
    cki("a hole is counted, not called a problem", archive_check(0,3), 0);

    /* restore record 0 */
    xf = open("index.dat", O_RDWR);
    if (pwrite(xf, r0, 48, 0)!=48) printf("FAIL: restore record\n");
    close(xf);

    /* 8. prune budget -> height. Two blocks of 285 bytes each. */
    cki("budget below one block retains everything above the tip",
        archive_prune_height_for_budget(100), 2);
    cki("budget for exactly one block retains from height 1",
        archive_prune_height_for_budget(285), 1);
    cki("budget for both blocks retains from height 0",
        archive_prune_height_for_budget(570), 0);
    cki("budget larger than the archive retains everything",
        archive_prune_height_for_budget(1<<20), 0);
    cki("zero budget is refused", archive_prune_height_for_budget(0), -1);

    /* 9. the PRUNE DECISION, every verdict. This is the gate in front of
     *    store_prune, which physically unlinks block files -- the same class
     *    of primitive that destroyed this archive once. It is a separate pure
     *    function precisely so all five outcomes can be exercised here on a
     *    two-block fixture instead of needing a 550 MiB one. */
    { long ph=-7, det=-7;

      /* budget covers everything -> nothing to do */
      cki("verdict: budget covers the archive -> NOTHING",
          archive_prune_decide(1<<20, &ph, &det), ARCHIVE_PRUNE_NOTHING);

      /* unusable budget -> ERROR, and no height is proposed */
      ph=-7; det=-7;
      cki("verdict: zero budget -> ERROR", archive_prune_decide(0, &ph, &det), ARCHIVE_PRUNE_ERROR);
      cki("  ERROR proposes no prune height", ph, 0);

      /* a budget that fits only the last block -> safe to prune below it */
      ph=-7; det=-7;
      cki("verdict: one-block budget on a clean archive -> OK",
          archive_prune_decide(285, &ph, &det), ARCHIVE_PRUNE_OK);
      cki("  OK retains from height 1", ph, 1);
      cki("  OK reports no offending height", det, -1);

      /* REFUSE_HOLE needs a block BELOW the prune height. On a two-block
       * archive with a hole at height 0 the budget walk simply skips the hole
       * (a hole occupies no bytes), concludes everything fits, and returns
       * NOTHING before the hole check is ever consulted -- which is what the
       * first version of this test hit. Use a third block so the gate lands
       * at height 2 with a real hole beneath it. */
      { unsigned char r2[48];
        const long POS2 = POS1 + FRAME_LEN + 285;
        bf = open("blk00000.dat", O_RDWR);
        if (write_framed(bf, POS2, gen, 285) < 0) printf("FAIL: third block\n");
        close(bf);
        put_rec(r2, gh, 0, (unsigned long long)POS2, 285);
        xf = open("index.dat", O_RDWR);
        if (pwrite(xf, r2, 48, 96)!=48) printf("FAIL: third index record\n");
        close(xf);

        /* hole at height 0, gate at height 2 */
        unsigned char zero[48]; memset(zero,0,48);
        xf = open("index.dat", O_RDWR);
        if (pwrite(xf, zero, 48, 0)!=48) printf("FAIL: hole for prune test\n");
        close(xf);
        ph=-7; det=-7;
        cki("verdict: hole below the gate -> REFUSE_HOLE",
            archive_prune_decide(285, &ph, &det), ARCHIVE_PRUNE_REFUSE_HOLE);
        cki("  REFUSE_HOLE names height 0", det, 0);
        cki("  REFUSE_HOLE still reports the height it would have used", ph, 2);
        xf = open("index.dat", O_RDWR);
        if (pwrite(xf, r0, 48, 0)!=48) printf("FAIL: restore after hole\n");
        close(xf);

        /* non-monotonic layout is refused BEFORE the hole check, so it wins
         * even on an archive that also has holes */
        unsigned char bad[48]; memcpy(bad, r1, 48);
        unsigned long long farpos = 1ULL<<40;
        memcpy(bad+36, &farpos, 8);
        xf = open("index.dat", O_RDWR);
        if (pwrite(xf, bad, 48, 48)!=48) printf("FAIL: break monotonicity\n");
        close(xf);
        ph=-7; det=-7;
        cki("verdict: non-monotonic layout -> REFUSE_LAYOUT",
            archive_prune_decide(285, &ph, &det), ARCHIVE_PRUNE_REFUSE_LAYOUT);
        cki("  REFUSE_LAYOUT names the break height", det, 2);
        xf = open("index.dat", O_RDWR);
        if (pwrite(xf, r1, 48, 48)!=48) printf("FAIL: restore monotonic\n");
        close(xf);

        /* drop back to the two-record archive the rest of the file assumes */
        if (truncate("index.dat", 96)!=0) printf("FAIL: shrink index\n");
      }

      /* and back to a clean OK, proving the refusals were about the damage
       * and not a sticky state */
      ph=-7;
      cki("verdict: OK again once the archive is repaired",
          archive_prune_decide(285, &ph, &det), ARCHIVE_PRUNE_OK);
    }

    /* clean up the fixture; leaving it behind would let a later run pass or
     * fail against stale data. */
    if (chdir("/storage/bitcoinmachinecode/asm")!=0) printf("FAIL: chdir back\n");
    snprintf(cmd,sizeof cmd,"rm -rf %s", dir);
    if (system(cmd)!=0) printf("FAIL: cleanup\n");

    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures?1:0;
}
