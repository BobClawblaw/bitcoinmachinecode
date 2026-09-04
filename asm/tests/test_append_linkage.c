/* tests/test_append_linkage.c -- incident #46's fix: idxscan_append_locked's
 * linkage gate. The live failure: two keep-up legs closed the same block;
 * the slower leg's append landed the SAME block again at tip+1, because the
 * height is assigned at append time (under the lock) while the block's
 * validation used the leg's pass-start chain view -- and nothing at the
 * append checked that the block's prev field actually links to the tip.
 * The gate now refuses (-2) inside the same critical section that assigns
 * the height. This test replays exactly that shape:
 *   A(h0), B(h1 linking A), then B AGAIN (prev=A, tip=B) -> must be -2 with
 *   the store untouched; then C linking B appends normally at h2; and a
 *   block with a garbage prev is also refused. */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "test_tmpdir.h"

extern long store_init(void* st);
extern long store_append(void* st, const unsigned char hash[32], const void* raw, long len);
extern long idxscan_append_locked(void* st, const unsigned char hash[32],
                                  const void* raw, long len);
extern long idxscan_tip(void* st);

static int failures = 0;
static void ck(const char* l, long long g, long long e){
    if (g==e) printf("PASS %s (got %lld)\n", l, g);
    else { printf("FAIL %s got=%lld exp=%lld\n", l, g, e); failures++; }
}
static unsigned char store_buf[4096];

/* a "block": 90 bytes, header-shaped enough for the gate -- version at 0..4,
 * PREV FIELD at bytes 4..36 (what the gate reads), filler after. */
static void mk_raw(unsigned char raw[90], const unsigned char prev[32], int tag){
    memset(raw, (unsigned char)tag, 90);
    raw[0]=1; raw[1]=0; raw[2]=0; raw[3]=0;
    memcpy(raw+4, prev, 32);
}

int main(void){
    tt_isolate();
    memset(store_buf, 0, sizeof store_buf);
    ck("store_init", store_init(store_buf), 1);

    unsigned char zero[32]; memset(zero, 0, 32);
    unsigned char ha[32], hb[32], hc[32], hx[32];
    memset(ha, 0xAA, 32); memset(hb, 0xBB, 32); memset(hc, 0xCC, 32); memset(hx, 0xEE, 32);
    static unsigned char A[90], B[90], C[90], X[90];

    /* A at height 0: empty store, nothing to link to */
    mk_raw(A, zero, 1);
    ck("append A on the empty store -> h0", idxscan_append_locked(store_buf, ha, A, 90), 0);

    /* B links A -> h1 */
    mk_raw(B, ha, 2);
    ck("append B (prev=A) -> h1", idxscan_append_locked(store_buf, hb, B, 90), 1);

    /* THE INCIDENT: the same B again. Its prev is A; the tip is B. Before
     * the gate this landed at h2 exactly as the live node stored 964031's
     * bytes at 964032. Now: refused, store untouched. */
    ck("re-append of B (stale duplicate) -> REFUSED (-2)",
       idxscan_append_locked(store_buf, hb, B, 90), -2);
    ck("tip unchanged after the refusal", idxscan_tip(store_buf), 1);

    /* garbage prev is refused the same way */
    mk_raw(X, hc, 9);   /* prev = hc, which is nowhere on the chain */
    ck("append with a non-linking prev -> REFUSED (-2)",
       idxscan_append_locked(store_buf, hx, X, 90), -2);
    ck("tip still unchanged", idxscan_tip(store_buf), 1);

    /* a genuinely-next block still appends fine after refusals */
    mk_raw(C, hb, 3);
    ck("append C (prev=B) -> h2", idxscan_append_locked(store_buf, hc, C, 90), 2);
    ck("final tip 2", idxscan_tip(store_buf), 2);

    /* ================================================================
     * STO-5 (audit 2026-09-03): a stale writer must not collide.
     *
     * store_append seeks to the in-memory cur_file_pos and takes NO flock,
     * while every other live writer appends under append.lock. cur_file_pos
     * is refreshed only by store_reload/store_append/store_truncate_to, so a
     * process whose last reload predates another writer's append still
     * believes the tip is T -- and writes the next block at the offset the
     * other writer already used. If the newer block is larger, its tail runs
     * over the frame after it and that height's index record points at
     * rubbish.
     *
     * Two store states over one directory reproduce it with no forking: S2
     * opens the archive while the tip is C, then S1 appends D behind its
     * back. The locked appender re-reads the true tip INSIDE the critical
     * section, so a stale writer can never be handed a height another block
     * already owns.
     * ================================================================ */
    printf("\n== STO-5: a stale second writer ==\n");
    {
        static unsigned char s2[4096];
        unsigned char hd[32], he[32], hf[32];
        memset(hd, 0xDD, 32); memset(he, 0x11, 32); memset(hf, 0x22, 32);
        static unsigned char D[90], E[90], F[90];

        memset(s2, 0, sizeof s2);
        ck("second writer opens the archive", store_init(s2), 1);
        ck("...and sees the current tip", idxscan_tip(s2), 2);

        /* S1 appends D behind S2's back: the archive is now at height 3. */
        mk_raw(D, hc, 4);
        ck("first writer appends D -> h3", idxscan_append_locked(store_buf, hd, D, 90), 3);

        /* S2 is now stale. E links to C, the tip S2 still believes in. */
        mk_raw(E, hc, 5);
        long r = idxscan_append_locked(s2, he, E, 90);
        printf("      (stale writer, block linking to its STALE tip -> %ld)\n", r);
        ck("STO-5 the locked appender refuses it", r, -2);
        ck("STO-5 ...and the archive still ends at D", idxscan_tip(store_buf), 3);

        /* A block that links to the TRUE tip lands at the true next height --
         * 4, not the 3 the stale view would have chosen. */
        mk_raw(F, hd, 6);
        long rf = idxscan_append_locked(s2, hf, F, 90);
        printf("      (stale writer, block linking to the TRUE tip -> h%ld)\n", rf);
        ck("STO-5 a linking block lands at the TRUE next height", rf, 4);
        ck("STO-5 ...so no height was handed out twice", idxscan_tip(store_buf), 4);

        /* THE CONTROL: the UNLOCKED appender that submitblock and the serve
         * child used to call, from a state that did not observe the archive
         * grow.
         *
         * It writes wherever its cached cur_file_pos points, and that field
         * is refreshed only by store_reload / store_append / store_truncate_to
         * -- so a state that never did any of those still reads ZERO, and the
         * block lands at height 0, over the first block in the archive. The
         * audit's scenario is the milder form of the same thing: a worker
         * whose last reload predates another writer's append lands on THAT
         * writer's frame instead. Either way the position is a cached guess
         * rather than the truth, which is what taking the lock and re-reading
         * the tip inside it fixes.
         *
         * Asserted as an inequality, because the point is that the two
         * appenders DISAGREE about where the next block goes and store_append
         * is behind -- not that it is behind by any particular amount. */
        {
            static unsigned char s3[4096];
            unsigned char hg[32]; memset(hg, 0x33, 32);
            static unsigned char G[90];
            memset(s3, 0, sizeof s3);
            store_init(s3);                       /* opens while the tip is 4 */
            long true_tip = idxscan_tip(store_buf);
            mk_raw(G, hf, 7);
            ck("control: the archive is at h4 before the stale write", true_tip, 4);
            /* advance the archive behind s3's back, twice */
            unsigned char hh[32]; memset(hh, 0x44, 32); static unsigned char H[90];
            mk_raw(H, hg, 8);
            (void)idxscan_append_locked(store_buf, hg, G, 90);   /* h5 */
            (void)idxscan_append_locked(store_buf, hh, H, 90);   /* h6 */
            ck("control: archive advanced to h6", idxscan_tip(store_buf), 6);
            unsigned char hi[32]; memset(hi, 0x55, 32); static unsigned char I[90];
            mk_raw(I, hh, 9);
            long stale = store_append(s3, hi, I, 90);
            printf("      (UNLOCKED store_append from a stale state -> h%ld, while the archive was at h6)\n", stale);
            ck("STO-5 control: the unlocked appender writes BEHIND the true tip", (long long)(stale < 6), 1);
        }
    }

    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures ? 1 : 0;
}
