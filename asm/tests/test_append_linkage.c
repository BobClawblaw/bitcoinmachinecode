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

    printf(failures ? "\n%d FAILURE(S)\n" : "\nALL TESTS PASSED\n", failures);
    return failures ? 1 : 0;
}
