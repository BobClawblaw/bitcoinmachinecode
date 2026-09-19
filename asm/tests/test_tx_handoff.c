/* tests/test_tx_handoff.c -- daemon/tx_handoff.c: an inbound serve child
 * hands the transactions its peer sends to the download worker, which
 * validates them against the live UTXO set (2026-09-19: the child validated
 * against the boot-time snapshot and dropped every tx spending a coin newer
 * than the process -- validation/tx_relay_regtest_e2e.sh is the end-to-end
 * proof against Core; this pins the ring the fix rides on).
 *
 * What it proves:
 *   1. without a ring, txho_push says so (-1) and the caller falls back;
 *   2. records written by FORKED producers reach the consumer in order,
 *      byte-exact, with the producer's peer slot;
 *   3. the ring wraps -- 12,000 records (~18 MB) through an 8 MB ring, some of
 *      them straddling the end of the buffer;
 *   4. a full ring drops the newest and counts it; draining makes room again;
 *   5. a tx no policy could accept (over MAX_STANDARD_TX_WEIGHT bytes) is
 *      refused at the door and counted, never queued;
 *   6. a producer killed while holding the lock does not wedge the others
 *      (robust mutex): the next push succeeds.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/wait.h>
#include "tx_handoff.h"

static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c ? "ok  :" : "FAIL:", m); }

static void fill(unsigned char* b, unsigned long n, unsigned seed){ for (unsigned long i = 0; i < n; i++) b[i] = (unsigned char)(seed * 131u + i * 7u); }

static int got_n, got_bad, got_slot_bad; static unsigned long got_bytes;
static unsigned expect_seed; static int expect_slot;
static unsigned long expect_len(unsigned seed){ return 60 + (seed * 977u) % 3000u; }
static void check_cb(const unsigned char* tx, unsigned long len, int slot, void* ctx){
    (void)ctx;
    static unsigned char want[TXHO_MAX_TX];
    unsigned long wl = expect_len(expect_seed);
    fill(want, wl, expect_seed);
    if (len != wl || memcmp(tx, want, wl)) got_bad++;
    if (slot != expect_slot) got_slot_bad++;
    got_n++; got_bytes += len; expect_seed++;
}
static void count_cb(const unsigned char* tx, unsigned long len, int slot, void* ctx){ (void)tx; (void)len; (void)slot; (*(int*)ctx)++; }

int main(void){
    static unsigned char buf[TXHO_MAX_TX + 16];
    printf("== 1. no ring: the caller is told to validate locally ==\n");
    ok(!txho_ready() && txho_push((const unsigned char*)"x", 1, 0) == -1, "txho_push without a ring returns -1");

    ok(txho_create() == 1 && txho_ready(), "txho_create maps the shared ring");

    printf("== 2. forked producers, byte-exact, in order, with their slot ==\n");
    pid_t p = fork();
    if (p == 0){
        int bad = 0;
        for (unsigned s = 0; s < 200; s++){ fill(buf, expect_len(s), s); if (txho_push(buf, expect_len(s), 7) != 1) bad++; }
        _exit(bad ? 1 : 0);
    }
    int stt = 0; waitpid(p, &stt, 0);
    ok(WIFEXITED(stt) && WEXITSTATUS(stt) == 0, "a forked child queued 200 transactions");
    expect_seed = 0; expect_slot = 7;
    long n = txho_drain(check_cb, 0, 1000);
    ok(n == 200 && got_n == 200 && !got_bad && !got_slot_bad, "the worker drained all 200: same bytes, same order, slot 7");
    ok(txho_drain(check_cb, 0, 1000) == 0, "an empty ring drains nothing");

    printf("== 3. wrap: far more bytes than the ring holds ==\n");
    got_n = got_bad = got_slot_bad = 0; got_bytes = 0; expect_seed = 1000; expect_slot = 3;
    unsigned s = 1000; long pushed = 0;
    for (int round = 0; round < 120; round++){
        for (int k = 0; k < 100; k++, s++){ fill(buf, expect_len(s), s); if (txho_push(buf, expect_len(s), 3) == 1) pushed++; }
        txho_drain(check_cb, 0, 1000);
    }
    ok(pushed == 12000 && got_n == 12000 && !got_bad && !got_slot_bad, "12000 records through the ring, every one intact");
    ok(got_bytes > 2 * TXHO_RING_BYTES, "and they add up to more than twice the ring (it wrapped)");

    printf("== 4. a full ring drops the newest, and draining makes room ==\n");
    unsigned long long pf0, pb0, pf1, pb1;
    txho_stats(0, 0, &pf0, &pb0);
    fill(buf, TXHO_MAX_TX, 9);
    int q = 0; while (txho_push(buf, TXHO_MAX_TX, 1) == 1) q++;
    txho_stats(0, 0, &pf1, &pb1);
    ok(q == (int)(TXHO_RING_BYTES / (TXHO_MAX_TX + 8)) && pf1 == pf0 + 1, "the ring filled with max-size txs, the next was dropped and counted");
    int drained = 0; txho_drain(count_cb, &drained, 1);
    ok(drained == 1 && txho_push(buf, TXHO_MAX_TX, 1) == 1, "one drained -> one more fits");
    drained = 0; txho_drain(count_cb, &drained, 100000);
    ok(drained == q, "everything queued comes back out");

    printf("== 5. over MAX_STANDARD_TX_WEIGHT bytes: refused at the door ==\n");
    ok(txho_push(buf, TXHO_MAX_TX + 1, 1) == 0, "a tx of 400,001 bytes is not queued");
    txho_stats(0, 0, 0, &pb1);
    ok(pb1 == pb0 + 1, "and the refusal is counted");
    drained = 0; txho_drain(count_cb, &drained, 10);
    ok(drained == 0, "nothing was queued for it");

    printf("== 6. a producer dies holding the lock: the next one proceeds ==\n");
    {
        p = fork();
        if (p == 0){ txho_test_lock_and_die(); _exit(0); }
        waitpid(p, &stt, 0);
        pid_t c = fork();
        if (c == 0){ alarm(5); fill(buf, 100, 5); _exit(txho_push(buf, 100, 2) == 1 ? 0 : 1); }
        waitpid(c, &stt, 0);
        ok(WIFEXITED(stt) && WEXITSTATUS(stt) == 0, "a push after the holder's death succeeds (no hang, no refusal)");
        drained = 0; txho_drain(count_cb, &drained, 10);
        ok(drained == 1, "and exactly its record is visible -- the dead producer published nothing");
    }

    printf("\n%d checks, %d failed\n", checks, fails);
    if (fails){ printf("FAILED\n"); return 1; }
    printf("ALL TESTS PASSED\n");
    return 0;
}
