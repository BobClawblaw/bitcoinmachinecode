/* test_utxo_probe_bound.c -- utxo_get and utxo_del must TERMINATE on a full
 * table, not spin.
 *
 * WHY THIS EXISTS
 *
 *   Both probe loops in bitcoin_utxo.asm had exactly two exits: an empty slot
 *   (.miss) or a key match (.hit). With no empty slot anywhere -- a table
 *   filled to capacity -- a key that is not present wraps forever. Not slow;
 *   non-terminating.
 *
 *   The bound was already known in this very file: utxo_put's .next carries a
 *   probe counter whose comment says "we must report full rather than looping
 *   forever (mirrors mpool_put's existing bounded probe)". Written twice,
 *   applied to neither get nor del, because both leaned on put's promise that
 *   the table never fills completely.
 *
 *   That promise does not hold. utxo_lsm_reload's WAL-tail replay writes
 *   through these raw primitives and bypasses put's bookkeeping (see
 *   daemon/flush_wal_tail.c), so a tail bigger than the memtable fills it and
 *   nothing reports full. On 2026-08-23 that hung the live daemon (2^16 slots)
 *   and flush_wal_tail (2^22) on the same 1.83 GB tail -- the two different
 *   sizes are what ruled out "undersized" and pointed at "unbounded".
 *
 * WHY IT FORKS
 *
 *   Against the unfixed code this test does not fail -- it HANGS. A hanging
 *   test in `make test` is worse than a missing one: CI stops, nobody knows
 *   why. So each probe runs in a forked child under alarm(), and the parent
 *   reports a timeout as a normal failure. Verified against the pre-fix
 *   bitcoin_utxo.asm: both children hit the alarm; after the fix, both return.
 *
 * Usage: ./test_utxo_probe_bound
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

typedef uint8_t u8; typedef uint32_t u32; typedef uint64_t u64;

extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_put(void* u, const u8 txid[32], unsigned long index, u64 value,
                     unsigned long height, unsigned long is_coinbase,
                     const u8* spk, unsigned long spklen);
extern long utxo_get(void* u, const u8 txid[32], unsigned long index, u64* value,
                     unsigned long* height, unsigned long* is_coinbase,
                     const u8** spk, unsigned long* slen);
extern long utxo_del(void* u, const u8 txid[32], unsigned long index);

#define SLOTS_LOG2 10                 /* 1024 slots -- small enough to fill fast */
#define SLOTS      (1UL << SLOTS_LOG2)

static int fails = 0;
static void ck(const char* what, int ok, const char* detail){
    if (ok) printf("PASS %s\n", what);
    else { printf("FAIL %s -- %s\n", what, detail); fails++; }
}

static void mktxid(u8 out[32], unsigned n){
    memset(out, 0, 32);
    out[0]=(u8)n; out[1]=(u8)(n>>8); out[2]=(u8)(n>>16); out[3]=(u8)(n>>24);
    out[31]=0xA5;
}

/* Runs one probe in a child under a wall-clock alarm. Returns:
 *   1 = the call returned (whatever its answer)
 *   0 = the child was killed by the alarm, i.e. the probe did not terminate */
static int probe_terminates(void* u, const u8* txid, int do_del){
    fflush(stdout);
    pid_t pid = fork();
    if (pid < 0){ perror("fork"); exit(1); }
    if (pid == 0){
        alarm(10);                                  /* generous: this is ms of work */
        if (do_del) (void)utxo_del(u, txid, 7);
        else {
            u64 v; unsigned long h, cb, sl; const u8* sp;
            (void)utxo_get(u, txid, 7, &v, &h, &cb, &sp, &sl);
        }
        _exit(0);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0){ perror("waitpid"); exit(1); }
    return WIFEXITED(st) && WEXITSTATUS(st) == 0;
}

int main(void){
    unsigned long ssz = (unsigned long)utxo_struct_size(SLOTS);
    void* u    = malloc(ssz);
    void* blob = malloc(1u<<22);
    if (!u || !blob){ printf("FAIL out of memory\n"); return 1; }
    utxo_init(u, SLOTS, blob, 1u<<22);

    /* Fill the table to capacity. utxo_put reports 2 = full; we stop there,
     * which leaves EVERY slot occupied -- the state get/del could not escape. */
    static const u8 spk[2] = { 0x51, 0x75 };
    unsigned long placed = 0, n = 0;
    for (; n < SLOTS * 4; n++){
        u8 t[32]; mktxid(t, (unsigned)n);
        long r = utxo_put(u, t, 7, 1000 + n, 1, 0, spk, sizeof spk);
        if (r == 2) break;                          /* table full */
        if (r != 1){ printf("FAIL utxo_put returned %ld at n=%lu\n", r, n); return 1; }
        placed++;
    }
    ck("utxo_put reports the table full instead of looping",
       n < SLOTS * 4, "put never returned 2");
    printf("     filled %lu of %lu slots\n", placed, SLOTS);
    ck("the table really is full (no empty slot remains)",
       placed >= SLOTS - 1, "did not fill to capacity");

    /* A key that is definitely absent: every stored txid ends 0xA5. */
    u8 absent[32]; memset(absent, 0x5A, 32);

    int get_ok = probe_terminates(u, absent, 0);
    int del_ok = probe_terminates(u, absent, 1);
    ck("utxo_get TERMINATES on a full-table miss",
       get_ok, "child hit the 10s alarm -- probe did not terminate");
    ck("utxo_del TERMINATES on a full-table miss",
       del_ok, "child hit the 10s alarm -- probe did not terminate");

    /* Terminating is not enough: it must still give the RIGHT answer, or a
     * bound that simply returns early would pass the two checks above.
     *
     * These run IN THIS PROCESS, so they are guarded by the results above.
     * Without the guard, an unbounded build hangs the test here instead of
     * failing it -- which is the exact outcome the forking exists to avoid,
     * and which this file got wrong on its first draft. */
    if (!get_ok || !del_ok){
        printf("SKIP correctness checks -- the probes do not terminate, so\n");
        printf("     calling them in-process would hang rather than fail\n");
    } else {
        u64 v; unsigned long h, cb, sl; const u8* sp;
        ck("...and utxo_get still reports the absent key as missing",
           utxo_get(u, absent, 7, &v, &h, &cb, &sp, &sl) != 1, "claimed to find it");
        u8 present[32]; mktxid(present, 0);
        ck("...and a key that IS present is still found in the full table",
           utxo_get(u, present, 7, &v, &h, &cb, &sp, &sl) == 1, "lost a live entry");
        ck("...with its value intact", v == 1000, "wrong value");
    }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
