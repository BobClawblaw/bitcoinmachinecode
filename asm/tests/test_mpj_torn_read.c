/* test_mpj_torn_read.c -- a journal reader must not return a record whose
 * writer finished WHILE the reader was copying it.
 *
 * mpj_append stamps TAIL=0, then HEAD=seq, then the body, then TAIL=seq. The
 * reader used to check HEAD first, copy the body, then check TAIL. A reader
 * that arrived mid-write saw HEAD==seq (the write had only STARTED), copied a
 * half-written body, and -- if the writer finished before its last check --
 * saw TAIL==seq and returned half the old record and half the new one as
 * whole. That is a race on x86 too (bmc_osx 0e916bca; the osx note
 * worklog/2026-09-25-note-for-x86-2.md item 2).
 *
 * test_mempool_journal's torn-record case leaves TAIL wrong for good, which
 * both readers skip. This one makes the interleaving deterministic: the
 * journal source is compiled into this file with memcpy routed through a
 * hook, and the hook completes the pending write right after the reader has
 * copied the stale wtxid and aux.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

static void* mpj_test_memcpy(void* d, const void* s, size_t n);
#define memcpy mpj_test_memcpy
#include "../daemon/mempool_journal.c"
#undef memcpy

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static void fill(mpj_rec* r, unsigned n, uint32_t reason){
    memset(r, 0, sizeof *r);
    for (int i = 0; i < 32; i++){
        r->txid[i]  = (unsigned char)(n + i);
        r->wtxid[i] = (unsigned char)(n + i + 1);
        r->aux[i]   = (unsigned char)(n + i + 2);
    }
    r->first_seen = 1000 + n; r->departed_at = 2000 + n;
    r->vsize = 100 + n; r->fee_sat = 500 + n; r->reason = reason; r->height = 700000 + n;
}

/* ---- the hook: finish the pending write after the reader's Nth slot copy -- */
static unsigned char* g_slot;        /* slot being written, or NULL when disarmed */
static const mpj_rec* g_pending;     /* the record the "other process" is writing */
static uint64_t g_pending_seq;
static int g_copies, g_fire_after, g_fired;

static void finish_pending_write(void){
    unsigned char* s = g_slot;
    const mpj_rec* r = g_pending;
    __builtin_memcpy(s + MPJ_OFF_WTXID, r->wtxid, 32);
    __builtin_memcpy(s + MPJ_OFF_AUX,   r->aux,   32);
    st64(s + MPJ_OFF_FIRST_SEEN, (uint64_t)r->first_seen);
    st64(s + MPJ_OFF_DEPARTED,   (uint64_t)r->departed_at);
    st64(s + MPJ_OFF_VSIZE,      r->vsize);
    st64(s + MPJ_OFF_FEE,        r->fee_sat);
    st32(s + MPJ_OFF_REASON,     r->reason);
    st32(s + MPJ_OFF_HEIGHT,     r->height);
    st64(s + MPJ_OFF_SEQ_TAIL,   g_pending_seq);
}

static void* mpj_test_memcpy(void* d, const void* s, size_t n){
    void* ret = __builtin_memcpy(d, s, n);
    const unsigned char* p = s;
    if (g_slot && !g_fired && p >= g_slot && p < g_slot + MPJ_REC_BYTES){
        if (++g_copies == g_fire_after){ finish_pending_write(); g_fired = 1; }
    }
    return ret;
}

int main(void){
    char path[256];
    snprintf(path, sizeof path, "/tmp/bmc_mpj_torn_%d.dat", (int)getpid());
    unlink(path);

    /* A one-record ring: seq 2 overwrites seq 1's slot, so a half-written
     * seq 2 still carries seq 1's bytes -- stale data that looks plausible. */
    ck("opens a one-record ring", mpj_open(path, 1) == 1);
    mpj_rec a, b, got;
    fill(&a, 1, MPJ_EVICTED);
    fill(&b, 50, MPJ_EVICTED);
    mpj_append(&a);
    ck("seq 1 is written and read back", mpj_lookup(a.txid, &got) == 1 && got.seq == 1);

    /* Another process has begun seq 2: it took the sequence, invalidated
     * TAIL, stamped HEAD and wrote the txid, and has not reached the rest. */
    unsigned char* s = slot_at(2);
    __atomic_store_n((uint64_t*)(g_mpj + MPJ_HOFF_NEXTSEQ), 3, __ATOMIC_RELAXED);
    st64(s + MPJ_OFF_SEQ_TAIL, 0);
    st64(s + MPJ_OFF_SEQ_HEAD, 2);
    __builtin_memcpy(s + MPJ_OFF_TXID, b.txid, 32);

    /* It finishes right after the reader has copied txid, wtxid and aux. */
    g_slot = s; g_pending = &b; g_pending_seq = 2; g_copies = 0; g_fire_after = 3; g_fired = 0;
    int found = mpj_lookup(b.txid, &got);
    if (!g_fired) finish_pending_write();    /* a reader that skipped early never copied */
    g_slot = 0;

    int whole = found && got.seq == 2
             && memcmp(got.txid,  b.txid,  32) == 0
             && memcmp(got.wtxid, b.wtxid, 32) == 0
             && memcmp(got.aux,   b.aux,   32) == 0
             && got.first_seen == b.first_seen && got.fee_sat == b.fee_sat;
    ck("a record the writer finished mid-read is skipped, not returned torn", !found || whole);
    if (found && !whole)
        printf("      returned seq %llu with wtxid[0]=%u (seq 1's is %u, seq 2's is %u) and fee %llu\n",
               (unsigned long long)got.seq, got.wtxid[0], a.wtxid[0], b.wtxid[0],
               (unsigned long long)got.fee_sat);

    /* The fix must not cost the record once it is complete. */
    ck("once complete, the record reads back whole",
       mpj_lookup(b.txid, &got) == 1 && got.seq == 2 &&
       memcmp(got.wtxid, b.wtxid, 32) == 0 && memcmp(got.aux, b.aux, 32) == 0 &&
       got.fee_sat == b.fee_sat && got.height == b.height);
    ck("seq 1, lapped, is gone", mpj_lookup(a.txid, &got) == 0);

    mpj_close();
    unlink(path);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
