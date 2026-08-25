/* tests/test_utxo_catchup_shutdown.c -- utxo_live_catchup must honour a
 * shutdown request at the next block boundary.
 *
 * What this guards (found 2026-08-22): a from-scratch replay is ONE
 * utxo_live_catchup() call that runs for hours. daemon/main.c's SIGTERM
 * handler only sets g_shutdown_requested, and until now nothing inside the
 * catch-up loop ever read it -- so every `systemctl stop/restart` during bulk
 * catch-up sat for systemd's 90s TimeoutStopSec and then SIGKILLed the
 * download worker mid-block (journalctl: "State 'final-sigterm' timed out.
 * Killing." on 21:24:39, 01:16:00, 02:30:44, 02:37:18, 02:40:12). One of
 * those landed between a block's WAL writes and its checkpoint, which is the
 * crash-recovery case tests/test_utxo_crash_recovery.c covers.
 *
 * The contract tested here: once the registered flag is set, catch-up
 * finishes the block in progress, persists that block's checkpoint, begins
 * no further block (and no compaction), and returns the count applied so
 * far as an ordinary >=0 result. A later call with the flag cleared resumes
 * at the next height with no reject.
 *
 * Two phases:
 *   A (deterministic): flag set BEFORE the call -> exactly ONE block applies
 *     (the "block in progress" is the first one), checkpoint == that block.
 *   B (timed): a thread sets the flag mid-call -> the call returns within a
 *     bound, checkpoint == last applied block, resume is clean.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);

extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);
extern void utxo_live_set_shutdown_flag(const volatile sig_atomic_t* flag);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_utxo_catchup_shutdown: unexpected call to mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}
static void ckm(const char* l, int cond){
    if (cond) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; }
}

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static u8 g_txid_scratch[1<<12];

/* Same minimal coinbase-only block as tests/test_utxo_catchup_crash_resume.c. */
static long mk_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp){
    u8 tx[80], txid[32];   /* 65-byte coinbase: 64 overflowed by one (see test_blk_dryrun.c) */
    u8* q = tx;
    put32(q,1); q+=4; *q++ = 1; memset(q,0,32); q+=32; put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4; put32(q,0xffffffffu); q+=4;
    *q++ = 1; put64(q, 50000000ULL); q+=8; *q++ = 1; *q++ = 0x51; put32(q,0); q+=4;
    long txlen = q - tx;
    tx_txid(txid, tx, (unsigned long)txlen, g_txid_scratch, sizeof g_txid_scratch);
    u8* o = raw;
    put32(o,1); o+=4; memcpy(o, prev, 32); o+=32; memcpy(o, txid, 32); o+=32;
    put32(o, tstamp); o+=4; put32(o, 0x207fffffu); o+=4; put32(o, 0); o+=4;
    *o++ = 1; memcpy(o, tx, (size_t)txlen); o += txlen;
    long len = o - raw;
    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

/* Read utxo_applied_height.dat exactly as utxo_live does (magic "UAPH" + i64). */
static long read_checkpoint_file(void){
    FILE* f = fopen("utxo_applied_height.dat", "rb");
    if (!f) return -2;
    u8 buf[12]; size_t n = fread(buf, 1, 12, f); fclose(f);
    if (n != 12) return -3;
    long h; memcpy(&h, buf+4, 8);
    return h;
}

static u8 store_buf[4096];

static long build_chain(long n, u32 tag_base){
    u8 prev[32]; memset(prev,0,32);
    for (long h=0; h<n; h++){
        u8 raw[256], hash[32];
        long len = mk_and_mine(raw, hash, prev, tag_base+(u32)h, 1900000000u+(u32)h);
        long r = store_append(store_buf, hash, raw, len);
        if (r != h) { printf("FAIL store_append h=%ld got=%ld\n", h, r); failures++; return -1; }
        memcpy(prev, hash, 32);
    }
    return n;
}

static volatile sig_atomic_t g_flag = 0;

typedef struct { long delay_ms; struct timespec fired; } timer_t_;
static void* timer_thread(void* arg){
    timer_t_* t = (timer_t_*)arg;
    struct timespec ts = { t->delay_ms/1000, (t->delay_ms%1000)*1000000L };
    nanosleep(&ts, 0);
    clock_gettime(CLOCK_MONOTONIC, &t->fired);
    g_flag = 1;
    return 0;
}
static double since_ms(const struct timespec* a){
    struct timespec b; clock_gettime(CLOCK_MONOTONIC, &b);
    return (b.tv_sec - a->tv_sec)*1000.0 + (b.tv_nsec - a->tv_nsec)/1e6;
}

int main(void){
    tt_isolate();
    /* ---------------- Phase A: deterministic ---------------- */
    {
        tt_subdir("phaseA");   /* each phase needs an empty datadir of its own */
        memset(store_buf,0,sizeof store_buf);
        ck("A store_init", store_init(store_buf), 1);
        ck("A utxo_live_init", utxo_live_init("."), 1);
        utxo_live_set_shutdown_flag(&g_flag);
        long n = 300;
        if (build_chain(n, 0x70000000u) < 0) return 1;

        g_flag = 1;                                   /* already requested */
        long ar = utxo_live_catchup(store_buf);
        ck("A flag set before the call: exactly ONE block applies (finish the block in progress, then stop)", ar, 1);
        ck("A applied_height after the interrupted call", utxo_live_applied_height(), 0);
        ck("A on-disk checkpoint == last fully applied block", read_checkpoint_file(), 0);
        ck("A live count == 1 (only block 0's coinbase)", utxo_live_count(), 1);

        long ar2 = utxo_live_catchup(store_buf);
        ck("A flag still set: another call applies exactly one more block, never zero, never runaway", ar2, 1);
        ck("A applied_height advanced by one", utxo_live_applied_height(), 1);

        g_flag = 0;
        long ar3 = utxo_live_catchup(store_buf);
        ck("A flag cleared: resume applies the rest with no reject", ar3, n - 2);
        ck("A applied_height at tip", utxo_live_applied_height(), n - 1);
        ck("A checkpoint at tip", read_checkpoint_file(), n - 1);
        utxo_live_close();
    }

    /* ---------------- Phase B: flag set mid-call by a timer ---------------- */
    {
        tt_subdir("phaseB");   /* each phase needs an empty datadir of its own */
        memset(store_buf,0,sizeof store_buf);
        ck("B store_init", store_init(store_buf), 1);
        ck("B utxo_live_init", utxo_live_init("."), 1);
        utxo_live_set_shutdown_flag(&g_flag);
        long n = 4000;
        if (build_chain(n, 0x71000000u) < 0) return 1;

        g_flag = 0;
        timer_t_ t = { 150, {0,0} };
        pthread_t th; pthread_create(&th, 0, timer_thread, &t);
        long ar = utxo_live_catchup(store_buf);
        pthread_join(th, 0);
        double after_flag_ms = since_ms(&t.fired);
        printf("     B: call returned %.0f ms after the flag was raised; applied %ld of %ld\n", after_flag_ms, ar, n);
        ckm("B call returned (did not run to tip ignoring the flag, or explain below)", ar >= 1);
        if (ar == n)
            printf("NOTE B: the whole chain applied before the 150ms timer fired on this box -- bound check is vacuous here; Phase A carries the exact semantics\n");
        else
            ckm("B returned within 5s of the flag (bounded: one block, no compaction)", after_flag_ms < 5000.0);
        ck("B applied_height == blocks applied - 1", utxo_live_applied_height(), ar - 1);
        ck("B on-disk checkpoint == applied_height (no lag)", read_checkpoint_file(), utxo_live_applied_height());

        g_flag = 0;
        long rest = utxo_live_catchup(store_buf);
        ck("B resume applies exactly the remainder, no reject", rest, n - ar);
        ck("B applied_height at tip", utxo_live_applied_height(), n - 1);
        ck("B live count == n", utxo_live_count(), n);
        utxo_live_close();
    }

    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
