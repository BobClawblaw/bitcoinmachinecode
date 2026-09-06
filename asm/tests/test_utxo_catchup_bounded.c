/* tests/test_utxo_catchup_bounded.c -- step 1 of
 * docs/audits/UTXO_INLINE_BUILD_PERF_SCOPE.md (2026-09-06): the bounded
 * connect call the parallel downloader's monitor loop runs while the helpers
 * are still filling the archive.
 *
 * utxo_live_catchup_bounded(store_buf, max_ms, stop_at_hole) shares its loop
 * body with utxo_live_catchup. What is pinned here is the two things that
 * differ, against a synthetic archive with HOLES at known heights (an
 * all-zero index.dat record, exactly what a chunk a helper has not delivered
 * yet looks like):
 *
 *   A. the bounded call connects exactly the contiguous prefix and stops AT
 *      the hole (stop reason HOLE, no failure classification, no WARNING),
 *      returns 0 while the hole stays, resumes past it once the record is
 *      filled, and reaches the tip (stop reason TIP) once every hole is;
 *      utxo_applied_height.dat equals the applied height after every call;
 *   B. the time budget: a 4,000-block chain with a 1 ms budget connects a
 *      prefix -- at least one block, far from all of them -- with stop
 *      reason BUDGET and a consistent checkpoint; repeated bounded calls
 *      make progress every time and never exceed the chain;
 *   C. the shutdown flag is honoured at the same boundary: flag set, the
 *      bounded call connects exactly one block and stops (reason SHUTDOWN);
 *   D. NEGATIVE CONTROL: the unbounded call on an archive with a hole does
 *      what it did before this change -- connects the prefix, prints the
 *      "hole/short block" WARNING, classes the stop archive/recovery (kind
 *      3), returns the count applied (not -1), and resumes once the hole is
 *      filled. (The scope's text says the unbounded call "stops at the hole
 *      by failing"; it returns >= 0 and always has -- this phase pins the
 *      real behaviour.)
 *
 * Watched to FAIL before the change: with utxo_live_catchup_bounded reduced
 * to the unbounded body (budget and stop_at_hole ignored), A's "no failure
 * classification" and "stop reason HOLE" fail (the hole is classed
 * archive/recovery, reason FAIL), B's "stopped on the budget" fails (all
 * 4,000 blocks connect, reason TIP), C's reason is SHUTDOWN either way.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
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
extern long utxo_live_catchup_bounded(void* store_buf, long max_ms, int stop_at_hole);
extern long utxo_live_last_stop_reason(void);
extern long utxo_live_last_fail_kind(void);
extern long utxo_live_count(void);
extern long utxo_live_applied_height(void);
extern void utxo_live_close(void);
extern void utxo_live_set_shutdown_flag(const volatile sig_atomic_t* flag);

/* utxo_live.c's UTXO_STOP_* (a private enum; mirrored here on purpose so a
 * renumbering shows up as a failure, not a silent pass) */
enum { STOP_TIP = 0, STOP_HOLE = 1, STOP_BUDGET = 2, STOP_SHUTDOWN = 3, STOP_REJECT = 4, STOP_FAIL = 5 };
enum { FAIL_NONE = 0, FAIL_REJECT = 1, FAIL_STORE = 2, FAIL_OTHER = 3 };

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    fprintf(stderr, "test_utxo_catchup_bounded: unexpected call to mempool_resolve_confirmed_utxo\n");
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

/* Same minimal coinbase-only block as tests/test_utxo_catchup_shutdown.c. */
static long mk_and_mine(u8* raw, u8 hash[32], const u8 prev[32], u32 tag, u32 tstamp){
    u8 tx[80], txid[32];
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

/* ---- the hole: zero index.dat's 48-byte record for height h, keeping a
 * copy so it can be "delivered" later exactly as a helper would leave it ---- */
static int punch_hole(long h, u8 saved[48]){
    int fd = open("index.dat", O_RDWR); if (fd < 0) return 0;
    u8 z[48]; memset(z, 0, 48);
    int ok = pread(fd, saved, 48, h*48) == 48 && pwrite(fd, z, 48, h*48) == 48;
    close(fd); return ok;
}
static int fill_hole(long h, const u8 saved[48]){
    int fd = open("index.dat", O_RDWR); if (fd < 0) return 0;
    int ok = pwrite(fd, saved, 48, h*48) == 48;
    close(fd); return ok;
}

/* stderr -> a file for one call, so the WARNING line can be asserted on */
static int g_saved_stderr = -1;
static void capture_begin(const char* path){
    fflush(stderr);
    g_saved_stderr = dup(2);
    int fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0){ perror("open capture"); exit(1); }
    dup2(fd, 2); close(fd);
}
static char* capture_end(const char* path){
    fflush(stderr);
    dup2(g_saved_stderr, 2); close(g_saved_stderr); g_saved_stderr = -1;
    FILE* f = fopen(path, "rb"); if (!f) return 0;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char* buf = malloc((size_t)n + 1); if (!buf){ fclose(f); return 0; }
    size_t got = fread(buf, 1, (size_t)n, f); fclose(f); buf[got] = 0;
    return buf;
}

static volatile sig_atomic_t g_flag = 0;

int main(void){
    tt_isolate();

    /* ---------------- A: holes at known heights ---------------- */
    {
        tt_subdir("holes");
        memset(store_buf,0,sizeof store_buf);
        ck("A store_init", store_init(store_buf), 1);
        ck("A utxo_live_init", utxo_live_init("."), 1);
        long n = 300;
        if (build_chain(n, 0x70000000u) < 0) return 1;
        u8 rec100[48], rec200[48];
        ckm("A punched holes at 100 and 200", punch_hole(100, rec100) && punch_hole(200, rec200));

        capture_begin("a1.log");
        long ar = utxo_live_catchup_bounded(store_buf, 60000, 1);
        char* log = capture_end("a1.log");
        ck("A1 bounded call connects exactly the contiguous prefix [0,99]", ar, 100);
        ck("A1 applied_height == 99", utxo_live_applied_height(), 99);
        ck("A1 stop reason == HOLE", utxo_live_last_stop_reason(), STOP_HOLE);
        ck("A1 no failure classification (a hole is expected, not archive/recovery)", utxo_live_last_fail_kind(), FAIL_NONE);
        ckm("A1 no 'hole/short block' WARNING logged", log && !strstr(log, "hole/short block"));
        ck("A1 utxo_applied_height.dat == applied height", read_checkpoint_file(), 99);
        ck("A1 live count == 100", utxo_live_count(), 100);
        free(log);

        ar = utxo_live_catchup_bounded(store_buf, 60000, 1);
        ck("A2 hole still there: the next call connects nothing", ar, 0);
        ck("A2 stop reason still HOLE", utxo_live_last_stop_reason(), STOP_HOLE);
        ck("A2 applied_height unchanged", utxo_live_applied_height(), 99);

        ckm("A3 height 100 delivered", fill_hole(100, rec100));
        ar = utxo_live_catchup_bounded(store_buf, 60000, 1);
        ck("A3 resumes past it: connects [100,199] and stops at the next hole", ar, 100);
        ck("A3 applied_height == 199", utxo_live_applied_height(), 199);
        ck("A3 stop reason == HOLE", utxo_live_last_stop_reason(), STOP_HOLE);
        ck("A3 checkpoint == 199", read_checkpoint_file(), 199);

        ckm("A4 height 200 delivered", fill_hole(200, rec200));
        ar = utxo_live_catchup_bounded(store_buf, 60000, 1);
        ck("A4 connects the rest [200,299]", ar, 100);
        ck("A4 applied_height == 299 (the tip)", utxo_live_applied_height(), 299);
        ck("A4 stop reason == TIP", utxo_live_last_stop_reason(), STOP_TIP);
        ck("A4 checkpoint == 299", read_checkpoint_file(), 299);
        ck("A4 live count == 300", utxo_live_count(), 300);
        ck("A5 caught up: another bounded call is a no-op", utxo_live_catchup_bounded(store_buf, 60000, 1), 0);
        utxo_live_close();
    }

    /* ---------------- B: the time budget ---------------- */
    {
        tt_subdir("budget");
        memset(store_buf,0,sizeof store_buf);
        ck("B store_init", store_init(store_buf), 1);
        ck("B utxo_live_init", utxo_live_init("."), 1);
        long n = 4000;
        if (build_chain(n, 0x71000000u) < 0) return 1;

        long ar = utxo_live_catchup_bounded(store_buf, 1, 1);
        printf("     B: a 1 ms budget connected %ld of %ld\n", ar, n);
        ckm("B1 a tiny budget still connects at least one block (the check is after the block)", ar >= 1);
        ckm("B1 ...and only a prefix, not the whole chain", ar < n);
        ck("B1 stop reason == BUDGET", utxo_live_last_stop_reason(), STOP_BUDGET);
        ck("B1 applied_height == blocks connected - 1", utxo_live_applied_height(), ar - 1);
        ck("B1 checkpoint == applied_height (the pending batch landed on exit)", read_checkpoint_file(), utxo_live_applied_height());
        ck("B1 no failure classification", utxo_live_last_fail_kind(), FAIL_NONE);

        /* repeated bounded calls: every one makes progress, none overshoots */
        long total = ar, calls = 1; int monotone = 1;
        while (utxo_live_applied_height() < n - 1 && calls < 100000){
            long got = utxo_live_catchup_bounded(store_buf, 1, 1);
            if (got < 1) { monotone = 0; break; }
            total += got; calls++;
        }
        printf("     B: %ld bounded call(s) to the tip\n", calls);
        ckm("B2 every bounded call connected >= 1 block until the tip", monotone);
        ck("B2 the calls sum to the chain exactly", total, n);
        ck("B2 applied_height at the tip", utxo_live_applied_height(), n - 1);
        ck("B2 last stop reason == TIP", utxo_live_last_stop_reason(), STOP_TIP);
        ck("B2 checkpoint == tip", read_checkpoint_file(), n - 1);
        ck("B2 live count == n", utxo_live_count(), n);
        ck("B3 max_ms == 0 with stop_at_hole: unbounded in time, a no-op when caught up", utxo_live_catchup_bounded(store_buf, 0, 1), 0);
        utxo_live_close();
    }

    /* ---------------- C: the shutdown flag ---------------- */
    {
        tt_subdir("shutdown");
        memset(store_buf,0,sizeof store_buf);
        ck("C store_init", store_init(store_buf), 1);
        ck("C utxo_live_init", utxo_live_init("."), 1);
        utxo_live_set_shutdown_flag(&g_flag);
        long n = 50;
        if (build_chain(n, 0x72000000u) < 0) return 1;
        g_flag = 1;
        long ar = utxo_live_catchup_bounded(store_buf, 60000, 1);
        ck("C flag set: the bounded call finishes the block in progress and stops (exactly 1)", ar, 1);
        ck("C stop reason == SHUTDOWN", utxo_live_last_stop_reason(), STOP_SHUTDOWN);
        ck("C checkpoint == applied (0)", read_checkpoint_file(), 0);
        g_flag = 0;
        ck("C flag cleared: the rest connects", utxo_live_catchup_bounded(store_buf, 60000, 1), n - 1);
        ck("C applied at tip", utxo_live_applied_height(), n - 1);
        utxo_live_set_shutdown_flag(NULL);
        utxo_live_close();
    }

    /* ---------------- D: NEGATIVE CONTROL -- the unbounded call ---------------- */
    {
        tt_subdir("control");
        memset(store_buf,0,sizeof store_buf);
        ck("D store_init", store_init(store_buf), 1);
        ck("D utxo_live_init", utxo_live_init("."), 1);
        long n = 300;
        if (build_chain(n, 0x73000000u) < 0) return 1;
        u8 rec150[48];
        ckm("D punched a hole at 150", punch_hole(150, rec150));

        capture_begin("d1.log");
        long ar = utxo_live_catchup(store_buf);
        char* log = capture_end("d1.log");
        ck("D1 unbounded call connects the prefix [0,149] and returns the count (not -1)", ar, 150);
        ck("D1 applied_height == 149", utxo_live_applied_height(), 149);
        ck("D1 the hole is classed archive/recovery (kind 3) -- today's behaviour", utxo_live_last_fail_kind(), FAIL_OTHER);
        ck("D1 stop reason == FAIL", utxo_live_last_stop_reason(), STOP_FAIL);
        ckm("D1 the 'hole/short block' WARNING is logged", log && strstr(log, "hole/short block at height 150"));
        ck("D1 checkpoint == 149", read_checkpoint_file(), 149);
        free(log);

        ckm("D2 height 150 delivered", fill_hole(150, rec150));
        ar = utxo_live_catchup(store_buf);
        ck("D2 the unbounded call resumes and connects the rest", ar, 150);
        ck("D2 applied at tip", utxo_live_applied_height(), n - 1);
        ck("D2 stop reason == TIP", utxo_live_last_stop_reason(), STOP_TIP);
        ck("D2 live count == n", utxo_live_count(), n);
        utxo_live_close();
    }

    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
