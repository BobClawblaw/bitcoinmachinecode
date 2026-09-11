#include <string.h>
#include <time.h>
#include <poll.h>
#include <stdio.h>
#include <sys/mman.h>
#include "ibd_pipeline.h"

#define IBD_PIPE_MAX 256          /* chunk sizes in use are 40; the cap bounds the arrays */
/* Out-of-order arrivals are HELD until every earlier height in the chunk has
 * been stored, so the archive still grows in ascending height order. That
 * matters because the connect loop walks heights upward THROUGH these writes
 * (the 2026-09-06 interleave): storing in arrival order put block h+1 on disk
 * while h was still missing, and a real sync then refused a valid block at
 * 48,585 with a false bad-txns-BIP30 -- its coinbase already in the set.
 * Peers answer a getdata in request order in practice, so the hold is
 * normally empty; the cap is what a misbehaving peer can cost us. */
#define IBD_HOLD_BYTES (24u << 20)

/* These MUST match daemon/main.c's declarations exactly -- there is no shared
 * header for them, so a mismatch links cleanly and misbehaves at run time.
 * The first cut of this file declared cons_verify with two parameters (it
 * takes four) and p2p_read as returning long (it returns int, so the high 32
 * bits of the register are garbage): every chunk failed, the download wrote
 * zero blocks, and only the real fixture caught it -- the unit test could
 * not, because its stubs matched the wrong declarations. */
extern long p2p_write(int fd, const char* cmd, unsigned cmdlen, const void* pl, unsigned plen);
extern int  p2p_read(int fd, char cmd[12], void* pl, unsigned cap, unsigned* len);
extern int  hst_get_at(void* hst, unsigned long long idx, void* rec112);
extern int  cons_verify(const void* block, long len, void* scratch, unsigned cap);
extern void block_hash(unsigned char out[32], const unsigned char* hdr80);
extern long store_append_shared(void* st, long height, const unsigned char hash[32],
                                const unsigned char* raw, unsigned len);

/* 2026-09-08: the sink (see ibd_pipeline.h). NULL = store_append_shared. */
static ibd_sink_fn g_sink = 0;
void ibd_pipeline_set_sink(ibd_sink_fn sink){ g_sink = sink; }
static long ibd_sink(void* st, long height, const unsigned char hash[32], const unsigned char* raw, unsigned len){
    return g_sink ? g_sink(st, height, hash, raw, len) : store_append_shared(st, height, hash, raw, len);
}

static long g_last_batch = 0; static int g_last_fail = 0;
/* How long the last chunk spent BLOCKED IN THE SOCKET READ, against its total
 * wall clock. Measured 2026-09-11 on run 22 from outside the process: the
 * eight workers were idle 11-20% of wall time, waiting on peer bytes, while
 * the daemon's own line said "8/8 worker(s) active". Occupancy is the number
 * that decides whether more peers would help, and it was the one number the
 * download did not report. */
static long long g_wait_ms = 0, g_wall_ms = 0;
long ibd_pipeline_last_wait_ms(void){ return g_wait_ms; }
long ibd_pipeline_last_wall_ms(void){ return g_wall_ms; }
/* How long this socket had NOTHING to give us, in milliseconds.
 *
 * IDLE IS THE TIME BEFORE THE FIRST BYTE, NOT THE TIME INSIDE THE READ. The
 * first cut of this timed the whole p2p_read call, which also RECEIVES the
 * message -- a 1.4 MB block at a peer's 1.2 MB/s is most of a second of
 * productive transfer -- so it reported 99% and said nothing. Run 23 printed
 * "pool idle 99%" within ten minutes of starting, which is how it was caught.
 *
 * The question the number answers is "is this peer keeping the pipe full?", so
 * only the stretch with nothing on the socket counts. A zero-timeout poll
 * separates the two for free: bytes already waiting means there was no idle.
 * The blocking poll is bounded so a dead peer still reaches the caller's alarm
 * rather than sitting here. */
static long long ibd_now_ms(void);
long ibd_idle_before_read(int fd)
{
    struct pollfd pfd;
    long long t0;
    pfd.fd = fd; pfd.events = POLLIN; pfd.revents = 0;
    if (poll(&pfd, 1, 0) != 0) return 0;        /* data already there: not idle */
    t0 = ibd_now_ms();
    (void)poll(&pfd, 1, 1000);
    return (long)(ibd_now_ms() - t0);
}

static long long ibd_now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}
long ibd_pipeline_last_batch(void){ return g_last_batch; }
static long g_wave = 0;                  /* 0 = the whole chunk in one getdata */
void ibd_pipeline_set_wave(long n){ g_wave = (n > 0 && n < IBD_PIPE_MAX) ? n : 0; }
static void (*g_progress)(void*) = 0; static void* g_progress_arg = 0;
static void (*g_bytes)(long) = 0;
void ibd_pipeline_set_bytes(void (*cb)(long)){ g_bytes = cb; }
void ibd_pipeline_set_progress(void (*cb)(void*), void* arg){ g_progress = cb; g_progress_arg = arg; }

/* CompactSize for a count < 253 (the only sizes this builds: <= IBD_PIPE_MAX). */
static unsigned build_getdata(unsigned char* out, const unsigned char hashes[][32], long n)
{
    unsigned p = 0;
    out[p++] = (unsigned char)n;                     /* inventory count */
    for (long i = 0; i < n; i++){
        out[p++] = 0x02; out[p++] = 0x00; out[p++] = 0x00; out[p++] = 0x40;  /* MSG_WITNESS_BLOCK, LE */
        memcpy(out + p, hashes[i], 32); p += 32;
    }
    return p;
}

long ibd_fetch_chunk_pipelined(int fd, void* st, void* hst, long lo_real, long nloc,
                               unsigned char* buf, unsigned buflen,
                               void* scratch, unsigned scratch_cap)
{
    /* declared before the first `goto fail`, or the jump skips the
     * initialiser and the compiler is right to refuse it. */
    const long long chunk_t0 = ibd_now_ms(); g_wait_ms = 0; g_wall_ms = 0;
    if (nloc <= 0 || nloc > IBD_PIPE_MAX) return IBD_FAIL_ARGS;
    static unsigned held_off[IBD_PIPE_MAX], held_len[IBD_PIPE_MAX];
    static unsigned char held_hash[IBD_PIPE_MAX][32];
    unsigned char* hold = 0; unsigned held_bytes = 0;
    for (long i = 0; i < nloc; i++) held_len[i] = 0;
    long next = 0;                               /* the next height to STORE */
    static unsigned char want[IBD_PIPE_MAX][32];     /* the chunk's block hashes, by local index */
    static unsigned char prev[IBD_PIPE_MAX][32];     /* each block's expected prevhash */
    static unsigned char got[IBD_PIPE_MAX];
    static unsigned char gd[1 + IBD_PIPE_MAX * 36];
    unsigned char rec[112]; int why = IBD_FAIL_READ;

    for (long i = 0; i < nloc; i++){
        if (hst_get_at(hst, (unsigned long long)i, rec) != 1){ why = IBD_FAIL_HEADERS; goto fail; }
        memcpy(want[i], rec + 80, 32);               /* the header store keeps the block hash at +80 */
        memcpy(prev[i], rec + 4, 32);                /* prevhash inside the 80-byte header */
        got[i] = 0;
    }

    long stored = 0;
    long wave = g_wave > 0 ? g_wave : nloc;      /* one message for the chunk, unless a bench asks otherwise */
    long sent_to = 0;                            /* hashes requested so far */
    /* Every message the peer sends until the chunk is complete. The bound is
     * generous because a peer may interleave inv/addr/ping traffic, but it is
     * finite: a peer that never completes the chunk trips it and is dropped,
     * exactly as the serial path's own skip budget did. */
    long budget = nloc * 8 + 256;
    while (stored < nloc && budget-- > 0){
        if (sent_to < nloc && stored >= sent_to - wave + 1){    /* keep `wave` hashes outstanding */
            long take = nloc - sent_to; if (take > wave) take = wave;
            unsigned glen = build_getdata(gd, (const unsigned char (*)[32])(want + sent_to), take);
            g_last_batch = take;
            if (p2p_write(fd, "getdata", 7, gd, glen) < 0){ why = IBD_FAIL_WRITE; goto fail; }
            sent_to += take;
        }
        char cmd[12]; unsigned len = 0;
        /* IDLE IS THE TIME BEFORE THE FIRST BYTE, NOT THE TIME INSIDE THE READ.
         *
         * The first cut of this timed the whole p2p_read call. That call also
         * RECEIVES the message -- a 1.4 MB block at a peer's 1.2 MB/s is most
         * of a second of productive transfer -- so the figure came out at 99%
         * and said nothing. (Seen immediately on run 23: "pool idle 99%".)
         *
         * What the number is supposed to answer is "is this peer keeping the
         * pipe full?", so it must count only the stretch where the socket has
         * NOTHING to give us. poll() with a zero timeout distinguishes the two
         * for free: if bytes are already waiting, there was no idle at all. */
        g_wait_ms += ibd_idle_before_read(fd);
        int r = p2p_read(fd, cmd, buf, buflen, &len);
        if (r <= 0){ why = IBD_FAIL_READ; goto fail; }
        if (!strncmp(cmd, "ping", 12) && len == 8){ p2p_write(fd, "pong", 4, buf, 8); continue; }
        if (strncmp(cmd, "block", 12) != 0) continue;         /* inv, addr, feefilter, ... */
        if (g_bytes) g_bytes((long)len);                       /* charged whether or not we wanted it */
        if (len < 81) continue;

        if (cons_verify(buf, (long)len, scratch, scratch_cap) != 1){ why = IBD_FAIL_CONSENSUS; goto fail; }   /* same gate, same scratch, as the serial path */
        unsigned char bh[32];
        block_hash(bh, buf);

        long idx = -1;
        for (long i = 0; i < nloc; i++) if (!got[i] && memcmp(bh, want[i], 32) == 0){ idx = i; break; }
        if (idx < 0) continue;   /* a block we did not ask for, or a duplicate: drain it */

        /* the chain link, checked against the HEADERS (already linked and
         * PoW-checked by the header phase), so an out-of-order arrival is
         * verified as strictly as an in-order one. */
        if (idx > 0 && memcmp(buf + 4, want[idx - 1], 32) != 0){ why = IBD_FAIL_LINK; goto fail; }
        if (memcmp(buf + 4, prev[idx], 32) != 0){ why = IBD_FAIL_LINK; goto fail; }

        /* ---- store in ASCENDING height order ---------------------------
         * If this is the next height, write it and then drain whatever the
         * hold has for the heights that follow. Otherwise park it. */
        if (idx == next){
            if (g_progress) g_progress(g_progress_arg);       /* a wanted block arrived: progress */
            if (ibd_sink(st, lo_real + idx, bh, buf, len) < 0){ why = IBD_FAIL_STORE; goto fail; }
            got[idx] = 1; stored++; next++;
            while (next < nloc && held_len[next]){
                if (ibd_sink(st, lo_real + next, held_hash[next],
                             hold + held_off[next], held_len[next]) < 0){ why = IBD_FAIL_STORE; goto fail; }
                /* The hold is a BUMP allocator: freed space is never reused
                 * within a chunk. The first cut subtracted the drained length
                 * from the bump pointer here, which moved it BACK over blocks
                 * still parked -- and when two parked blocks were the same
                 * size (early-chain blocks very often are) the next arrival
                 * landed exactly on a parked block's offset, so that block was
                 * later drained with ANOTHER block's bytes under its own hash.
                 * That is the "record names X, body is Y" archive the 2026-09-06
                 * run 5 left behind. 24 MB per chunk is plenty; nothing needs
                 * reclaiming. (Found by test_shared_stress proving the store
                 * itself correct under 48,000 interleaved appends, which left
                 * only this file to blame.) */
                held_len[next] = 0; got[next] = 1; stored++; next++;
            }
        } else {
            if (held_len[idx]) continue;                       /* already held */
            if (g_progress) g_progress(g_progress_arg);       /* parked out of order, but it DID arrive */
            if (!hold){
                hold = mmap(0, IBD_HOLD_BYTES, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
                if (hold == MAP_FAILED){ hold = 0; why = IBD_FAIL_HOLD; goto fail; }
            }
            if (held_bytes + len > IBD_HOLD_BYTES){ why = IBD_FAIL_HOLD; goto fail; }   /* a peer answering wildly out of order */
            memcpy(hold + held_bytes, buf, len);
            held_off[idx] = held_bytes; held_len[idx] = len;
            memcpy(held_hash[idx], bh, 32);
            held_bytes += len;
        }
    }
    if (stored != nloc){ why = IBD_FAIL_BUDGET; goto fail; }
    if (hold) munmap(hold, IBD_HOLD_BYTES);
    g_wall_ms = ibd_now_ms() - chunk_t0;
    return stored;
fail:
    /* every failure path releases the hold: dlc_worker retries a failed chunk
     * against another peer, so a leak here would be per retry, not per run. */
    if (hold) munmap(hold, IBD_HOLD_BYTES);
    g_wall_ms = ibd_now_ms() - chunk_t0;
    g_last_fail = why;
    return why;
}
int ibd_pipeline_last_fail(void){ return g_last_fail; }
const char* ibd_pipeline_fail_name(int code){
    switch(code){
    case IBD_FAIL_ARGS: return "bad chunk size"; case IBD_FAIL_HEADERS: return "chunk headers unreadable";
    case IBD_FAIL_WRITE: return "getdata write failed"; case IBD_FAIL_READ: return "socket read failed or closed";
    case IBD_FAIL_CONSENSUS: return "a block failed cons_verify"; case IBD_FAIL_LINK: return "a block's prevhash breaks the header chain";
    case IBD_FAIL_STORE: return "store_append_shared failed"; case IBD_FAIL_HOLD: return "hold exhausted or unmappable";
    case IBD_FAIL_BUDGET: return "message budget spent before the chunk completed"; default: return "ok"; }
}
