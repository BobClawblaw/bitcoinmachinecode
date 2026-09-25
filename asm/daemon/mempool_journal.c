/* daemon/mempool_journal.c -- the mempool DEPARTURE journal.
 *
 * See daemon/mempool_journal_fmt.h for why this exists and for the record
 * layout. In short: when a transaction leaves the mempool, Core forgets it,
 * so an explorer cannot say whether a broadcast transaction was mined,
 * replaced, evicted or expired. This writes one 152-byte record per departure
 * into a fixed-capacity ring in the datadir.
 *
 * PROCESS MODEL. The node forks per connection and the mempool region is
 * MAP_SHARED, so a departure can be recorded by the download worker, by a
 * connection child, or by the parent. The ring is therefore MAP_SHARED too and
 * the sequence counter is bumped with an atomic fetch-add: two processes
 * removing at the same moment take different slots instead of the same one.
 *
 * READERS never lock. A record is accepted only when its two sequence stamps
 * agree AND its slot matches its sequence, so a reader that catches a writer
 * mid-record, or a slot being overwritten by the wrap, skips it rather than
 * returning half of one record and half of another. A ring read is inherently
 * a snapshot of a moving structure; the guarantee offered here is that every
 * record RETURNED is one that was really written, not that the set is
 * complete.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include "mempool_journal_fmt.h"
#include "mempool_journal.h"

static unsigned char* g_mpj;          /* mmap base, or NULL when disabled */
static uint64_t       g_mpj_cap;      /* records */
static size_t         g_mpj_bytes;

/* ---- little-endian accessors (the file is LE on every platform) ---------- */
static inline uint64_t ld64(const unsigned char* p){
    uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v;
}
static inline void st64(unsigned char* p, uint64_t v){
    for (int i = 0; i < 8; i++){ p[i] = (unsigned char)(v & 0xff); v >>= 8; }
}
static inline uint32_t ld32(const unsigned char* p){
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline void st32(unsigned char* p, uint32_t v){
    p[0]=(unsigned char)(v&0xff); p[1]=(unsigned char)((v>>8)&0xff);
    p[2]=(unsigned char)((v>>16)&0xff); p[3]=(unsigned char)((v>>24)&0xff);
}

static inline unsigned char* slot_at(uint64_t seq){
    /* seq is 1-based, so slot 0 holds seq 1 */
    return g_mpj + MPJ_HDR_BYTES + (size_t)((seq - 1) % g_mpj_cap) * MPJ_REC_BYTES;
}

int mpj_is_open(void){ return g_mpj != 0; }
uint64_t mpj_capacity(void){ return g_mpj_cap; }

/* ---- open / create ------------------------------------------------------- */
int mpj_open(const char* path, uint64_t capacity){
    if (g_mpj) return 1;                       /* already open */
    if (!path || !*path || capacity == 0) return 0;

    uint64_t want = MPJ_FILE_BYTES(capacity);
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return 0;

    struct stat sb;
    if (fstat(fd, &sb) != 0){ close(fd); return 0; }

    if ((uint64_t)sb.st_size >= MPJ_HDR_BYTES){
        /* An existing ring: adopt ITS capacity, whatever the config now says.
         * Re-sizing in place would renumber every slot and scramble the
         * history the file exists to keep. A capacity change takes effect when
         * the operator removes the file, which is the honest version of a
         * migration we have no reason to write yet. */
        unsigned char hdr[MPJ_HDR_BYTES];
        if (pread(fd, hdr, MPJ_HDR_BYTES, 0) != (ssize_t)MPJ_HDR_BYTES){ close(fd); return 0; }
        if (memcmp(hdr + MPJ_HOFF_MAGIC, MPJ_MAGIC, 8) != 0 ||
            ld32(hdr + MPJ_HOFF_VERSION)  != MPJ_VERSION ||
            ld32(hdr + MPJ_HOFF_RECBYTES) != MPJ_REC_BYTES){
            close(fd); return 0;               /* foreign or future file: refuse, never rewrite */
        }
        uint64_t filecap = ld64(hdr + MPJ_HOFF_CAPACITY);
        if (filecap == 0 || (uint64_t)sb.st_size < MPJ_FILE_BYTES(filecap)){ close(fd); return 0; }
        capacity = filecap;
        want = MPJ_FILE_BYTES(capacity);
    } else {
        if (ftruncate(fd, (off_t)want) != 0){ close(fd); return 0; }
        unsigned char hdr[MPJ_HDR_BYTES];
        memset(hdr, 0, sizeof hdr);
        memcpy(hdr + MPJ_HOFF_MAGIC, MPJ_MAGIC, 8);
        st32(hdr + MPJ_HOFF_VERSION,  MPJ_VERSION);
        st32(hdr + MPJ_HOFF_RECBYTES, MPJ_REC_BYTES);
        st64(hdr + MPJ_HOFF_CAPACITY, capacity);
        st64(hdr + MPJ_HOFF_NEXTSEQ,  1);      /* sequences are 1-based; 0 means "never written" */
        if (pwrite(fd, hdr, MPJ_HDR_BYTES, 0) != (ssize_t)MPJ_HDR_BYTES){ close(fd); return 0; }
    }

    void* m = mmap(0, (size_t)want, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);                                  /* the mapping keeps the file alive */
    if (m == MAP_FAILED) return 0;
    g_mpj = (unsigned char*)m;
    g_mpj_cap = capacity;
    g_mpj_bytes = (size_t)want;
    return 1;
}

void mpj_close(void){
    if (!g_mpj) return;
    munmap(g_mpj, g_mpj_bytes);
    g_mpj = 0; g_mpj_cap = 0; g_mpj_bytes = 0;
}

/* ---- append -------------------------------------------------------------- */
void mpj_append(const mpj_rec* r){
    if (!g_mpj || !r) return;
    if (r->reason == 0 || r->reason > MPJ_REASON_MAX) return;

    /* One atomic bump per departure: two processes removing at the same moment
     * take different slots. Without this they would race onto one slot and the
     * loser's record would be silently lost -- the pool really is written by
     * several processes (see the header note). */
    uint64_t seq = __atomic_fetch_add((uint64_t*)(g_mpj + MPJ_HOFF_NEXTSEQ), 1, __ATOMIC_RELAXED);
    if (seq == 0) seq = __atomic_fetch_add((uint64_t*)(g_mpj + MPJ_HOFF_NEXTSEQ), 1, __ATOMIC_RELAXED);

    unsigned char* s = slot_at(seq);

    /* head stamp first, then the body, then the tail stamp. A reader requires
     * the two stamps to agree, so any interruption in between reads as a torn
     * record and is skipped rather than returned as a whole one. */
    st64(s + MPJ_OFF_SEQ_TAIL, 0);             /* invalidate before touching the body */
    __atomic_thread_fence(__ATOMIC_RELEASE);
    st64(s + MPJ_OFF_SEQ_HEAD, seq);
    memcpy(s + MPJ_OFF_TXID,  r->txid,  32);
    memcpy(s + MPJ_OFF_WTXID, r->wtxid, 32);
    memcpy(s + MPJ_OFF_AUX,   r->aux,   32);
    st64(s + MPJ_OFF_FIRST_SEEN, (uint64_t)r->first_seen);
    st64(s + MPJ_OFF_DEPARTED,   (uint64_t)r->departed_at);
    st64(s + MPJ_OFF_VSIZE,      r->vsize);
    st64(s + MPJ_OFF_FEE,        r->fee_sat);
    st32(s + MPJ_OFF_REASON,     r->reason);
    st32(s + MPJ_OFF_HEIGHT,     r->height);
    __atomic_thread_fence(__ATOMIC_RELEASE);
    st64(s + MPJ_OFF_SEQ_TAIL, seq);
}

/* ---- read ---------------------------------------------------------------- */
/* Decode slot `seq` if it holds a complete record for that sequence. */
static int read_slot(uint64_t seq, mpj_rec* out){
    const unsigned char* s = slot_at(seq);
    /* 2026-09-25 (ARM ordering review; the bug is on x86 too): check the
     * TAIL stamp FIRST. The writer stamps HEAD before the body and TAIL after
     * it, so HEAD==seq only says a write has STARTED; a reader that checked
     * HEAD, copied a half-written body and then saw the writer's final
     * TAIL==seq returned a torn record as whole. TAIL==seq says the body is
     * complete; the re-check below (TAIL and HEAD still seq) says no new
     * write -- which zeroes TAIL and restamps HEAD first -- began meanwhile. */
    if (ld64(s + MPJ_OFF_SEQ_TAIL) != seq) return 0;   /* empty, incomplete, or already lapped */
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    mpj_rec r;
    r.seq = seq;
    memcpy(r.txid,  s + MPJ_OFF_TXID,  32);
    memcpy(r.wtxid, s + MPJ_OFF_WTXID, 32);
    memcpy(r.aux,   s + MPJ_OFF_AUX,   32);
    r.first_seen  = (int64_t)ld64(s + MPJ_OFF_FIRST_SEEN);
    r.departed_at = (int64_t)ld64(s + MPJ_OFF_DEPARTED);
    r.vsize       = ld64(s + MPJ_OFF_VSIZE);
    r.fee_sat     = ld64(s + MPJ_OFF_FEE);
    r.reason      = ld32(s + MPJ_OFF_REASON);
    r.height      = ld32(s + MPJ_OFF_HEIGHT);
    __atomic_thread_fence(__ATOMIC_ACQUIRE);
    if (ld64(s + MPJ_OFF_SEQ_TAIL) != seq || ld64(s + MPJ_OFF_SEQ_HEAD) != seq) return 0;   /* overwritten while we read */
    if (r.reason == 0 || r.reason > MPJ_REASON_MAX) return 0;
    *out = r;
    return 1;
}

uint64_t mpj_next_seq(void){
    if (!g_mpj) return 0;
    return __atomic_load_n((uint64_t*)(g_mpj + MPJ_HOFF_NEXTSEQ), __ATOMIC_RELAXED);
}

/* Oldest sequence the ring can still hold. */
static uint64_t oldest_seq(uint64_t next){
    return (next > g_mpj_cap) ? next - g_mpj_cap : 1;
}

long mpj_recent(long want, int (*cb)(void*, const mpj_rec*), void* ctx){
    if (!g_mpj || want <= 0 || !cb) return 0;
    uint64_t next = mpj_next_seq();
    if (next <= 1) return 0;
    uint64_t oldest = oldest_seq(next);
    long n = 0;
    for (uint64_t seq = next - 1; seq >= oldest && n < want; seq--){
        mpj_rec r;
        if (read_slot(seq, &r)){ if (!cb(ctx, &r)) break; n++; }
        if (seq == 1) break;                   /* unsigned: do not wrap below 1 */
    }
    return n;
}

int mpj_lookup(const unsigned char txid[32], mpj_rec* out){
    if (!g_mpj || !txid || !out) return 0;
    uint64_t next = mpj_next_seq();
    if (next <= 1) return 0;
    uint64_t oldest = oldest_seq(next);
    /* Newest first: a transaction can depart more than once (broadcast, evicted,
     * rebroadcast, mined) and the newest record is the one that answers "what
     * happened to it". */
    for (uint64_t seq = next - 1; seq >= oldest; seq--){
        mpj_rec r;
        if (read_slot(seq, &r) && memcmp(r.txid, txid, 32) == 0){ *out = r; return 1; }
        if (seq == 1) break;
    }
    return 0;
}

void mpj_stats(mpj_stats_t* st){
    if (!st) return;
    memset(st, 0, sizeof *st);
    if (!g_mpj) return;
    st->capacity = g_mpj_cap;
    uint64_t next = mpj_next_seq();
    st->written  = next - 1;
    st->held     = (st->written < g_mpj_cap) ? st->written : g_mpj_cap;
    if (st->written == 0) return;
    uint64_t oldest = oldest_seq(next);
    mpj_rec r;
    if (read_slot(oldest, &r))   st->oldest_departed = r.departed_at;
    if (read_slot(next - 1, &r)) st->newest_departed = r.departed_at;
    for (uint64_t seq = next - 1; seq >= oldest; seq--){
        if (read_slot(seq, &r) && r.reason <= MPJ_REASON_MAX) st->by_reason[r.reason]++;
        if (seq == 1) break;
    }
}
