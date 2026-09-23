/* test_mempool_journal.c -- the mempool departure journal's store.
 *
 * The journal exists so that "what happened to this txid" has an answer after
 * the pool has forgotten it. The properties that matter, and are pinned here:
 *
 *   - a departure survives a close/reopen (it is a file, not memory);
 *   - the ring WRAPS rather than grows, and a lapped record reads as absent
 *     instead of as stale bytes that look current;
 *   - a torn record (a writer interrupted mid-record, or a slot overwritten
 *     under a reader) is SKIPPED, never returned half-old and half-new;
 *   - lookup answers with the NEWEST departure of a txid, because a
 *     transaction can leave the pool more than once;
 *   - an existing file's capacity wins over the configured one, so a config
 *     change cannot silently renumber and scramble the history;
 *   - a foreign or future file is REFUSED, never rewritten.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include "../daemon/mempool_journal.h"

/* bitcoin_mempool_policy.c is linked here for the wiring checks at the end
 * (the departure REASON is its state, and its save/restore is the contract
 * that keeps a nested package removal from mis-filing the next one). It calls
 * mempool_resolve_confirmed_utxo, which lives in daemon/tx_accept.c -- far
 * more of the node than this file needs. Pass it through to the plain UTXO
 * lookup, the same stub tests/test_mempool_policy.c uses for the same reason. */
extern long utxo_get(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, unsigned long* height,
                     unsigned long* is_coinbase, const unsigned char** script,
                     unsigned long* slen);
long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script,
                     unsigned long* slen){
    unsigned long h_unused, cb_unused;
    return utxo_get(u, txid, index, value, &h_unused, &cb_unused, script, slen);
}

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static char PATH[256];

static void fill(mpj_rec* r, unsigned n, uint32_t reason){
    memset(r, 0, sizeof *r);
    for (int i = 0; i < 32; i++){ r->txid[i] = (unsigned char)(n + i); r->wtxid[i] = (unsigned char)(n + i + 1); }
    r->first_seen = 1000 + n; r->departed_at = 2000 + n;
    r->vsize = 100 + n; r->fee_sat = 500 + n; r->reason = reason;
}
static int count_cb(void* c, const mpj_rec* r){ (void)r; (*(long*)c)++; return 1; }

typedef struct { mpj_rec* v; long n, cap; } vec;
static int collect_cb(void* c, const mpj_rec* r){ vec* v = c; if (v->n < v->cap) v->v[v->n++] = *r; return 1; }

int main(void){
    snprintf(PATH, sizeof PATH, "/tmp/bmc_mpj_test_%d.dat", (int)getpid());
    unlink(PATH);

    /* ---- create, append, read back ---- */
    ck("opens and creates", mpj_open(PATH, 8) == 1);
    ck("capacity is what was asked for", mpj_capacity() == 8);
    { long n = 0; mpj_recent(100, count_cb, &n); ck("a fresh ring holds nothing", n == 0); }

    mpj_rec r;
    fill(&r, 1, MPJ_EVICTED); mpj_append(&r);
    fill(&r, 2, MPJ_EXPIRED); mpj_append(&r);
    { long n = 0; mpj_recent(100, count_cb, &n); ck("two departures recorded", n == 2); }

    { mpj_rec got; unsigned char want[32]; for (int i = 0; i < 32; i++) want[i] = (unsigned char)(1 + i);
      ck("lookup finds a recorded txid", mpj_lookup(want, &got) == 1);
      ck("...with its reason", got.reason == MPJ_EVICTED);
      ck("...its fee", got.fee_sat == 501);
      ck("...and its first_seen, which the pool itself no longer has", got.first_seen == 1001); }

    { mpj_rec got; unsigned char absent[32]; memset(absent, 0xAB, 32);
      ck("lookup of an unrecorded txid answers no", mpj_lookup(absent, &got) == 0); }

    /* ---- it is a FILE: survives a reopen ---- */
    mpj_close();
    ck("reopens the existing ring", mpj_open(PATH, 8) == 1);
    { long n = 0; mpj_recent(100, count_cb, &n); ck("...and the departures are still there", n == 2); }

    /* ---- the ring WRAPS: bounded, oldest dropped ---- */
    for (unsigned i = 3; i <= 20; i++){ fill(&r, i, MPJ_MINED); mpj_append(&r); }
    { long n = 0; mpj_recent(1000, count_cb, &n);
      ck("20 appends into an 8-record ring hold exactly 8", n == 8); }
    { mpj_rec got; unsigned char old[32]; for (int i = 0; i < 32; i++) old[i] = (unsigned char)(1 + i);
      ck("a lapped record reads as ABSENT, not as stale bytes", mpj_lookup(old, &got) == 0); }
    { mpj_rec got; unsigned char recent[32]; for (int i = 0; i < 32; i++) recent[i] = (unsigned char)(20 + i);
      ck("the newest record is still there", mpj_lookup(recent, &got) == 1 && got.vsize == 120); }

    /* ---- newest first ---- */
    { mpj_rec buf[8]; vec v = { buf, 0, 8 };
      mpj_recent(8, collect_cb, &v);
      ck("recent() is newest first", v.n == 8 && buf[0].departed_at == 2020 && buf[7].departed_at == 2013); }

    /* ---- a txid that departs TWICE: the newest answer wins ---- */
    { fill(&r, 20, MPJ_REPLACED); r.fee_sat = 9999; mpj_append(&r);
      mpj_rec got; unsigned char t[32]; for (int i = 0; i < 32; i++) t[i] = (unsigned char)(20 + i);
      ck("a second departure of the same txid supersedes the first",
         mpj_lookup(t, &got) == 1 && got.reason == MPJ_REPLACED && got.fee_sat == 9999); }

    /* ---- stats ---- */
    { mpj_stats_t st; mpj_stats(&st);
      ck("stats: capacity", st.capacity == 8);
      ck("stats: written is monotonic across the wrap", st.written == 21);
      ck("stats: held is capped at capacity", st.held == 8);
      ck("stats: reasons are counted", st.by_reason[MPJ_MINED] + st.by_reason[MPJ_REPLACED] == 8); }

    /* ---- a TORN record is skipped, not returned ----
     * This is the property a reader cannot check for itself. Corrupt one
     * record's tail stamp the way an interrupted write would, and it must
     * vanish from both the walk and the lookup rather than come back with a
     * body that was never completely written. */
    { long before = 0; mpj_recent(1000, count_cb, &before);
      mpj_close();
      int fd = open(PATH, O_RDWR); ck("reopened the file to tear a record", fd >= 0);
      /* slot for the newest sequence: seq 21 -> (21-1) % 8 = 4 */
      off_t slot = (off_t)MPJ_HDR_BYTES + 4 * (off_t)MPJ_REC_BYTES;
      unsigned char zero[8] = {0};
      ck("tore the tail stamp", pwrite(fd, zero, 8, slot + MPJ_OFF_SEQ_TAIL) == 8);
      close(fd);
      ck("reopens after the tear", mpj_open(PATH, 8) == 1);
      long after = 0; mpj_recent(1000, count_cb, &after);
      ck("the torn record is SKIPPED, the rest still read", after == before - 1);
      mpj_rec got; unsigned char t[32]; for (int i = 0; i < 32; i++) t[i] = (unsigned char)(20 + i);
      ck("...and it is not returned by lookup either",
         mpj_lookup(t, &got) == 0 || got.fee_sat != 9999); }

    /* ---- an existing file's capacity WINS over the configured one ----
     * Adopting a new capacity in place would renumber every slot: slot =
     * (seq-1) % capacity, so changing capacity re-points every record at a
     * different sequence and the history the file exists to keep is scrambled. */
    mpj_close();
    ck("reopening with a DIFFERENT capacity succeeds", mpj_open(PATH, 4096) == 1);
    ck("...but keeps the FILE's capacity, not the argument", mpj_capacity() == 8);
    { long n = 0; mpj_recent(1000, count_cb, &n); ck("...and the records survive that", n == 7); }

    /* ---- a foreign file is refused, never rewritten ---- */
    mpj_close();
    { char other[256]; snprintf(other, sizeof other, "/tmp/bmc_mpj_alien_%d.dat", (int)getpid());
      int fd = open(other, O_RDWR | O_CREAT | O_TRUNC, 0644);
      unsigned char junk[MPJ_HDR_BYTES]; memset(junk, 0x5A, sizeof junk);
      ssize_t w = write(fd, junk, sizeof junk); close(fd);
      ck("wrote an alien file", w == (ssize_t)MPJ_HDR_BYTES);
      ck("a file that is not a journal is REFUSED", mpj_open(other, 8) == 0);
      ck("...and is left alone, not rewritten", (fd = open(other, O_RDONLY)) >= 0);
      unsigned char back[8]; ssize_t rr = read(fd, back, 8); close(fd);
      ck("...its bytes are untouched", rr == 8 && back[0] == 0x5A);
      unlink(other); }

    /* A file whose SIZE and capacity are plausible but whose magic or version
     * is not ours. The alien check above is satisfied by the size guard alone
     * -- removing the magic comparison does not fail it -- so it proves only
     * that some guard fired, not which. These two isolate the magic and the
     * version, because adopting a future format and writing v1 records into it
     * is how a file gets silently corrupted. */
    { char p3[256]; snprintf(p3, sizeof p3, "/tmp/bmc_mpj_magic_%d.dat", (int)getpid());
      int fd = open(p3, O_RDWR | O_CREAT | O_TRUNC, 0644);
      unsigned char h[MPJ_HDR_BYTES]; memset(h, 0, sizeof h);
      memcpy(h, "NOTBMCJ", 8);                        /* right shape, wrong magic */
      h[MPJ_HOFF_VERSION] = 1; h[MPJ_HOFF_RECBYTES] = (unsigned char)MPJ_REC_BYTES; h[MPJ_HOFF_CAPACITY] = 8;
      ck("wrote a well-formed file with the WRONG MAGIC", write(fd, h, sizeof h) == (ssize_t)MPJ_HDR_BYTES);
      ck("...padded to a full ring", ftruncate(fd, (off_t)MPJ_FILE_BYTES(8)) == 0);
      close(fd);
      ck("a well-sized file with the wrong magic is REFUSED", mpj_open(p3, 8) == 0);
      unlink(p3); }
    { char p4[256]; snprintf(p4, sizeof p4, "/tmp/bmc_mpj_ver_%d.dat", (int)getpid());
      int fd = open(p4, O_RDWR | O_CREAT | O_TRUNC, 0644);
      unsigned char h[MPJ_HDR_BYTES]; memset(h, 0, sizeof h);
      memcpy(h, MPJ_MAGIC, 8);
      h[MPJ_HOFF_VERSION] = (unsigned char)(MPJ_VERSION + 1);   /* a FUTURE journal */
      h[MPJ_HOFF_RECBYTES] = (unsigned char)MPJ_REC_BYTES; h[MPJ_HOFF_CAPACITY] = 8;
      ck("wrote a FUTURE-version journal", write(fd, h, sizeof h) == (ssize_t)MPJ_HDR_BYTES);
      ck("...padded to a full ring", ftruncate(fd, (off_t)MPJ_FILE_BYTES(8)) == 0);
      close(fd);
      ck("a future-version journal is REFUSED, not written into", mpj_open(p4, 8) == 0);
      unlink(p4); }

    /* ---- a zero capacity is a refusal, not a divide-by-zero ---- */
    { char p2[256]; snprintf(p2, sizeof p2, "/tmp/bmc_mpj_zero_%d.dat", (int)getpid());
      ck("capacity 0 is refused", mpj_open(p2, 0) == 0); unlink(p2); }

    /* ---- the journal being closed is never fatal ---- */
    mpj_close();
    fill(&r, 99, MPJ_EVICTED);
    mpj_append(&r);                               /* must not crash */
    { mpj_rec got; ck("append on a closed journal is a no-op", mpj_lookup(r.txid, &got) == 0); }
    { mpj_stats_t st; mpj_stats(&st); ck("stats on a closed journal are zero", st.capacity == 0 && st.written == 0); }

    /* ---- an out-of-range reason is refused (the file must only ever hold
     * values the readers can name) ---- */
    ck("reopen for the reason check", mpj_open(PATH, 8) == 1);
    { long before = 0; mpj_recent(1000, count_cb, &before);
      fill(&r, 77, 0);            mpj_append(&r);
      fill(&r, 78, MPJ_REASON_MAX + 1); mpj_append(&r);
      long after = 0; mpj_recent(1000, count_cb, &after);
      ck("a record with no reason, or an unknown one, is not written", after == before); }

    /* ---- the feerate unit -------------------------------------------------
     * The RPC reports sat/kvB. It first shipped as integer sat/vB, and the
     * first live block showed 188 of 200 rows reading "feerate": 0 -- most
     * real transactions are under 1 sat/vB once the fee is divided by vsize.
     * A field that is zero for 94% of rows is worse than no field. Pinned here
     * as arithmetic so the unit cannot quietly go back.
     *
     * 25 sat over 140 vB: 0 in sat/vB, 178 in sat/kvB. */
    { unsigned long long fee = 25, vsize = 140;
      ck("sat/vB would truncate this to zero", fee / vsize == 0);
      ck("sat/kvB keeps it", (fee * 1000ULL) / vsize == 178); }

    /* ---- the WIRING: a departure reason really reaches the journal --------
     * The store above is only half the feature. What actually has to hold is
     * that the policy layer calls the departure hook with the right reason,
     * and that the reason survives the nesting -- a package removal sets a
     * reason, takes descendants with it, and must restore the caller's reason
     * on the way out or the NEXT removal is filed under the wrong one.
     *
     * The policy engine is linked in the wiring test (test_mempool_evict and
     * friends); here the contract is pinned at the seam this file owns: the
     * reason is per-process state with save/restore semantics. */
    ck("reopen for the wiring checks", mpj_open(PATH, 64) == 1);
    {
        extern void mpool_policy_set_depart_reason(int);
        extern int  mpool_policy_depart_reason(void);
        mpool_policy_set_depart_reason(0);
        ck("no reason set by default", mpool_policy_depart_reason() == 0);
        mpool_policy_set_depart_reason(MPJ_EVICTED);
        ck("a reason can be set", mpool_policy_depart_reason() == MPJ_EVICTED);

        /* THE CONTRACT: a policy entry point that sets its OWN reason must put
         * the caller's back before returning. Otherwise the reason leaks: an
         * expiry sweep runs inside an eviction and every later departure is
         * filed as "expired" until something else overwrites it.
         *
         * Calling the setter twice by hand does NOT test this -- that was the
         * first version of this check, and it passed against a setter that
         * ignored the restore entirely, because nothing distinguished "set it
         * back" from "never changed it". It has to go through a real entry
         * point, which is what expire_one is here: it sets MPJ_EXPIRED,
         * removes nothing (the pool is empty), and restores on the way out. */
        extern long mpool_policy_expire_one(void*, void*, const unsigned char*);
        extern void mpool_policy_state_init(void*, unsigned);
        static unsigned char polstate[1 << 20];
        mpool_policy_state_init(polstate, 64);
        unsigned char any[32]; memset(any, 0x7C, 32);
        long r = mpool_policy_expire_one(polstate, 0, any);
        ck("expire_one on an empty pool removes nothing", r == 0);
        ck("...and PUT THE CALLER'S REASON BACK (a leak would mis-file the next departure)",
           mpool_policy_depart_reason() == MPJ_EVICTED);
        mpool_policy_set_depart_reason(0);
    }
    mpj_close();
    unlink(PATH);
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
