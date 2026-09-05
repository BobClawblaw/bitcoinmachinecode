/* daemon/serve_rejects.c -- MEM-10 (audit 2026-09-03): a shared memory of
 * transactions we have already refused.
 *
 * THE DEFECT. bitcoin_serve.asm's .inv_txann checked node_relay_flag, the
 * per-connection validation flag, and whether the transaction was already in
 * the pool -- and then sent a getdata. There was no memory of having REFUSED
 * it. So an inbound peer could announce the txid of a valid-signature,
 * policy-rejected transaction (a 100 kvB one with thousands of inputs paying
 * just under the floor, say) once per second, and every announcement was
 * fetched and fully re-verified: thousands of ECDSA and Schnorr checks per
 * announcement, by that connection's serve child, which also takes mp_lock
 * for the policy pass. The download worker has a 60-second request ring and
 * the reconsiderable bypass budget; the inbound path had neither.
 *
 * Core's AlreadyHaveTx consults m_recent_rejects before asking for anything,
 * so the second announcement of a refused transaction costs nothing.
 *
 * SHAPE. A direct-mapped table of 8-byte txid prefixes with timestamps,
 * living in a MAP_SHARED region allocated before the serve children fork --
 * so a transaction one child refused is not re-fetched by the next. It is a
 * CACHE, not a ledger: a collision or a wrapped-away entry costs one extra
 * fetch, never a wrong verdict, because nothing here decides acceptance. That
 * is why 8-byte prefixes and overwrite-on-collision are enough, and why no
 * lock is needed: a torn read yields a prefix that does not match, which
 * falls back to fetching.
 *
 * RECONSIDERABLE IS NOT RECORDED. Core keeps fee-only failures
 * (TX_RECONSIDERABLE) in a separate filter precisely because a CPFP child can
 * overturn them; suppressing re-announcement of those would break 1p1c relay,
 * which this codebase already went to some trouble to support. Only final
 * verdicts land here.
 *
 * CLEARED ON BLOCK CONNECT, as Core resets m_recent_rejects each block: a
 * block can make a previously-invalid transaction valid (its missing input
 * just confirmed), and a stale "no" would keep us from ever fetching it.
 */
#include <string.h>
#include <stdint.h>
#include <time.h>

typedef unsigned char u8;

#define SRJ_SLOTS   8192u          /* direct-mapped; ~64 KB shared */
#define SRJ_TTL_MS  (15*60*1000LL) /* a backstop under the per-block clear */

typedef struct { u8 pfx[8]; long long t_ms; } srj_ent;
typedef struct { volatile long long generation; srj_ent e[SRJ_SLOTS]; } srj_tab;

static srj_tab* g_srj;             /* NULL = feature off, every call a no-op */

unsigned long serve_rejects_size(void){ return sizeof(srj_tab); }

/* Called once, pre-fork, with a MAP_SHARED region of serve_rejects_size(). */
void serve_rejects_attach(void* region){
    g_srj = (srj_tab*)region;
    if (g_srj) memset(g_srj, 0, sizeof *g_srj);
}

static long long srj_now_ms(void){
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
static unsigned srj_slot(const u8* txid){
    /* FNV-1a over the 8 prefix bytes, the model used elsewhere in the tree. */
    unsigned h = 2166136261u;
    for (int i = 0; i < 8; i++){ h ^= txid[i]; h *= 16777619u; }
    return h & (SRJ_SLOTS - 1u);
}

/* 1 = we refused this recently, so do not ask for it again. */
int serve_reject_has(const u8 txid[32]){
    if (!g_srj) return 0;
    const srj_ent* e = &g_srj->e[srj_slot(txid)];
    if (memcmp(e->pfx, txid, 8) != 0) return 0;
    long long age = srj_now_ms() - e->t_ms;
    if (age < 0 || age > SRJ_TTL_MS) return 0;
    return 1;
}

/* Record a FINAL refusal. Callers must not record a reconsiderable one. */
void serve_reject_note(const u8 txid[32]){
    if (!g_srj) return;
    srj_ent* e = &g_srj->e[srj_slot(txid)];
    memcpy(e->pfx, txid, 8);
    e->t_ms = srj_now_ms();
}

/* Core resets m_recent_rejects on every new block, because a block can make a
 * previously-invalid transaction valid. Same here. */
void serve_rejects_clear(void){
    if (!g_srj) return;
    memset(g_srj->e, 0, sizeof g_srj->e);
    g_srj->generation++;
}
long long serve_rejects_generation(void){ return g_srj ? g_srj->generation : 0; }
