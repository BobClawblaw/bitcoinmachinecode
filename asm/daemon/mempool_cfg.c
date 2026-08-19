/* daemon/mempool_cfg.c -- Core -maxmempool and -mempoolexpiry.
 *
 * MAXMEMPOOL. bitcoin_serve.asm holds the relay mempool in STATIC buffers
 * (MP_SLOTS=1024, mp_blob = 2 MiB), so -maxmempool -- Core's default is 300 MB
 * -- could not be honoured at all: the setting would have parsed cleanly and
 * done nothing. mpool_init already takes (mp, slots, blob, blob_cap), so the
 * only thing missing was a right-sized region. We allocate one here and
 * publish it through mp_ext_* before node_serve_loop runs; the asm falls back
 * to its statics when mp_ext_area is null, so nothing that does not call this
 * changes behaviour.
 *
 * MEMPOOLEXPIRY. Mempool slots are [len][txid[32]][blob_off] -- there is no
 * timestamp, so the asm cannot expire anything on its own, and adding one
 * would change the slot layout and struct size for every consumer. Instead we
 * keep insertion times in a parallel C table keyed by txid and evict via the
 * exported mpool_del. That keeps the on-disk/in-memory mempool format
 * untouched while making expiry real.
 */
#include <stdio.h>
#include "log_ts.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/mman.h>
#include "node_config.h"

extern unsigned long mpool_struct_size(unsigned long slots);
extern long mpool_del(void* mp, const unsigned char txid[32]);
extern long mpool_count(void* mp);

/* Published to bitcoin_serve.asm, which declares these extern. Defined HERE
 * so the dependency runs C -> asm and not the reverse: when the asm owned
 * them, every target linking this file without bitcoin_serve.o failed to
 * link. A null area means "use the asm's static fallback". */
void*         mp_ext_area    = 0;
void*         mp_ext_blob    = 0;
unsigned long mp_ext_slots   = 0;
unsigned long mp_ext_blobcap = 0;

/* ---- expiry bookkeeping -------------------------------------------------
 * Open-addressed, same shape as the mempool itself so the two stay in step.
 * Sized to the mempool's slot count; a miss just means we cannot expire that
 * tx, never a wrong deletion. */
typedef struct { unsigned char txid[32]; long t; int used; } mp_seen_t;
static mp_seen_t*   g_seen = 0;
static unsigned long g_seen_mask = 0;
static void*        g_mp_area = 0;

static unsigned long tx_hash(const unsigned char* txid){
    unsigned long h = 1469598103934665603UL;
    for(int i=0;i<32;i++){ h ^= txid[i]; h *= 1099511628211UL; }
    return h;
}

/* Size the region from Core's -maxmempool (MB). Slots are derived from the
 * byte budget at a conservative ~512B per tx and rounded to a power of two,
 * because mpool indexes with a mask. Returns 1 if a region was published. */
int mempool_configure(void){
    long mb = g_cfg.maxmempool_mb;
    if(mb <= 0) return 0;                       /* 0 == keep the asm statics */

    unsigned long long blob_cap = (unsigned long long)mb << 20;
    unsigned long slots = 1024;
    while(slots < (blob_cap / 512UL) && slots < (1UL<<22)) slots <<= 1;

    unsigned long struct_sz = mpool_struct_size(slots);
    void* area = mmap(0, struct_sz, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    void* blob = mmap(0, (size_t)blob_cap, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(area==MAP_FAILED || blob==MAP_FAILED){
        if(area!=MAP_FAILED) munmap(area, struct_sz);
        if(blob!=MAP_FAILED) munmap(blob, (size_t)blob_cap);
        fprintf(stderr,"[mempool] could not allocate %ldMB -- falling back to the built-in 2MiB mempool\n", mb);
        return 0;                                /* degrade, never fail boot */
    }
    mp_ext_area    = area;
    mp_ext_blob    = blob;
    mp_ext_slots   = slots;
    mp_ext_blobcap = (unsigned long)blob_cap;
    g_mp_area      = area;

    g_seen_mask = slots - 1;
    g_seen = (mp_seen_t*)mmap(0, sizeof(mp_seen_t)*slots, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if(g_seen==MAP_FAILED){ g_seen=0; g_seen_mask=0; }   /* expiry off, pool still sized */

    fprintf(stderr,"[mempool] maxmempool=%ldMB -> %lu slots, %lluMB tx storage%s\n",
            mb, slots, blob_cap>>20, g_seen?"":" (expiry tracking unavailable)");
    return 1;
}

/* Record an accepted tx's arrival time. Called from the accept path. */
void mempool_note_accept(const unsigned char txid[32]){
    if(!g_seen) return;
    unsigned long i = tx_hash(txid) & g_seen_mask;
    for(unsigned long p=0; p<=g_seen_mask; p++){
        mp_seen_t* e = &g_seen[(i+p) & g_seen_mask];
        if(!e->used || !memcmp(e->txid, txid, 32)){
            memcpy(e->txid, txid, 32); e->t = (long)time(0); e->used = 1;
            return;
        }
    }
}

/* Evict anything older than -mempoolexpiry hours. Returns entries removed.
 * Safe to call often: it is a linear scan of a bounded table and does nothing
 * when expiry is disabled or the pool is empty. */
long mempool_expire_now(void){
    if(!g_seen || !g_mp_area) return 0;
    long hours = g_cfg.mempoolexpiry_h;
    if(hours <= 0) return 0;
    long cutoff = (long)time(0) - hours*3600;
    long removed = 0;
    for(unsigned long i=0;i<=g_seen_mask;i++){
        mp_seen_t* e = &g_seen[i];
        if(!e->used || e->t > cutoff) continue;
        if(mpool_del(g_mp_area, e->txid) == 1) removed++;
        e->used = 0;                              /* forget either way */
    }
    if(removed)
        fprintf(stderr,"[mempool] expired %ld tx older than %ldh (%ld remain)\n",
                removed, hours, mpool_count(g_mp_area));
    return removed;
}
