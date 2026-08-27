/* daemon/mempool_compact.c -- reclaim freed blob space in the structural
 * mempool (bitcoin_mempool.asm).
 *
 * WHY: that pool's tx-blob is a bump allocator -- mpool_del frees the SLOT
 * but leaves the bytes in place ("not compacted", by its own note), so the
 * fill pointer only ever grows. That is fine for a pool that only grows
 * until a block clears it, but it defeats TrimToSize eviction: evicting a
 * low-feerate tx frees a slot yet no blob bytes, so mpool_put stays full and
 * the higher-feerate replacement cannot be stored. This slides every live
 * entry's blob region down to close the gaps and resets the fill pointer,
 * so the freed bytes become usable again. Called by the policy layer's
 * eviction path right before it retries the store.
 *
 * Layout (bitcoin_mempool.asm header): +8 mask (slots-1), +16 blob base,
 * +24 blob_cap, +32 fill, +40 slots[48]: {+0 len, +8 txid[32], +40 off}.
 * An empty slot has len == 0 or len == 0xFFFFFFFFFFFFFFFF.
 */
#include <stdlib.h>
#include <string.h>

typedef unsigned long u64;

static int cmp_off(const void* a, const void* b){
    u64 x = ((const u64*)a)[0], y = ((const u64*)b)[0];
    return x < y ? -1 : x > y ? 1 : 0;
}

void mpool_compact(void* mp){
    unsigned char* base = (unsigned char*)mp;
    u64 mask;     memcpy(&mask, base + 8, 8);
    u64 slots = mask + 1;
    unsigned char* blob; memcpy(&blob, base + 16, 8);
    unsigned char* slotbase = base + 40;

    /* collect (blob_off, slot_index) of every live slot -- carrying the
     * index avoids re-searching for it after the sort (O(n log n) total) */
    u64* live = malloc((size_t)slots * 2 * sizeof(u64));   /* [off, slotidx] pairs */
    if (!live) return;                                     /* no reclaim; caller still safe */
    u64 nlive = 0;
    for (u64 i = 0; i < slots; i++){
        unsigned char* s = slotbase + i * 48;
        u64 len; memcpy(&len, s, 8);
        if (len == 0 || len == 0xFFFFFFFFFFFFFFFFULL) continue;   /* empty */
        u64 off; memcpy(&off, s + 40, 8);
        live[nlive*2] = off; live[nlive*2+1] = i;
        nlive++;
    }
    if (nlive == 0){ u64 z = 0; memcpy(base + 32, &z, 8); free(live); return; }

    /* sort by ascending blob offset so sliding down never overlaps forward */
    qsort(live, (size_t)nlive, 2 * sizeof(u64), cmp_off);

    /* slide each region down; repoint its slot; track the new fill */
    u64 newfill = 0;
    for (u64 k = 0; k < nlive; k++){
        u64 off = live[k*2], idx = live[k*2+1];
        unsigned char* s = slotbase + idx * 48;
        u64 len; memcpy(&len, s, 8);
        if (off != newfill) memmove(blob + newfill, blob + off, (size_t)len);
        memcpy(s + 40, &newfill, 8);
        newfill += len;
    }
    memcpy(base + 32, &newfill, 8);   /* fill = compacted size */
    free(live);
}
