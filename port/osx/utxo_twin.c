/* ============================================================================
 * utxo_twin.c -- in-memory UTXO set for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_utxo.asm (branch bmc_osx).
 *
 * Layout (offsets from the x86 listing, 48-byte slots):
 *   u+0   slots (count)          u+8   mask = slots-1
 *   u+16  blob base              u+24  blob cap
 *   u+32  blob_used              u+40  slot array (48 B/slot)
 *   slot: +0 blob_off (u64), +8 txid (32), +40 index (u32, 0xFFFFFFFF empty)
 *   record: value(8), height<<32|is_coinbase(8), slen(8), script
 *
 * Hash: FNV-1a over the first 8 txid bytes, xor index, AND mask, *48 + 40.
 * Probing wraps over slots*48 bytes; stops when back at the home slot.
 *
 *   long utxo_put(u, txid, index, value, height, is_coinbase, script, slen)
 *        -> 1 ok / 0 duplicate / 2 full
 *   long utxo_get(u, txid, index, &value, &height, &is_coinbase,
 *                 &script, &slen) -> 1 hit / 0 miss
 *   long utxo_del(u, txid, index) -> 1 / 0
 *   long utxo_count(u)
 *   long utxo_walk_live(u, cb, ctx)  (cb NULL = count live)
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef unsigned char u8;

#define SLOT_SIZE 48
#define SLOTBASE  40

static u64 utxo_hash(const u8 txid[32], u64 index, u64 mask)
{
    u32 h = 0x811c9dc5u;
    for (int i = 0; i < 8; i++) {
        h ^= txid[i];
        h *= 16777619u;
    }
    u64 off = (u64)h ^ index;
    off &= mask;
    return off * SLOT_SIZE + SLOTBASE;
}

void utxo_init(void *u, unsigned long slots, void *blob, unsigned long cap)
{
    u8 *U = (u8 *)u;
    *(u64 *)(U + 0) = 0;                     /* count */
    *(u64 *)(U + 8) = slots - 1;             /* mask */
    *(u64 *)(U + 16) = (u64)(uintptr_t)blob; /* blob base */
    *(u64 *)(U + 24) = cap;
    *(u64 *)(U + 32) = 0;                    /* blob_used */
    u8 *slot = U + SLOTBASE;
    for (unsigned long i = 0; i < slots; i++, slot += SLOT_SIZE)
        *(u32 *)(slot + 40) = 0xFFFFFFFFu;   /* empty */
}

long utxo_put(void *u, const u8 txid[32], unsigned long index,
              u64 value, unsigned height, unsigned is_coinbase,
              const void *script, unsigned long slen)
{
    u8 *U = (u8 *)u;
    u64 mask = *(u64 *)(U + 8);
    u64 off = utxo_hash(txid, index, mask);
    u64 home = off;
    u8 *slot;
    for (;;) {
        slot = U + off;
        u32 idx = *(u32 *)(slot + 40);
        if (idx == 0xFFFFFFFFu) break;                    /* empty: insert */
        if (idx == (u32)index &&
            memcmp(slot + 8, txid, 32) == 0) return 0;    /* duplicate */
        off += SLOT_SIZE;
        if (off >= (mask + 1) * SLOT_SIZE + SLOTBASE) off = SLOTBASE;
        if (off == home) return 2;                        /* table full */
    }
    u64 blob_off = *(u64 *)(U + 32);
    u64 rec_len = slen + 24;
    if (blob_off + rec_len > *(u64 *)(U + 24)) return 2;   /* full */
    u8 *rec = (u8 *)(uintptr_t)(*(u64 *)(U + 16)) + blob_off;
    *(u64 *)(slot) = blob_off;
    memcpy(slot + 8, txid, 32);                     /* slot txid */
    *(u32 *)(slot + 40) = (u32)index;               /* slot index */
    memcpy(rec, &value, 8);
    u64 hc = (u64)height | ((u64)(is_coinbase & 0xFF) << 32);
    memcpy(rec + 8, &hc, 8);
    memcpy(rec + 16, &slen, 8);
    memcpy(rec + 24, script, slen);
    *(u64 *)(U + 32) = blob_off + rec_len;
    (*(u64 *)(U + 0))++;
    return 1;
}

long utxo_get(void *u, const u8 txid[32], unsigned long index,
              u64 *value, unsigned long *height, unsigned long *is_coinbase,
              const void **script, unsigned long *slen)
{
    u8 *U = (u8 *)u;
    u64 mask = *(u64 *)(U + 8);
    u64 off = utxo_hash(txid, index, mask);
    u64 home = off;
    for (;;) {
        u8 *slot = U + off;
        u32 idx = *(u32 *)(slot + 40);
        if (idx == 0xFFFFFFFFu) return 0;                 /* miss */
        if (idx == (u32)index && memcmp(slot + 8, txid, 32) == 0) {
            u8 *rec = (u8 *)(uintptr_t)(*(u64 *)(U + 16)) + *(u64 *)slot;
            memcpy(value, rec, 8);
            u64 hc;
            memcpy(&hc, rec + 8, 8);
            *height = (unsigned long)(hc & 0xFFFFFFFFu);
            *is_coinbase = (unsigned long)((hc >> 32) & 0xFF);
            *script = rec + 24;
            memcpy(slen, rec + 16, 8);
            return 1;
        }
        off += SLOT_SIZE;
        if (off >= (mask + 1) * SLOT_SIZE + SLOTBASE) off = SLOTBASE;
        if (off == home) return 0;                        /* full wrap */
    }
}

long utxo_del(void *u, const u8 txid[32], unsigned long index)
{
    u8 *U = (u8 *)u;
    u64 mask = *(u64 *)(U + 8);
    u64 off = utxo_hash(txid, index, mask);
    u64 home = off;
    for (;;) {
        u8 *slot = U + off;
        u32 idx = *(u32 *)(slot + 40);
        if (idx == 0xFFFFFFFFu) return 0;
        if (idx == (u32)index && memcmp(slot + 8, txid, 32) == 0) {
            /* backward-shift deletion (x86-faithful): open the gap, then
             * scan forward and pull any slot whose probe distance from its
             * home is <= the gap's distance into the gap. */
            unsigned long mask_slots = (unsigned long)mask + 1;
            unsigned long i = (off - SLOTBASE) / SLOT_SIZE;
            *(u32 *)(slot + 40) = 0xFFFFFFFFu;
            (*(u64 *)(U + 0))--;
            unsigned long j = i;
            for (;;) {
                j = (j + 1) & mask;
                u8 *sj = U + (u64)j * SLOT_SIZE + SLOTBASE;
                u32 jidx = *(u32 *)(sj + 40);
                if (jidx == 0xFFFFFFFFu) break;   /* hole fully propagated */
                u64 home_off = utxo_hash(sj + 8, jidx, mask);
                unsigned long k = (home_off - SLOTBASE) / SLOT_SIZE;
                unsigned long di = (i - k) & mask;
                unsigned long dj = (j - k) & mask;
                if (di >= dj) continue;           /* not safe to move */
                u8 *si = U + (u64)i * SLOT_SIZE + SLOTBASE;
                memcpy(si, sj, SLOT_SIZE);
                *(u32 *)(sj + 40) = 0xFFFFFFFFu;
                i = j;
            }
            return 1;   /* blob space is not reclaimed (x86 leaks too) */
        }
        off += SLOT_SIZE;
        if (off >= (mask + 1) * SLOT_SIZE + SLOTBASE) off = SLOTBASE;
        if (off == home) return 0;
    }
}

long utxo_count(void *u)
{
    return *(long *)u;
}

long utxo_walk_live(void *u,
                    int (*cb)(void *, const u8 *, unsigned long, u64,
                              unsigned, unsigned, const void *, unsigned long),
                    void *ctx)
{
    u8 *U = (u8 *)u;
    unsigned long slots = (unsigned long)(*(u64 *)(U + 8)) + 1;
    u8 *blob = (u8 *)(uintptr_t)(*(u64 *)(U + 16));
    long emitted = 0;
    for (unsigned long s = 0; s < slots; s++) {
        u8 *slot = U + (u64)s * SLOT_SIZE + SLOTBASE;
        u32 idx = *(u32 *)(slot + 40);
        if (idx == 0xFFFFFFFFu) continue;
        emitted++;
        if (!cb) continue;
        u64 v; memcpy(&v, slot, 8);
        u8 txid[32]; memcpy(txid, slot + 8, 32);
        u8 *rec = blob + v;
        u64 value; memcpy(&value, rec, 8);
        u64 hc; memcpy(&hc, rec + 8, 8);
        u64 slen; memcpy(&slen, rec + 16, 8);
        if (cb(ctx, txid, (unsigned long)idx, value,
               (unsigned)(hc & 0xFFFFFFFFu),
               (unsigned)((hc >> 32) & 0xFF), rec + 24, slen) != 0)
            return emitted;
    }
    return emitted;
}

void utxo_prefetch(void *u, const u8 txid[32], unsigned long index);
void utxo_prefetch(void *u, const u8 txid[32], unsigned long index)
{
    /* AArch64 has no prefetcht0 equivalent needed for correctness; the
     * harness treats prefetch as a pure hint.  Volatile touch: */
    (void)u; (void)txid; (void)index;
}
