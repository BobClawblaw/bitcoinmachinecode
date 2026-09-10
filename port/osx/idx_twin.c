/* ============================================================================
 * idx_twin.c -- persisted block hash -> height open-addressing index,
 * macOS/AArch64. Functional twin of asm/bitcoin_idx.asm (branch bmc_osx).
 *
 * Memory layout of the index object (caller supplies a zero-initialized
 * buffer) -- MUST match the x86 layout byte-for-byte:
 *   +0   qword  n           (number of live entries)
 *   +8   qword  mask        (slot count = mask+1, a power of two)
 *   +16  [8]    reserved
 *   +24  ...    array of slots (48 bytes each; stride 48):
 *               [ +0  qword height ][ +8  u8 hash[32] ][ +40 u8 pad[8] ]
 *   slot address = (idx+24) + slot*48; an empty slot has height == -1.
 *
 *   void idx_init(void *idx, u64 slots_pow2_cap);
 *   int  idx_put (void *idx, const u8 hash[32], long height);
 *        -> 1 new / 0 dup / 2 full
 *   int  idx_get (void *idx, const u8 hash[32], long *height);
 *        -> 1 found (writes *height) / 0
 *   long idx_count(void *idx);
 *   long idx_build_from_file(void *idx, const char *path);
 *        -> 0 ok / -1 can't open
 *
 * idx_hash: FNV-1a over the FULL 32 bytes (the prefix-only first cut
 * clustered catastrophically on real PoW hashes -- leading bytes are
 * near-zero by construction), XOR-folded (>>15) before masking. Linear
 * probing, probe budget = mask+1, full 32-byte compare for dups.
 *
 * idx_build_from_file: buffered pread (4096 records / 192KB window) over a
 * positional index.dat (48-byte records: presence = first 4 bytes non-zero,
 * hash stored in WIRE order at rec[0..31]); idx_puts each present record's
 * hash UNCHANGED -- the serve loop looks up with the hash as it arrives on
 * the p2p wire, so the table must be keyed the same way (the byte-reversal
 * "fix" of 2026-08-27 keyed the table backwards; do not reintroduce it).
 * A record whose hash is already present (dup) is skipped by idx_put's 0 --
 * matching the x86, which ignores the return value.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

typedef uint64_t u64;
typedef int64_t i64;
typedef uint32_t u32;
typedef unsigned char u8;

#define STRIDE 48
#define IDXBUILD_BUFRECS 4096
#define IDXBUILD_BUFBYTES (IDXBUILD_BUFRECS * 48)

static u8 idxbuild_buf[IDXBUILD_BUFBYTES];

void idx_init(void *idx, u64 slots)
{
    u8 *I = (u8 *)idx;
    *(u64 *)(I + 0) = 0;                       /* n = 0 */
    *(u64 *)(I + 8) = slots - 1;               /* mask = slots-1 */
    for (u64 s = 0; s < slots; s++)
        *(i64 *)(I + 24 + s * STRIDE) = -1;    /* height = -1 (empty) */
}

/* FNV-1a over all 32 bytes, XOR-fold, mask. */
static u64 idx_hash(const u8 *hash32, u64 mask)
{
    u32 h = 0x811C9DC5u;                       /* FNV offset basis */
    for (int i = 0; i < 32; i++) {
        h ^= hash32[i];
        h *= 0x01000193u;                      /* FNV prime */
    }
    h ^= (h >> 15);                            /* XOR-fold high bits into low */
    return (u64)h & mask;
}

int idx_put(void *idx, const u8 hash[32], long height)
{
    u8 *I = (u8 *)idx;
    u64 mask = *(u64 *)(I + 8);
    u64 slot = idx_hash(hash, mask);
    u64 budget = mask + 1;
    u8 *base = I + 24;
    for (;;) {
        u8 *sp = base + slot * STRIDE;
        if (*(i64 *)sp == -1) {                /* empty: insert here */
            *(i64 *)sp = (i64)height;
            memcpy(sp + 8, hash, 32);
            (*(u64 *)I)++;
            return 1;
        }
        if (memcmp(sp + 8, hash, 32) == 0)
            return 0;                          /* duplicate */
        if (--budget == 0)
            return 2;                          /* full */
        slot = (slot + 1) & mask;
    }
}

int idx_get(void *idx, const u8 hash[32], long *height)
{
    u8 *I = (u8 *)idx;
    u64 mask = *(u64 *)(I + 8);
    u64 slot = idx_hash(hash, mask);
    u64 budget = mask + 1;
    u8 *base = I + 24;
    for (;;) {
        u8 *sp = base + slot * STRIDE;
        if (*(i64 *)sp == -1)
            return 0;                          /* hit an empty slot: absent */
        if (memcmp(sp + 8, hash, 32) == 0) {
            if (height) *height = (long)*(i64 *)sp;
            return 1;
        }
        if (--budget == 0)
            return 0;                          /* exhausted: absent */
        slot = (slot + 1) & mask;
    }
}

long idx_count(void *idx)
{
    return (long)*(u64 *)idx;
}

long idx_build_from_file(void *idx, const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    off_t sz = lseek(fd, 0, SEEK_END);
    if (sz < 0) { close(fd); return 0; }
    u64 n = (u64)sz / 48;
    u64 pos = 0;
    while (pos < n) {
        u64 remaining = n - pos;
        u64 take = remaining < IDXBUILD_BUFRECS ? remaining : IDXBUILD_BUFRECS;
        ssize_t got = pread(fd, idxbuild_buf, (size_t)(take * 48),
                            (off_t)(pos * 48));
        if (got <= 0) break;                   /* nothing read -> stop */
        u64 full = (u64)got / 48;
        for (u64 i = 0; i < full; i++) {
            const u8 *rec = idxbuild_buf + i * 48;
            u32 presence;
            memcpy(&presence, rec, 4);
            if (presence == 0) continue;       /* hole */
            idx_put(idx, rec, (long)(pos + i));   /* hash UNCHANGED (wire order) */
        }
        pos += full;
        if (full < IDXBUILD_BUFRECS) break;    /* short/final read */
    }
    close(fd);
    return 0;
}
