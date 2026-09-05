/* block_filter.c -- BIP158 basic compact block filters.
 *
 * WHY: getblockfilter / scanblocks / getdescriptoractivity all refused for
 * want of a filter, while both inputs a filter is built from were already on
 * disk -- the block itself and, for the spent-prevout scripts, the per-block
 * undo data (daemon/undo_log.c). This module is the construction; it holds
 * no state and reads no files, so it can be validated byte-for-byte against
 * Bitcoin Core's own filters in a hermetic test (tests/test_block_filter.c
 * does exactly that, against two real mainnet blocks).
 *
 * THE ALGORITHM (BIP158 "basic" filter):
 *   elements = every output scriptPubKey in the block that is non-empty and
 *              not OP_RETURN, plus every spent prevout's scriptPubKey
 *              (coinbase input excluded), de-duplicated;
 *   each element is SipHash-2-4'd with the key = the first 16 bytes of the
 *   block hash (wire order), then mapped uniformly onto [0, N*M) by the
 *   high 64 bits of a 128-bit multiply;
 *   the mapped values are sorted and delta-encoded, each delta written
 *   Golomb-Rice coded with P=19 (quotient in unary, remainder in 19 bits);
 *   the serialized filter is CompactSize(N) followed by the bitstream.
 *   M = 784931, P = 19 -- BIP158's constants for the basic filter.
 *
 * The filter HEADER chains: header(h) = sha256d(sha256d(filter) || header(h-1)),
 * with header(-1) = 32 zero bytes. bf_header computes one link; whether the
 * previous link is knowable is the CALLER's problem, and rpc_chain is honest
 * about it (see cmd_getblockfilter there).
 */

#include "block_filter.h"
#include <stdlib.h>
#include <string.h>

extern void sha256d(unsigned char out[32], const void* data, unsigned long len);

/* ---- SipHash-2-4, variable length --------------------------------------
 * bitcoin_cmpct.asm's siphash24_uint256 is fixed to 32-byte messages
 * (BIP152's use), so the variable-length form lives here. Standard
 * SipHash-2-4, verified transitively by the whole-filter KATs: a wrong
 * rotation or finalization produces a completely different filter. */
static unsigned long long rotl64(unsigned long long x, int b){
    return (x << b) | (x >> (64 - b));
}
#define SIPROUND do { \
    v0 += v1; v1 = rotl64(v1,13); v1 ^= v0; v0 = rotl64(v0,32); \
    v2 += v3; v3 = rotl64(v3,16); v3 ^= v2; \
    v0 += v3; v3 = rotl64(v3,21); v3 ^= v0; \
    v2 += v1; v1 = rotl64(v1,17); v1 ^= v2; v2 = rotl64(v2,32); \
} while (0)

static unsigned long long bf_siphash(unsigned long long k0, unsigned long long k1,
                                     const unsigned char* m, unsigned long len){
    unsigned long long v0 = 0x736f6d6570736575ULL ^ k0;
    unsigned long long v1 = 0x646f72616e646f6dULL ^ k1;
    unsigned long long v2 = 0x6c7967656e657261ULL ^ k0;
    unsigned long long v3 = 0x7465646279746573ULL ^ k1;
    unsigned long i = 0;
    for (; i + 8 <= len; i += 8){
        unsigned long long mi = 0;
        for (int b = 0; b < 8; b++) mi |= (unsigned long long)m[i+b] << (8*b);
        v3 ^= mi; SIPROUND; SIPROUND; v0 ^= mi;
    }
    unsigned long long last = (unsigned long long)(len & 0xff) << 56;
    for (unsigned long b = 0; i + b < len; b++) last |= (unsigned long long)m[i+b] << (8*b);
    v3 ^= last; SIPROUND; SIPROUND; v0 ^= last;
    v2 ^= 0xff; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

/* map a 64-bit hash uniformly onto [0, nm): the high 64 bits of hash * nm */
static unsigned long long bf_map(unsigned long long h, unsigned long long nm){
    unsigned __int128 p = (unsigned __int128)h * nm;
    return (unsigned long long)(p >> 64);
}

/* ---- bit writer --------------------------------------------------------- */
typedef struct { unsigned char* out; unsigned long cap; unsigned long bitpos; int overflow; } bf_bw;
/* STO-2 (audit 2026-09-03): the writer OWNS every byte it touches.
 *
 * This used to OR into a buffer the CALLER was expected to have zeroed, and
 * bf_basic_build zeroed only the first 64 KiB of it (see the removed memset
 * below). Every caller passes a REUSED buffer -- bfilter_index.c's static
 * BFI_MAX_FILTER malloc, build_block_filters.c's `static u8 filter[1u<<20]`,
 * rpc_chain.c's `static unsigned char flt[1<<20]` -- so any filter whose
 * bitstream ran past 65,536 bytes came out as `previous_filter_bits |
 * this_filter_bits`. A basic filter is ~2.6 bytes per element, so ~25k
 * distinct scripts in one block crosses the line, which consolidation-era and
 * inscription-era mainnet blocks do. The stored filter, its sha256d, and
 * every bf_header after it then diverge from Core permanently.
 *
 * Clearing the byte on FIRST TOUCH removes the caller contract entirely: the
 * bitstream no longer depends on the buffer's prior contents at any size, so
 * there is no zeroing window left to get wrong. It is also strictly cheaper
 * than the memset it replaces -- O(bytes actually written) instead of
 * O(cap) -- which matters because cap is 1 MiB and a typical filter is a few
 * KiB. The trailing bits of the final partial byte are zero for the same
 * reason: that byte was cleared when its first bit was written. */
static void bw_bit(bf_bw* w, int bit){
    unsigned long byte = w->bitpos >> 3;
    unsigned bitidx = (unsigned)(w->bitpos & 7);
    if (byte >= w->cap){ w->overflow = 1; return; }
    if (bitidx == 0) w->out[byte] = 0;
    if (bit) w->out[byte] |= (unsigned char)(0x80u >> bitidx);
    w->bitpos++;
}
static void bw_bits(bf_bw* w, unsigned long long v, int n){
    for (int i = n - 1; i >= 0; i--) bw_bit(w, (int)((v >> i) & 1));
}

/* ---- element collection ------------------------------------------------- */
static unsigned long bf_varint(const unsigned char* p, const unsigned char* end,
                               unsigned long* consumed){
    *consumed = 0;
    if (p >= end) return 0;
    unsigned char b = p[0];
    if (b < 0xfd){ *consumed = 1; return b; }
    if (b == 0xfd){ if (p+3 > end) return 0; *consumed = 3;
        return (unsigned long)p[1] | ((unsigned long)p[2] << 8); }
    if (b == 0xfe){ if (p+5 > end) return 0; *consumed = 5;
        return (unsigned long)p[1] | ((unsigned long)p[2]<<8) |
               ((unsigned long)p[3]<<16) | ((unsigned long)p[4]<<24); }
    if (p+9 > end) return 0;
    *consumed = 9;
    unsigned long v = 0;
    for (int i = 0; i < 8; i++) v |= (unsigned long)p[1+i] << (8*i);
    return v;
}

/* A filter element: skipped when empty or OP_RETURN, per BIP158. */
static int bf_element_ok(const unsigned char* spk, unsigned long len){
    if (len == 0) return 0;
    if (spk[0] == 0x6a) return 0;      /* OP_RETURN */
    return 1;
}

static int bf_cmp_u64(const void* a, const void* b){
    unsigned long long x = *(const unsigned long long*)a, y = *(const unsigned long long*)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* STO-14: order two elements by CONTENT, so equal elements land adjacent and
 * can be dropped. Core keeps its elements in
 * `std::unordered_set<std::vector<unsigned char>>`, which de-duplicates by
 * VALUE; sorting is this implementation's way of reaching the same set
 * without a hash table. The particular order does not matter -- only that
 * equal elements compare equal -- so length first (cheap, and it makes the
 * memcmp safe) then bytes. */
static int bf_cmp_el(const void* a, const void* b){
    const bf_script* x = (const bf_script*)a;
    const bf_script* y = (const bf_script*)b;
    if (x->len != y->len) return x->len < y->len ? -1 : 1;
    return memcmp(x->script, y->script, x->len);
}

long bf_basic_build(const unsigned char* block, unsigned long blocklen,
                    const unsigned char block_hash[32],
                    const bf_script* prevouts, unsigned long n_prevouts,
                    unsigned char* out, unsigned long cap){
    /* SipHash key: first 16 bytes of the block hash, wire order, LE words */
    unsigned long long k0 = 0, k1 = 0;
    for (int i = 0; i < 8; i++) k0 |= (unsigned long long)block_hash[i]   << (8*i);
    for (int i = 0; i < 8; i++) k1 |= (unsigned long long)block_hash[8+i] << (8*i);

    /* worst case: every output plus every prevout is an element */
    unsigned long max_el = n_prevouts + blocklen / 9 + 16;
    /* STO-14 (audit 2026-09-03): collect the ELEMENTS, de-duplicate them by
     * content, and only then hash -- which is what Core does. See the block
     * below the walk for why the old order (hash first, de-duplicate the
     * hashes) was not equivalent. */
    bf_script* el = malloc(max_el * sizeof *el);
    unsigned long long* h = malloc(max_el * sizeof *h);
    if (!el || !h){ free(el); free(h); return -1; }
    unsigned long n = 0;

    for (unsigned long i = 0; i < n_prevouts; i++)
        if (bf_element_ok(prevouts[i].script, prevouts[i].len) && n < max_el){
            el[n].script = prevouts[i].script; el[n].len = prevouts[i].len; n++;
        }

    /* walk the block's transactions for output scripts */
    const unsigned char* p = block + 80;
    const unsigned char* end = block + blocklen;
    unsigned long cc;
    unsigned long ntx = bf_varint(p, end, &cc);
    if (cc == 0){ free(el); free(h); return -1; }
    p += cc;
    for (unsigned long t = 0; t < ntx; t++){
        if (p + 4 > end) goto malformed;
        p += 4;
        int segwit = 0;
        if (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01){ segwit = 1; p += 2; }
        unsigned long n_in = bf_varint(p, end, &cc);
        if (cc == 0 || n_in == 0) goto malformed;
        p += cc;
        for (unsigned long i = 0; i < n_in; i++){
            if (p + 36 > end) goto malformed;
            p += 36;
            unsigned long sl = bf_varint(p, end, &cc);
            if (cc == 0) goto malformed;
            p += cc + sl + 4;
            if (p > end) goto malformed;
        }
        unsigned long n_out = bf_varint(p, end, &cc);
        if (cc == 0) goto malformed;
        p += cc;
        for (unsigned long i = 0; i < n_out; i++){
            if (p + 8 > end) goto malformed;
            p += 8;
            unsigned long sl = bf_varint(p, end, &cc);
            if (cc == 0) goto malformed;
            p += cc;
            if (p + sl > end) goto malformed;
            if (bf_element_ok(p, sl) && n < max_el){
                el[n].script = p; el[n].len = sl; n++;      /* STO-14 */
            }
            p += sl;
        }
        if (segwit){
            for (unsigned long i = 0; i < n_in; i++){
                unsigned long items = bf_varint(p, end, &cc);
                if (cc == 0) goto malformed;
                p += cc;
                for (unsigned long k = 0; k < items; k++){
                    unsigned long il = bf_varint(p, end, &cc);
                    if (cc == 0) goto malformed;
                    p += cc + il;
                    if (p > end) goto malformed;
                }
            }
        }
        if (p + 4 > end) goto malformed;
        p += 4;
    }

    /* ---- STO-14 (audit 2026-09-03): de-duplicate the ELEMENT SET, as Core
     * does, and then hash. --------------------------------------------------
     *
     * This used to hash first and de-duplicate the 64-bit SipHash values.
     * That is NOT equivalent to Core, in two ways, and both are fixed here:
     *
     *  1. THE DEDUP KEY. Core holds its elements in
     *       std::unordered_set<std::vector<unsigned char>, ByteVectorHash>
     *     (blockfilter.h), so N is the count of distinct ELEMENTS. Hashing
     *     first makes N the count of distinct HASHES. Those agree until two
     *     DISTINCT scripts collide on 64 bits, at which point our N was one
     *     lower -- and since N scales the Golomb-Rice range (N * M below),
     *     the WHOLE filter changed, not one entry.
     *
     *  2. CORE DOES NOT DE-DUPLICATE AFTER HASHING. BuildHashedSet maps every
     *     element through HashToRange and sorts; it never drops equal values.
     *     So when two distinct elements DO collide, Core emits both (the
     *     second as a zero delta). Dropping one, as we did, is a second
     *     divergence hiding behind the first. There is deliberately no dedup
     *     of `h` below.
     *
     * Identical scripts still collapse to one element, exactly as before and
     * exactly as Core -- equal bytes are equal in the set. The behaviour that
     * changes is only the collision case.
     *
     * Cost: one extra sort over (pointer, length) pairs. The elements are not
     * copied; el[] points into the block and the caller's prevout scripts,
     * both of which outlive this function. */
    qsort(el, n, sizeof *el, bf_cmp_el);
    { unsigned long w = 0;
      for (unsigned long i = 0; i < n; i++){
          if (w > 0 && el[w-1].len == el[i].len &&
              memcmp(el[w-1].script, el[i].script, el[i].len) == 0) continue;
          el[w++] = el[i];
      }
      n = w; }
    for (unsigned long i = 0; i < n; i++)
        h[i] = bf_siphash(k0, k1, el[i].script, el[i].len);

    unsigned long long nm = (unsigned long long)n * 784931ULL;
    for (unsigned long i = 0; i < n; i++) h[i] = bf_map(h[i], nm);
    qsort(h, n, sizeof *h, bf_cmp_u64);

    /* serialize: CompactSize(N) then the Golomb-Rice stream */
    unsigned long o = 0;
    if (n < 0xfd){ if (o >= cap){ free(el); free(h); return -1; } out[o++] = (unsigned char)n; }
    else if (n <= 0xffff){
        if (o + 3 > cap){ free(el); free(h); return -1; }
        out[o++] = 0xfd; out[o++] = (unsigned char)n; out[o++] = (unsigned char)(n >> 8);
    } else {
        if (o + 5 > cap){ free(el); free(h); return -1; }
        out[o++] = 0xfe;
        for (int i = 0; i < 4; i++) out[o++] = (unsigned char)(n >> (8*i));
    }
    bf_bw w = { out + o, cap - o, 0, 0 };
    /* No memset: bw_bit clears each byte on first touch (STO-2). */
    unsigned long long prev = 0;
    for (unsigned long i = 0; i < n; i++){
        unsigned long long d = h[i] - prev;
        prev = h[i];
        unsigned long long q = d >> 19;
        while (q--) bw_bit(&w, 1);
        bw_bit(&w, 0);
        bw_bits(&w, d & ((1ULL << 19) - 1), 19);
    }
    free(el); free(h);
    if (w.overflow) return -1;
    return (long)(o + ((w.bitpos + 7) >> 3));

malformed:
    free(el); free(h);
    return -1;
}

void bf_header(const unsigned char* filter, unsigned long len,
               const unsigned char prev_header[32], unsigned char out[32]){
    unsigned char buf[64];
    sha256d(buf, filter, len);                 /* the filter hash */
    memcpy(buf + 32, prev_header, 32);
    sha256d(out, buf, 64);
}
