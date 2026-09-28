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
typedef struct {
    unsigned char* out; unsigned long cap;
    unsigned long bitpos;            /* bits committed to out[] plus those still in acc */
    int overflow;
    unsigned long long acc; int nacc; /* the pending bits, MSB first; nacc < 40 */
} bf_bw;
/* The Golomb-Rice stream is MSB-first. This writer (2026-09-28) accumulates
 * up to 32 bits per call in a 64-bit word and stores whole bytes; the old
 * one stored one BIT per call, and on a 100,000-element filter (2.4 million
 * bits) that alone was ~5 ms of a 13 ms build. bw_finish pads the last byte
 * with zeros, as the bit-at-a-time writer's untouched bits were. */
static void bw_emit(bf_bw* w){
    while (w->nacc >= 8){
        unsigned long byte = w->bitpos >> 3;
        if (byte >= w->cap){ w->overflow = 1; w->nacc = 0; return; }
        w->out[byte] = (unsigned char)(w->acc >> (w->nacc - 8));
        w->nacc -= 8; w->bitpos += 8;
    }
}
static void bw_put(bf_bw* w, unsigned long long v, int n){          /* 1 <= n <= 32 */
    w->acc = (w->acc << n) | (v & ((1ULL << n) - 1));
    w->nacc += n;
    bw_emit(w);
}
static void bw_ones(bf_bw* w, unsigned long long q){
    while (q >= 32){ bw_put(w, 0xffffffffULL, 32); q -= 32; }
    if (q) bw_put(w, (1ULL << q) - 1, (int)q);
}
static void bw_finish(bf_bw* w){
    if (w->nacc){
        unsigned long byte = w->bitpos >> 3;
        if (byte >= w->cap){ w->overflow = 1; return; }
        w->out[byte] = (unsigned char)(w->acc << (8 - w->nacc));
        w->bitpos += (unsigned long)w->nacc; w->nacc = 0;
    }
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

/* LSD radix sort of the mapped hashes, 8 passes of 8 bits through a scratch
 * array (2026-09-28). The values are < N*M < 2^37 for any real filter, so a
 * pass whose byte is zero everywhere is skipped by its histogram. qsort on
 * 100,000 values was ~8 ms of a 21 ms filter; this is well under 1 ms. */
static void bf_radix_sort_u64(unsigned long long* h, unsigned long long* tmp, unsigned long n){
    unsigned long long* src = h; unsigned long long* dst = tmp;
    for (int pass = 0; pass < 8; pass++){
        unsigned long cnt[256]; memset(cnt, 0, sizeof cnt);
        int shift = pass * 8;
        for (unsigned long i = 0; i < n; i++) cnt[(src[i] >> shift) & 0xff]++;
        if (cnt[0] == n) continue;
        unsigned long pos = 0;
        for (int b = 0; b < 256; b++){ unsigned long c = cnt[b]; cnt[b] = pos; pos += c; }
        for (unsigned long i = 0; i < n; i++) dst[cnt[(src[i] >> shift) & 0xff]++] = src[i];
        unsigned long long* t = src; src = dst; dst = t;
    }
    if (src != h) memcpy(h, src, n * sizeof *h);
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
    { long r = bf_build_hashed(k0, k1, el, n, out, cap); free(el); free(h); return r; }
malformed:
    free(el); free(h);
    return -1;
}

/* The filter from a collected element list: de-duplicate by content, hash,
 * sort, Golomb-Rice encode. This is the part Core's GCSFilterConstruct
 * benchmark times (GCSFilter(params, elements) over 100,000 ready-made
 * elements); bf_basic_build parses the block and calls it. el[] is sorted in
 * place. Returns the encoded length, -1 on overflow or allocation failure. */
long bf_build_hashed(unsigned long long k0, unsigned long long k1,
                     bf_script* el, unsigned long n,
                     unsigned char* out, unsigned long cap){
    unsigned long long* h = malloc((n + 1) * sizeof *h);
    unsigned long long* tmp = malloc((n + 1) * sizeof *tmp);
    if (!h || !tmp){ free(h); free(tmp); return -1; }
    /* De-duplicate by CONTENT (STO-14: Core's element set is keyed by value),
     * through an open-addressing table on each element's SipHash (2026-09-28;
     * a qsort by content was ~5 ms of a 13 ms build for 100,000 elements).
     * Exact: a hash match is confirmed by memcmp, so two distinct elements
     * that collide on 64 bits are BOTH kept and both hashes go to the filter
     * -- as Core, which never drops equal hashes. The survivors' hashes are
     * kept, so the filter's own hashing is this same pass. */
    { unsigned long tsz = 1; while (tsz < 2 * n + 2) tsz <<= 1;
      unsigned long* tab = malloc(tsz * sizeof *tab);
      if (!tab){ free(h); free(tmp); return -1; }
      memset(tab, 0xff, tsz * sizeof *tab);                /* ~0UL = empty */
      unsigned long w = 0;
      for (unsigned long i = 0; i < n; i++){
          unsigned long long hv = bf_siphash(k0, k1, el[i].script, el[i].len);
          unsigned long pos = (unsigned long)hv & (tsz - 1);
          int dup = 0;
          while (tab[pos] != ~0UL){
              unsigned long j = tab[pos];
              if (h[j] == hv && el[j].len == el[i].len && memcmp(el[j].script, el[i].script, el[i].len) == 0){ dup = 1; break; }
              pos = (pos + 1) & (tsz - 1);
          }
          if (!dup){ tab[pos] = w; el[w] = el[i]; h[w] = hv; w++; }
      }
      n = w; free(tab); }
    unsigned long long nm = (unsigned long long)n * 784931ULL;
    for (unsigned long i = 0; i < n; i++) h[i] = bf_map(h[i], nm);
    bf_radix_sort_u64(h, tmp, n);

    /* serialize: CompactSize(N) then the Golomb-Rice stream */
    unsigned long o = 0;
    if (n < 0xfd){ if (o >= cap){ free(h); free(tmp); return -1; } out[o++] = (unsigned char)n; }
    else if (n <= 0xffff){
        if (o + 3 > cap){ free(h); free(tmp); return -1; }
        out[o++] = 0xfd; out[o++] = (unsigned char)n; out[o++] = (unsigned char)(n >> 8);
    } else {
        if (o + 5 > cap){ free(h); free(tmp); return -1; }
        out[o++] = 0xfe;
        for (int i = 0; i < 4; i++) out[o++] = (unsigned char)(n >> (8*i));
    }
    bf_bw w = { out + o, cap - o, 0, 0, 0, 0 };
    /* No memset: every byte is stored whole (STO-2 held for the bit writer too). */
    unsigned long long prev = 0;
    for (unsigned long i = 0; i < n; i++){
        unsigned long long d = h[i] - prev;
        prev = h[i];
        bw_ones(&w, d >> 19);                           /* the quotient in unary */
        bw_put(&w, 0, 1);
        bw_put(&w, d & ((1ULL << 19) - 1), 19);         /* the remainder, P = 19 bits */
    }
    bw_finish(&w);
    free(h); free(tmp);
    if (w.overflow) return -1;
    return (long)(o + ((w.bitpos + 7) >> 3));

}


void bf_header(const unsigned char* filter, unsigned long len,
               const unsigned char prev_header[32], unsigned char out[32]){
    unsigned char buf[64];
    sha256d(buf, filter, len);                 /* the filter hash */
    memcpy(buf + 32, prev_header, 32);
    sha256d(out, buf, 64);
}
