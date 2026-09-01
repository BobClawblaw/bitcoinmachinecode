/* daemon/txosp_format.h -- the txo-spender index (Core's -txospenderindex):
 * outpoint -> the transaction that spent it, for CONFIRMED spends. Shared by
 * the offline builder (build_txospender_index.c), the daemon's incremental
 * tail (txosp_tail.c) and the reader (rpc_chain.c), so no two of them can
 * disagree on what a record means.
 *
 * LAYOUT (little-endian):
 *   header, 48 bytes:
 *     "BMCTXOSP" | u64 n_records | u64 sparse_off | u64 sparse_n
 *     | u32 from_height | u32 to_height | u64 reserved
 *   records: n_records x 28 bytes, SORTED by (prefix, vout):
 *     u8 prefix[12] (first 12 WIRE bytes of the spent txid) | u32 vout
 *     | u32 height | u32 offset | u32 len   (the SPENDING tx in its block)
 *   sparse index: every TSP_STRIDE'th record, 24 bytes each:
 *     u8 prefix[12] | u32 vout | u64 byte offset of that record
 *
 * A 12-byte prefix is not a proof: the reader VERIFIES every candidate by
 * reading the spending transaction out of the archive and checking that one
 * of its inputs is the FULL outpoint asked about -- the same discipline
 * txi_format.h uses for the txid index. Coinbase inputs are never indexed.
 */
#ifndef TXOSP_FORMAT_H
#define TXOSP_FORMAT_H
#include <stdint.h>
#include <string.h>
#define TSP_MAGIC   "BMCTXOSP"
#define TSP_HDR     48
#define TSP_REC     28
#define TSP_SPARSE  24
#define TSP_STRIDE  256
#define TSP_BASE_FILE "txospender.dat"
#define TSP_TAIL_FILE "txospender.tail"
typedef struct { uint8_t prefix[12]; uint32_t vout; uint32_t height; uint32_t offset; uint32_t len; } tsp_rec;

static uint64_t tsp_rd_varint(const uint8_t* p, const uint8_t* end, uint64_t* consumed){
    if (p >= end){ *consumed = 0; return 0; }
    if (p[0] < 0xfd){ *consumed = 1; return p[0]; }
    if (p[0] == 0xfd){ if (p + 3 > end){ *consumed = 0; return 0; } *consumed = 3; return (uint64_t)p[1] | ((uint64_t)p[2] << 8); }
    if (p[0] == 0xfe){ if (p + 5 > end){ *consumed = 0; return 0; } *consumed = 5; return (uint64_t)p[1] | ((uint64_t)p[2] << 8) | ((uint64_t)p[3] << 16) | ((uint64_t)p[4] << 24); }
    if (p + 9 > end){ *consumed = 0; return 0; }
    *consumed = 9; uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)p[1+i] << (8*i); return v;
}
static void tsp_pack(uint8_t out[TSP_REC], const tsp_rec* r){
    memcpy(out, r->prefix, 12);
    for (int b = 0; b < 4; b++) out[12+b] = (uint8_t)(r->vout   >> (8*b));
    for (int b = 0; b < 4; b++) out[16+b] = (uint8_t)(r->height >> (8*b));
    for (int b = 0; b < 4; b++) out[20+b] = (uint8_t)(r->offset >> (8*b));
    for (int b = 0; b < 4; b++) out[24+b] = (uint8_t)(r->len    >> (8*b));
}
static void tsp_unpack(tsp_rec* r, const uint8_t in[TSP_REC]){
    memcpy(r->prefix, in, 12); r->vout = r->height = r->offset = r->len = 0;
    for (int b = 0; b < 4; b++) r->vout   |= (uint32_t)in[12+b] << (8*b);
    for (int b = 0; b < 4; b++) r->height |= (uint32_t)in[16+b] << (8*b);
    for (int b = 0; b < 4; b++) r->offset |= (uint32_t)in[20+b] << (8*b);
    for (int b = 0; b < 4; b++) r->len    |= (uint32_t)in[24+b] << (8*b);
}
/* key order: prefix bytes, then vout */
static int tsp_key_cmp(const uint8_t* prefix_a, uint32_t vout_a, const uint8_t* prefix_b, uint32_t vout_b){
    int c = memcmp(prefix_a, prefix_b, 12); if (c) return c;
    return vout_a < vout_b ? -1 : vout_a > vout_b ? 1 : 0;
}
/* Walk a block; call cb(ctx, prevout_txid_wire, vout, tx_offset, tx_len) for
 * every non-coinbase input. Returns 0 on a malformed block. */
static int tsp_walk_block(const uint8_t* blk, long blen,
                          void (*cb)(void*, const uint8_t*, uint32_t, uint32_t, uint32_t), void* ctx){
    const uint8_t* p = blk + 80; const uint8_t* end = blk + blen;
    uint64_t cc, ntx = tsp_rd_varint(p, end, &cc);
    if (!cc || !ntx) return 0;
    p += cc;
    static const uint8_t ZERO32[32] = {0};
    for (uint64_t t = 0; t < ntx; t++){
        const uint8_t* s = p;
        if (p + 4 > end) return 0;
        p += 4;
        int segwit = (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01);
        if (segwit) p += 2;
        uint64_t nin = tsp_rd_varint(p, end, &cc); if (!cc || !nin) return 0;
        p += cc;
        const uint8_t* ins[1]; (void)ins;
        const uint8_t* in_start = p;
        for (uint64_t i = 0; i < nin; i++){
            if (p + 36 > end) return 0;
            p += 36;
            uint64_t sl = tsp_rd_varint(p, end, &cc); if (!cc) return 0;
            p += cc + sl + 4;
            if (p > end) return 0;
        }
        uint64_t nout = tsp_rd_varint(p, end, &cc); if (!cc) return 0;
        p += cc;
        for (uint64_t i = 0; i < nout; i++){
            if (p + 8 > end) return 0;
            p += 8;
            uint64_t sl = tsp_rd_varint(p, end, &cc); if (!cc) return 0;
            p += cc + sl;
            if (p > end) return 0;
        }
        if (segwit){
            for (uint64_t i = 0; i < nin; i++){
                uint64_t items = tsp_rd_varint(p, end, &cc); if (!cc) return 0;
                p += cc;
                for (uint64_t k = 0; k < items; k++){
                    uint64_t il = tsp_rd_varint(p, end, &cc); if (!cc) return 0;
                    p += cc + il;
                    if (p > end) return 0;
                }
            }
        }
        if (p + 4 > end) return 0;
        p += 4;
        /* second pass over this tx's inputs now that its extent is known */
        const uint8_t* q = in_start;
        for (uint64_t i = 0; i < nin; i++){
            uint32_t vo = (uint32_t)q[32] | ((uint32_t)q[33] << 8) | ((uint32_t)q[34] << 16) | ((uint32_t)q[35] << 24);
            int coinbase = (vo == 0xffffffffu && memcmp(q, ZERO32, 32) == 0);
            if (!coinbase) cb(ctx, q, vo, (uint32_t)(s - blk), (uint32_t)(p - s));
            q += 36;
            uint64_t sl = tsp_rd_varint(q, end, &cc); q += cc + sl + 4;
        }
    }
    return 1;
}
#endif
