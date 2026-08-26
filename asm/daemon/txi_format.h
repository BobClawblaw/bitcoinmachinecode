/* daemon/txi_format.h -- the txid index's shared record format and block
 * walk, used by the offline builder (build_tx_index.c) and the daemon's
 * incremental tail writer (tx_index_tail.c).
 *
 * WHY A SHARED HEADER: the tail writer emits records the reader must treat
 * exactly like the builder's -- same 20-byte layout, same walk deciding each
 * transaction's (offset, len). Two copies of that walk is how the P2WPKH
 * scriptCode bug happened (a verifier and its generator sharing one wrong
 * assumption in two files); one copy is the fix that lasts.
 *
 * Record: u8 prefix[8] (txid WIRE order) | u32 height | u32 offset | u32 len,
 * little-endian. The 8-byte key is exact-by-verification, not probabilistic:
 * every reader recomputes the full txid from the archive bytes before
 * answering (see rpc_chain.c txi_lookup).
 */
#ifndef TXI_FORMAT_H
#define TXI_FORMAT_H

#include <stdint.h>

#define TXI_MAGIC   "BMCTXIDX"
#define TXI_HDR     48
#define TXI_REC     20
#define TXI_SPARSE  16
#define TXI_TAIL_FILE "txindex.tail"

typedef struct { uint8_t prefix[8]; uint32_t height; uint32_t offset; uint32_t len; } txi_rec;

static uint64_t txi_rd_varint(const uint8_t* p, const uint8_t* end, uint64_t* consumed){
    *consumed = 0;
    if (p >= end) return 0;
    uint8_t b = p[0];
    if (b < 0xfd){ *consumed = 1; return b; }
    if (b == 0xfd){ if (p+3 > end) return 0; *consumed = 3; return (uint64_t)p[1] | ((uint64_t)p[2]<<8); }
    if (b == 0xfe){ if (p+5 > end) return 0; *consumed = 5;
        return (uint64_t)p[1] | ((uint64_t)p[2]<<8) | ((uint64_t)p[3]<<16) | ((uint64_t)p[4]<<24); }
    if (p+9 > end) return 0;
    *consumed = 9;
    uint64_t v = 0; for (int i = 0; i < 8; i++) v |= (uint64_t)p[1+i] << (8*i);
    return v;
}

/* Walk one block's transactions, calling back with (tx ptr, offset, len) for
 * each. Returns 1 if the whole block parsed, 0 on any malformation -- a
 * caller must treat 0 as "index nothing from this block", never "index what
 * we got": a partially-indexed block answers "no such transaction" for the
 * rest of it. */
static int txi_walk_block(const uint8_t* blk, long blen,
                          void (*cb)(void*, const uint8_t*, uint32_t, uint32_t), void* ctx){
    const uint8_t* p = blk + 80; const uint8_t* end = blk + blen;
    uint64_t cc, ntx = txi_rd_varint(p, end, &cc);
    if (!cc || !ntx) return 0;
    p += cc;
    for (uint64_t t = 0; t < ntx; t++){
        const uint8_t* s = p;
        if (p + 4 > end) return 0;
        p += 4;
        int segwit = (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01);
        if (segwit) p += 2;
        uint64_t nin = txi_rd_varint(p, end, &cc); if (!cc || !nin) return 0;
        p += cc;
        for (uint64_t i = 0; i < nin; i++){
            if (p + 36 > end) return 0;
            p += 36;
            uint64_t sl = txi_rd_varint(p, end, &cc); if (!cc) return 0;
            p += cc + sl + 4;
            if (p > end) return 0;
        }
        uint64_t nout = txi_rd_varint(p, end, &cc); if (!cc) return 0;
        p += cc;
        for (uint64_t i = 0; i < nout; i++){
            if (p + 8 > end) return 0;
            p += 8;
            uint64_t sl = txi_rd_varint(p, end, &cc); if (!cc) return 0;
            p += cc + sl;
            if (p > end) return 0;
        }
        if (segwit){
            for (uint64_t i = 0; i < nin; i++){
                uint64_t items = txi_rd_varint(p, end, &cc); if (!cc) return 0;
                p += cc;
                for (uint64_t k = 0; k < items; k++){
                    uint64_t il = txi_rd_varint(p, end, &cc); if (!cc) return 0;
                    p += cc + il;
                    if (p > end) return 0;
                }
            }
        }
        if (p + 4 > end) return 0;
        p += 4;
        cb(ctx, s, (uint32_t)(s - blk), (uint32_t)(p - s));
    }
    return 1;
}

#endif
