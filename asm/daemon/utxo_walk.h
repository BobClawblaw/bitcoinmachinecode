/* daemon/utxo_walk.h -- shared block input/output walking, used by both
 * build_utxo.c (one-shot batch archive replay) and utxo_live.c (live
 * daemon's incremental catch-up). Extracted verbatim from build_utxo.c's
 * own read_varint/walk_tx_io (byte-for-byte unchanged logic) so both
 * callers stay in lockstep on this parsing rather than drifting via two
 * hand-maintained copies.
 *
 * header-only/static inline: no separate .o or Makefile wiring needed --
 * each including .c file gets its own compiled copy, which is fine since
 * these are pure, self-contained functions with no shared mutable state.
 */
#ifndef UTXO_WALK_H
#define UTXO_WALK_H

#include <string.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int u32;

/* ---- varint reader, matching tx_parse's own CompactSize decode exactly ---- */
/* ---- VAL-10 / SER-3 (audit 2026-09-03): CANONICAL CompactSize ----
 *
 * Core's ReadCompactSize (serialize.h) throws "non-canonical
 * ReadCompactSize()" when a value is encoded in a wider form than it needs,
 * and "ReadCompactSize(): size too large" above MAX_SIZE (0x02000000). Every
 * decoder here accepted `fd 01 00` for 1, so a block containing such a
 * transaction parsed cleanly HERE and is undeserializable to every Core node
 * on the network -- and since txids are computed over the verbatim bytes, the
 * merkle root still matches, so nothing else caught it. A miner producing one
 * would split this node onto a chain no one else can follow.
 *
 * The minimum a width may encode: 0xfd for the 3-byte form, 0x10000 for the
 * 5-byte form, 0x100000000 for the 9-byte form. Nothing valid is lost --
 * a canonical encoder never emits the wider form -- and nothing already in
 * the archive can be affected, because a non-canonical transaction could
 * never have been relayed to us by a Core node in the first place. */
#define UTXO_WALK_CS_MAX_SIZE 0x02000000ULL
static inline u64 utxo_walk_read_varint(const u8* p, const u8* end, u64* consumed){
    if (p >= end) { *consumed = 0; return (u64)-1; }
    u8 c = p[0];
    if (c < 0xfd) { *consumed = 1; return c; }
    if (c == 0xfd) { if (p+3 > end) { *consumed=0; return (u64)-1; }
                     u64 v = (u64)p[1] | ((u64)p[2]<<8);
                     if (v < 0xfdULL || v > UTXO_WALK_CS_MAX_SIZE) { *consumed=0; return (u64)-1; }
                     *consumed=3; return v; }
    if (c == 0xfe) { if (p+5 > end) { *consumed=0; return (u64)-1; }
                     u32 v32; memcpy(&v32,p+1,4); u64 v = v32;
                     if (v <= 0xffffULL || v > UTXO_WALK_CS_MAX_SIZE) { *consumed=0; return (u64)-1; }
                     *consumed=5; return v; }
    if (p+9 > end) { *consumed=0; return (u64)-1; }
    u64 v; memcpy(&v,p+1,8);
    if (v <= 0xffffffffULL || v > UTXO_WALK_CS_MAX_SIZE) { *consumed=0; return (u64)-1; }
    *consumed=9; return v;
}

typedef void (*utxo_walk_input_cb)(void* ctx, const u8 txid[32], u32 index);
typedef void (*utxo_walk_output_cb)(void* ctx, u32 out_index, u64 value, const u8* script, u32 slen);

/* Walk one tx's input/output section (identical shape whether legacy or
 * segwit); returns the observed n_in/n_out via out params for cross-check
 * against tx_parse's own count, and 1/0 for well-formed/truncated. */
static inline int utxo_walk_tx_io(const u8* tx, const u8* end, void* ctx,
                                   utxo_walk_input_cb icb, utxo_walk_output_cb ocb,
                                   u64* out_nin, u64* out_nout){
    const u8* p = tx;
    if (p+4 > end) return 0;
    p += 4; /* version */
    if (p+2 <= end && p[0]==0x00 && p[1]==0x01) p += 2; /* segwit marker/flag */
    u64 consumed;
    u64 n_in = utxo_walk_read_varint(p, end, &consumed); if(!consumed) return 0; p += consumed;
    *out_nin = n_in;
    for (u64 i=0;i<n_in;i++){
        if (p+36 > end) return 0;
        const u8* txid = p; u32 index; memcpy(&index, p+32, 4);
        if (icb) icb(ctx, txid, index);
        p += 36;
        u64 slen = utxo_walk_read_varint(p, end, &consumed); if(!consumed) return 0; p += consumed;
        /* VAL-15 (audit 2026-09-03): split so `slen + 4` cannot wrap. */
        { u64 avail = (u64)(end - p);
          if (slen > avail || avail - slen < 4) return 0; }
        p += slen + 4; /* script + sequence */
    }
    u64 n_out = utxo_walk_read_varint(p, end, &consumed); if(!consumed) return 0; p += consumed;
    *out_nout = n_out;
    for (u64 i=0;i<n_out;i++){
        if (p+8 > end) return 0;
        u64 value; memcpy(&value, p, 8);
        p += 8;
        u64 slen = utxo_walk_read_varint(p, end, &consumed); if(!consumed) return 0; p += consumed;
        if ((u64)(end - p) < slen) return 0;
        if (ocb) ocb(ctx, (u32)i, value, p, (u32)slen);
        p += slen;
    }
    return 1;
}

#endif /* UTXO_WALK_H */
