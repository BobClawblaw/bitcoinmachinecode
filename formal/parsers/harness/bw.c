/* P-BWTX / P-BWBLK: BIP141 witness checks (daemon/block_witness.c) over
 * transactions from an untrusted block (a peer's block or a compact-block
 * reconstruction): bw_walk_tx and block_check_witness_commitment.
 *
 * P-BWTX claims, for every tx of length <= FP_N:
 *   - memory safety; no read outside tx[0..len),
 *   - acceptance equals Core's UnserializeTransaction (serialize.h,
 *     primitives/transaction.h) re-implemented below as a reference -- in
 *     BOTH directions -- outside one documented domain: a non-witness
 *     serialization with zero inputs (Core then reads a flags byte; such a tx
 *     fails CheckTransaction "bad-txns-vin-empty" regardless),
 *   - on acceptance the commitment pointer (if any) lies in the tx, with 32
 *     readable bytes, and input 0's first witness item lies in the tx.
 * P-BWBLK claims, for blocks of 1..FP_NTX transactions of <= FP_N bytes each:
 *   - memory safety with scratch of exactly ntx*32 bytes (cmpct_recv's and
 *     utxo_live's sizing), merkle_root/sha256d (asm) stubbed as free functions
 *     of readable inputs,
 *   - r == 1 and no commitment => no tx has witness data (Core
 *     "unexpected-witness"); r == 1 with a commitment => every tx walked. */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
void merkle_root(uint8_t out[32], uint8_t* hashes, uint64_t n){
    CHECK(n >= 1 && __CPROVER_w_ok(hashes, n * 32), "merkle_root: hashes in place");
    for (int i = 0; i < 32; i++) out[i] = nondet_uchar();
}
void sha256d(uint8_t out[32], const void* msg, int64_t len){
    CHECK(len >= 0 && __CPROVER_r_ok(msg, (size_t)len), "sha256d input readable");
    CHECK(__CPROVER_w_ok(out, 32), "sha256d output writable");
    for (int i = 0; i < 32; i++) out[i] = nondet_uchar();
}
#include SRC
/* ---- Core's UnserializeTransaction as a reference: 1 deserializes, 0 throws */
static int c_cs(const uint8_t* p, size_t len, size_t* pos, uint64_t* v){
    if (*pos >= len) return 0;
    uint8_t c = p[*pos]; unsigned w = c < 0xfd ? 1 : c == 0xfd ? 3 : c == 0xfe ? 5 : 9;
    if (*pos + w > len) return 0;
    uint64_t x = 0; if (w == 1) x = c; else for (unsigned i = 0; i + 1 < w; i++) x |= (uint64_t)p[*pos + 1 + i] << (8*i);
    if ((w == 3 && x < 0xfd) || (w == 5 && x <= 0xffff) || (w == 9 && x <= 0xffffffffULL)) return 0;
    if (x > 0x02000000ULL) return 0;
    *pos += w; *v = x; return 1;
}
static int c_bytes(size_t len, size_t* pos, uint64_t n){ if (n > len - *pos) return 0; *pos += n; return 1; }
static int c_vin(const uint8_t* p, size_t len, size_t* pos, uint64_t* nin){
    if (!c_cs(p, len, pos, nin)) return 0;
    for (uint64_t i = 0; i < *nin; i++){ uint64_t sl; if (!c_bytes(len, pos, 36) || !c_cs(p, len, pos, &sl) || !c_bytes(len, pos, sl) || !c_bytes(len, pos, 4)) return 0; }
    return 1;
}
static int c_vout(const uint8_t* p, size_t len, size_t* pos){
    uint64_t n; if (!c_cs(p, len, pos, &n)) return 0;
    for (uint64_t i = 0; i < n; i++){ uint64_t sl; if (!c_bytes(len, pos, 8) || !c_cs(p, len, pos, &sl) || !c_bytes(len, pos, sl)) return 0; }
    return 1;
}
/* *zero_in_legacy = the excluded domain (vin empty, flags byte 0) */
static int core_tx_ok(const uint8_t* p, size_t len, int* zero_in_legacy){
    size_t pos = 0; uint64_t nin; uint8_t flags = 0; int haswit = 0; *zero_in_legacy = 0;
    if (!c_bytes(len, &pos, 4)) return 0;
    if (!c_vin(p, len, &pos, &nin)) return 0;
    if (nin == 0){
        if (pos >= len) return 0; flags = p[pos++];
        if (flags != 0){ if (!c_vin(p, len, &pos, &nin) || !c_vout(p, len, &pos)) return 0; }
        else *zero_in_legacy = 1;
    } else if (!c_vout(p, len, &pos)) return 0;
    if (flags & 1){
        flags ^= 1;
        for (uint64_t i = 0; i < nin; i++){ uint64_t k; if (!c_cs(p, len, &pos, &k)) return 0; if (k) haswit = 1;
            for (uint64_t j = 0; j < k; j++){ uint64_t il; if (!c_cs(p, len, &pos, &il) || !c_bytes(len, &pos, il)) return 0; } }
        if (!haswit) return 0;                                   /* Superfluous witness record */
    }
    if (flags) return 0;                                         /* Unknown transaction optional data */
    if (!c_bytes(len, &pos, 4)) return 0;
    return pos == len;      /* the walk is over one tx's exact span: no trailing bytes */
}
#ifndef FP_N
#define FP_N 24
#endif
#ifndef FP_NTX
#define FP_NTX 3
#endif
int main(void){
#ifndef FP_BLOCK
    size_t len = nondet_size(); ASSUME(len <= FP_N);
    uint8_t* tx = nd_buf(len);
    int hw; uint64_t sn, il; const uint8_t* it; const uint8_t* cm;
    int r = bw_walk_tx(tx, len, &hw, &sn, &il, &it, &cm);
    int zl; int core = core_tx_ok(tx, len, &zl);
    if (!zl){ CHECK(r == core, "bw_walk_tx accepts exactly what Core deserializes"); }
    if (r){
        if (cm) CHECK(cm >= tx && cm + 32 <= tx + len, "commitment inside the tx");
        if (it) CHECK(it >= tx && it + il <= tx + len, "input 0 witness item inside the tx");
    }
    free(tx);
    COVER(r && hw, "a witness tx accepted");
    COVER(r && !hw && len >= 20, "a legacy tx with an output accepted");
    COVER(!r && core == 0 && len >= 10 && tx[4] == 0 && tx[5] == 1, "superfluous or truncated witness refused");
#else
    uint64_t ntx = nondet_ull(); ASSUME(ntx >= 1 && ntx <= FP_NTX);
    bw_txref_t refs[FP_NTX];
    for (uint64_t i = 0; i < FP_NTX; i++){ size_t l = nondet_size(); ASSUME(l <= FP_N); refs[i].ptr = nd_buf(l); refs[i].len = l; }
    uint8_t* scratch = nd_buf(ntx * 32);
    const char* why = 0; int seg = nondet_int() & 1;
    long r = block_check_witness_commitment(refs, ntx, sizeof refs[0], seg, scratch, ntx * 32, &why);
    CHECK(r >= -1 && r <= 1 && (r == 1 || why != 0), "result and reason");
    int cw; uint64_t a, b; const uint8_t* c; const uint8_t* cm;
    int ok0 = bw_walk_tx(refs[0].ptr, refs[0].len, &cw, &a, &b, &c, &cm);
    if (r == 1 && !(seg && cm)){
        for (uint64_t i = 0; i < ntx; i++){ int hw; const uint8_t* d; if (bw_walk_tx(refs[i].ptr, refs[i].len, &hw, &a, &b, &c, &d)) CHECK(!hw, "no witness without a commitment"); }
    }
    if (r == 1 && seg && cm) for (uint64_t i = 0; i < ntx; i++){ int hw; const uint8_t* d; CHECK(bw_walk_tx(refs[i].ptr, refs[i].len, &hw, &a, &b, &c, &d), "every tx walks under a commitment"); }
    (void)ok0;
    for (uint64_t i = 0; i < FP_NTX; i++) free((void*)refs[i].ptr);
    free(scratch);
    COVER(r == 1 && seg && cm && ntx >= 2, "commitment verified over two txs");
    COVER(r == 0, "a BLOCK_MUTATED verdict");
#endif
    return 0;
}
