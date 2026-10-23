/* P-CMPCT / P-BTXN: BIP152 compact-block receive (daemon/cmpct_recv.c),
 * cmpct_recv_cmpctblock and cmpct_recv_blocktxn, reached by any outbound peer
 * we asked for a compact block (no authentication beyond the header hash,
 * which the peer chooses freely: block_hash is modelled as a free function).
 *
 * Environment (stubs; trusted):
 *   tx_parse (bitcoin_tx.asm)    : 0, or 1 with a length 1 <= tl <= cap in
 *                                  info[0..8); it may only read p[0..cap)
 *   block_hash, sha256_full, siphash24_uint256, bip152_shortid, tx_wtxid
 *                                : free functions of their (readable) inputs
 *   mpool_wtxid_at_slot          : the slot's +48 field (bitcoin_mempool.asm)
 *   the mempool                  : NULL, or a pool of 1..2 slots whose header
 *                                  (count, mask, blob, blob_cap) describes its
 *                                  own allocation; slot lens/offsets free
 *                                  (torn slots allowed, MEM-21)
 *   p2p_write                    : records each message; checks its bytes
 *   getenv                       : NULL (BMC_CMPCT_DUMP / _DEBUG unset)
 * Claims, for every payload of length <= N (FP_N):
 *   - memory safety of both entry points and of the reconstruction,
 *   - r > 0  => r <= cap and the block is out[0..r),
 *   - r == CMPCT_INVALID => nothing was sent to the peer,
 *   - every getblocktxn sent names only positions < ntx, its count equals
 *     the indexes it lists, and its differential indexes reconstruct
 *     strictly increasing positions (Core BlockTransactionsRequest),
 *   - every getdata fallback is one MSG_WITNESS_BLOCK entry for the block,
 *   - at most one message is sent per call. */
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "nd.h"
char* getenv(const char* n){ (void)n; return 0; }
int tx_parse(unsigned char info[64], const unsigned char* p, unsigned long cap){
    CHECK(cap == 0 || __CPROVER_r_ok(p, cap), "tx_parse: the span it may read is readable");
    if (!nondet_int()) return 0;
    unsigned long long tl = nondet_ull(); ASSUME(tl >= 1 && tl <= cap);
    memcpy(info, &tl, 8); return 1;
}
void block_hash(unsigned char out[32], const unsigned char hdr[80]){
    CHECK(__CPROVER_r_ok(hdr, 80), "block_hash: 80 readable bytes");
    for (int i = 0; i < 32; i++) out[i] = nondet_uchar();
}
void sha256_full(unsigned char out[32], const void* msg, long len){
    CHECK(len >= 0 && __CPROVER_r_ok(msg, (size_t)len), "sha256_full input readable");
    for (int i = 0; i < 32; i++) out[i] = nondet_uchar();
}
unsigned long long siphash24_uint256(unsigned long long k0, unsigned long long k1, const unsigned char msg[32]){
    (void)k0; (void)k1; CHECK(__CPROVER_r_ok(msg, 32), "siphash input readable"); return nondet_ull();
}
void bip152_shortid(unsigned char out[6], const unsigned char hdr[80], unsigned long long nonce, const unsigned char w[32]){
    (void)nonce; CHECK(__CPROVER_r_ok(hdr, 80) && __CPROVER_r_ok(w, 32), "shortid inputs readable");
    for (int i = 0; i < 6; i++) out[i] = nondet_uchar();
}
void tx_wtxid(unsigned char out[32], const unsigned char* tx, unsigned long len){
    CHECK(__CPROVER_r_ok(tx, len), "tx_wtxid input readable");
    for (int i = 0; i < 32; i++) out[i] = nondet_uchar();
}
const unsigned char* mpool_wtxid_at_slot(const void* mp, unsigned long i){
    return (const unsigned char*)mp + 40 + i * 80 + 48;
}
static unsigned long g_ntx_seen; static int g_sent; static const unsigned char* g_want;
long p2p_write(int fd, const char* cmd, unsigned cl, const void* pv, unsigned plen){
    (void)fd; const unsigned char* p = pv; g_sent++;
    CHECK(__CPROVER_r_ok(p, plen), "sent payload readable");
    if (cl == 7 && !memcmp(cmd, "getdata", 7)){
        CHECK(plen == 37 && p[0] == 1 && p[1] == 2 && p[2] == 0 && p[3] == 0 && p[4] == 0x40, "fallback is one MSG_WITNESS_BLOCK entry");
        CHECK(!memcmp(p + 5, g_want, 32), "fallback names the block");
    } else {
        CHECK(cl == 11 && !memcmp(cmd, "getblocktxn", 11), "only getdata or getblocktxn is sent");
        CHECK(plen >= 33 && !memcmp(p, g_want, 32), "getblocktxn names the block");
        unsigned long o = 32; unsigned long long n;
        if (p[o] < 0xfd){ n = p[o]; o += 1; } else { CHECK(p[o] == 0xfd, "count fits 3 bytes"); n = p[o+1] | (p[o+2] << 8); o += 3; }
        CHECK(n >= 1, "asks for at least one tx");
        long last = -1;
        for (unsigned long long k = 0; k < n; k++){
            CHECK(o < plen, "index inside the request");
            unsigned long long d;
            if (p[o] < 0xfd){ d = p[o]; o += 1; } else { CHECK(p[o] == 0xfd, "index fits 3 bytes"); d = p[o+1] | (p[o+2] << 8); o += 3; }
            last = last + (long)d + 1;
            CHECK((unsigned long)last < g_ntx_seen, "requested position < ntx");
        }
        CHECK(o == plen, "request has no trailing bytes");
    }
    return (long)plen + 24;
}
#include SRC
#ifndef FP_N
#define FP_N 104
#endif
#ifndef FP_BLOB
#define FP_BLOB 8
#endif
/* the mempool area: header + up to 2 slots (+8 tail, MPOOL_AREA_BYTES) */
static void* mk_pool(void){
    if (!nondet_int()) return 0;
    unsigned long nslots = nondet_ulong(); ASSUME(nslots == 1 || nslots == 2);
    unsigned char* m = nd_buf(40 + nslots * 80 + 8);
    unsigned long long mask = nslots - 1, cap = nondet_ull(); ASSUME(cap <= FP_BLOB);
    unsigned char* blob = nd_buf(cap);
    memcpy(m + 8, &mask, 8); memcpy(m + 16, &blob, sizeof blob); memcpy(m + 24, &cap, 8);
    return m;
}
int main(void){
    cmpct_recv_set_writer(0);
    void* mp = mk_pool();
    unsigned char want[32]; for (int i = 0; i < 32; i++) want[i] = nondet_uchar(); g_want = want;
    size_t plen = nondet_size(); ASSUME(plen <= FP_N);
    unsigned char* pl = nd_buf(plen);
    size_t cap = nondet_size(); ASSUME(cap <= FP_N + 16);
    unsigned char* out = nd_buf(cap);
    long r = cmpct_recv_cmpctblock(3, mp, pl, plen, out, cap, want);
    g_ntx_seen = S.ntx;
    CHECK(g_sent <= 1, "at most one message per cmpctblock");
    CHECK(r == -1 || r == CMPCT_INVALID || r >= 0, "result domain");
    if (r > 0) CHECK((size_t)r <= cap, "block fits out");
    if (r == CMPCT_INVALID) CHECK(g_sent == 0, "INVALID sends nothing");
    if (r == 0) CHECK(g_sent == 1, "pending means a request went out");
    COVER(r > 0, "reconstructed from the pool and prefilled");
    COVER(r == CMPCT_INVALID, "bogus index scored");
    COVER(r == 0 && S.active && S.nmiss >= 2, "getblocktxn for two missing");
    COVER(r == 0 && !S.active, "fallback to a full block");
#ifdef FP_BLOCKTXN
    /* then the peer's blocktxn reply */
    size_t blen = nondet_size(); ASSUME(blen <= FP_N);
    unsigned char* bl = nd_buf(blen);
    int sent0 = g_sent;
    long r2 = cmpct_recv_blocktxn(3, bl, blen, out, cap, nondet_int() ? (const unsigned char*)want : (const unsigned char*)0);
    CHECK(g_sent - sent0 <= 1, "at most one message per blocktxn");
    if (r2 > 0) CHECK((size_t)r2 <= cap, "block fits out (blocktxn)");
    COVER(r2 > 0, "completed by blocktxn");
    COVER(r2 == 0 && g_sent - sent0 == 1, "blocktxn fallback");
    free(bl);
#endif
    free(pl); free(out);
    if (mp){ unsigned char* b; memcpy(&b, (unsigned char*)mp + 16, sizeof b); free(b); free(mp); }
    return 0;
}
/* verified on its own (P-BW*): here only its read footprint is checked */
long block_check_witness_commitment(const void* txs, uint64_t ntx, uint64_t stride, int segwit_active,
                                    uint8_t* scratch, uint64_t scratch_cap, const char** reason){
    (void)segwit_active; (void)scratch; (void)scratch_cap;
    CHECK(ntx >= 1 && ntx <= CR_MAX_TX && stride == sizeof(bw_txref_t), "commitment check gets the parsed refs");
    const bw_txref_t* t = (const bw_txref_t*)txs;
    CHECK(__CPROVER_r_ok(t[0].ptr, t[0].len) && __CPROVER_r_ok(t[ntx-1].ptr, t[ntx-1].len), "first and last tx spans readable");
    *reason = "stub"; long r = nondet_long(); ASSUME(r >= -1 && r <= 1); return r;
}
