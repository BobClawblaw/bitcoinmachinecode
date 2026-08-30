/* daemon/signet_block.c -- BIP325 at the level of a whole block.
 *
 * Layers 1-3 answer "is this solution valid for these header fields?". This
 * turns a BLOCK into that question: find the coinbase's witness commitment,
 * carve the solution out, rebuild the coinbase without it, and take the
 * merkle root the signature actually commits to.
 *
 * Where Core does it: CheckBlock, immediately after CheckBlockHeader, gated
 * on `consensusParams.signet_blocks && fCheckPOW` (validation.cpp:3947). The
 * gate matters -- BIP23 proposal mode (fCheckPOW=0) must NOT demand a
 * signature, or getblocktemplate proposals from a miner that has not signed
 * yet would be rejected.
 *
 * THE COINBASE IS REBUILT, NOT PATCHED IN PLACE. The block buffer belongs to
 * the caller and is shared with every other validator; rewriting a
 * scriptPubKey inside it to compute a hash and then restoring it would be a
 * data race waiting to happen, and would corrupt the block if anything
 * returned early in between.
 */
#include <string.h>
#include "signet.h"
#include "signet_block.h"

typedef unsigned char u8;
typedef unsigned long u64;

extern void merkle_root(u8 out[32], u8* hashes, unsigned long n);
extern int  tx_txid(u8 out32[32], const u8* tx, unsigned long txlen,
                    u8* buf, unsigned long buflen);

/* CompactSize read/write, bounded. Local for the same reason signet.c's are:
 * this file is meant to link without dragging the tx machinery in. */
static int rd_cs(const u8** p, const u8* end, u64* v){
    if (*p >= end) return 0;
    u8 f = *(*p)++;
    if (f < 0xfd){ *v = f; return 1; }
    int extra = (f == 0xfd) ? 2 : (f == 0xfe ? 4 : 8);
    if (end - *p < extra) return 0;
    u64 x = 0;
    for (int i = 0; i < extra; i++) x |= (u64)(*p)[i] << (8*i);
    *p += extra;
    /* canonical, as Core's ReadCompactSize insists */
    u64 min = (f == 0xfd) ? 0xfdUL : (f == 0xfe ? 0x10000UL : 0x100000000UL);
    if (x < min) return 0;
    *v = x; return 1;
}
static u64 wr_cs(u8* d, u64 n){
    if (n < 0xfdUL){ d[0] = (u8)n; return 1; }
    if (n <= 0xffffUL){ d[0]=0xfd; d[1]=(u8)n; d[2]=(u8)(n>>8); return 3; }
    if (n <= 0xffffffffUL){ d[0]=0xfe; for (int i=0;i<4;i++) d[1+i]=(u8)(n>>(8*i)); return 5; }
    d[0]=0xff; for (int i=0;i<8;i++) d[1+i]=(u8)(n>>(8*i)); return 9;
}

/* Rebuild the coinbase's UNWITNESSED serialisation with the commitment
 * output's scriptPubKey replaced, and hash it. That hash is the leaf the
 * modified merkle root starts from.
 *
 * Unwitnessed because a txid is: the witness is dropped, exactly as tx_txid
 * reconstructs it. Getting this wrong would be invisible -- the hash would
 * simply be some other 32 bytes, and every signature on the network would
 * fail against a root built on it. */
static int modified_coinbase_txid(u8 out32[32], const u8* tx, u64 len,
                                  long target_out, const u8* repl, u64 repl_len,
                                  u8* buf, u64 bufcap){
    const u8* end = tx + len;
    const u8* p = tx;
    u8* d = buf;
    u64 v, nin, nout;

    if (len < 10 || bufcap < len + repl_len + 9) return 0;
    memcpy(d, p, 4); d += 4; p += 4;                    /* version */
    if (end - p >= 2 && p[0] == 0x00 && p[1] == 0x01) p += 2;   /* drop marker */

    if (!rd_cs(&p, end, &nin)) return 0;
    d += wr_cs(d, nin);
    for (u64 i = 0; i < nin; i++){
        if (end - p < 36) return 0;
        memcpy(d, p, 36); d += 36; p += 36;
        const u8* ss = p;
        if (!rd_cs(&p, end, &v)) return 0;
        if ((u64)(end - p) < v) return 0;
        memcpy(d, ss, (u64)(p - ss)); d += (p - ss);    /* the length prefix */
        memcpy(d, p, v); d += v; p += v;
        if (end - p < 4) return 0;
        memcpy(d, p, 4); d += 4; p += 4;                /* sequence */
    }

    if (!rd_cs(&p, end, &nout)) return 0;
    d += wr_cs(d, nout);
    for (u64 o = 0; o < nout; o++){
        if (end - p < 8) return 0;
        memcpy(d, p, 8); d += 8; p += 8;                /* value */
        if (!rd_cs(&p, end, &v)) return 0;
        if ((u64)(end - p) < v) return 0;
        if ((long)o == target_out){
            d += wr_cs(d, repl_len);
            memcpy(d, repl, repl_len); d += repl_len;
        } else {
            d += wr_cs(d, v);
            memcpy(d, p, v); d += v;
        }
        p += v;
    }
    /* locktime is the LAST four bytes of the transaction; any witness data
     * sits between the outputs and it, and is skipped by construction. */
    memcpy(d, end - 4, 4); d += 4;

    extern void sha256d(u8 out[32], const void* msg, long long len);
    sha256d(out32, buf, (long long)(d - buf));
    return 1;
}

/* Locate the commitment output: the LAST one whose scriptPubKey passes
 * signet_is_commitment_spk. Returns its index, or -1. Fills spk/spk_len. */
static long find_commitment(const u8* tx, u64 len, const u8** spk, u64* spk_len){
    const u8* end = tx + len;
    const u8* p = tx;
    u64 v, nin, nout;
    long idx = -1;
    if (len < 10) return -2;
    p += 4;
    if (end - p >= 2 && p[0] == 0x00 && p[1] == 0x01) p += 2;
    if (!rd_cs(&p, end, &nin)) return -2;
    for (u64 i = 0; i < nin; i++){
        if (end - p < 36) return -2;
        p += 36;
        if (!rd_cs(&p, end, &v)) return -2;
        if ((u64)(end - p) < v + 4) return -2;
        p += v + 4;
    }
    if (!rd_cs(&p, end, &nout)) return -2;
    for (u64 o = 0; o < nout; o++){
        if (end - p < 8) return -2;
        p += 8;
        if (!rd_cs(&p, end, &v)) return -2;
        if ((u64)(end - p) < v) return -2;
        if (signet_is_commitment_spk(p, v)){ idx = (long)o; *spk = p; *spk_len = v; }
        p += v;
    }
    return idx;
}

long signet_check_block(const void* txs, unsigned long ntx, unsigned long stride,
                        const unsigned char hdr80[80],
                        const unsigned char* challenge, unsigned long challenge_len,
                        unsigned char* scratch, unsigned long cap,
                        const char** reason){
    const char* dummy = 0;
    if (!reason) reason = &dummy;
    *reason = 0;
    #define TX(i) ((const signet_txref_t*)((const u8*)txs + (u64)(i)*stride))

    if (!txs || ntx == 0){ *reason = "bad-signet-no-coinbase"; return 0; }
    if (!hdr80 || !challenge || challenge_len == 0){
        *reason = "signet: no challenge configured"; return -1; }

    /* scratch: leaves | rebuild | verifier work */
    u64 leaves_bytes = (u64)ntx * 32;
    u64 cb_len = TX(0)->len;
    /* The rebuild buffer is reused for tx_txid of EVERY transaction, not just
     * the coinbase, so it must fit the LARGEST one. Sizing it from the
     * coinbase alone made any block whose biggest transaction exceeded its
     * coinbase fail as "malformed" -- which the block-level test caught on a
     * real 17-transaction block, and which no decomposed test could have. */
    u64 maxtx = cb_len;
    for (u64 t = 1; t < ntx; t++) if (TX(t)->len > maxtx) maxtx = TX(t)->len;
    u64 rebuild = maxtx * 2 + 1024;
    if (cap < leaves_bytes + rebuild + SIGNET_WORK_MIN){
        *reason = "signet: scratch too small"; return -1; }
    u8* leaves = scratch;
    u8* buf    = scratch + leaves_bytes;
    u8* work   = buf + rebuild;
    u64 workcap = cap - leaves_bytes - rebuild;

    const u8* spk = 0; u64 spk_len = 0;
    long ci = find_commitment(TX(0)->ptr, cb_len, &spk, &spk_len);
    if (ci == -2){ *reason = "bad-signet-coinbase-malformed"; return 0; }
    if (ci < 0){
        /* Core: GetWitnessCommitmentIndex == NO_WITNESS_COMMITMENT makes
         * SignetTxs::Create return nullopt, and the block is invalid. */
        *reason = "bad-signet-no-commitment"; return 0;
    }

    static __thread u8 sol[4096], stripped[4096];
    u64 sol_len = 0, stripped_len = 0;
    int found = signet_extract_solution(spk, spk_len, sol, &sol_len,
                                        stripped, &stripped_len, sizeof sol);
    if (found < 0){ *reason = "bad-signet-commitment-malformed"; return 0; }
    if (!found){
        /* No solution section: the commitment stands unmodified, and the
         * challenge had better be one that needs no signature. */
        stripped_len = spk_len;
        if (spk_len > sizeof stripped){ *reason = "bad-signet-commitment-size"; return 0; }
        memcpy(stripped, spk, spk_len);
    }

    if (!modified_coinbase_txid(leaves, TX(0)->ptr, cb_len, ci,
                                stripped, stripped_len, buf, rebuild)){
        *reason = "bad-signet-coinbase-malformed"; return 0;
    }
    for (u64 t = 1; t < ntx; t++)
        if (!tx_txid(leaves + t*32, TX(t)->ptr, TX(t)->len, buf, rebuild)){
            *reason = "bad-signet-tx-malformed"; return 0;
        }

    u8 root[32];
    merkle_root(root, leaves, ntx);        /* destroys `leaves`, which is ours */

    int nversion = (int)((u64)hdr80[0] | ((u64)hdr80[1]<<8) |
                         ((u64)hdr80[2]<<16) | ((u64)hdr80[3]<<24));
    unsigned int ntime = (unsigned int)((u64)hdr80[68] | ((u64)hdr80[69]<<8) |
                         ((u64)hdr80[70]<<16) | ((u64)hdr80[71]<<24));

    int r = signet_check_solution(nversion, hdr80 + 4, ntime, root,
                                  found ? sol : 0, found ? sol_len : 0,
                                  challenge, challenge_len, work, workcap);
    if (r < 0){ *reason = "signet: scratch too small"; return -1; }
    if (r == 0){ *reason = "bad-signet-blksig"; return 0; }
    return 1;
    #undef TX
}

/* ---------------------------------------------------------------------------
 * Scratch-owning form. Chain-AGNOSTIC on purpose: the caller passes the
 * challenge, and nothing here reads chainparams.
 *
 * The gate that decides "is this signet?" lives as an inline in the header
 * instead, because a reference to g_chainp from THIS file would be taken on
 * by every target that merely links it -- 35 test binaries and 68 undefined
 * references, none of which validate a signet block. The inline puts the
 * dependency only where the call actually is.
 * ------------------------------------------------------------------------- */
#include <stdlib.h>

static __thread unsigned char* g_sb_scratch;
static __thread unsigned long  g_sb_cap;

long signet_check_block_auto(const void* txs, unsigned long ntx,
                             unsigned long stride,
                             const unsigned char hdr80[80],
                             const unsigned char* challenge,
                             unsigned long challenge_len,
                             const char** reason){
    if (!challenge || challenge_len == 0){
        if (reason) *reason = "signet: no challenge configured";
        return -1;
    }
    #define TX(i) ((const signet_txref_t*)((const u8*)txs + (u64)(i)*stride))
    u64 maxtx = 0;
    for (u64 t = 0; t < ntx; t++) if (TX(t)->len > maxtx) maxtx = TX(t)->len;
    #undef TX
    u64 need = (u64)ntx * 32 + maxtx * 2 + 1024 + SIGNET_WORK_MIN + 64;
    if (need > g_sb_cap){
        unsigned char* p = realloc(g_sb_scratch, (size_t)need);
        if (!p){ if (reason) *reason = "signet: out of memory"; return -1; }
        g_sb_scratch = p; g_sb_cap = need;
    }
    return signet_check_block(txs, ntx, stride, hdr80, challenge, challenge_len,
                              g_sb_scratch, g_sb_cap, reason);
}
