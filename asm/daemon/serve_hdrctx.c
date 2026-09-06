/* daemon/serve_hdrctx.c -- NET-5 (audit 2026-09-03).
 *
 * Split out of daemon/tx_accept.c rather than living beside it: tx_accept.c
 * is linked into nine targets that have no serve loop and no archive (the
 * mempool-policy suites among them), and putting pow_check_bits / store_get_at
 * / store_rd_fd references into that object forced every one of those rules
 * to grow objects it has no other use for. This file is linked only where
 * bitcoin_serve.o is -- the one place the symbol it defines is called from.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
/* ------------------------------------------------------------------- NET-5
 * Contextual header rules for a peer-PUSHED block, applied BEFORE it is
 * appended to the durable archive (bitcoin_serve.asm's .do_block).
 *
 * That path used to append after two gates and nothing else: cons_verify,
 * which is entirely context-FREE (PoW against the header's own nBits, every
 * tx parses, first tx is a coinbase, merkle root matches), and
 * store_validates_prevhash, which only asks that the block extend our tip.
 * Core refuses a header far earlier than that, in AcceptBlockHeader /
 * ContextualCheckBlockHeader: the nBits RETARGET SCHEDULE (the header's own
 * bits being internally consistent says nothing about their being the bits
 * this height requires), the median-time-past floor, the 2-hour future
 * ceiling, and the BIP34/66/65 legacy-version rules.
 *
 * Consensus itself was not at risk -- daemon/utxo_live.c re-checks the nBits
 * schedule when a block is CONNECTED, and would refuse this one there. The
 * ARCHIVE was. A block has to extend our tip to reach here, so a header Core
 * would never accept became our archive tip, durably, at a height it can
 * never connect at; the node then keeps re-reading a tip it cannot advance
 * past. That stall is the confirmed half of NET-5.
 *
 * Armed by daemon/main.c after chainparams_select and DEFAULT OFF, exactly
 * like reorg_set_pow_rules / reorg_set_header_rules and for the same reason:
 * the hermetic serve suites (tests/test_serve, test_keepup, test_bitcoind
 * and friends) build synthetic chains with arbitrary bits, timestamps and
 * versions, and only the daemon knows which chain it is on.
 *
 * The header reader and the median-time-past window are duplicated from
 * daemon/utxo_live.c rather than shared: utxo_live.c is deliberately NOT
 * linked into the serve binaries (that is why bidx_get needs
 * tests/txacc_bidx_stub.c), and a forked serve child has no access to its
 * state anyway. The store is the one thing both do share, and it is passed
 * in.
 */
#include "../bitcoin_pow_rules.h"
#include "hdrrules.h"

extern int store_get_at(void* st, u64 height, u64 out_meta[3]);
extern int store_rd_fd(void* st, unsigned file_no);
extern unsigned long long script_flags_for_block(unsigned long long height,
                                                 const unsigned char blockhash[32]);

static int g_sv_rules_on;
static int g_sv_no_rt, g_sv_mindiff, g_sv_bip94;
static unsigned int g_sv_lim;
static long g_sv_bip34_h = -1;

void serve_set_header_rules(int no_retarget, int allow_min_diff,
                            int enforce_bip94, unsigned int pow_limit_bits,
                            long bip34_height){
    g_sv_no_rt = no_retarget; g_sv_mindiff = allow_min_diff;
    g_sv_bip94 = enforce_bip94; g_sv_lim = pow_limit_bits;
    g_sv_bip34_h = bip34_height;
    g_sv_rules_on = 1;
}

/* Read the stored header at `h`. +8 skips the [len][magic] frame header,
 * exactly as store_read_meta's own pread does (bitcoin_store_fast.asm). */
static int sv_hdr_at(void* ctx, long h, u8 hdr[80]){
    u64 meta[3];
    if (!ctx || h < 0 || store_get_at(ctx, (u64)h, meta) != 1) return 0;
    int fd = store_rd_fd(ctx, (unsigned)meta[2]);
    if (fd < 0) return 0;
    return pread(fd, hdr, 80, (off_t)meta[0] + 8) == 80 ? 1 : 0;
}

/* Core's GetMedianTimePast: median nTime of the up-to-11 blocks ending at
 * `h`. Returns 0 if any header in the window is unreadable -- the caller
 * refuses rather than passing a 0 floor, matching hdrrules.h's contract and
 * what daemon/main.c and daemon/reorg.c already do. */
static int sv_mtp(void* st, long h, unsigned int* out){
    unsigned int ts[11];
    int n = 0;
    for (long k = h; k > h - 11 && k >= 0; k--){
        u8 hdr[80];
        if (!sv_hdr_at(st, k, hdr)) return 0;
        memcpy(&ts[n++], hdr + 68, 4);
    }
    if (n == 0) return 0;
    for (int i = 1; i < n; i++){                 /* insertion sort, n <= 11 */
        unsigned int v = ts[i]; int j = i - 1;
        while (j >= 0 && ts[j] > v){ ts[j+1] = ts[j]; j--; }
        ts[j+1] = v;
    }
    *out = ts[n / 2];
    return 1;
}

/* serve_block_ctx_ok(st, hdr80) -> 1 accept / 0 reject.
 * Called from bitcoin_serve.asm once the block is known to extend our tip,
 * so its height is the tip's + 1. Returns 1 unchanged when the rules are not
 * armed, so every hermetic serve suite behaves exactly as before. */
int serve_block_ctx_ok(void* st, const unsigned char* hdr80){
    if (!g_sv_rules_on || !st) return 1;
    /* the tip height, read the way daemon/reorg.c's store_tip does */
    long tip = (long)*(int*)((char*)st + 24);
    long height = tip + 1;
    if (height < 1) return 1;            /* empty store: this is the first block */

    int pr = pow_check_bits(height, hdr80, sv_hdr_at, st,
                            g_sv_no_rt, g_sv_mindiff, g_sv_bip94, g_sv_lim);
    if (pr != 1){
        fprintf(stderr, "[serve] inbound block at height %ld REJECTED: bad-diffbits "
                        "(not appended)\n", height);
        return 0;
    }

    unsigned int mtp = 0;
    if (!sv_mtp(st, tip, &mtp)){
        fprintf(stderr, "[serve] inbound block at height %ld REJECTED: median-time-past "
                        "window unreadable (not appended)\n", height);
        return 0;
    }

    unsigned char bh[32]; memset(bh, 0, 32);
    unsigned long long flags = script_flags_for_block((unsigned long long)height, bh);
    const char* reason = "?";
    if (!hdr_contextual_ok(height, hdr80, (unsigned long)mtp, (long)time(0),
                           flags, g_sv_bip34_h, &reason)){
        fprintf(stderr, "[serve] inbound block at height %ld REJECTED: %s (not appended)\n",
                height, reason);
        return 0;
    }
    return 1;
}
