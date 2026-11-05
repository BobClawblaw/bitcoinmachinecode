/* tests/test_serve_block_ctx.c -- NET-5 (audit 2026-09-03).
 *
 * bitcoin_serve.asm's .do_block appended a peer-PUSHED block to the durable
 * archive after cons_verify (context-FREE: PoW against the header's own
 * nBits, parses, coinbase, merkle root) and store_validates_prevhash ("it
 * extends our tip") -- and nothing else. Core refuses a header far earlier,
 * in ContextualCheckBlockHeader: the nBits RETARGET SCHEDULE for the height,
 * the median-time-past floor, the 2-hour future ceiling, and the BIP34/66/65
 * version rules.
 *
 * Consensus survived that (utxo_live.c re-checks the schedule at CONNECT),
 * but the archive did not: the block has to extend our tip to get here, so a
 * header Core rejects became our durable tip at a height it can never
 * connect at, and the node stalls behind it.
 *
 * serve_block_ctx_ok (daemon/tx_accept.c) is the gate. It is INJECTED and
 * default-OFF, so this test opens with the negative control that matters:
 * every rejected header below is ACCEPTED while the rules are unarmed. If
 * the gate were removed, those four control cases would still pass and the
 * four armed cases would fail -- the suite cannot go vacuously green.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "test_tmpdir.h"

extern long store_init(void* st);
extern long store_append(void* st, const unsigned char hash[32], const void* raw, long len);
extern void serve_set_header_rules(int no_retarget, int allow_min_diff,
                                   int enforce_bip94, unsigned int pow_limit_bits,
                                   long bip34_height);
extern int  serve_block_ctx_ok(void* st, const unsigned char* hdr80);

static int failures = 0;
static void ck(const char* l, int got, int exp){
    if (got == exp) printf("PASS %s (got %d)\n", l, got);
    else { printf("FAIL %s got=%d exp=%d\n", l, got, exp); failures++; }
}

#define LIM 0x207fffffu          /* regtest-style powLimit, compact */
#define NBLK 12

static unsigned char store_buf[4096];

/* 90 bytes: a real 80-byte header (version@0, prev@4, nTime@68, nBits@72)
 * plus filler, which is all sv_hdr_at/pow_check_bits ever read. */
static void mk_hdr(unsigned char h[90], int ver, const unsigned char prev[32],
                   unsigned int t, unsigned int bits){
    memset(h, 0, 90);
    memcpy(h,      &ver,  4);
    memcpy(h + 4,  prev, 32);
    memcpy(h + 68, &t,    4);
    memcpy(h + 72, &bits, 4);
}

int main(void){
    tt_isolate();
    memset(store_buf, 0, sizeof store_buf);
    if (store_init(store_buf) != 1){ printf("FAIL store_init\n"); return 1; }

    unsigned int now = (unsigned int)time(0);
    /* a 12-block chain ending ~10 minutes ago, one minute apart. The tip's
     * median-time-past is therefore the median of the last 11 timestamps. */
    unsigned int base = now - 3600;
    unsigned char prev[32]; memset(prev, 0, 32);
    unsigned int tip_times[NBLK];
    for (int i = 0; i < NBLK; i++){
        unsigned char blk[90], hash[32];
        unsigned int t = base + (unsigned)i * 60u;
        tip_times[i] = t;
        mk_hdr(blk, 4, prev, t, LIM);
        memset(hash, 0, 32); hash[0] = (unsigned char)(i + 1);
        if (store_append(store_buf, hash, blk, 90) != i){
            printf("FAIL store_append at %d\n", i); return 1;
        }
        memcpy(prev, hash, 32);
    }
    /* median of the last 11 (indices 1..11), which are already sorted */
    unsigned int mtp = tip_times[NBLK - 1 - 5];

    /* the four headers the gate must refuse, plus one it must accept */
    unsigned char good[90], too_old[90], too_new[90], bad_ver[90], bad_bits[90];
    mk_hdr(good,     4, prev, tip_times[NBLK-1] + 60, LIM);
    mk_hdr(too_old,  4, prev, mtp,                    LIM);  /* nTime <= MTP */
    mk_hdr(too_new,  4, prev, now + 7201 + 60,        LIM);  /* > now + 2h   */
    mk_hdr(bad_ver,  1, prev, tip_times[NBLK-1] + 60, LIM);  /* v1 past BIP34 */
    mk_hdr(bad_bits, 4, prev, tip_times[NBLK-1] + 60, LIM - 1);

    /* ---- negative control: UNARMED, every one of them is accepted ------- */
    puts("-- negative control: rules not armed (the pre-NET-5 behaviour) --");
    ck("unarmed: time-too-old header ACCEPTED",  serve_block_ctx_ok(store_buf, too_old),  1);
    ck("unarmed: time-too-new header ACCEPTED",  serve_block_ctx_ok(store_buf, too_new),  1);
    ck("unarmed: bad-version header ACCEPTED",   serve_block_ctx_ok(store_buf, bad_ver),  1);
    ck("unarmed: bad-diffbits header ACCEPTED",  serve_block_ctx_ok(store_buf, bad_bits), 1);

    /* ---- armed: no_retarget, so the expected bits are the parent's ------ */
    puts("-- armed (bip34_height=0, so v1 is a bad-version at every height) --");
    serve_set_header_rules(1 /*no_retarget*/, 0, 0, LIM, 0 /*bip34*/);
    ck("armed: a well-formed header is still ACCEPTED", serve_block_ctx_ok(store_buf, good),     1);
    ck("armed: nTime <= parent MTP  -> REJECTED",       serve_block_ctx_ok(store_buf, too_old),  0);
    ck("armed: nTime > now + 2h     -> REJECTED",       serve_block_ctx_ok(store_buf, too_new),  0);
    ck("armed: nVersion 1 past BIP34 -> REJECTED",      serve_block_ctx_ok(store_buf, bad_ver),  0);
    ck("armed: wrong nBits for the height -> REJECTED", serve_block_ctx_ok(store_buf, bad_bits), 0);

    /* BIP34 above the tip: the same v1 header is fine again, proving the
     * version rule reads the injected activation height and is not a
     * blanket "reject v1". */
    puts("-- armed with bip34_height above the tip --");
    serve_set_header_rules(1, 0, 0, LIM, 1000000);
    ck("armed: v1 below BIP34 activation is ACCEPTED",  serve_block_ctx_ok(store_buf, bad_ver),  1);

    /* ---- CON-8 (audit 2026-10-23): BIP94's time-timewarp-attack ----------
     * Extend the chain to height 2015 so the next header is the first of a
     * difficulty period (2016 % 2016 == 0). The last stored block jumps
     * 3000 s ahead, so the parent's MTP sits far below the parent's own
     * time and only the timewarp rule can refuse a header 601 s before it. */
    puts("-- CON-8: BIP94 timewarp at a retarget boundary --");
    {
        unsigned int t = tip_times[NBLK-1];
        for (int i = NBLK; i < 2016; i++){
            unsigned char blk[90], hash[32];
            t += (i == 2015) ? 3000u : 1u;
            mk_hdr(blk, 4, prev, t, LIM);
            memset(hash, 0, 32); hash[0] = (unsigned char)i; hash[1] = (unsigned char)(i >> 8); hash[2] = 0x5a;
            if (store_append(store_buf, hash, blk, 90) != i){ printf("FAIL store_append at %d\n", i); return 1; }
            memcpy(prev, hash, 32);
        }
        unsigned char warp[90], edge[90];
        mk_hdr(warp, 4, prev, t - 601, LIM);
        mk_hdr(edge, 4, prev, t - 600, LIM);
        serve_set_header_rules(1, 0, 1 /*enforce_bip94*/, LIM, 0);
        ck("BIP94: a height-2016 header 601 s before its parent -> REJECTED", serve_block_ctx_ok(store_buf, warp), 0);
        ck("BIP94: 600 s before is ACCEPTED",                                serve_block_ctx_ok(store_buf, edge), 1);
        serve_set_header_rules(1, 0, 0 /*no BIP94*/, LIM, 0);
        ck("no BIP94 (mainnet): the 601 s header is ACCEPTED",               serve_block_ctx_ok(store_buf, warp), 1);
    }

    if (failures){ printf("TESTS FAILED (%d failures)\n", failures); return 1; }
    printf("ALL TESTS PASSED (0 failures)\n");
    return 0;
}
