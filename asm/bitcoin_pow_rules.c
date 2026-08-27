/* bitcoin_pow_rules.c -- see bitcoin_pow_rules.h. The retarget arithmetic is
 * MOVED (not copied) from rpc_chain.c's rpc_chain_retarget, which now wraps
 * pow_retarget_bits; the schedule logic is moved from gbt_next_bits, which
 * now calls pow_expected_bits. One implementation, two consumers.
 *
 * Every constant is Core's (pow.cpp / chainparams): 14-day target timespan,
 * 2016-block interval, the 20-minute testnet exception (2 * 10-minute
 * spacing), and Satoshi's first-block-of-window timespan measurement
 * (tip - 2015, an interval of 2015 gaps -- deliberately NOT 2016).
 */
#include <string.h>
#include "bitcoin_pow_rules.h"

typedef unsigned char u8;
typedef unsigned int u32;

#define POW_TIMESPAN 1209600L          /* 14 days                            */
#define POW_INTERVAL 2016L             /* DifficultyAdjustmentInterval       */
#define POW_SPACING  600L              /* nPowTargetSpacing                  */

static u32 rd32le(const u8* p){
    return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24);
}

/* arith_uint256::SetCompact -> 32 big-endian bytes (fNegative impossible for
 * any real nBits; overflow callers never pass). Mirrors rpc_chain.c's
 * target_bytes, kept private here so this unit stays freestanding. */
static void powr_target_bytes(u32 bits, u8 t[32]){
    memset(t, 0, 32);
    int size = bits >> 24;
    u32 word = bits & 0x007fffff;
    if (size <= 3){
        word >>= 8 * (3 - size);
        t[31] = (u8)word; t[30] = (u8)(word >> 8); t[29] = (u8)(word >> 16);
    } else {
        int shift = size - 3;                  /* bytes above the mantissa */
        int pos = 32 - 3 - shift;              /* mantissa MSB position    */
        if (pos < 0) return;                   /* would overflow 256 bits  */
        t[pos]     = (u8)(word >> 16);
        if (pos + 1 < 32) t[pos + 1] = (u8)(word >> 8);
        if (pos + 2 < 32) t[pos + 2] = (u8)word;
    }
}

/* arith_uint256::GetCompact (fNegative=false) over a big-endian target.
 * Mirrors rpc_chain.c's gbt_compact. */
static u32 powr_compact(const u8 t[32]){
    int size = 32; while (size > 0 && t[32-size] == 0) size--;
    u32 word = 0;
    for (int i = 0; i < 3; i++){
        int pos = 32 - size + i;
        word = (word << 8) | (u8)(pos < 32 && i < size ? t[pos] : 0);
    }
    if (size < 3) word <<= 8 * (3 - size);
    if (word & 0x00800000){ word >>= 8; size++; }
    return ((u32)size << 24) | (word & 0x007fffff);
}

u32 pow_retarget_bits(u32 base_bits, long actual_timespan, u32 pow_limit_bits){
    long ts = actual_timespan;
    if (ts < POW_TIMESPAN/4) ts = POW_TIMESPAN/4;
    if (ts > POW_TIMESPAN*4) ts = POW_TIMESPAN*4;
    /* new_target = base_target * ts / POW_TIMESPAN over a 40-byte big int
     * (LE limbs for the arithmetic, flipped from/to big-endian) */
    u8 be[32]; powr_target_bytes(base_bits, be);
    u8 n[40]; memset(n, 0, sizeof n);
    for (int i = 0; i < 32; i++) n[i] = be[31-i];          /* -> LE */
    { unsigned long long carry = 0;                         /* *= ts */
      for (int i = 0; i < 40; i++){
          unsigned long long v = (unsigned long long)n[i] * (unsigned long long)ts + carry;
          n[i] = (u8)v; carry = v >> 8;
      } }
    { unsigned long long rem = 0;                           /* /= timespan */
      for (int i = 39; i >= 0; i--){
          unsigned long long v = (rem << 8) | n[i];
          n[i] = (u8)(v / (unsigned long long)POW_TIMESPAN);
          rem = v % (unsigned long long)POW_TIMESPAN;
      } }
    int over = 0; for (int i = 32; i < 40; i++) if (n[i]) over = 1;
    u8 out[32]; for (int i = 0; i < 32; i++) out[i] = n[31-i];   /* -> BE */
    u8 lim[32]; powr_target_bytes(pow_limit_bits, lim);
    if (!over){ for (int i = 0; i < 32; i++){ if (out[i] > lim[i]){ over = 1; break; } if (out[i] < lim[i]) break; } }
    if (over) memcpy(out, lim, 32);
    return powr_compact(out);
}

u32 pow_expected_bits(long height, long blocktime,
                      powr_hdr_fn get, void* ctx,
                      int no_retarget, int allow_min_diff,
                      int enforce_bip94, u32 pow_limit_bits){
    if (height <= 0) return 0;                  /* genesis is never evaluated */
    u8 hdr[80];
    long tip = height - 1;                      /* pindexLast */
    if (get(ctx, tip, hdr) != 1) return 0;
    u32 last_bits = rd32le(hdr + 72);
    if (no_retarget) return last_bits;          /* regtest: fPowNoRetargeting */
    if (height % POW_INTERVAL != 0){
        if (allow_min_diff){
            u32 prev_time = rd32le(hdr + 68);
            /* the 20-minute exception: a block whose time is more than
             * 2*spacing past its parent MUST carry min-difficulty bits */
            if (blocktime > (long)prev_time + 2*POW_SPACING) return pow_limit_bits;
            /* else the last non-min-difficulty block's bits (Core's exact
             * walk-back, stopping at a period boundary) */
            long h = tip; u32 bits = last_bits;
            while (h > 0 && (h % POW_INTERVAL) != 0 && bits == pow_limit_bits){
                h--;
                if (get(ctx, h, hdr) != 1) return 0;
                bits = rd32le(hdr + 72);
            }
            return bits;
        }
        return last_bits;
    }
    /* boundary: timespan over the window's 2015 gaps (Satoshi's off-by-one,
     * consensus since block 2016) */
    u32 last_time = rd32le(hdr + 68);
    if (get(ctx, tip - (POW_INTERVAL - 1), hdr) != 1) return 0;
    u32 first_time = rd32le(hdr + 68);
    /* BIP94 (testnet4): base the retarget on the FIRST block of the period,
     * whose bits can never be a min-difficulty exception */
    u32 base_bits = enforce_bip94 ? rd32le(hdr + 72) : last_bits;
    return pow_retarget_bits(base_bits, (long)last_time - (long)first_time, pow_limit_bits);
}

int pow_check_bits(long height, const u8 hdr80[80],
                   powr_hdr_fn get, void* ctx,
                   int no_retarget, int allow_min_diff,
                   int enforce_bip94, u32 pow_limit_bits){
    if (height <= 0) return 1;                  /* genesis: nothing to check */
    long blocktime = (long)rd32le(hdr80 + 68);
    u32 want = pow_expected_bits(height, blocktime, get, ctx,
                                 no_retarget, allow_min_diff,
                                 enforce_bip94, pow_limit_bits);
    if (want == 0) return -1;                   /* cannot evaluate */
    return rd32le(hdr80 + 72) == want ? 1 : 0;
}
