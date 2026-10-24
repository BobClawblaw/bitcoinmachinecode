/* core_port.h -- a C port of Bitcoin Core v31.1's arith_uint256 (the parts
 * consensus PoW uses) and pow.cpp / chain.cpp formulas. Each function is a
 * line-for-line transcription of the named Core function; the only change is
 * C syntax (a struct of 8 uint32 limbs, pn[0] least significant, exactly
 * base_uint<256>'s layout).
 *
 *   arith_uint256.cpp  operator<<=, operator>>=, operator*=(uint32_t),
 *                      operator/=, CompareTo, bits(), SetCompact, GetCompact
 *   arith_uint256.h    operator~, operator+=, operator-=, operator++,
 *                      GetLow64, base_uint(uint64_t)
 *   pow.cpp            CalculateNextWorkRequired (arithmetic part),
 *                      DeriveTarget, CheckProofOfWorkImpl
 *   chain.cpp          GetBlockProof
 *
 * Used by the CBMC harnesses (the "Core side") and by the differential
 * drivers. Header-only, static functions.
 */
#ifndef FORMAL_CORE_PORT_H
#define FORMAL_CORE_PORT_H
#include <stdint.h>
#include <string.h>

#define CP_WIDTH 8
typedef struct { uint32_t pn[CP_WIDTH]; } cu256;

static cu256 cu_from64(uint64_t b){            /* base_uint(uint64_t b) */
    cu256 r; r.pn[0] = (uint32_t)b; r.pn[1] = (uint32_t)(b >> 32);
    for (int i = 2; i < CP_WIDTH; i++) r.pn[i] = 0;
    return r;
}
static cu256 cu_not(cu256 a){                  /* operator~ */
    cu256 r; for (int i = 0; i < CP_WIDTH; i++) r.pn[i] = ~a.pn[i]; return r;
}
static void cu_add(cu256* t, const cu256* b){  /* operator+=(const base_uint&) */
    uint64_t carry = 0;
    for (int i = 0; i < CP_WIDTH; i++){
        uint64_t n = carry + t->pn[i] + b->pn[i];
        t->pn[i] = n & 0xffffffff;
        carry = n >> 32;
    }
}
static void cu_neg(cu256* t){                  /* operator-(): ~x, ++ */
    for (int i = 0; i < CP_WIDTH; i++) t->pn[i] = ~t->pn[i];
    int i = 0; while (i < CP_WIDTH && ++t->pn[i] == 0) i++;
}
static void cu_sub(cu256* t, const cu256* b){  /* operator-=: *this += -b */
    cu256 nb = *b; cu_neg(&nb); cu_add(t, &nb);
}
static void cu_inc(cu256* t){                  /* operator++ */
    int i = 0; while (i < CP_WIDTH && ++t->pn[i] == 0) i++;
}
static void cu_shl(cu256* t, unsigned int shift){   /* operator<<= */
    cu256 a = *t;
    for (int i = 0; i < CP_WIDTH; i++) t->pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < CP_WIDTH; i++){
        if (i + k + 1 < CP_WIDTH && shift != 0) t->pn[i + k + 1] |= (a.pn[i] >> (32 - shift));
        if (i + k < CP_WIDTH) t->pn[i + k] |= (a.pn[i] << shift);
    }
}
static void cu_shr(cu256* t, unsigned int shift){   /* operator>>= */
    cu256 a = *t;
    for (int i = 0; i < CP_WIDTH; i++) t->pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < CP_WIDTH; i++){
        if (i - k - 1 >= 0 && shift != 0) t->pn[i - k - 1] |= (a.pn[i] << (32 - shift));
        if (i - k >= 0) t->pn[i - k] |= (a.pn[i] >> shift);
    }
}
static void cu_mul32(cu256* t, uint32_t b32){       /* operator*=(uint32_t) */
    uint64_t carry = 0;
    for (int i = 0; i < CP_WIDTH; i++){
        uint64_t n = carry + (uint64_t)b32 * t->pn[i];
        t->pn[i] = n & 0xffffffff;
        carry = n >> 32;
    }
}
static int cu_cmp(const cu256* a, const cu256* b){  /* CompareTo */
    for (int i = CP_WIDTH - 1; i >= 0; i--){
        if (a->pn[i] < b->pn[i]) return -1;
        if (a->pn[i] > b->pn[i]) return 1;
    }
    return 0;
}
static int cu_iszero(const cu256* a){
    for (int i = 0; i < CP_WIDTH; i++) if (a->pn[i]) return 0;
    return 1;
}
static unsigned int cu_bits(const cu256* a){        /* bits() */
    for (int pos = CP_WIDTH - 1; pos >= 0; pos--){
        if (a->pn[pos]){
            for (int nbits = 31; nbits > 0; nbits--){
                if (a->pn[pos] & 1U << nbits) return 32 * pos + nbits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}
static uint64_t cu_low64(const cu256* a){ return a->pn[0] | (uint64_t)a->pn[1] << 32; }

/* operator/= ; Core throws on division by zero -- callers never divide by 0
 * here (the divisor is a nonzero constant or target+1 with target != 2^256-1);
 * the CBMC harnesses assert that. */
static void cu_div(cu256* t, const cu256* b){
    cu256 div = *b;
    cu256 num = *t;
    for (int i = 0; i < CP_WIDTH; i++) t->pn[i] = 0;
    int num_bits = (int)cu_bits(&num);
    int div_bits = (int)cu_bits(&div);
#ifdef __CPROVER__
    __CPROVER_assert(div_bits != 0, "core port: no division by zero");
#endif
    if (div_bits > num_bits) return;
    int shift = num_bits - div_bits;
    cu_shl(&div, (unsigned)shift);
    while (shift >= 0){
        if (cu_cmp(&num, &div) >= 0){
            cu_sub(&num, &div);
            t->pn[shift / 32] |= (1U << (shift & 31));
        }
        cu_shr(&div, 1);
        shift--;
    }
}

/* SetCompact */
static cu256 cu_set_compact(uint32_t nCompact, int* pfNegative, int* pfOverflow){
    cu256 r;
    int nSize = nCompact >> 24;
    uint32_t nWord = nCompact & 0x007fffff;
    if (nSize <= 3){
        nWord >>= 8 * (3 - nSize);
        r = cu_from64(nWord);
    } else {
        r = cu_from64(nWord);
        cu_shl(&r, 8 * (nSize - 3));
    }
    if (pfNegative) *pfNegative = nWord != 0 && (nCompact & 0x00800000) != 0;
    if (pfOverflow) *pfOverflow = nWord != 0 && ((nSize > 34) ||
                                                 (nWord > 0xff && nSize > 33) ||
                                                 (nWord > 0xffff && nSize > 32));
    return r;
}

/* GetCompact(fNegative) */
static uint32_t cu_get_compact(const cu256* a, int fNegative){
    int nSize = (int)(cu_bits(a) + 7) / 8;
    uint32_t nCompact = 0;
    if (nSize <= 3){
        nCompact = (uint32_t)(cu_low64(a) << 8 * (3 - nSize));
    } else {
        cu256 bn = *a; cu_shr(&bn, 8 * (nSize - 3));
        nCompact = (uint32_t)cu_low64(&bn);
    }
    if (nCompact & 0x00800000){
        nCompact >>= 8;
        nSize++;
    }
#ifdef __CPROVER__
    __CPROVER_assert((nCompact & ~0x007fffffU) == 0, "core GetCompact assert 1");
    __CPROVER_assert(nSize < 256, "core GetCompact assert 2");
#endif
    nCompact |= (uint32_t)nSize << 24;
    nCompact |= (fNegative && (nCompact & 0x007fffff) ? 0x00800000 : 0);
    return nCompact;
}

/* Byte views: Core's uint256 is little-endian bytes; UintToArith256 reads
 * 4-byte little-endian words. */
static cu256 cu_from_le32(const uint8_t b[32]){
    cu256 r;
    for (int x = 0; x < CP_WIDTH; x++)
        r.pn[x] = (uint32_t)b[4*x] | (uint32_t)b[4*x+1] << 8 | (uint32_t)b[4*x+2] << 16 | (uint32_t)b[4*x+3] << 24;
    return r;
}
static void cu_to_be32(const cu256* a, uint8_t be[32]){
    for (int i = 0; i < 32; i++) be[31 - i] = (uint8_t)(a->pn[i / 4] >> (8 * (i % 4)));
}
static cu256 cu_from_be32(const uint8_t be[32]){
    uint8_t le[32]; for (int i = 0; i < 32; i++) le[i] = be[31 - i];
    return cu_from_le32(le);
}

/* pow.cpp CalculateNextWorkRequired, the arithmetic after fPowNoRetargeting:
 * nActualTimespan clamp, SetCompact(base), *= (uint32 overload), /=, cap,
 * GetCompact. pow_limit = UintToArith256(params.powLimit). */
static uint32_t core_calc_next_work(uint32_t base_bits, int64_t nActualTimespan,
                                    const cu256* bnPowLimit){
    const int64_t nPowTargetTimespan = 14 * 24 * 60 * 60;
    if (nActualTimespan < nPowTargetTimespan / 4) nActualTimespan = nPowTargetTimespan / 4;
    if (nActualTimespan > nPowTargetTimespan * 4) nActualTimespan = nPowTargetTimespan * 4;
    cu256 bnNew = cu_set_compact(base_bits, 0, 0);
    cu_mul32(&bnNew, (uint32_t)nActualTimespan);          /* int64 -> uint32_t overload */
    cu256 d = cu_from64((uint64_t)nPowTargetTimespan);    /* int64 -> base_uint(uint64_t) */
    cu_div(&bnNew, &d);
    if (cu_cmp(&bnNew, bnPowLimit) > 0) bnNew = *bnPowLimit;
    return cu_get_compact(&bnNew, 0);
}

/* DeriveTarget + CheckProofOfWorkImpl; hash = the 32 hash bytes as stored */
static int core_check_pow(const uint8_t hash[32], uint32_t nBits, const cu256* pow_limit){
    int fNegative, fOverflow;
    cu256 bnTarget = cu_set_compact(nBits, &fNegative, &fOverflow);
    if (fNegative || cu_iszero(&bnTarget) || fOverflow || cu_cmp(&bnTarget, pow_limit) > 0) return 0;
    cu256 h = cu_from_le32(hash);
    if (cu_cmp(&h, &bnTarget) > 0) return 0;
    return 1;
}

/* chain.cpp GetBlockProof */
static cu256 core_block_proof(uint32_t nBits){
    int fNegative, fOverflow;
    cu256 bnTarget = cu_set_compact(nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || cu_iszero(&bnTarget)) return cu_from64(0);
    cu256 num = cu_not(bnTarget);
    cu256 den = bnTarget; cu_inc(&den);
    cu_div(&num, &den);
    cu_inc(&num);
    return num;
}

/* chainparams.cpp consensus.powLimit, big-endian hex -> cu256 */
static cu256 core_pow_limit(uint32_t chain_bits){
    uint8_t be[32]; memset(be, 0, 32);
    if (chain_bits == 0x1d00ffffu){ memset(be + 4, 0xff, 28); }                 /* main, testnet4 */
    else if (chain_bits == 0x1e0377aeu){ be[2] = 0x03; be[3] = 0x77; be[4] = 0xae; } /* signet */
    else { be[0] = 0x7f; memset(be + 1, 0xff, 31); }                          /* regtest */
    return cu_from_be32(be);
}
#endif
