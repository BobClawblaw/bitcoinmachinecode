/* diff_pow.c -- differential tests of the REAL assembled bmc objects
 * (bitcoin_hash.o, bitcoin_chainwork.o, sha256.o) against core_port.h.
 *
 *   pow_check(hdr)          vs core_check_pow(block_hash(hdr), bits, powLimit)
 *   diff_target(t, bits)    vs SetCompact (equal whenever Core's flags are clear
 *                           and exponent >= 3; other cases counted by class)
 *   u256_div(q, a, b)       vs cu_div
 *   block_work(w, bits)     vs low 128 bits of GetBlockProof, on pow-valid bits
 *   chainwork_add           vs (a+b) with saturation at 2^128-1
 *   pow_retarget_bits       vs core_calc_next_work, Core-valid bases <= powLimit
 *                           (main/testnet4 and signet), any int64 timespan
 *
 * usage: diff_pow <iterations> <seed>     exit 0 iff no unexpected mismatch
 * With "dump N" as the first argument it prints N lines of core_port results
 * for check_core_port.py (an independent Python big-int transcription).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "core_port.h"

extern int  pow_check(const uint8_t hdr[80]);
extern void block_hash(uint8_t out[32], const uint8_t hdr[80]);
extern void diff_target(uint8_t target_be[32], uint32_t bits);
extern unsigned int pow_pow_limit_bits;
extern void u256_div(uint8_t q[32], const uint8_t a[32], const uint8_t b[32]);
extern void block_work(uint8_t work[16], uint32_t bits);
extern void chainwork_add(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]);
extern unsigned int pow_retarget_bits(unsigned int base_bits, long actual_timespan, unsigned int pow_limit_bits);

static uint64_t s_state;
static uint64_t rnd(void){                      /* splitmix64 */
    uint64_t z = (s_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
/* nBits with every interesting shape: all exponents 0..255 (weighted to
 * 0..0x24), mantissas at the edges (0, 1, 0x7f.., 0x80.., 0xff.., 0x7fffff,
 * 0x800000, 0xffffff), byte-boundary values and uniform randoms. */
static uint32_t rnd_bits(void){
    uint32_t e, m;
    uint64_t r = rnd();
    switch (r & 7){
    case 0: case 1: case 2: e = (uint32_t)(rnd() % 0x25); break;
    case 3: e = (uint32_t)(rnd() & 0xff); break;
    default: e = 0x1c + (uint32_t)(rnd() % 9); break;      /* the live region */
    }
    static const uint32_t edge[] = {0, 1, 0x7f, 0x80, 0xff, 0x100, 0x7fff, 0x8000, 0xffff,
        0x10000, 0x7fffff, 0x800000, 0x800001, 0xffffff, 0x00ffff, 0x0377ae, 0x7fff00, 0x008000};
    switch ((r >> 8) & 3){
    case 0: m = edge[rnd() % (sizeof edge / sizeof edge[0])]; break;
    case 1: m = (uint32_t)(rnd() & 0xffffff) & ((1u << (rnd() % 25)) - 1); break;
    default: m = (uint32_t)(rnd() & 0xffffff); break;
    }
    return (e << 24) | m;
}
static void rnd_bytes(uint8_t* p, int n){ for (int i = 0; i < n; i++) p[i] = (uint8_t)rnd(); }
static void cu_to_le(const cu256* a, uint8_t le[32]){ for (int i = 0; i < 32; i++) le[i] = (uint8_t)(a->pn[i/4] >> (8*(i%4))); }

int main(int argc, char** argv){
    if (argc >= 3 && !strcmp(argv[1], "dump")){
        long n = atol(argv[2]); s_state = 7;
        for (long i = 0; i < n; i++){
            uint32_t b = rnd_bits(); int neg, ovf;
            cu256 t = cu_set_compact(b, &neg, &ovf);
            uint8_t be[32]; cu_to_be32(&t, be);
            cu256 w = core_block_proof(b); uint8_t wb[32]; cu_to_be32(&w, wb);
            uint8_t rb[32]; rnd_bytes(rb, 32); cu256 r = cu_from_be32(rb);
            if (rnd() & 1) cu_shr(&r, (unsigned)(rnd() % 256));
            uint32_t gc = cu_get_compact(&r, 0);
            int64_t ts = (int64_t)(rnd() % 6000000) - 500000;
            uint32_t lb = (rnd() & 1) ? 0x1d00ffffu : 0x1e0377aeu; cu256 lim = core_pow_limit(lb);
            uint32_t nb = core_calc_next_work(b, ts, &lim);
            printf("%08x %d %d ", b, neg, ovf);
            for (int k = 0; k < 32; k++) printf("%02x", be[k]);
            printf(" ");
            for (int k = 0; k < 32; k++) printf("%02x", wb[k]);
            printf(" ");
            for (int k = 0; k < 32; k++){ uint8_t x[32]; cu_to_be32(&r, x); printf("%02x", x[k]); }
            printf(" %08x %lld %08x %08x\n", gc, (long long)ts, lb, nb);
        }
        return 0;
    }
    long iters = argc > 1 ? atol(argv[1]) : 1000000;
    s_state = argc > 2 ? strtoull(argv[2], 0, 0) : 1;
    long bad = 0;
    static const uint32_t limits[] = {0x1d00ffffu, 0x1e0377aeu, 0x207fffffu, 0};
    long n_pow = 0, n_acc = 0, n_resid = 0, n_unarmed_extra = 0;
    long n_dt = 0, n_dt_eq = 0, n_dt_off = 0;
    long n_rt = 0, n_rt_cap = 0;
    long n_div = 0, n_bw = 0, n_bw_dom = 0, n_cw = 0, n_bw_lowexp = 0, n_bw_hiexp = 0, n_bw_trunc = 0;

    for (long it = 0; it < iters; it++){
        /* ---- pow_check ---- */
        uint8_t hdr[80]; rnd_bytes(hdr, 80);
        uint32_t bits = rnd_bits();
        if ((rnd() & 3) == 0) bits = 0x20000000u | (bits & 0x00ffffffu);   /* targets near 2^256: ~half accept */
        if ((rnd() & 7) == 0) bits = 0x1f000000u | (bits & 0x00ffffffu);
        memcpy(hdr + 72, &bits, 4);
        uint32_t lb = limits[it & 3];
        pow_pow_limit_bits = lb;
        int got = pow_check(hdr);
        uint8_t h[32]; block_hash(h, hdr);
        cu256 lim = lb ? core_pow_limit(lb) : cu_not(cu_from64(0));
        int want = core_check_pow(h, bits, &lim);
        n_pow++; n_acc += want;
        if (got != want){
            /* the one proved residual: Core accepts, bmc rejects, exponent < 3 */
            if (want == 1 && got == 0 && (bits >> 24) < 3) n_resid++;
            else { if (bad < 10) printf("MISMATCH pow_check bits=%08x limit=%08x got=%d want=%d\n", bits, lb, got, want); bad++; }
        }
        if (lb == 0 && got == 1){
            cu256 ml = core_pow_limit(0x207fffffu);
            if (!core_check_pow(h, bits, &ml)) n_unarmed_extra++;
        }

        /* ---- diff_target vs SetCompact ---- */
        uint32_t b2 = rnd_bits();
        uint8_t tb[32]; diff_target(tb, b2);
        int neg, ovf; cu256 ct = cu_set_compact(b2, &neg, &ovf);
        uint8_t cb[32]; cu_to_be32(&ct, cb);
        n_dt++;
        /* the claimed domain: no overflow, exponent >= 3, sign bit clear
         * (diff_target decodes the full 24-bit mantissa; pow_check rejects a
         * set sign bit / zero mantissa before calling it) */
        int dom = !ovf && (b2 >> 24) >= 3 && !(b2 & 0x00800000u);
        if (dom){
            if (memcmp(tb, cb, 32)){ if (bad < 10) printf("MISMATCH diff_target bits=%08x\n", b2); bad++; } else n_dt_eq++;
        } else n_dt_off++;

        /* ---- u256_div vs cu_div ---- */
        uint8_t a[32], bb[32], q[32];
        rnd_bytes(a, 32); rnd_bytes(bb, 32);
        if (rnd() & 3){ int sh = (int)(rnd() % 256); cu256 x = cu_from_le32(bb); cu_shr(&x, (unsigned)sh); cu_to_le(&x, bb); }
        else bb[31] |= 0x80;                      /* divisor >= 2^255: the 257th remainder bit (COUT) matters */
        if ((rnd() & 15) == 0){ memset(bb, 0, 32); bb[0] = (uint8_t)(1 + (rnd() % 255)); }
        if ((rnd() & 31) == 0) memcpy(bb, a, 32);
        { cu256 x = cu_from_le32(bb); if (cu_iszero(&x)) bb[0] = 1; }
        u256_div(q, a, bb);
        cu256 ca = cu_from_le32(a), cbv = cu_from_le32(bb); cu_div(&ca, &cbv);
        uint8_t cq[32]; cu_to_le(&ca, cq);
        n_div++;
        if (memcmp(q, cq, 32)){ if (bad < 10) printf("MISMATCH u256_div\n"); bad++; }

        /* ---- block_work vs GetBlockProof (low 128 bits) ---- */
        uint32_t b3 = rnd_bits();
        uint8_t w[16]; block_work(w, b3);
        cu256 cw = core_block_proof(b3); uint8_t cwl[32]; cu_to_le(&cw, cwl);
        n_bw++;
        {
            int n3, o3; cu256 t3 = cu_set_compact(b3, &n3, &o3);
            int pow_valid = !n3 && !o3 && !cu_iszero(&t3);
            /* domain: pow-valid, exponent >= 3, and Core's work < 2^128 */
            int fits = 1; for (int k = 16; k < 32; k++) if (cwl[k]) fits = 0;
            /* compact_to_target_le leaves target 0 (work 0) for exponents
             * 33/34 even when Core decodes a nonzero, non-overflowing target */
            if (pow_valid && (b3 >> 24) >= 3 && (b3 >> 24) <= 32 && fits){
                n_bw_dom++;
                if (memcmp(w, cwl, 16)){ if (bad < 10) printf("MISMATCH block_work bits=%08x\n", b3); bad++; }
            } else if (pow_valid && memcmp(w, cwl, 16)) {
                if ((b3 >> 24) < 3) n_bw_lowexp++;
                else if ((b3 >> 24) > 32) n_bw_hiexp++;
                else n_bw_trunc++;
            }
        }

        /* ---- pow_retarget_bits vs CalculateNextWorkRequired ---- */
        {
            uint32_t lbr = (it & 1) ? 0x1d00ffffu : 0x1e0377aeu;
            cu256 limr = core_pow_limit(lbr);
            uint32_t base = 0; int found = 0;
            for (int tries = 0; tries < 64 && !found; tries++){
                base = (rnd() & 3) ? rnd_bits() : lbr - (uint32_t)(rnd() % 4);
                int nn, oo; cu256 bt = cu_set_compact(base, &nn, &oo);
                found = !nn && !oo && !cu_iszero(&bt) && cu_cmp(&bt, &limr) <= 0;
            }
            if (found){
                int64_t ts;
                switch (rnd() & 7){
                case 0: ts = (int64_t)rnd(); break;                                   /* any int64 */
                case 1: ts = 302400 + (int64_t)(rnd() % 3) - 1; break;                /* T/4 edge */
                case 2: ts = 4838400 + (int64_t)(rnd() % 3) - 1; break;               /* 4T edge */
                case 3: ts = (rnd() & 1) ? INT64_MIN : INT64_MAX; break;
                default: ts = (int64_t)(rnd() % 6000000) - 500000; break;
                }
                unsigned int got = pow_retarget_bits(base, (long)ts, lbr);
                unsigned int want = core_calc_next_work(base, ts, &limr);
                n_rt++;
                if (want == lbr) n_rt_cap++;
                if (got != want){ if (bad < 10) printf("MISMATCH retarget base=%08x ts=%lld got=%08x want=%08x\n", base, (long long)ts, got, want); bad++; }
            }
        }

        /* ---- chainwork_add ---- */
        uint8_t x[16], y[16], z[16];
        rnd_bytes(x, 16); rnd_bytes(y, 16);
        if (rnd() & 1){ x[15] &= 0x7f; y[15] &= 0x7f; }
        chainwork_add(z, x, y);
        unsigned __int128 X, Y, Z; memcpy(&X, x, 16); memcpy(&Y, y, 16); memcpy(&Z, z, 16);
        unsigned __int128 S = X + Y; if (S < X) S = ~(unsigned __int128)0;
        n_cw++;
        if (S != Z){ if (bad < 10) printf("MISMATCH chainwork_add\n"); bad++; }
    }
    printf("[diff] pow_check %ld (Core-accept %ld, exp<3 residual %ld, unarmed accepts Core-regtest-rejects %ld)\n",
           n_pow, n_acc, n_resid, n_unarmed_extra);
    printf("[diff] diff_target %ld (in-domain equal %ld, out-of-domain %ld)\n", n_dt, n_dt_eq, n_dt_off);
    printf("[diff] u256_div %ld, block_work %ld (in-domain %ld), chainwork_add %ld\n", n_div, n_bw, n_bw_dom, n_cw);
    printf("[diff] block_work out-of-domain differences (pow-valid bits): exp<3 %ld, exp 33/34 %ld, work>=2^128 %ld\n",
           n_bw_lowexp, n_bw_hiexp, n_bw_trunc);
    printf("[diff] pow_retarget_bits %ld (powLimit cap %ld)\n", n_rt, n_rt_cap);
    printf("[diff] unexpected mismatches: %ld\n", bad);
    return bad ? 1 : 0;
}
