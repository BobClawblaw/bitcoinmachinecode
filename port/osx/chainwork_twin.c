/* ============================================================================
 * chainwork_twin.c -- Bitcoin chainwork layer for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_chainwork.asm (branch bmc_osx).
 *
 *   void compact_to_target_le(u8 out_le[32], u32 bits);
 *   void u256_div(u8 q_le[32], const u8 a_le[32], const u8 b_le[32]);
 *   void block_work(u64 work[2], u32 bits);
 *   void chainwork_add(u64 out[2], const u64 a[2], const u64 b[2]);
 *   int  chainwork_cmp(const u64 a[2], const u64 b[2]);
 *   int  store_chainwork_init(void *st);
 *   int  store_chainwork_append(void *st, long height, const u64 work[2]);
 *   int  store_chainwork_get_at(void *st, long height, u64 out[2]);
 *   int  store_chainwork_get_tip(void *st, u64 out[2]);
 *   long store_chainwork_reload(void *st);
 *   int  store_chainwork_truncate(void *st, long target_height);
 *
 * u256_div: the x86 is a bit-by-bit restoring division, 255 down to 0,
 * committing (R-B, set quotient bit) when no-borrow OR carry-out of the
 * previous shift; transcribed identically with plain u64 limbs.
 * Syscall layer: Darwin pread/pwrite/ftruncate/open/close/lseek via libc.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

typedef uint64_t u64;
typedef unsigned int u32;
typedef unsigned char u8;

/* ---- compact_to_target_le ---------------------------------------------- */
void compact_to_target_le(u8 out_le[32], u32 bits)
{
    memset(out_le, 0, 32);
    u32 exp = bits >> 24;
    u32 mant = bits & 0x00ffffffu;
    if (exp < 3) return;                    /* exponent<3 -> target=0 */
    u32 off = exp - 3;                      /* byte offset of mantissa LSB */
    if (off > 29) return;                   /* would pass out[31] */
    out_le[off] = (u8)(mant & 0xff);
    if (off >= 31) return;
    out_le[off + 1] = (u8)((mant >> 8) & 0xff);
    if (off >= 30) return;
    out_le[off + 2] = (u8)((mant >> 16) & 0xff);
}

/* ---- u256_div: q = a / b (restoring, bit-by-bit, MSB-first) ------------- */
void u256_div(u8 q_le[32], const u8 a_le[32], const u8 b_le[32])
{
    u64 A[4], B[4], Q[4], R[4];
    memcpy(A, a_le, 32);
    memcpy(B, b_le, 32);
    memset(Q, 0, 32);
    memset(R, 0, 32);

    for (int bit = 255; bit >= 0; bit--) {
        /* R = R<<1 | a_bit  (shift the 4-limb accumulator left one) */
        u64 cout = R[3] >> 63;
        R[3] = (R[3] << 1) | (R[2] >> 63);
        R[2] = (R[2] << 1) | (R[1] >> 63);
        R[1] = (R[1] << 1) | (R[0] >> 63);
        R[0] = (R[0] << 1) | ((A[bit >> 6] >> (bit & 63)) & 1);

        /* subtract B: t = R - B, borrow */
        u64 t[4];
        u64 borrow = 0;
        for (int i = 0; i < 4; i++) {
            /* 128-bit limb subtraction with borrow */
            u64 bi = B[i] + borrow;
            if (R[i] < bi) { t[i] = R[i] - bi; borrow = 1; }
            else if (bi == 0) { t[i] = R[i]; borrow = 0; }
            else if (R[i] >= bi) { t[i] = R[i] - bi; borrow = 0; }
            else { t[i] = R[i] - bi; borrow = 1; }
        }
        /* x86: commit iff (no-borrow from sub) OR (carry-out of shift) */
        if (!borrow || cout) {
            memcpy(R, t, 32);
            Q[bit >> 6] |= (u64)1 << (bit & 63);
        }
    }
    memcpy(q_le, Q, 32);
}

/* ---- block_work: work = 2^256/(target+1), low 128 bits ------------------ */
void block_work(u64 work[2], u32 bits)
{
    u8 target[32];
    compact_to_target_le(target, bits);

    if (*(u64 *)target == 0 && *(u64 *)(target + 8) == 0 &&
        *(u64 *)(target + 16) == 0 && *(u64 *)(target + 24) == 0) {
        work[0] = 0; work[1] = 0;
        return;
    }
    /* num = ~target (2^256-1-target); den = target+1 */
    u8 num[32], den[32];
    for (int i = 0; i < 4; i++) {
        u64 v;
        memcpy(&v, target + 8 * i, 8);
        v = ~v;
        memcpy(num + 8 * i, &v, 8);
    }
    u64 carry = 1;                       /* den = target + 1 */
    for (int i = 0; i < 4; i++) {
        u64 v;
        memcpy(&v, target + 8 * i, 8);
        u64 s = v + carry;
        carry = (s < v) ? 1 : 0;
        memcpy(den + 8 * i, &s, 8);
    }
    /* x86: jc .overflow -- target+1 wrapped => den = 2^256 => work = low of
     * 2^256/2^256 = 1?  The asm jumps to .overflow which writes work=1,0?
     * Actually overflow sets work = (1, 0)?  Emulate: den==0 mod 2^256. */
    u64 d0, d1, d2, d3;
    memcpy(&d0, den + 0, 8); memcpy(&d1, den + 8, 8);
    memcpy(&d2, den + 16, 8); memcpy(&d3, den + 24, 8);
    if (carry) {
        /* target was 2^256-1: den wrapped to 0 (x86 jc .overflow) */
        work[0] = 0; work[1] = 0;
        return;
    }

    u8 q[32];
    u256_div(q, num, den);
    u64 w0, w1, hi;
    memcpy(&w0, q + 0, 8);
    memcpy(&w1, q + 8, 8);
    work[0] = w0 + 1;                       /* x86: add rax, 1 */
    hi = (work[0] < w0) ? 1 : 0;
    work[1] = w1 + hi;
}

/* ---- chainwork_add: 128-bit saturating add ------------------------------ */
void chainwork_add(u64 out[2], const u64 a[2], const u64 b[2])
{
    u64 s0 = a[0] + b[0];
    u64 s1 = a[1] + b[1] + (s0 < a[0] ? 1 : 0);
    if (s1 < a[1] && (s0 < a[0])) {
        /* carry out of bit 127 -> saturate to all-ones (x86 .no_ovf) */
        out[0] = ~(u64)0; out[1] = ~(u64)0;
        return;
    }
    /* x86 semantics: the saturation fires when the ADD OF LIMB1 carries;
     * limb0's carry is consumed by limb1's adc, so only limb1's carry
     * saturates. */
    if (s1 < a[1]) {
        out[0] = ~(u64)0; out[1] = ~(u64)0;
        return;
    }
    out[0] = s0; out[1] = s1;
}

int chainwork_cmp(const u64 a[2], const u64 b[2])
{
    if (a[1] != b[1]) return a[1] > b[1] ? 1 : -1;
    if (a[0] != b[0]) return a[0] > b[0] ? 1 : -1;
    return 0;
}

/* ---- store layer: chainwork.dat of 16-byte cumulative records ----------- */
static int cw_fd = -1;
static u64 cw_cum[2];

int store_chainwork_init(void *st)
{
    (void)st;
    if (cw_fd >= 0) { close(cw_fd); cw_fd = -1; }
    cw_fd = open("chainwork.dat", O_RDWR | O_CREAT, 0644);
    if (cw_fd < 0) return -1;
    cw_cum[0] = 0; cw_cum[1] = 0;
    return 1;
}

int store_chainwork_append(void *st, long height, const u64 work[2])
{
    (void)st;
    if (cw_fd < 0) return -1;
    u64 prev_cum[2] = { 0, 0 };
    if (height != 0) {
        if (pread(cw_fd, prev_cum, 16, (off_t)(height - 1) * 16) != 16)
            return -1;
    }
    u64 new_cum[2];
    chainwork_add(new_cum, prev_cum, work);
    if (pwrite(cw_fd, new_cum, 16, (off_t)height * 16) != 16) return -1;
    cw_cum[0] = new_cum[0]; cw_cum[1] = new_cum[1];
    return 1;
}

int store_chainwork_get_at(void *st, long height, u64 out[2])
{
    (void)st;
    if (cw_fd < 0) return -1;
    if (pread(cw_fd, out, 16, (off_t)height * 16) != 16) return -1;
    return 1;
}

int store_chainwork_get_tip(void *st, u64 out[2])
{
    (void)st;
    out[0] = cw_cum[0]; out[1] = cw_cum[1];
    return 1;
}

long store_chainwork_reload(void *st)
{
    (void)st;
    if (cw_fd < 0) return -1;
    off_t sz = lseek(cw_fd, 0, SEEK_END);
    if (sz < 0) return -1;
    long n = (long)(sz / 16);           /* floor; partial trailing ignored */
    cw_cum[0] = 0; cw_cum[1] = 0;
    if (n == 0) return 0;
    u64 last[2];
    if (pread(cw_fd, last, 16, (off_t)(n - 1) * 16) != 16) return -1;
    cw_cum[0] = last[0]; cw_cum[1] = last[1];
    return n;
}

int store_chainwork_truncate(void *st, long target_height)
{
    (void)st;
    if (target_height < -1) return -1;
    if (cw_fd < 0) return -1;
    long n = store_chainwork_reload(NULL);
    if (n == -1) return -1;
    if ((long)(target_height + 1) < n) {
        if (ftruncate(cw_fd, (off_t)(target_height + 1) * 16) < 0) return -1;
        if (store_chainwork_reload(NULL) == -1) return -1;
    }
    return 1;
}
