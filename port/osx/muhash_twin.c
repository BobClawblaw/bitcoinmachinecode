/* ============================================================================
 * muhash_twin.c -- MuHash3072 layer for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_muhash.asm (branch bmc_osx): the generic
 * num3072 path, muhash_to_num3072 (SHA256 + ChaCha20 keystream), insert,
 * combine, finalize, and the utxo_stats layer on top.
 *
 *   p = 2^3072 - 1103717, 48 x u64 little-endian limbs.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef unsigned __int128 u128;
typedef unsigned char u8;

#define NLIMBS 48
#define NBYTES_ 384
#define MAX_PRIME_DIFF 1103717ULL

static unsigned num3072_mul_path = 2;

void sha256_full(u8 *out, const u8 *in, unsigned long len);

void num3072_set_one(u64 r[NLIMBS])
{
    memset(r, 0, NBYTES_);
    r[0] = 1;
}

void muhash_init(u64 r[NLIMBS]) { num3072_set_one(r); }

int num3072_is_overflow(const u64 a[NLIMBS])
{
    if (a[0] <= (u64)0 - 1 - MAX_PRIME_DIFF) return 0;
    for (int i = 1; i < NLIMBS; i++)
        if (a[i] != ~(u64)0) return 0;
    return 1;
}

void num3072_full_reduce(u64 a[NLIMBS])
{
    u64 c0 = MAX_PRIME_DIFF, c1 = 0;
    for (int i = 0; i < NLIMBS; i++) {
        u64 c2;
        u128 s = (u128)c0 + a[i];
        c0 = (u64)s;
        u128 t = (u128)c1 + (u64)(s >> 64);
        c1 = (u64)t;
        c2 = (u64)(t >> 64);
        a[i] = c0;
        c0 = c1;
        c1 = c2;
    }
}

void num3072_mul_generic(u64 out[NLIMBS], const u64 a[NLIMBS], const u64 b[NLIMBS])
{
    /* Exact schoolbook 3072x3072 -> 6144, then Chaum-style reduction:
     * value = L + H*2^3072, 2^3072 = MPD (mod p), so fold H*MPD back in
     * until the value fits in 3072 bits, then canonical subtract.  This
     * matches the num3072 oracle bit-for-bit (vectors are the ground
     * truth; the x86 asm's bounded-fold shortcuts are an optimization of
     * the same math). */
    u64 t[96];
    memset(t, 0, sizeof t);
    for (int i = 0; i < NLIMBS; i++) {
        u64 carry = 0;
        for (int j = 0; j < NLIMBS; j++) {
            u128 cur = (u128)a[i] * b[j] + t[i + j] + carry;
            t[i + j] = (u64)cur;
            carry = (u64)(cur >> 64);
        }
        /* propagate the final carry */
        int k = i + NLIMBS;
        while (carry && k < 96) {
            u128 cur = (u128)t[k] + carry;
            t[k] = (u64)cur;
            carry = (u64)(cur >> 64);
            k++;
        }
    }
    /* fold the high half back: value = L + H*MPD (H < 2^3072, H*MPD may
     * still exceed 2^3072: iterate) */
    for (int round = 0; round < 3; round++) {
        /* H = t[48..95] */
        u64 H[48];
        memcpy(H, t + 48, 384);
        int nonzero = 0;
        for (int i = 0; i < 48; i++) if (H[i]) { nonzero = 1; break; }
        if (!nonzero) break;
        /* acc = H * MPD (384+8 bytes) */
        u64 acc[49];
        memset(acc, 0, sizeof acc);
        for (int i = 0; i < 48; i++) {
            u128 cur = (u128)H[i] * MAX_PRIME_DIFF + acc[i];
            acc[i] = (u64)cur;
            u64 carry = (u64)(cur >> 64);
            int k = i + 1;
            while (carry && k <= 48) {
                u128 c2 = (u128)acc[k] + carry;
                acc[k] = (u64)c2;
                carry = (u64)(c2 >> 64);
                k++;
            }
        }
        /* t = L + acc[0..47] (mod 2^3072); the excess (acc[48] + carry)
         * is folded in the next round via H' (t[48] = excess) */
        u64 carry = 0;
        for (int i = 0; i < 48; i++) {
            u128 s2 = (u128)t[i] + acc[i] + carry;
            t[i] = (u64)s2;
            carry = (u64)(s2 >> 64);
        }
        t[48] = acc[48] + carry;
        memset(t + 49, 0, (96 - 49) * 8);
    }
    /* canonicalize: t >= p  <=>  (t + MPD) carries out of 2^3072; the
     * wrapped sum equals t - p.  At most a couple of rounds. */
    for (int round = 0; round < 4; round++) {
        u64 probe[48];
        u64 carry = MAX_PRIME_DIFF;
        for (int i = 0; i < 48; i++) {
            u128 s2 = (u128)t[i] + carry;
            probe[i] = (u64)s2;
            carry = (u64)(s2 >> 64);
        }
        if (!carry) break;          /* t + MPD < 2^3072  =>  t < p: done */
        memcpy(t, probe, 384);      /* carry out: wrapped t = t - p */
    }
    memcpy(out, t, 384);
}


/* test-visible ABI: num3072_mul(a, b) computes a = a*b in place */
void num3072_mul(u64 a[NLIMBS], const u64 b[NLIMBS])
{
    u64 tmp[NLIMBS];
    memcpy(tmp, a, NBYTES_);
    num3072_mul_generic(a, tmp, b);
}

void num3072_mul_force_path(int p)
{
    (void)p;                            /* AArch64: generic only */
    num3072_mul_path = 2;
}

int num3072_cpu_has_ifma(void) { return 0; }
int num3072_cpu_has_adx(void) { return 0; }
int num3072_mul_current_path(void) { return (int)num3072_mul_path; }

/* ---- ChaCha20 keystream (sigma, 32-byte key, zero counter+nonce) -------- */
static void qround(u32 x[16], int a, int b, int c, int d)
{
    x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d] << 16) | (x[d] >> 16);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b] << 12) | (x[b] >> 20);
    x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d] << 8) | (x[d] >> 24);
    x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b] << 7) | (x[b] >> 25);
}

void chacha20_keystream_k0(u8 *out, u64 blocks, const u8 key[32])
{
    static const u32 sigma[4] = { 0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u };
    u32 st[16];
    st[0] = sigma[0]; st[1] = sigma[1]; st[2] = sigma[2]; st[3] = sigma[3];
    for (int i = 0; i < 8; i++)
        memcpy(&st[4 + i], key + 4 * i, 4);
    st[12] = 0; st[13] = 0; st[14] = 0; st[15] = 0;
    while (blocks--) {
        u32 x[16];
        memcpy(x, st, 64);
        for (int i = 0; i < 10; i++) {
            qround(x, 0, 4, 8, 12);
            qround(x, 1, 5, 9, 13);
            qround(x, 2, 6, 10, 14);
            qround(x, 3, 7, 11, 15);
            qround(x, 0, 5, 10, 15);
            qround(x, 1, 6, 11, 12);
            qround(x, 2, 7, 8, 13);
            qround(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) {
            u32 v = x[i] + st[i];       /* x86 .add_out */
            memcpy(out + 4 * i, &v, 4);
        }
        st[12] += 1;
        out += 64;
    }
}

void muhash_to_num3072(u8 out384[NBYTES_], const void *data, unsigned long len)
{
    u8 digest[32];
    sha256_full(digest, (const u8 *)data, len);
    chacha20_keystream_k0(out384, NBYTES_ / 64, digest);
}

void muhash_insert(u64 acc[NLIMBS], const void *data, unsigned long len)
{
    u64 elem[NLIMBS], tmp[NLIMBS];
    muhash_to_num3072((u8 *)elem, data, len);
    memcpy(tmp, acc, NBYTES_);
    num3072_mul_generic(acc, tmp, elem);
}

void muhash_combine(u64 acc[NLIMBS], const u64 other[NLIMBS])
{
    u64 tmp[NLIMBS];
    memcpy(tmp, acc, NBYTES_);
    num3072_mul_generic(acc, tmp, other);
}

void muhash_finalize(u8 out[32], const void *acc_)
{
    const u64 *acc = (const u64 *)acc_;
    u64 work[NLIMBS], one[NLIMBS], tmp[NLIMBS];
    memcpy(work, acc, NBYTES_);
    num3072_set_one(one);
    if (num3072_is_overflow(work)) num3072_full_reduce(work);
    memcpy(tmp, work, NBYTES_);
    num3072_mul_generic(work, tmp, one);
    if (num3072_is_overflow(work)) num3072_full_reduce(work);
    sha256_full(out, (const u8 *)work, NBYTES_);
}
