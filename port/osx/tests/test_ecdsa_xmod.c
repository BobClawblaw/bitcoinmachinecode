/* test_ecdsa_xmod.c -- gate for ecdsa_x_eq_mod_n's r+n branch and the
 * p-n bound (bmc_osx).
 *
 * REGRESSIONS (testnet4 h=126,683 tx=93, 2026-09-11), both in the twin's
 * ecdsa_x_eq_mod_n, both invisible to random differentials:
 *
 *   1. The compare chain was translated as `if (!(r[3] < PMN[3])) return 0;`
 *      which returns on r[3] == PMN[3] == 0 -- the x86 falls through per
 *      limb on equality -- so the second candidate (X_affine == r + n, i.e.
 *      R.x in [n, p)) was DEAD CODE. A random differential vector lands in
 *      that band with probability (p-n)/p ~ 2^-127; a real block carried a
 *      CONSTRUCTED signature (sha256 of a brute-forced 16-byte preimage is a
 *      valid DER signature; r is 10 bytes, s is 15) whose R.x sits there.
 *   2. The twin's PMN_LIMBS transcription was 0x402DA1732FC9BEBF instead of
 *      the x86's 0x402DA1722FC9BAEE (python p-n) -- a wrong branch bound.
 *
 * The gate pins the CONTRACT directly:
 *     ecdsa_x_eq_mod_n(r, X, Z) == 1  iff  X * Z^-2 == r (mod n)
 * The function compares FIELD elements limb-for-limb, so the Jacobian
 * numerator for affine x under Z is X = x * Z^2 (mod p) -- built here with
 * the same fe_twin primitives the module itself uses.
 *
 * Build (osx, from asm/):
 *   cc -O2 -arch arm64 -I. -Itests -I../port/osx/compat -D_DARWIN_C_SOURCE \
 *     -o test_ecdsa_xmod tests/test_ecdsa_xmod.c ../port/osx/ecdsa_twin.c \
 *     ../port/osx/fe_twin.c ../port/osx/point_twin.c \
 *     ../port/osx/g_comb_table_data.c ../port/osx/sc_mul_c.c \
 *     ../port/osx/sc_mul_512_c.c secp256k1_scalar_c.c secp256k1_glv_c.c \
 *     ../port/osx/secp256k1_scalar.S
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern int ecdsa_x_eq_mod_n(const uint64_t r[4], const uint64_t X[4], const uint64_t Z[4]);
extern void fe_mul(uint64_t out[4], const uint64_t a[4], const uint64_t b[4]);

static const uint64_t N[4]   = {0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
static const uint64_t PMN[4] = {0x402DA1722FC9BAEEULL,0x4551231950B75FC4ULL,0x0000000000000001ULL,0x0000000000000000ULL};

static uint64_t r_[4], X_[4], Z_[4];
static int fails;

static int expect(const char* name, int want){
    int got = ecdsa_x_eq_mod_n(r_, X_, Z_);
    if (got == want) { printf("  ok   %-46s -> %d\n", name, got); return 1; }
    printf("  FAIL %-46s -> %d (want %d)\n", name, got, want);
    fails++;
    return 0;
}

/* X = affine * Z^2 mod p -- the Jacobian numerator whose affine value is
 * `affine` under the given Z (fe ops reduce mod p) */
static void set_X_affine(const uint64_t affine[4]){
    uint64_t z2[4];
    fe_mul(z2, Z_, Z_);
    fe_mul(X_, affine, z2);
}

static void add_n(uint64_t out[4], const uint64_t a[4]){
    unsigned carry = 0;
    for (int i = 0; i < 4; i++){
        unsigned __int128 s = (unsigned __int128)a[i] + N[i] + carry;
        out[i] = (uint64_t)s; carry = (unsigned)(s >> 64);
    }
}
static void sub1(uint64_t out[4], const uint64_t a[4]){
    unsigned borrow = 1;
    for (int i = 0; i < 4 && borrow; i++){
        if (a[i] >= borrow){ out[i] = a[i] - borrow; borrow = 0; }
        else { out[i] = ~0ULL; borrow = 1; }
    }
}

int main(void){
    setvbuf(stdout, NULL, _IONBF, 0);

    const uint64_t Zs[3][4] = {
        {1,0,0,0},
        {0x123456789abcdef0ULL,0x0fedcba987654321ULL,0x5555555555555555ULL,0x0ULL},
        {0xFFFFFFFEFFFFFC2EULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL}
    };
    /* the real h=126,683 signature's r = 0x7993dad81d0e10285a7e (LE limbs) */
    const uint64_t r_small[4] = {0xdad81d0e10285a7eULL, 0x79ULL, 0, 0};
    char nm[80];

    for (int zi = 0; zi < 3; zi++){
        memcpy(Z_, Zs[zi], 32);

        /* 1. affine X == r (primary branch) */
        memcpy(r_, r_small, 32);
        set_X_affine(r_);
        snprintf(nm, sizeof nm, "Z#%d affine==r (primary)", zi);
        expect(nm, 1);

        /* 2. affine X == r + n (second branch) -- THE regression */
        memcpy(r_, r_small, 32);
        { uint64_t rn[4]; add_n(rn, r_); set_X_affine(rn); }
        snprintf(nm, sizeof nm, "Z#%d affine==r+n (second branch)", zi);
        expect(nm, 1);

        /* 3. affine X == r + n + 1 -> reject */
        memcpy(r_, r_small, 32);
        { uint64_t rn[4]; add_n(rn, r_);
          unsigned c = 1;
          for (int i = 0; i < 4; i++){ unsigned __int128 s=(unsigned __int128)rn[i]+c; rn[i]=(uint64_t)s; c=(unsigned)(s>>64); }
          set_X_affine(rn); }
        snprintf(nm, sizeof nm, "Z#%d affine==r+n+1 (reject)", zi);
        expect(nm, 0);

        /* 4. affine X == r - 1 -> reject */
        memcpy(r_, r_small, 32);
        { uint64_t rm[4]; sub1(rm, r_); set_X_affine(rm); }
        snprintf(nm, sizeof nm, "Z#%d affine==r-1 (reject)", zi);
        expect(nm, 0);

        /* 5. r = p-n-1: r+n = p-1, both branches' boundary -- must hit the
         * second candidate (affine p-1 == r+n) */
        sub1(r_, PMN);
        { uint64_t rn[4]; add_n(rn, r_); set_X_affine(rn); }
        snprintf(nm, sizeof nm, "Z#%d r=p-n-1, affine==r+n=p-1", zi);
        expect(nm, 1);

        /* 6. r == p-n exactly: r+n == p overflows the field; X affine == r
         * must pass via the primary; affine == r+n == p is not representable
         * (p reduces to 0) -- pin X=0 rejects (0 != r*Z^2 for these Z). */
        memcpy(r_, PMN, 32);
        set_X_affine(r_);
        snprintf(nm, sizeof nm, "Z#%d r==p-n, affine==r (primary)", zi);
        expect(nm, 1);
        { uint64_t zero[4] = {0,0,0,0}; memcpy(X_, zero, 32); }
        snprintf(nm, sizeof nm, "Z#%d r==p-n, affine==0 (reject)", zi);
        expect(nm, 0);
    }

    /* 7. r > n with r[3] > 0 (>= p-n): only the primary is reachable */
    memcpy(r_, N, 32);
    { unsigned c = 0;
      for (int i = 0; i < 4; i++){
          unsigned __int128 s = (unsigned __int128)r_[i] + 0x1234ULL + c;
          r_[i] = (uint64_t)s; c = (unsigned)(s >> 64);
      } }
    memcpy(Z_, Zs[0], 32);
    set_X_affine(r_);
    expect("r>n r[3]>0, affine==r (primary)", 1);
    { uint64_t rm[4]; sub1(rm, r_); set_X_affine(rm); }
    expect("r>n r[3]>0, affine==r-1 (reject)", 0);

    if (fails == 0) { printf("ALL PASS\n"); return 0; }
    printf("%d FAILURES\n", fails);
    return 1;
}
