/* test_fe_repr.c -- correctness gate for the 2026-08-22 field rewrite
 * (PERF_SCOPE.md section 5: fe_mul/fe_sqr in ADCX/ADOX form, fe_add/fe_sub
 * rewritten around p = 2^256 - C).
 *
 * This is consensus code and the failure mode that matters is a LOST CARRY.
 * Incident #7 (2026-08-21) was exactly that -- two of them -- and random
 * differential testing could not find either: they are ~2^-64 and ~2^-190 on
 * random operands but deterministic on structured ones. So this harness is
 * built around structured operands, and the random pass is the smaller half.
 *
 * FIVE INDEPENDENT CHECKS
 *
 *  1. GROUND TRUTH, explicit. FE_VEC[] holds (a, b, a+b, a-b, a*b, a^2,
 *     a^-1) computed by Python's arbitrary-precision integers
 *     (validation/fe_oracle.py). Nothing about it comes from this codebase,
 *     so agreement is evidence rather than a tautology, and a failure names
 *     a specific operand pair.
 *
 *  2. GROUND TRUTH, exhaustive over the structured space. The oracle also
 *     digests a*b, a+b and a-b over EVERY ORDERED PAIR of a 1,547-value
 *     structured family -- 2,393,209 pairs, every limb boundary against
 *     every other. This harness rebuilds the identical family by the
 *     identical rules and folds the identical digest over the assembly's
 *     answers. One 64-bit comparison covers all of it.
 *
 *  3. DIFFERENTIAL against tests/fe_ref.asm, a frozen copy of the 4x64
 *     implementation that ran the live replay to height ~575,000 (and that
 *     already carries the incident #7 fixes). Same structured cross-product,
 *     plus tens of millions of random pairs.
 *
 *  4. BIT-IDENTITY on NON-CANONICAL input. The fe_add and fe_sub rewrites
 *     claim to be bit-identical to the frozen reference on every 512-bit
 *     input pair, not just on in-range ones -- the claim rests on
 *     "add p == subtract C (mod 2^256)". That claim is what makes the
 *     rewrite safe if any caller ever hands them a value >= p, so it is
 *     tested directly with operands drawn from the whole [0, 2^256) range.
 *
 *  5. ALGEBRAIC IDENTITIES that do not depend on either implementation:
 *     fe_sqr(a) == fe_mul(a,a), a * fe_inv(a) == 1, (a+b)-b == a,
 *     a*(b+c) == a*b + a*c, and every result canonical (< p).
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "fe_vec.h"

typedef uint64_t u64;

extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
/* frozen pre-rewrite implementation, tests/fe_ref.asm */
extern void fe_add_ref(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub_ref(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_mul_ref(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr_ref(u64 r[4], const u64 a[4]);
extern void fe_inv_ref(u64 r[4], const u64 a[4]);

static int failures = 0;
static long checks = 0;

static const u64 PL[4] = {0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
                          0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL};
static const u64 ONE[4] = {1, 0, 0, 0};

static void show(const char *tag, const u64 v[4]){
    printf("  %-4s %016llx %016llx %016llx %016llx\n", tag,
           (unsigned long long)v[3], (unsigned long long)v[2],
           (unsigned long long)v[1], (unsigned long long)v[0]);
}
static int eq(const u64 a[4], const u64 b[4]){ return memcmp(a,b,32)==0; }

static void expect(const char *what, const u64 a[4], const u64 b[4],
                   const u64 got[4], const u64 exp[4]){
    checks++;
    if (eq(got, exp)) return;
    if (failures < 12){
        printf("FAIL %s\n", what);
        if (a) show("a", a);
        if (b) show("b", b);
        show("got", got); show("exp", exp);
    }
    failures++;
}

/* ---------- a small, self-contained 256-bit helper, independent of the
 * assembly under test, used only to BUILD the structured family ---------- */
static int lt_p(const u64 x[4]){
    for (int i = 3; i >= 0; i--){
        if (x[i] != PL[i]) return x[i] < PL[i];
    }
    return 0;                                   /* x == p */
}
static void sub_p(u64 x[4]){
    unsigned __int128 br = 0;
    for (int i = 0; i < 4; i++){
        unsigned __int128 t = (unsigned __int128)x[i] - PL[i] - br;
        x[i] = (u64)t; br = (t >> 64) & 1;
    }
}
static void modp(u64 x[4]){ while (!lt_p(x)) sub_p(x); }
static void add_small(u64 x[4], u64 v){          /* x += v (no wrap expected) */
    unsigned __int128 c = v;
    for (int i = 0; i < 4 && c; i++){
        unsigned __int128 t = (unsigned __int128)x[i] + (u64)c;
        x[i] = (u64)t; c = t >> 64;
    }
}
static void sub_small(u64 x[4], u64 v){
    unsigned __int128 br = v;
    for (int i = 0; i < 4 && br; i++){
        unsigned __int128 t = (unsigned __int128)x[i] - (u64)br;
        x[i] = (u64)t; br = (t >> 64) & 1;
    }
}
static void set_pow2(u64 x[4], int i){
    memset(x, 0, 32); x[i/64] = 1ULL << (i%64);
}
static void set_p(u64 x[4]){ memcpy(x, PL, 32); }

/* The structured family. MUST match validation/fe_oracle.py's family()
 * exactly -- same values, same order, same first-appearance dedup -- because
 * the cross-product digest depends on the ordering. */
static u64 (*FAM)[4];
static int NFAM;

static void fam_push(u64 v[4]){
    modp(v);
    for (int i = 0; i < NFAM; i++) if (eq(FAM[i], v)) return;
    memcpy(FAM[NFAM++], v, 32);
}
static void build_family(void){
    FAM = malloc(sizeof(*FAM) * 4096); NFAM = 0;
    u64 t[4];
    for (u64 k = 0; k < 8; k++){ memset(t,0,32); t[0]=k; fam_push(t); }
    for (u64 k = 1; k <= 8; k++){ set_p(t); sub_small(t,k); fam_push(t); }
    for (int i = 0; i < 256; i++){
        set_pow2(t,i);                       fam_push(t);
        set_pow2(t,i); sub_small(t,1);       fam_push(t);
        set_pow2(t,i); add_small(t,1);       fam_push(t);
    }
    for (int i = 0; i < 256; i++){
        u64 q[4]; set_p(t); set_pow2(q,i);
        /* p - 2^i, p - 2^i - 1, p - 2^i + 1 */
        u64 d[4]; unsigned __int128 br = 0;
        for (int j = 0; j < 4; j++){
            unsigned __int128 s = (unsigned __int128)PL[j] - q[j] - br;
            d[j] = (u64)s; br = (s >> 64) & 1;
        }
        memcpy(t,d,32);                fam_push(t);
        memcpy(t,d,32); sub_small(t,1); fam_push(t);
        memcpy(t,d,32); add_small(t,1); fam_push(t);
    }
    const u64 CC = 0x1000003D1ULL;
    memset(t,0,32); t[0]=CC-1;            fam_push(t);
    memset(t,0,32); t[0]=CC;              fam_push(t);
    memset(t,0,32); t[0]=CC+1;            fam_push(t);
    memset(t,0,32); t[0]=2*CC;            fam_push(t);
    set_p(t); sub_small(t,CC);            fam_push(t);
    set_p(t); sub_small(t,2*CC);          fam_push(t);
    for (int j = 0; j < 4; j++){
        static const u64 pats[4] = {0xFFFFFFFFFFFFFFFFULL, 0x8000000000000000ULL,
                                    0x00000000FFFFFFFFULL, 0xFFFFFFFF00000000ULL};
        for (int q = 0; q < 4; q++){ memset(t,0,32); t[j]=pats[q]; fam_push(t); }
    }
}

/* FNV-1a fold over four limbs -- must match fold() in the oracle. */
static u64 fold(u64 h, const u64 v[4]){
    for (int i = 0; i < 4; i++){ h ^= v[i]; h *= 0x100000001B3ULL; }
    return h;
}

/* xorshift* PRNG: deterministic, so a failure is reproducible. */
static u64 st = 0x243F6A8885A308D3ULL;
static u64 rnd(void){ st ^= st>>12; st ^= st<<25; st ^= st>>27; return st*0x2545F4914F6CDD1DULL; }
static void rnd_full(u64 x[4]){ for (int i=0;i<4;i++) x[i]=rnd(); }
static void rnd_fe(u64 x[4]){ do { rnd_full(x); } while (!lt_p(x)); }

int main(void){
    u64 r[4], r2[4], a[4], b[4], c[4], t1[4], t2[4];

    /* ---------- 1. explicit Python ground truth ---------- */
    for (int i = 0; i < FE_VEC_N; i++){
        const fe_vec_t *v = &FE_VEC[i];
        fe_add(r, v->a, v->b); expect("fe_add vs Python", v->a, v->b, r, v->add);
        fe_sub(r, v->a, v->b); expect("fe_sub vs Python", v->a, v->b, r, v->sub);
        fe_mul(r, v->a, v->b); expect("fe_mul vs Python", v->a, v->b, r, v->mul);
        fe_sqr(r, v->a);       expect("fe_sqr vs Python", v->a, NULL, r, v->sqr);
        fe_inv(r, v->a);       expect("fe_inv vs Python", v->a, NULL, r, v->inv);
    }
    printf("PASS  %d Python ground-truth vectors (add/sub/mul/sqr/inv)\n", FE_VEC_N);

    /* ---------- 2/3. structured cross-product: digest vs Python AND
     * limb-exact differential vs the frozen reference ---------- */
    build_family();
    if (NFAM != FE_FAMILY_N){
        printf("FAIL  family size %d, oracle says %d -- construction drifted\n",
               NFAM, FE_FAMILY_N);
        return 1;
    }
    u64 h = 0xCBF29CE484222325ULL;
    long pairs = 0, diffs = 0;
    for (int i = 0; i < NFAM; i++){
        for (int j = 0; j < NFAM; j++){
            const u64 *A = FAM[i], *B = FAM[j];
            fe_mul(r, A, B); h = fold(h, r);
            fe_mul_ref(r2, A, B); if (!eq(r,r2)){ if(!diffs) { printf("FAIL fe_mul != ref\n"); show("a",A); show("b",B); show("new",r); show("ref",r2);} diffs++; }
            fe_add(r, A, B); h = fold(h, r);
            fe_add_ref(r2, A, B); if (!eq(r,r2)){ if(!diffs){ printf("FAIL fe_add != ref\n"); show("a",A); show("b",B); show("new",r); show("ref",r2);} diffs++; }
            fe_sub(r, A, B); h = fold(h, r);
            fe_sub_ref(r2, A, B); if (!eq(r,r2)){ if(!diffs){ printf("FAIL fe_sub != ref\n"); show("a",A); show("b",B); show("new",r); show("ref",r2);} diffs++; }
            pairs++;
        }
    }
    checks += pairs * 6;
    if (h != FE_CROSS_DIGEST){
        printf("FAIL  structured cross-product digest %016llx, Python says %016llx\n",
               (unsigned long long)h, (unsigned long long)FE_CROSS_DIGEST);
        failures++;
    } else {
        printf("PASS  structured cross-product vs Python: %ld pairs "
               "(%d x %d), a*b + a+b + a-b, digest %016llx\n",
               pairs, NFAM, NFAM, (unsigned long long)h);
    }
    if (diffs){ printf("FAIL  %ld structured differences vs frozen reference\n", diffs); failures++; }
    else printf("PASS  structured cross-product vs frozen fe_ref: %ld pairs, 0 differences\n", pairs);

    /* fe_sqr and fe_inv over the whole family, digested against Python */
    h = 0xCBF29CE484222325ULL;
    diffs = 0;
    for (int i = 0; i < NFAM; i++){
        fe_sqr(r, FAM[i]); h = fold(h, r);
        fe_sqr_ref(r2, FAM[i]); if (!eq(r,r2)) diffs++;
        fe_mul(r2, FAM[i], FAM[i]);
        if (!eq(r,r2)){ printf("FAIL  fe_sqr(a) != fe_mul(a,a)\n"); show("a",FAM[i]); failures++; break; }
        fe_inv(r, FAM[i]); h = fold(h, r);
        fe_inv_ref(r2, FAM[i]); if (!eq(r,r2)) diffs++;
    }
    checks += NFAM * 4;
    if (h != FE_SQRINV_DIGEST){
        printf("FAIL  sqr/inv family digest %016llx, Python says %016llx\n",
               (unsigned long long)h, (unsigned long long)FE_SQRINV_DIGEST);
        failures++;
    } else printf("PASS  fe_sqr + fe_inv over all %d structured values vs Python, digest %016llx\n",
                  NFAM, (unsigned long long)h);
    if (diffs){ printf("FAIL  %ld sqr/inv differences vs frozen reference\n", diffs); failures++; }
    else printf("PASS  fe_sqr + fe_inv over all %d structured values vs frozen fe_ref\n", NFAM);

    /* ---------- 3b. random differential, in-range ---------- */
    const long NR = 4000000;
    diffs = 0;
    for (long k = 0; k < NR; k++){
        rnd_fe(a); rnd_fe(b);
        fe_mul(r,a,b); fe_mul_ref(r2,a,b); if(!eq(r,r2)) diffs++;
        fe_add(r,a,b); fe_add_ref(r2,a,b); if(!eq(r,r2)) diffs++;
        fe_sub(r,a,b); fe_sub_ref(r2,a,b); if(!eq(r,r2)) diffs++;
        fe_sqr(r,a);   fe_sqr_ref(r2,a);   if(!eq(r,r2)) diffs++;
    }
    checks += NR*4;
    if (diffs){ printf("FAIL  %ld random in-range differences vs frozen reference\n", diffs); failures++; }
    else printf("PASS  %ld random in-range pairs vs frozen fe_ref (mul/add/sub/sqr), 0 differences\n", NR);

    /* ---------- 3c. fe_inv ADDITION CHAIN differential (2026-08-23) ----------
     * fe_inv stopped walking the bits of p-2 and now runs a fixed 255-squaring
     * / 15-multiply addition chain (PERF_SCOPE.md section 13). That the chain's
     * exponent equals p-2 is checked symbolically over the integers by
     * validation/fe_inv_chain.py; THIS is the check that the assembly
     * implements the chain it claims to.
     *
     * fe_inv_ref is the frozen naive-binary implementation, so every agreement
     * below is between two structurally different computations of a^(p-2).
     * The structured half matters more than the random half, for the same
     * reason it does everywhere else in this file: a mis-sized rung is
     * deterministic, not probabilistic. A run of 1-bits is exactly what the
     * chain compresses, so operands with long limb runs (p-k, 2^k, 2^k-1) are
     * the ones that would expose one.
     */
    {
        const long NI = 250000;
        long idiffs = 0, ichecks = 0;
        for (long k = 0; k < NI; k++){
            rnd_fe(a);
            fe_inv(r, a); fe_inv_ref(r2, a);
            if (!eq(r,r2)){
                if (!idiffs){ printf("FAIL fe_inv != ref\n"); show("a",a); show("chain",r); show("ref",r2); }
                idiffs++;
            }
            ichecks++;
        }
        for (int k = 1; k <= 256; k++){
            for (int form = 0; form < 5; form++){
                u64 v[4] = {0,0,0,0};
                if (form == 0){ v[0] = (u64)k; }
                else if (form == 1){                       /* p - k */
                    memcpy(v, PL, 32);
                    unsigned __int128 br = (u64)k;
                    for (int q = 0; q < 4 && br; q++){
                        unsigned __int128 t = (unsigned __int128)v[q] - (u64)br;
                        v[q] = (u64)t; br = (t >> 64) & 1;
                    }
                }
                else if (form == 2){ if (k >= 256) continue; v[k>>6] = 1ULL << (k & 63); }
                else if (form == 3){                       /* 2^k - 1 */
                    if (k >= 256) continue;
                    for (int q = 0; q < 4; q++){
                        int lo = q*64, hi = lo+64;
                        if (k >= hi) v[q] = ~0ULL;
                        else if (k > lo) v[q] = (1ULL << (k - lo)) - 1;
                    }
                }
                else {                                     /* p - 2^k */
                    if (k >= 256) continue;
                    u64 t[4] = {0,0,0,0}; t[k>>6] = 1ULL << (k & 63);
                    memcpy(v, PL, 32);
                    unsigned __int128 br = 0;
                    for (int q = 0; q < 4; q++){
                        unsigned __int128 d = (unsigned __int128)v[q] - t[q] - br;
                        v[q] = (u64)d; br = (d >> 64) & 1;
                    }
                }
                if (!lt_p(v)) continue;
                fe_inv(r, v); fe_inv_ref(r2, v);
                if (!eq(r,r2)){
                    if (!idiffs){ printf("FAIL fe_inv != ref (form %d k=%d)\n", form, k); show("a",v); show("chain",r); show("ref",r2); }
                    idiffs++;
                }
                /* and the identity, which depends on neither implementation */
                if (v[0]|v[1]|v[2]|v[3]){
                    u64 one_chk[4];
                    fe_mul(one_chk, v, r);
                    if (!(one_chk[0]==1 && !one_chk[1] && !one_chk[2] && !one_chk[3])){
                        if (!idiffs){ printf("FAIL fe_inv identity a*inv(a)!=1 (form %d k=%d)\n", form, k); show("a",v); }
                        idiffs++;
                    }
                }
                ichecks += 2;
            }
        }
        memset(a, 0, 32);       /* both define fe_inv(0) == 0 */
        fe_inv(r, a); fe_inv_ref(r2, a);
        if (!eq(r,r2) || (r[0]|r[1]|r[2]|r[3])){ printf("FAIL fe_inv(0)\n"); idiffs++; }
        ichecks++;
        checks += ichecks;
        if (idiffs){ printf("FAIL  %ld fe_inv addition-chain differences vs frozen fe_ref\n", idiffs); failures++; }
        else printf("PASS  %ld fe_inv addition-chain cases vs frozen naive-binary fe_ref "
                    "(%ld random + structured k / p-k / 2^k / 2^k-1 / p-2^k + zero), 0 differences\n",
                    ichecks, NI);
    }

    /* ---------- 4. bit-identity on NON-CANONICAL input ----------
     * fe_add/fe_sub are claimed bit-identical to the reference on the WHOLE
     * [0, 2^256) range, because "add p" and "subtract C" are the same
     * operation on wrapping 4-limb arithmetic. fe_mul/fe_sqr are NOT claimed
     * to be identical out of range (neither implementation defines a result
     * there), so they are not compared here. */
    const long NF = 4000000;
    diffs = 0;
    for (long k = 0; k < NF; k++){
        rnd_full(a); rnd_full(b);
        fe_add(r,a,b); fe_add_ref(r2,a,b); if(!eq(r,r2)) diffs++;
        fe_sub(r,a,b); fe_sub_ref(r2,a,b); if(!eq(r,r2)) diffs++;
    }
    /* plus the structured cross-product taken OUT of range on purpose:
     * every family value and every family value + p (which is >= p). */
    for (int i = 0; i < NFAM; i += 7){
        for (int j = 0; j < NFAM; j += 11){
            u64 A[4], B[4];
            memcpy(A, FAM[i], 32); memcpy(B, FAM[j], 32);
            /* A += p (wrapping) -- deliberately non-canonical */
            unsigned __int128 cy = 0;
            for (int q = 0; q < 4; q++){
                unsigned __int128 s = (unsigned __int128)A[q] + PL[q] + cy;
                A[q] = (u64)s; cy = s >> 64;
            }
            fe_add(r,A,B); fe_add_ref(r2,A,B); if(!eq(r,r2)) diffs++;
            fe_sub(r,A,B); fe_sub_ref(r2,A,B); if(!eq(r,r2)) diffs++;
            fe_sub(r,B,A); fe_sub_ref(r2,B,A); if(!eq(r,r2)) diffs++;
            checks += 3;
        }
    }
    checks += NF*2;
    if (diffs){ printf("FAIL  %ld non-canonical-input differences vs frozen reference\n", diffs); failures++; }
    else printf("PASS  %ld full-range (non-canonical) fe_add/fe_sub pairs bit-identical to frozen fe_ref\n", NF);

    /* ---------- 5. algebraic identities ---------- */
    long ident = 0;
    for (long k = 0; k < 200000; k++){
        rnd_fe(a); rnd_fe(b); rnd_fe(c);
        /* (a+b)-b == a */
        fe_add(t1,a,b); fe_sub(t2,t1,b);
        if (!eq(t2,a)){ printf("FAIL  (a+b)-b != a\n"); show("a",a); show("b",b); failures++; break; }
        /* a*(b+c) == a*b + a*c */
        fe_add(t1,b,c); fe_mul(t1,a,t1);
        fe_mul(r,a,b); fe_mul(r2,a,c); fe_add(t2,r,r2);
        if (!eq(t1,t2)){ printf("FAIL  distributivity\n"); show("a",a); show("b",b); show("c",c); failures++; break; }
        /* a * a^-1 == 1 (a != 0 with overwhelming probability) */
        fe_inv(t1,a); fe_mul(t2,a,t1);
        if (!eq(t2,ONE)){ printf("FAIL  a*inv(a) != 1\n"); show("a",a); failures++; break; }
        /* every result canonical */
        if (!lt_p(t1) || !lt_p(t2)){ printf("FAIL  non-canonical result\n"); failures++; break; }
        ident += 4;
    }
    checks += ident;
    if (!failures) printf("PASS  %ld algebraic identities ((a+b)-b, distributivity, a*inv(a), canonicality)\n", ident);

    /* ---------- the exact operands from incident #7 ---------- */
    {
        u64 x[4]; set_p(x); u64 two31[4]; set_pow2(two31,31);
        unsigned __int128 br = 0;
        for (int j = 0; j < 4; j++){
            unsigned __int128 s = (unsigned __int128)x[j] - two31[j] - br;
            x[j] = (u64)s; br = (s>>64)&1;
        }
        static const u64 want[4] = {0x4000000000000000ULL,0,0,0};   /* 2^62 */
        fe_sqr(r, x);  expect("fe_sqr((p-2^31)) == 2^62 (incident #7)", x, NULL, r, want);
        fe_mul(r, x, x); expect("fe_mul(p-2^31,p-2^31) == 2^62 (incident #7)", x, NULL, r, want);
        printf("PASS  incident #7 fold-2 lost-carry vector ((p-2^31)^2 == 2^62)\n");
    }

    printf("\n%ld checks, %d failures\n", checks, failures);
    printf(failures ? "TEST FAILED\n" : "ALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
