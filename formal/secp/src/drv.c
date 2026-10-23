/* drv.c -- differential driver: runs the REAL compiled secp256k1 objects on
 * inputs read from stdin and prints their outputs, so run_diff.py can compare
 * them with Python big-integer arithmetic and with the lifter (x86sym.py).
 *
 * Line format: <fn> <arg> ...   where a 256-bit argument is 64 hex digits
 * (big-endian), an int argument is decimal. Output: one line per input. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef uint64_t u64;
typedef void (*f3)(u64 *, const u64 *, const u64 *);
typedef void (*f2)(u64 *, const u64 *);
extern void fe_add(u64*, const u64*, const u64*), fe_sub(u64*, const u64*, const u64*), fe_mul(u64*, const u64*, const u64*);
extern void fe_sqr(u64*, const u64*), fe_inv(u64*, const u64*), fe_pow_sqrt(u64*, const u64*), fe_inv_var(u64*, const u64*);
extern void w_fe_addm(u64*, const u64*, const u64*), w_fe_subm(u64*, const u64*, const u64*), w_fe_dbl(u64*, const u64*);
extern void sc_add(u64*, const u64*, const u64*), sc_sub(u64*, const u64*, const u64*), sc_mul(u64*, const u64*, const u64*);
extern void sc_sqr(u64*, const u64*), sc_inv(u64*, const u64*), sc_inv_var(u64*, const u64*), sc_half_ct(u64*, const u64*);
extern void sc_mul_512(u64 r[8], const u64*, const u64*);
extern int sc_split_lambda(u64 r1[4], u64 r2[4], const u64 k[4]);
extern int scalar_small_nonzero(const unsigned char k[32]);
extern int ecdsa_in_range(void *unused, const u64 *x);   /* the asm reads rsi */
extern void reduce_n(u64 r[4], const u64 a[4]);
extern void cneg_n(u64 r[4], const u64 a[4], int flag);
extern int fe_is_zero(const u64 a[4]);
extern int fe_equal(const u64 a[4], const u64 b[4]);
extern int fe_sqrt(u64 r[4], const u64 a[4]);
extern void sc_inv_batch(u64 *out, const u64 *x, long n);

static void rd(u64 v[4], const char *h){
    for (int i = 0; i < 4; i++){
        char buf[17]; memcpy(buf, h + 16 * (3 - i), 16); buf[16] = 0;
        v[i] = strtoull(buf, NULL, 16);
    }
}
static void pr(const u64 v[4]){ printf("%016llx%016llx%016llx%016llx", (unsigned long long)v[3], (unsigned long long)v[2], (unsigned long long)v[1], (unsigned long long)v[0]); }

static const struct { const char *n; f3 f; } F3[] = {
    {"fe_add", fe_add}, {"fe_sub", fe_sub}, {"fe_mul", fe_mul}, {"w_fe_addm", w_fe_addm}, {"w_fe_subm", w_fe_subm},
    {"sc_add", sc_add}, {"sc_sub", sc_sub}, {"sc_mul", sc_mul}, {0, 0}};
static const struct { const char *n; f2 f; } F2[] = {
    {"fe_sqr", fe_sqr}, {"fe_inv", fe_inv}, {"fe_pow_sqrt", fe_pow_sqrt}, {"fe_inv_var", fe_inv_var}, {"w_fe_dbl", w_fe_dbl},
    {"sc_sqr", sc_sqr}, {"sc_inv", sc_inv}, {"sc_inv_var", sc_inv_var}, {"sc_half_ct", sc_half_ct}, {"reduce_n", reduce_n}, {0, 0}};

int main(void){
    static char line[1 << 16];
    while (fgets(line, sizeof line, stdin)){
        char *tok[64]; int nt = 0;
        for (char *p = strtok(line, " \n"); p && nt < 64; p = strtok(NULL, " \n")) tok[nt++] = p;
        if (!nt) continue;
        u64 a[4], b[4], r[8], r2[4];
        int done = 0;
        for (int i = 0; F3[i].n; i++) if (!strcmp(tok[0], F3[i].n)){ rd(a, tok[1]); rd(b, tok[2]); F3[i].f(r, a, b); pr(r); done = 1; }
        for (int i = 0; !done && F2[i].n; i++) if (!strcmp(tok[0], F2[i].n)){ rd(a, tok[1]); F2[i].f(r, a); pr(r); done = 1; }
        if (done){}
        else if (!strcmp(tok[0], "sc_mul_512")){ rd(a, tok[1]); rd(b, tok[2]); sc_mul_512(r, a, b); pr(r + 4); pr(r); }
        else if (!strcmp(tok[0], "sc_split_lambda")){ rd(a, tok[1]); int ok = sc_split_lambda(r, r2, a); pr(r); printf(" "); pr(r2); printf(" %d", ok); }
        else if (!strcmp(tok[0], "scalar_small_nonzero")){
            unsigned char k[32]; rd(a, tok[1]);
            for (int i = 0; i < 32; i++) k[i] = (unsigned char)(a[3 - i / 8] >> (8 * (7 - i % 8)));
            printf("%d", scalar_small_nonzero(k)); }
        else if (!strcmp(tok[0], "ecdsa_in_range")){ rd(a, tok[1]); printf("%d", ecdsa_in_range(NULL, a)); }
        else if (!strcmp(tok[0], "cneg_n")){ rd(a, tok[1]); cneg_n(r, a, atoi(tok[2])); pr(r); }
        else if (!strcmp(tok[0], "fe_is_zero")){ rd(a, tok[1]); printf("%d", fe_is_zero(a)); }
        else if (!strcmp(tok[0], "fe_equal")){ rd(a, tok[1]); rd(b, tok[2]); printf("%d", fe_equal(a, b)); }
        else if (!strcmp(tok[0], "fe_sqrt")){ rd(a, tok[1]); memset(r, 0, 32); int ok = fe_sqrt(r, a); pr(r); printf(" %d", ok); }
        else if (!strcmp(tok[0], "sc_inv_batch")){
            long n = nt - 1; u64 *x = malloc(32 * n), *o = malloc(32 * n);
            for (long i = 0; i < n; i++) rd(x + 4 * i, tok[1 + i]);
            sc_inv_batch(o, x, n);
            for (long i = 0; i < n; i++){ if (i) printf(" "); pr(o + 4 * i); }
            free(x); free(o); }
        else { printf("ERR unknown %s", tok[0]); }
        printf("\n");
        fflush(stdout);
    }
    return 0;
}
