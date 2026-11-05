/* dsl.c -- cross-arch differential driver for sc_mul_512 / sc_split_lambda
 * and the 256-bit primitives sc_mul / sc_add / sc_sub.
 * stdin: records.  op(1B):
 *   0: mul_512(a[32] b[32])            -> r[64]
 *   1: split_lambda(k[32])             -> ret(4B LE) + r1[32] + r2[32]
 *   2: sc_mul(a[32] b[32])             -> r[32]
 *   3: sc_add(a[32] b[32])             -> r[32]
 *   4: sc_sub(a[32] b[32])             -> r[32]
 * usage: dsl < vecs.bin > results.bin
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
extern void sc_mul_512(u64 r[8], const u64 a[4], const u64 b[4]);
extern int  sc_split_lambda(u64 r1[4], u64 r2[4], const u64 k[4]);
extern void sc_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void sc_sub(u64 r[4], const u64 a[4], const u64 b[4]);

static u64 in[4], in2[4], r1[4], r2[4], r8[8];

static void rd(void *p, size_t n){ if (fread(p, 1, n, stdin) != n) { fprintf(stderr,"eof\n"); exit(2);} }

int main(void){
    for (;;){
        int op = getchar();
        if (op == EOF) break;
        if (op == 0){
            rd(in, 32); rd(in2, 32);
            sc_mul_512(r8, in, in2);
            fwrite(r8, 8, 8, stdout);
        } else if (op == 1){
            rd(in, 32);
            uint32_t ok = (uint32_t)sc_split_lambda(r1, r2, in);
            fwrite(&ok, 4, 1, stdout);
            fwrite(r1, 8, 4, stdout);
            fwrite(r2, 8, 4, stdout);
        } else if (op == 2){
            rd(in, 32); rd(in2, 32);
            sc_mul(r1, in, in2);
            fwrite(r1, 8, 4, stdout);
        } else if (op == 3){
            rd(in, 32); rd(in2, 32);
            sc_add(r1, in, in2);
            fwrite(r1, 8, 4, stdout);
        } else if (op == 4){
            rd(in, 32); rd(in2, 32);
            sc_sub(r1, in, in2);
            fwrite(r1, 8, 4, stdout);
        }
    }
    return 0;
}
