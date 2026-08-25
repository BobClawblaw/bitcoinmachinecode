/* fz_point.c -- differential-fuzz driver for the point layer.
 * Reads vectors from stdin, one per line:
 *   dbl      P12            -> 2P
 *   dbl_ia   P12            -> 2P (in-place, r==p)
 *   add      P12 Q12        -> P+Q
 *   add_ia   P12 Q12        -> P+Q (in-place, r==p)
 *   mixed    P12 XY8        -> P + affine(XY)
 *   mixed_ia P12 XY8        -> P + affine(XY) (in-place, r==p)
 *   mixed_zr P12 XY8        -> P + affine(XY) + z-ratio (prints "zr x y zr")
 *   scalar   XY8 K4         -> K*affine(XY)
 * Each limb/coordinate is 16 hex digits. Skip blank lines / # comments.
 * For each vector prints one result line: `inf` for the point at infinity,
 * else `x y` (4+4 limbs). For mixed_zr, prints `x y zr(4 limbs)`.
 * Converts Jacobian -> affine using the (already-verified) fe_inv/fe_mul/fe_sqr.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_double(u64 r[12], const u64 p[12]);
extern void point_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void point_add_mixed(u64 r[12], const u64 p[12], const u64 xy[8]);
extern void point_add_mixed_zr(u64 r[12], const u64 p[12], const u64 xy[8], u64 zr[4]);
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);

static int rdlimbs(u64* o, char** p, int n){
    for (int i = 0; i < n; i++){
        char b[20]; int j = 0;
        while (**p && **p != ' ' && **p != '\n' && j < 16) b[j++] = *(*p)++;
        b[j] = 0;
        o[i] = strtoull(b, 0, 16);
        while (**p == ' ') (*p)++;
    }
    return n;
}

int main(void){
    char line[4096];
    while (fgets(line, sizeof line, stdin)){
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n') continue;
        char op[16]; int i = 0;
        while (*p != ' ' && *p && i < 15) op[i++] = *p++;
        op[i] = 0;
        while (*p == ' ') p++;
        u64 P[12], Q[12], XY[8], K[4], R[12], ZR[4];
        int ia = 0;
        if (strcmp(op, "dbl") == 0){
            rdlimbs(P, &p, 12);
            point_double(R, P);
            memcpy(R, R, 96);
        } else if (strcmp(op, "dbl_ia") == 0){
            rdlimbs(P, &p, 12); memcpy(R, P, 96);
            point_double(R, R);
        } else if (strcmp(op, "add") == 0){
            rdlimbs(P, &p, 12); rdlimbs(Q, &p, 12);
            point_add(R, P, Q);
        } else if (strcmp(op, "add_ia") == 0){
            rdlimbs(P, &p, 12); rdlimbs(Q, &p, 12); memcpy(R, P, 96);
            point_add(R, R, Q);
        } else if (strcmp(op, "mixed") == 0){
            rdlimbs(P, &p, 12); rdlimbs(XY, &p, 8);
            point_add_mixed(R, P, XY);
        } else if (strcmp(op, "mixed_ia") == 0){
            rdlimbs(P, &p, 12); rdlimbs(XY, &p, 8); memcpy(R, P, 96);
            point_add_mixed(R, R, XY);
        } else if (strcmp(op, "mixed_zr") == 0){
            rdlimbs(P, &p, 12); rdlimbs(XY, &p, 8);
            point_add_mixed_zr(R, P, XY, ZR);
        } else if (strcmp(op, "scalar") == 0){
            rdlimbs(XY, &p, 8); rdlimbs(K, &p, 4);
            point_scalar_mul(R, XY, K);
        } else {
            fprintf(stderr, "bad op: %s\n", op); continue;
        }
        /* z ratio output handled below */
        (void)ia;
        /* convert Jacobian R -> affine */
        printf("%s", op);
        printf(" ");
        int zzero = 1;
        for (int j = 0; j < 4 && zzero; j++) if (R[8 + j]) zzero = 0;
        if (zzero){
            printf("inf");
        } else {
            u64 zi[4], zi2[4], zi3[4], ax[4], ay[4];
            fe_inv(zi, &R[8]);
            fe_sqr(zi2, zi);
            fe_mul(zi3, zi2, zi);
            fe_mul(ax, &R[0], zi2);
            fe_mul(ay, &R[4], zi3);
            printf("%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx",
                   ax[0], ax[1], ax[2], ax[3], ay[0], ay[1], ay[2], ay[3]);
        }
        if (strcmp(op, "mixed_zr") == 0 && !zzero){
            printf(" zr %016llx %016llx %016llx %016llx", ZR[0], ZR[1], ZR[2], ZR[3]);
        } else if (strcmp(op, "mixed_zr") == 0 && zzero){
            printf(" zr %016llx %016llx %016llx %016llx", ZR[0], ZR[1], ZR[2], ZR[3]);
        }
        printf("\n");
    }
    return 0;
}
