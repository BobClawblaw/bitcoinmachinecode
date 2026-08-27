/* t_pct.c -- differential-fuzz driver for the constant-time point layer.
 * Reads vectors from stdin, one per line:
 *   ctscalar XY8 K4 -> point_scalar_mul_ct(K*affineXY)  Jacobian, printed affine
 *   vtscalar XY8 K4 -> point_scalar_mul (variable-time, reference) affine
 *   hadd     P12 Q12 -> pointh_add (homogeneous)  -> affine (x y)
 *   hdouble  P12    -> pointh_double (homogeneous)-> affine (x y)
 * Each limb is 16 hex digits. Skip blank lines / # comments.
 * Jacobian -> affine via the (already-verified) fe_inv/fe_mul/fe_sqr.
 * Prints `inf` when the affine Z is zero, else `x y` (4+4 limbs).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
extern void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]);
extern void pointh_add(u64 r[12], const u64 p[12], const u64 q[12]);
extern void pointh_double(u64 r[12], const u64 p[12]);
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

static void print_affine(const u64 R[12]){
    int zzero = 1;
    for (int j = 0; j < 4 && zzero; j++) if (R[8 + j]) zzero = 0;
    if (zzero){ printf("inf"); return; }
    u64 zi[4], zi2[4], zi3[4], ax[4], ay[4];
    fe_inv(zi, &R[8]);
    fe_sqr(zi2, zi);
    fe_mul(zi3, zi2, zi);
    fe_mul(ax, &R[0], zi2);
    fe_mul(ay, &R[4], zi3);
    printf("%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx",
           ax[0], ax[1], ax[2], ax[3], ay[0], ay[1], ay[2], ay[3]);
}

/* pointh_add/pointh_double output HOMOGENEOUS (X:Y:Z): affine = (X/Z, Y/Z). */
static void print_affine_hom(const u64 R[12]){
    int zzero = 1;
    for (int j = 0; j < 4 && zzero; j++) if (R[8 + j]) zzero = 0;
    if (zzero){ printf("inf"); return; }
    u64 zi[4], ax[4], ay[4];
    fe_inv(zi, &R[8]);
    fe_mul(ax, &R[0], zi);
    fe_mul(ay, &R[4], zi);
    printf("%016llx %016llx %016llx %016llx %016llx %016llx %016llx %016llx",
           ax[0], ax[1], ax[2], ax[3], ay[0], ay[1], ay[2], ay[3]);
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
        u64 XY[8], K[4], P[12], Q[12], R[12];
        if (strcmp(op, "ctscalar") == 0){
            rdlimbs(XY, &p, 8); rdlimbs(K, &p, 4);
            point_scalar_mul_ct(R, XY, K);
        } else if (strcmp(op, "vtscalar") == 0){
            rdlimbs(XY, &p, 8); rdlimbs(K, &p, 4);
            point_scalar_mul(R, XY, K);
        } else if (strcmp(op, "hadd") == 0){
            rdlimbs(P, &p, 12); rdlimbs(Q, &p, 12);
            pointh_add(R, P, Q);
            printf("hadd "); print_affine_hom(R); printf("\n");
            continue;
        } else if (strcmp(op, "hdouble") == 0){
            rdlimbs(P, &p, 12);
            pointh_double(R, P);
            printf("hdouble "); print_affine_hom(R); printf("\n");
            continue;
        } else {
            fprintf(stderr, "bad op: %s\n", op); return 2;
        }
        printf("%s ", op); printf("%s", "");
        print_affine(R);
        printf("\n");
    }
    return 0;
}
