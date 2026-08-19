/* diff_add_ct_homog.c -- differential check of secp256k1_point_ct.asm's
 * pointh_add / pointh_double / point_scalar_mul_ct (homogeneous X:Y:Z,
 * complete Renes-Costello-Batina formulas) against the existing
 * variable-time Jacobian oracle (point_add / point_double), comparing in
 * affine space over random pairs incl. equal, opposite, and infinity
 * operands -- including a NON-canonical zero-Z infinity representative,
 * to catch a Z-scaling-dependent bug the canonical (0,1,0) case alone
 * would miss. This exercises pointh_add directly with an explicit
 * single-infinity operand; test_scalarmul_ct.c only observes infinity as
 * an emergent result of a full scalar multiplication (e.g. nG), not as an
 * input to the addition primitive itself.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef uint64_t u64;
extern void fe_add(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sub(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_mul(u64 r[4], const u64 a[4], const u64 b[4]);
extern void fe_sqr(u64 r[4], const u64 a[4]);
extern void fe_inv(u64 r[4], const u64 a[4]);
extern void point_double(u64 r[12], const u64 p[12]);      /* Jacobian, existing oracle */
extern void point_add(u64 r[12], const u64 p[12], const u64 q[12]); /* Jacobian oracle */
extern void point_scalar_mul(u64 r[12], const u64 xy[8], const u64 k[4]); /* Jacobian */
extern void pointh_add(u64 r[12], const u64 p[12], const u64 q[12]);      /* homogeneous, under test */
extern void pointh_double(u64 r[12], const u64 p[12]);                    /* homogeneous, under test */
extern void point_scalar_mul_ct(u64 r[12], const u64 xy[8], const u64 k[4]); /* -> Jacobian */

static u64 rng_state = 0xD1B54A32D192ED03ULL;
static u64 rnd(void){ u64 x = rng_state; x ^= x<<13; x ^= x>>7; x ^= x<<17; return (rng_state = x); }
static void rndfe(u64 a[4]){ for(int i=0;i<4;i++) a[i]=rnd(); }

static const u64 Gaff[8]={
    0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL,
    0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};

/* random affine on-curve point via the trusted Jacobian variable-time ladder */
static void rndaffine(u64 ax[4], u64 ay[4]){
    u64 k[4] = { rnd(), rnd(), rnd(), rnd() };
    u64 j[12];
    point_scalar_mul(j, Gaff, k);
    u64 zi[4], z2[4], z3[4];
    fe_inv(zi,&j[8]); fe_sqr(z2,zi); fe_mul(z3,z2,zi);
    fe_mul(ax,&j[0],z2); fe_mul(ay,&j[4],z3);
}
/* random homogeneous representative (ax*Z, ay*Z, Z) of a given affine point */
static void rndhomog(u64 p[12], const u64 ax[4], const u64 ay[4]){
    u64 Z[4]; do { rndfe(Z); } while(!(Z[0]|Z[1]|Z[2]|Z[3]));
    fe_mul(&p[0], ax, Z);
    fe_mul(&p[4], ay, Z);
    memcpy(&p[8], Z, 32);
}
static int hinf(const u64 j[12]){ return !(j[8]|j[9]|j[10]|j[11]); }
static void htoaff(u64 ox[4], u64 oy[4], const u64 j[12]){
    u64 zi[4];
    fe_inv(zi, &j[8]);
    fe_mul(ox, &j[0], zi);
    fe_mul(oy, &j[4], zi);
}
static int same_affine(const u64 ax[4], const u64 ay[4], const u64 bx[4], const u64 by[4]){
    return !memcmp(ax,bx,32) && !memcmp(ay,by,32);
}

int main(int argc, char**argv){
    int N = argc>1?atoi(argv[1]):5000;
    int fail=0;
    u64 zero[4]={0,0,0,0};
    for (int i=0;i<N;i++){
        u64 ax[4],ay[4],bx[4],by[4];
        rndaffine(ax,ay);
        int mode = i % 8;
        if (mode==6){ memcpy(bx,ax,32); memcpy(by,ay,32); }        /* q==p -> double */
        else if (mode==7){ memcpy(bx,ax,32); fe_sub(by,zero,ay); } /* q==-p -> opposite */
        else rndaffine(bx,by);

        u64 P[12], Q[12], R[12];
        rndhomog(P, ax, ay);
        rndhomog(Q, bx, by);
        pointh_add(R, P, Q);

        /* expected, from the trusted Jacobian oracle: point_add mishandles a
         * single-infinity operand (that's the exact FINDING-1 bug), but
         * neither operand here is ever infinity, so it's safe as an oracle
         * for the generic/self-add/opposite cases. */
        u64 rax[4], ray[4];
        if (mode==7){
            /* opposite points: expected result is the identity */
            if (!hinf(R)){ if (fail<5) printf("MISMATCH opposite-sum i=%d not inf\n", i); fail++; }
            continue;
        } else if (mode==6){
            u64 Ja[12]; memcpy(&Ja[0],ax,32); memcpy(&Ja[4],ay,32);
            Ja[8]=1; Ja[9]=Ja[10]=Ja[11]=0;
            u64 Jd[12]; point_double(Jd, Ja);
            u64 zi[4],z2[4],z3[4];
            fe_inv(zi,&Jd[8]); fe_sqr(z2,zi); fe_mul(z3,z2,zi);
            fe_mul(rax,&Jd[0],z2); fe_mul(ray,&Jd[4],z3);
        } else {
            u64 Ja[12], Jb[12];
            memcpy(&Ja[0],ax,32); memcpy(&Ja[4],ay,32); Ja[8]=1; Ja[9]=Ja[10]=Ja[11]=0;
            memcpy(&Jb[0],bx,32); memcpy(&Jb[4],by,32); Jb[8]=1; Jb[9]=Jb[10]=Jb[11]=0;
            u64 Jr[12]; point_add(Jr, Ja, Jb);
            u64 zi[4],z2[4],z3[4];
            fe_inv(zi,&Jr[8]); fe_sqr(z2,zi); fe_mul(z3,z2,zi);
            fe_mul(rax,&Jr[0],z2); fe_mul(ray,&Jr[4],z3);
        }
        if (hinf(R)){ if (fail<5) printf("MISMATCH i=%d mode=%d: pointh_add gave inf, expected finite\n", i, mode); fail++; continue; }
        u64 sx[4], sy[4]; htoaff(sx, sy, R);
        if (!same_affine(sx,sy,rax,ray)){ if (fail<5) printf("MISMATCH pointh_add i=%d mode=%d\n", i, mode); fail++; }

        /* pointh_add(P,P) must equal pointh_double(P) in affine terms */
        u64 Rd[12]; pointh_double(Rd, P);
        u64 Rs[12]; pointh_add(Rs, P, P);
        int di = hinf(Rd), si = hinf(Rs);
        if (di != si){ if (fail<5) printf("MISMATCH self-add-vs-double inf-mismatch i=%d\n", i); fail++; }
        else if (!di){
            u64 dx[4],dy[4],sxx[4],syy[4];
            htoaff(dx,dy,Rd); htoaff(sxx,syy,Rs);
            if (!same_affine(dx,dy,sxx,syy)){ if (fail<5) printf("MISMATCH self-add-vs-double i=%d\n", i); fail++; }
        }
    }

    /* explicit infinity-operand cases -- this is the EXACT bug FINDING 1
     * fixes: the old point_add returns garbage for a single-infinity
     * operand. Assert pointh_add's canonical identity (0:1:0) behaves
     * correctly, AND a NON-canonical zero-Z representative (Z-scaling
     * invariance at infinity too). */
    u64 canon_inf[12]; memset(canon_inf,0,96); canon_inf[4]=1; /* (0,1,0) */
    /* The ONLY valid points at infinity on Y^2 Z = X^3 + bZ^3 (Z=0) are
     * (0:t:0) for nonzero t -- (5,7,0) is NOT on the curve at all (0 != 125),
     * so a non-canonical-but-VALID representative must keep X=0 and vary Y. */
    u64 noncanon_inf[12]; memset(noncanon_inf,0,96);
    noncanon_inf[4]=5; /* (0,5,0) -- still Z=0, projectively == (0:1:0) */
    u64 ax[4],ay[4]; rndaffine(ax,ay);
    u64 P2[12]; rndhomog(P2, ax, ay);

    u64 R[12];
    pointh_add(R, canon_inf, P2);
    { u64 rx[4],ry[4]; if (hinf(R)){printf("FAIL ct(inf+P) gave inf\n");fail++;} else {htoaff(rx,ry,R); if(!same_affine(rx,ry,ax,ay)){printf("FAIL ct(inf+P) != P\n");fail++;}} }
    pointh_add(R, P2, canon_inf);
    { u64 rx[4],ry[4]; if (hinf(R)){printf("FAIL ct(P+inf) gave inf\n");fail++;} else {htoaff(rx,ry,R); if(!same_affine(rx,ry,ax,ay)){printf("FAIL ct(P+inf) != P\n");fail++;}} }
    pointh_add(R, canon_inf, canon_inf);
    if (!hinf(R)){ printf("FAIL ct(inf+inf) != inf\n"); fail++; }
    pointh_add(R, noncanon_inf, P2);
    { u64 rx[4],ry[4]; if (hinf(R)){printf("FAIL ct(noncanon_inf+P) gave inf\n");fail++;} else {htoaff(rx,ry,R); if(!same_affine(rx,ry,ax,ay)){printf("FAIL ct(noncanon_inf+P) != P (Z-scaling variance at infinity!)\n");fail++;}} }

    /* cross-check point_scalar_mul_ct's Jacobian output against the
     * variable-time oracle over random scalars (belt-and-suspenders on top
     * of the existing test_scalarmul_ct.c, using THIS test's own RNG/oracle
     * chain independently). */
    for (int i=0;i<200 && fail<50;i++){
        u64 k[4]={rnd(),rnd(),rnd(),rnd()};
        u64 j1[12], j2[12];
        point_scalar_mul(j1, Gaff, k);
        point_scalar_mul_ct(j2, Gaff, k);
        u64 zi[4],z2[4],z3[4],x1[4],y1[4],x2[4],y2[4];
        fe_inv(zi,&j1[8]); fe_sqr(z2,zi); fe_mul(z3,z2,zi); fe_mul(x1,&j1[0],z2); fe_mul(y1,&j1[4],z3);
        fe_inv(zi,&j2[8]); fe_sqr(z2,zi); fe_mul(z3,z2,zi); fe_mul(x2,&j2[0],z2); fe_mul(y2,&j2[4],z3);
        if (!same_affine(x1,y1,x2,y2)){ if(fail<5) printf("MISMATCH scalar_mul_ct vs scalar_mul i=%d\n", i); fail++; }
    }

    printf("diff_add_ct_homog: %d random pairs + infinity/scalar-mul checks, %d mismatches\n", N, fail);
    return fail?1:0;
}
