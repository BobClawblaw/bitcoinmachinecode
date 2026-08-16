/*
 * cuda_ecdsa_math.h -- secp256k1 ECDSA verification math (pure C + CUDA).
 * Mirrors the project's trusted asm ecdsa_verify semantics.  See
 * cuda_ecdsa_verify.cu for the GPU batch and end-to-end validation.
 *
 * Modular multiply uses a CORRECT (not constant-time) bounded-fold reduction
 * implemented on an oversized limb scratch, guaranteeing a canonical [0,M)
 * result for any inputs -- deliberately simple and verifiable rather than tuned
 * (this is an offline audit tool, not hot-path node code).  Point ops use the
 * standard secp256k1 Jacobian formulas (curve a=0).
 */
#ifndef BMC_ECDSA_H
#define BMC_ECDSA_H
#include <stdint.h>
#include <string.h>
typedef uint64_t u64;
typedef unsigned __int128 u128;
#ifndef __CUDACC__
#define DEVHOST static inline
#else
#define DEVHOST __device__ __host__ __forceinline__ static
#endif
DEVHOST void set4(u64 o[4],u64 a,u64 b,u64 c,u64 d){ o[0]=a;o[1]=b;o[2]=c;o[3]=d; }

/* big-int compare / subtract on n-limb arrays */
DEVHOST int bgeq(const u64*a,const u64*b,int n){ for(int i=n-1;i>=0;i--){ if(a[i]<b[i])return 0; if(a[i]>b[i])return 1; } return 1; }
DEVHOST void bsub(u64*a,const u64*b,int n){ u64 br=0; for(int i=0;i<n;i++){ u64 t=a[i]-br; u64 u1=(a[i]<br)?1:0; u64 u2=(t<b[i])?1:0; a[i]=(u64)(t-b[i]); br=u1|u2; } }

/* mmul_reduce: canonical [0,M) product of a*b.
 * Reduction = binary long division (compare/conditional-subtract M<<k), which
 * is unconditionally correct for ANY product < 2^512 and any M in (2^255,2^256)
 * -- deliberately simple and correct (offline audit tool, not hot-path). */
DEVHOST void mmul(u64 out[4], const u64 a[4], const u64 b[4], const u64 D[4], const u64 M[4]){
    (void)D;
    u64 cur[9]={0};                 /* 9-limb (576-bit) product, no dropped carries */
    /* row-based schoolbook multiply: correct, no interleaving hazards */
    for(int i=0;i<4;i++){
        u64 carry=0;
        for(int j=0;j<4;j++){
            u128 p=(u128)a[i]*b[j] + cur[i+j] + carry;
            cur[i+j]=(u64)p; carry=(u64)(p>>64);
        }
        int k=i+4;
        while(carry&&k<9){ u128 s=(u128)cur[k]+carry; cur[k]=(u64)s; carry=(u64)(s>>64); k++; }
    }
    /* reduce: for k = 256..0, if cur >= M<<k subtract M<<k.  cur < 2^512 and
       a,b < M < 2^256 so cur/M < 2^257, hence k must range 0..256 (an M<<256
       term may be required).  All compare/subtract/shift on 9 limbs. */
    for(int k=256;k>=0;k--){
        u64 sh[9]={0};
        /* build sh = M << k (9-limb) via per-limb lo/hi placement with carries */
        int li=k>>6, bi=k&63;
        for(int i=0;i<4;i++) if(M[i]){
            u64 v=M[i];
            int base=i+li;
            if(bi==0){
                u64 s=sh[base]+v; u64 c=(s<sh[base])?1:0; sh[base]=s;
                int j=base+1; while(c&&j<9){ u64 s2=sh[j]+c; c=(s2<sh[j])?1:0; sh[j]=s2; j++; }
            } else {
                u64 lo=v<<bi, h=v>>(64-bi);
                { u64 s=sh[base]+lo; u64 c=(s<sh[base])?1:0; sh[base]=s;
                  int j=base+1; while(c&&j<9){ u64 s2=sh[j]+c; c=(s2<sh[j])?1:0; sh[j]=s2; j++; } }
                if(h){ u64 s=sh[base+1]+h; u64 c=(s<sh[base+1])?1:0; sh[base+1]=s;
                  int j=base+2; while(c&&j<9){ u64 s2=sh[j]+c; c=(s2<sh[j])?1:0; sh[j]=s2; j++; } }
            }
        }
        if(bgeq(cur,sh,9)) bsub(cur,sh,9);
    }
    for(int i=0;i<4;i++) out[i]=cur[i];
}
DEVHOST void mulmod_p(u64 o[4],const u64 a[4],const u64 b[4]){
    u64 D[4]={977,0,0,0}; u64 M[4]; set4(M,0xFFFFFFFEFFFFFC2FULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL);
    mmul(o,a,b,D,M);
}
DEVHOST void mulmod_n(u64 o[4],const u64 a[4],const u64 b[4]){
    u64 D[4]={0x402DA1732FC9BEBFULL,0x4551231950B75FC4ULL,1,0}; u64 M[4];
    set4(M,0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL);
    mmul(o,a,b,D,M);
}
DEVHOST void psqr(u64 o[4],const u64 a[4]){ mulmod_p(o,a,a); }
DEVHOST void padd(u64 o[4],const u64 a[4],const u64 b[4]){
    u64 P[4],s[4],r[4]; set4(P,0xFFFFFFFEFFFFFC2FULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL);
    u64 c=0; for(int i=0;i<4;i++){ u128 t=(u128)a[i]+b[i]+c; s[i]=(u64)t; c=(u64)(t>>64); }
    u64 borrow=0; for(int i=0;i<4;i++){ u64 t=s[i]-borrow; u64 u1=(s[i]<borrow)?1:0; u64 u2=(t<P[i])?1:0; r[i]=(u64)(t-P[i]); borrow=u1|u2; }
    u64 ge = c | (borrow^1); for(int i=0;i<4;i++) o[i]= ge?r[i]:s[i];
}
DEVHOST void psub(u64 o[4],const u64 a[4],const u64 b[4]){
    u64 P[4],r[4]; set4(P,0xFFFFFFFEFFFFFC2FULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL);
    u64 borrow=0; for(int i=0;i<4;i++){ u64 t=a[i]-borrow; u64 u1=(a[i]<borrow)?1:0; u64 u2=(t<b[i])?1:0; r[i]=(u64)(t-b[i]); borrow=u1|u2; }
    if(borrow){ u64 c=0; for(int i=0;i<4;i++){ u128 t=(u128)r[i]+P[i]+c; r[i]=(u64)t; c=(u64)(t>>64); } }
    for(int i=0;i<4;i++) o[i]=r[i];
}

typedef struct { u64 X[4], Y[4], Z[4]; } jpoint;

DEVHOST int is_inf(const jpoint*p){ return p->Z[0]==0&&p->Z[1]==0&&p->Z[2]==0&&p->Z[3]==0; }
DEVHOST void jdouble(jpoint*O,const jpoint*P){
    u64 A[4],B[4],C[4],D[4],E[4],F[4],T[4],Y3[4],tt[4],Z3[4],X3[4],C8[4];
    psqr(A,P->X); psqr(B,P->Y); psqr(C,B);
    padd(tt,P->X,B); psqr(D,tt); psub(D,D,A); psub(D,D,C); padd(D,D,D);
    padd(E,A,A); padd(E,E,A); psqr(F,E);
    padd(T,D,D); psub(X3,F,T);
    psub(tt,D,X3); mulmod_p(tt,E,tt);               /* tt = E*(D-X3) */
    padd(C8,C,C); padd(C8,C8,C8); padd(C8,C8,C8); psub(Y3,tt,C8);  /* C8=8C */
    mulmod_p(tt,P->Y,P->Z); padd(Z3,tt,tt);
    for(int i=0;i<4;i++){ O->X[i]=X3[i]; O->Y[i]=Y3[i]; O->Z[i]=Z3[i]; }
}
DEVHOST void jadd_mixed(jpoint*O,const jpoint*P,const u64 Qx[4],const u64 Qy[4]){
    /* if P is the point at infinity, O = (Qx,Qy) */
    if(is_inf(P)){ for(int i=0;i<4;i++){ O->X[i]=Qx[i]; O->Y[i]=Qy[i]; O->Z[i]=(i==0)?1:0; } return; }
    u64 Z1Z1[4],U2[4],S2[4],H[4],HH[4],I[4],J[4],rr[4],V[4],X3[4],Y3[4],Z3[4],t2[4],tt[4],SmY[4];
    psqr(Z1Z1,P->Z);
    mulmod_p(U2,Qx,Z1Z1);
    mulmod_p(t2,P->Z,Z1Z1); mulmod_p(S2,Qy,t2);
    psub(H,U2,P->X);
    psub(SmY,S2,P->Y); padd(rr,SmY,SmY);     /* rr = 2*(S2-Y1) */
    /* self-add / negation guards */
    u64 hzero = H[0]==0&&H[1]==0&&H[2]==0&&H[3]==0;
    u64 rzero = ((S2[0]==P->Y[0])&&(S2[1]==P->Y[1])&&(S2[2]==P->Y[2])&&(S2[3]==P->Y[3]));
    if(hzero){ /* P == Q or P == -Q */
        if(rzero){ jdouble(O,P); return; }   /* same -> double */
        for(int i=0;i<4;i++){ O->X[i]=0; O->Y[i]=1; O->Z[i]=0; } /* -Q => infinity */
        return;
    }
    psqr(HH,H);
    padd(I,HH,HH); padd(I,I,I);
    mulmod_p(J,H,I);
    mulmod_p(V,P->X,I);
    psqr(tt,rr); psub(X3,tt,J); padd(tt,V,V); psub(X3,X3,tt);
    psub(tt,V,X3); mulmod_p(tt,rr,tt); mulmod_p(J,P->Y,J); padd(J,J,J); psub(Y3,tt,J);
    padd(tt,P->Z,H); psqr(tt,tt); psub(Z3,tt,Z1Z1); psub(Z3,Z3,HH);
    for(int i=0;i<4;i++){ O->X[i]=X3[i]; O->Y[i]=Y3[i]; O->Z[i]=Z3[i]; }
}
DEVHOST void scalar_mul(jpoint*O,const u64 k[4],const u64 Qx[4],const u64 Qy[4]){
    jpoint R; set4(R.X,0,0,0,0); set4(R.Y,0,0,0,0); set4(R.Z,0,0,0,0);
    for (int bit=255; bit>=0; bit--){
        int wi=bit>>6, bi=bit&63; int b=(int)((k[wi]>>bi)&1);
        jdouble(&R,&R);
        if (b){
            jpoint T;
            if (is_inf(&R)){ for(int i=0;i<4;i++){ T.X[i]=Qx[i]; T.Y[i]=Qy[i]; T.Z[i]=(i==0)?1:0; } }
            else jadd_mixed(&T,&R,Qx,Qy);
            for(int i=0;i<4;i++){ R.X[i]=T.X[i]; R.Y[i]=T.Y[i]; R.Z[i]=T.Z[i]; }
        }
    }
    for(int i=0;i<4;i++){ O->X[i]=R.X[i]; O->Y[i]=R.Y[i]; O->Z[i]=R.Z[i]; }
}
#endif
