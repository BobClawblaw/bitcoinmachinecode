#include <stdio.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t u8;
#include "cuda_ecdsa_math.h"
#define SET(A,c0,c1,c2,c3) do{A[0]=(u64)(c0);A[1]=(u64)(c1);A[2]=(u64)(c2);A[3]=(u64)(c3);}while(0)
static void p_exp(u64 o[4], const u64 base[4], const unsigned char *exp, int n){
    u64 R[4]={1,0,0,0};
    for(int i=n*8-1;i>=0;i--){ mulmod_p(R,R,R); if((exp[i>>3]>>(i&7))&1) mulmod_p(R,R,base); }
    memcpy(o,R,32);
}
static void p_inv(u64 o[4], const u64 a[4]){
    u64 p[4]; SET(p,0xFFFFFFFEFFFFFC2FULL,(u64)-1,(u64)-1,(u64)-1);
    u64 pm2[4]; pm2[0]=p[0]-2;pm2[1]=p[1];pm2[2]=p[2];pm2[3]=p[3];
    unsigned char ex[32]; for(int i=0;i<4;i++)for(int k=0;k<8;k++)ex[i*8+k]=(u8)((pm2[i]>>(k*8))&0xff);
    p_exp(o,a,ex,32);
}
static void n_exp(u64 o[4], const u64 base[4], const unsigned char *exp, int n){
    u64 R[4]={1,0,0,0};
    for(int i=n*8-1;i>=0;i--){ mulmod_n(R,R,R); if((exp[i>>3]>>(i&7))&1) mulmod_n(R,R,base); }
    memcpy(o,R,32);
}
static void n_inv(u64 o[4], const u64 a[4]){
    u64 n[4]; n[0]=0xBFD25E8CD0364141ULL;n[1]=0xBAAEDCE6AF48A03BULL;n[2]=0xFFFFFFFFFFFFFFFEULL;n[3]=0xFFFFFFFFFFFFFFFFULL;
    u64 nm2[4]; nm2[0]=n[0]-2; nm2[1]=n[1]; nm2[2]=n[2]; nm2[3]=n[3];
    unsigned char ex[32]; for(int i=0;i<4;i++)for(int k=0;k<8;k++)ex[i*8+k]=(u8)((nm2[i]>>(k*8))&0xff);
    n_exp(o,a,ex,32);
}
static int is_zero4(const u64 a[4]){ return a[0]==0&&a[1]==0&&a[2]==0&&a[3]==0; }
static int is_less_n(const u64 a[4]){
    u64 n[4]; n[0]=0xBFD25E8CD0364141ULL;n[1]=0xBAAEDCE6AF48A03BULL;n[2]=0xFFFFFFFFFFFFFFFEULL;n[3]=0xFFFFFFFFFFFFFFFFULL;
    for(int i=3;i>=0;i--){ if(a[i]<n[i]) return 1; if(a[i]>n[i]) return 0; }
    return 0; /* equal n -> not < n */
}
static void to_affine(u64 ax[4],u64 ay[4],const jpoint*P){
    if(is_inf(P)){ SET(ax,0,0,0,0); SET(ay,0,0,0,0); return; }
    u64 Zi[4],Z2[4],Z3[4]; p_inv(Zi,P->Z); mulmod_p(Z2,Zi,Zi); mulmod_p(Z3,Z2,Zi);
    mulmod_p(ax,P->X,Z2); mulmod_p(ay,P->Y,Z3);
}
/* ecdsa_verify mirroring the asm oracle semantics.
   Inputs in LE limbs. Returns 1 if valid, 0 otherwise. */
static int ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
                        const u64 Qx[4], const u64 Qy[4]){
    u64 n[4]; n[0]=0xBFD25E8CD0364141ULL;n[1]=0xBAAEDCE6AF48A03BULL;n[2]=0xFFFFFFFFFFFFFFFEULL;n[3]=0xFFFFFFFFFFFFFFFFULL;
    if(!is_less_n(r) || is_zero4(r)) return 0;
    if(!is_less_n(s) || is_zero4(s)) return 0;
    u64 Gx[4],Gy[4];
    SET(Gx,0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL);
    SET(Gy,0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL);
    u64 sinv[4],u1[4],u2[4];
    n_inv(sinv,s);
    mulmod_n(u1,z,sinv);
    mulmod_n(u2,r,sinv);
    jpoint R1,R2; scalar_mul(&R1,u1,Gx,Gy); scalar_mul(&R2,u2,Qx,Qy);
    u64 r2x[4],r2y[4]; to_affine(r2x,r2y,&R2);
    jpoint R; jadd_mixed(&R,&R1,r2x,r2y);
    if(is_inf(&R)) return 0;
    u64 Rx[4],Ry[4]; to_affine(Rx,Ry,&R);
    /* reduce Rx modulo n */
    u64 t[4]; memcpy(t,Rx,32);
    for(int k=0;k<3;k++){ if( (t[3]>n[3]) || (t[3]==n[3]&&t[2]>n[2]) || (t[3]==n[3]&&t[2]==n[2]&&t[1]>n[1]) || (t[3]==n[3]&&t[2]==n[2]&&t[1]==n[1]&&t[0]>=n[0]) ){ /* t>=n */
        u64 br=0; for(int i=0;i<4;i++){ u64 q=t[i]-br; u64 u1b=(t[i]<br)?1:0; u64 u2b=(q<n[i])?1:0; t[i]=(u64)(q-n[i]); br=u1b|u2b; }
    } }
    for(int i=0;i<4;i++) if(t[i]!=r[i]) return 0;
    return 1;
}
int main(void){
    u64 z[4]={0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL};
    u64 r[4]={0x2af4a71489e9f1dbULL,0xc0cb2fd43c3b6e75ULL,0x5fbff28aa15cced7ULL,0x592cb214ca60184fULL};
    u64 s[4]={0xc4a2c025aa14e92aULL,0x010761c8cf1d4450ULL,0x812cf05ef8411d64ULL,0x23d627acd53ebcd7ULL};
    u64 Qx[4]={0xfd723873aa170695ULL,0xe7bcc89470d63e1aULL,0x8947c271ac274529ULL,0x9651c463c001f731ULL};
    u64 Qy[4]={0x21837fb0e654eaf7ULL,0x3b16ba7a5a9b154dULL,0x73d6d17fe8b63c99ULL,0x4e362e7fe8ff06daULL};
    int fails=0;
    #define CK(lbl,g,e) do{ printf("%s: got=%d exp=%d %s\n",lbl,g,e,g==e?"OK":"FAIL"); if(g!=e)fails++; }while(0)
    CK("valid", ecdsa_verify(z,r,s,Qx,Qy), 1);
    u64 r2[4]={r[0]^1,r[1],r[2],r[3]};
    CK("tampered r", ecdsa_verify(z,r2,s,Qx,Qy), 0);
    u64 z2[4]={z[0]^1,z[1],z[2],z[3]};
    CK("tampered z", ecdsa_verify(z2,r,s,Qx,Qy), 0);
    u64 Qx2[4]={Qx[0]^1,Qx[1],Qx[2],Qx[3]};
    CK("wrong pub", ecdsa_verify(z,r,s,Qx2,Qy), 0);
    u64 zero[4]={0,0,0,0};
    CK("r=0", ecdsa_verify(z,zero,s,Qx,Qy), 0);
    CK("s=0", ecdsa_verify(z,r,zero,Qx,Qy), 0);
    u64 n_1[4]={0xbfd25e8cd0364140ULL,0xbaaedce6af48a03bULL,0xfffffffffffffffeULL,0xffffffffffffffffULL};
    CK("r=n-1", ecdsa_verify(z,n_1,s,Qx,Qy), 0);
    u64 zB[4]={0x0000000000000123ULL,0,0,0};
    u64 rB[4]={0xa3153339064fe63eULL,0xa65c4156d690fb12ULL,0xd91eea399c0858aeULL,0x3527053278c9f1ffULL};
    u64 sB[4]={0xb58e7e068ce2863aULL,0x8a9e493d602e86c7ULL,0x9a4c396fc74cbeb6ULL,0x5f4061d3e796efdbULL};
    CK("2nd valid", ecdsa_verify(zB,rB,sB,Qx,Qy), 1);
    printf("fails=%d\n",fails);
    return fails?1:0;
}
