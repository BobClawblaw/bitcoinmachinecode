/*
 * cuda_schnorr_verify.cu -- PLAN.md option D, Schnorr half: BIP340 batch verify.
 *
 * Complements cuda_ecdsa_verify.cu (the ECDSA half).  Reuses the validated
 * secp256k1 field/scalar/point math from cuda_ecdsa_math.h (no asm) and adds
 * the BIP340-specific pieces: mod-p sqrt (lift_x with even-y), a per-thread
 * SHA-256 for the tagged hash, and the full Verify(pk,m,sig) routine.
 *
 * Per-thread BIP340 Verify:
 *   P  = lift_x_even(pk)            (fail if no even-y curve point)
 *   r  = int(sig[0:32]);  fail if r >= p
 *   s  = int(sig[32:64]); fail if s >= n
 *   e  = tagged_hash("BIP0340/challenge", r||pk||m) mod n
 *   R  = s*G - e*P
 *   fail if R is infinity
 *   fail if y(R) odd  OR  x(R) != r
 *
 * GATE: must reproduce the official BIP340 test-vector result column exactly:
 * 9 TRUE (rows 0-4, 15-18 with msg lengths 32/0/1/17/100) + 10 FALSE (5-14).
 * Encoded here as a fixed structured batch (the tagged hash makes embedding
 * raw CSV impractical); every result is cross-checked against the host oracle
 * and against the authoritative TRUE/FALSE column.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
typedef uint8_t u8;
typedef uint32_t u32;
#include "cuda_ecdsa_math.h"

#if defined(__CUDACC__)
#define SHA_FN static __device__ __host__ inline
#else
#define SHA_FN static inline
#endif
SHA_FN u32 srotr32(u32 x,unsigned n){ return (x>>n)|(x<<(32u-n)); }
SHA_FN void scompress(u32 H[8],const u8 inb[64]){
    /* function-LOCAL static const: readable from BOTH host and device
       (a __constant__ global is unreadable from host; a file-scope static
       const is invisible to device code -- both corrupt/refuse the hash). */
    static const u32 K[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u };
    u32 W[64];
    for(int i=0;i<16;i++) W[i]=((u32)inb[4*i]<<24)|((u32)inb[4*i+1]<<16)|((u32)inb[4*i+2]<<8)|((u32)inb[4*i+3]);
    for(int i=16;i<64;i++){ u32 x=W[i-15],y=W[i-2];
        u32 s0=srotr32(x,7)^srotr32(x,18)^(x>>3), s1=srotr32(y,17)^srotr32(y,19)^(y>>10);
        W[i]=W[i-16]+s0+W[i-7]+s1; }
    u32 a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(int i=0;i<64;i++){
        u32 S1=srotr32(e,6)^srotr32(e,11)^srotr32(e,25), ch=(e&f)^(~e&g);
        u32 t1=h+S1+ch+K[i]+W[i];
        u32 S0=srotr32(a,2)^srotr32(a,13)^srotr32(a,22), maj=(a&b)^(a&c)^(b&c);
        u32 t2=S0+maj; h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2; }
    H[0]+=a;H[1]+=b;H[2]+=c;H[3]+=d;H[4]+=e;H[5]+=f;H[6]+=g;H[7]+=h;
}
/* sha256 over a contiguous in-buffer message of length len */
SHA_FN void sha256_msg(u8 out[32],const u8*msg,u64 len){
    u32 H[8]={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    u64 blks=len>>6, rem=len&63;
    for(u64 blk=0;blk<blks;blk++) scompress(H,msg+blk*64);
    u8 block[64]; u64 i;
    for(i=0;i<rem;i++) block[i]=msg[blks*64+i];
    block[rem]=0x80; rem+=1;
    if(rem>56){
        for(;rem<64;rem++) block[rem]=0;
        scompress(H,block);
        for(i=0;i<56;i++) block[i]=0;
    } else {
        for(;rem<56;rem++) block[rem]=0;
    }
    u64 bits=len<<3;
    for(int j=0;j<8;j++) block[56+j]=(u8)(bits>>(56-8*j));
    scompress(H,block);
    for(int j=0;j<8;j++){ out[4*j+0]=(u8)(H[j]>>24); out[4*j+1]=(u8)(H[j]>>16); out[4*j+2]=(u8)(H[j]>>8); out[4*j+3]=(u8)H[j]; }
}

/* ---- big-int helpers (LE limbs) ---- */
SHA_FN int sgeq(const u64*a,const u64*b){ for(int i=3;i>=0;i--){ if(a[i]<b[i])return 0; if(a[i]>b[i])return 1;} return 1; }
SHA_FN void ssub(u64*a,const u64*b){ u64 br=0; for(int i=0;i<4;i++){ u64 t=a[i]-br; u64 u1=(a[i]<br)?1:0; u64 u2=(t<b[i])?1:0; a[i]=(u64)(t-b[i]); br=u1|u2; } }
/* red_mod_n: canonical [0,n) residue of a raw 256-bit value.  Quotient of a
   full 256-bit by n (<2^256) is <2, so a couple of rounds suffice; loop up to
   3 for safety and give exact canonical result at the end via one more check. */
SHA_FN void red_mod_n(u64 o[4],const u64 a[4]){
    static const u64 N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
    u64 t[4]; for(int i=0;i<4;i++) t[i]=a[i];
    for(int r=0;r<3;r++){ if(sgeq(t,N)) ssub(t,N); }
    o[0]=t[0];o[1]=t[1];o[2]=t[2];o[3]=t[3];
}
/* pow_p: base^e mod p for a 256-bit exponent given as LE limbs */
SHA_FN void pow_p(u64 o[4],const u64 base[4],const u64 e[4]){
    u64 R[4]={1,0,0,0};
    for(int bit=255;bit>=0;bit--){
        mulmod_p(R,R,R);
        if((e[bit>>6]>>(bit&63))&1) mulmod_p(R,R,base);
    }
    for(int i=0;i<4;i++) o[i]=R[i];
}
/* mod-p sqrt (p==3 mod 4): value^((p+1)/4).  Returns 0 if not a square. */
SHA_FN int sqrt_p(u64 y[4],const u64 x[4]){
    static const u64 E[4]={0xffffffffbfffff0cULL,0xffffffffffffffffULL,0xffffffffffffffffULL,0x3fffffffffffffffULL};
    static const u64 P[4]={0xFFFFFFFEFFFFFC2FULL,(u64)-1,(u64)-1,(u64)-1};
    u64 c[4]; mulmod_p(c,x,x); mulmod_p(c,c,x);              /* c = x^3 */
    /* C = x^3 + 7 mod p  (x^3 < p, 7 < p  =>  sum < 2p, one subtract at most) */
    u64 C[4]; { u64 s=(u64)(c[0]+7); u64 cy=(c[0]>(u64)(-8))?1:0; C[0]=s; C[1]=c[1];C[2]=c[2];C[3]=c[3];
        if(cy){ u64 s2=(u64)(C[1]+1); C[1]=s2; if(C[1]==0&&c[2]==(u64)-1){ C[2]=0; C[3]=(u64)(C[3]+1);} }
        if(sgeq(C,P)) { u64 br=0; for(int i=0;i<4;i++){u64 t=C[i]-br,u1=(C[i]<br)?1:0;u64 u2=(t<P[i])?1:0;C[i]=(u64)(t-P[i]);br=u1|u2;} } }
    u64 Y[4]; pow_p(Y,C,E);
    u64 chk[4]; mulmod_p(chk,Y,Y);
    int ok = (chk[0]==C[0]&&chk[1]==C[1]&&chk[2]==C[2]&&chk[3]==C[3]);
    if(!ok) return 0;
    /* choose the even root: if odd, negate (the other root is p-y) */
    if(Y[0]&1){ u64 br=0; for(int i=0;i<4;i++){ u64 t=P[i]-Y[i]; u64 b0=(P[i]<Y[i])?1:0; u64 t2=(u64)(t-br); u64 b1=(t<br)?1:0; Y[i]=t2; br=b0|b1; } }
    for(int i=0;i<4;i++) y[i]=Y[i];
    return 1;
}

/* ---- BIP340 per-thread Verify ---- */
#if defined(__CUDACC__)
#define BIP_FN static __device__ __host__
#else
#define BIP_FN static
#endif
BIP_FN int schnorr_verify_one(const u8 sig[64], const u8 pk[32], const u8* msg, int msglen){
    static const u64 P[4]={0xFFFFFFFEFFFFFC2FULL,(u64)-1,(u64)-1,(u64)-1};
    static const u64 pMINUS2[4]={0xFFFFFFFEFFFFFC2DULL,(u64)-1,(u64)-1,(u64)-1}; /* p-2, exponent for Z^-1 */
    static const u64 N[4]={0xBFD25E8CD0364141ULL,0xBAAEDCE6AF48A03BULL,0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL};
    static const u64 Gx[4]={0x59F2815B16F81798ULL,0x029BFCDB2DCE28D9ULL,0x55A06295CE870B07ULL,0x79BE667EF9DCBBACULL};
    static const u64 Gy[4]={0x9C47D08FFB10D4B8ULL,0xFD17B448A6855419ULL,0x5DA4FBFC0E1108A8ULL,0x483ADA7726A3C465ULL};
    static const u8 TAGH[32]={0x7b,0xb5,0x2d,0x7a,0x9f,0xef,0x58,0x32,0x3e,0xb1,0xbf,0x7a,0x40,0x7d,0xb3,0x82,
                              0xd2,0xf3,0xf2,0xd8,0x1b,0xb1,0x22,0x4f,0x49,0xfe,0x51,0x8f,0x6d,0x48,0xd3,0x7c};
    /* BE bytes -> LE limbs */
    u64 rL[4],sL[4],pxL[4];
    for(int j=0;j<4;j++){
        u64 rw=0,sw=0,pw=0;
        for(int k=0;k<8;k++){ rw=(rw<<8)|sig[j*8+k]; sw=(sw<<8)|sig[32+j*8+k]; pw=(pw<<8)|pk[j*8+k]; }
        rL[3-j]=rw; sL[3-j]=sw; pxL[3-j]=pw;
    }
    /* lift_x(pk) -> P = (px, py even) */
    u64 py[4]; if(!sqrt_p(py,pxL)) return 0;
    /* r < p  and  s < n */
    if(sgeq(rL,P)) return 0;   /* r >= p -> reject */
    if(!(sL[3]<N[3]||(sL[3]==N[3]&&(sL[2]<N[2]||(sL[2]==N[2]&&(sL[1]<N[1]||(sL[1]==N[1]&&sL[0]<N[0]))))))) return 0;
    /* e = SHA256(TAGH||TAGH||r||pk||m) mod n */
    u8 buf[64+64+32+32+128];
    memcpy(buf,TAGH,32); memcpy(buf+32,TAGH,32);
    memcpy(buf+64,sig,32); memcpy(buf+96,pk,32);
    if(msglen>0) memcpy(buf+128,msg,(size_t)msglen);
    u8 H[32]; sha256_msg(H,buf,128+(u64)msglen);
    u64 hL[4]; for(int j=0;j<4;j++){ u64 w=0; for(int k=0;k<8;k++) w=(w<<8)|H[j*8+k]; hL[3-j]=w; }
    u64 e[4]; red_mod_n(e,hL);
    /* R = s*G - e*P = s*G + e*(-P); -P has y negated (p - py) */
    u64 npy[4]; { u64 br=0; for(int i=0;i<4;i++){ u64 t=P[i]-py[i]; u64 b0=(P[i]<py[i])?1:0; u64 t2=(u64)(t-br); u64 b1=(t<br)?1:0; npy[i]=t2; br=b0|b1; } }
    jpoint Rp; scalar_mul(&Rp,sL,Gx,Gy);       /* s*G */
    u64 eL[4]; for(int i=0;i<4;i++) eL[i]=e[i];
    jpoint Rq; scalar_mul(&Rq,eL,pxL,npy);     /* e*(-P) */
    /* add Rp + Rq : affine-ize Rq then mixed-add */
    u64 Zi[4]; pow_p(Zi,Rq.Z,pMINUS2);         /* Zi = Z^(p-2) = Z^-1 */
    u64 Z2[4],Z3[4]; mulmod_p(Z2,Zi,Zi); mulmod_p(Z3,Z2,Zi);
    u64 ax[4],ay[4]; mulmod_p(ax,Rq.X,Z2); mulmod_p(ay,Rq.Y,Z3);
    jpoint R; jadd_mixed(&R,&Rp,ax,ay);
    if(is_inf(&R)) return 0;
    u64 rx[4];
    pow_p(Zi,R.Z,pMINUS2); mulmod_p(Z2,Zi,Zi); mulmod_p(Z3,Z2,Zi);
    mulmod_p(rx,R.X,Z2);
    for(int i=0;i<4;i++) if(rx[i]!=rL[i]) return 0;
    /* y(R) even */
    u64 ry[4]; mulmod_p(ry,R.Y,Z3);
    if(ry[0]&1) return 0;
    return 1;
}

#if defined(__CUDACC__)
__global__ void schnorr_verify_batch(int*outs, const u8*sigs, const u8*pks,
                                     const u8*msgs, const int*msglens, int count){
    int i=blockIdx.x*blockDim.x+threadIdx.x;
    if(i<count){
        outs[i]=schnorr_verify_one(sigs+64*(size_t)i, pks+32*(size_t)i,
                                   msgs? msgs+128*(size_t)i:0, msglens[i]);
    }
}
#endif

/* host oracle (same math on CPU) */
int schnorr_verify_ref(const u8*sig, const u8*pk, const u8*msg, int msglen){
    return schnorr_verify_one(sig,pk,msg,msglen);
}

/* ---- host harness ----
 * Reads the official BIP340 test-vector CSV (asm/tests/bip340_test_vectors.csv,
 * same file the asm oracle is gated on), runs every row through BOTH the host
 * oracle and (when CUDA) a GPU batch kernel, and checks each against the
 * authoritative "verification result" column (9 TRUE + 10 FALSE).
 */
typedef struct { u8 pk[32], sig[64], msg[128]; int msglen, want; } V;

static int hex2b(const char*h,u8*out){ if(!h)return 0; int n=0; while(h[0]&&h[1]){unsigned v; if(sscanf(h,"%2x",&v)!=1)break; out[n++]=(u8)v; h+=2;} return n; }
static int split_csv(char*line,char**f,int maxf){ int n=0; char*p=line; if(!line[0])return 0;
    while(n<maxf){ f[n++]=p; char*c=strchr(p,','); if(!c)break; *c=0; p=c+1;} return n; }

int main(void){
    const char*path=getenv("BIP340_CSV");
    static const char* cands[]={
        "asm/tests/bip340_test_vectors.csv",
        "../tests/bip340_test_vectors.csv",
        "tests/bip340_test_vectors.csv",
        "bip340_test_vectors.csv",
    };
    if(path) cands[0]=path;
    FILE*fp=NULL; int ci=0;
    for(;ci<4;ci++){ fp=fopen(cands[ci],"rb"); if(fp) break; }
    if(!fp && ci==4){ printf("cannot open BIP340 vector CSV (try BIP340_CSV=<path>)\n"); return 2; }
    const char*used=cands[ci]; (void)used;
    fseek(fp,0,SEEK_END); long sz=ftell(fp); fseek(fp,0,SEEK_SET);
    char*buf=(char*)malloc((size_t)sz+1); if(!buf) return 2; size_t rd=fread(buf,1,(size_t)sz,fp); (void)rd; buf[sz]=0; fclose(fp);

    V v[64]; int nv=0;
    char*save=NULL; int lineno=0; char*line=strtok_r(buf,"\n",&save);
    while(line){ lineno++; if(lineno==1){ line=strtok_r(NULL,"\n",&save); continue; }
        size_t l=strlen(line); while(l&&(line[l-1]=='\r'||line[l-1]=='\n'))line[--l]=0;
        if(!line[0]){ line=strtok_r(NULL,"\n",&save); continue; }
        char*f[8]={0}; int nf=split_csv(line,f,8); if(nf<7){ line=strtok_r(NULL,"\n",&save); continue; }
        V*pv=&v[nv];
        if(hex2b(f[2],pv->pk)!=32){ line=strtok_r(NULL,"\n",&save); continue; }
        if(hex2b(f[5],pv->sig)!=64){ line=strtok_r(NULL,"\n",&save); continue; }
        pv->msglen=hex2b(f[4],pv->msg);
        pv->want=(strncmp(f[6],"TRUE",4)==0)?1:0;
        nv++;
        line=strtok_r(NULL,"\n",&save);
    }
    if(nv==0){ printf("no vectors parsed\n"); return 2; }
    printf("loaded %d BIP340 vectors\n",nv);

    /* CPU oracle on every row */
    int cfail=0;
    for(int i=0;i<nv;i++){
        int got=schnorr_verify_ref(v[i].sig,v[i].pk,v[i].msg,v[i].msglen);
        if(got!=v[i].want){ cfail++; printf("  CPU MISMATCH row %d want=%d got=%d\n",i,v[i].want,got); }
        else printf("  row %2d msg_len=%3d  %s  (got=%d)\n",i,v[i].msglen, v[i].want?"TRUE ":"FALSE",got);
    }
    printf("CPU: %d vectors, %d mismatches\n",nv,cfail);

#if defined(__CUDACC__)
    /* GPU batch kernel on every row */
    u8 *dsigs,*dpks,*dmsgs; int *dml,*dout;
    cudaMalloc(&dsigs,64*(size_t)nv); cudaMalloc(&dpks,32*(size_t)nv);
    cudaMalloc(&dmsgs,128*(size_t)nv); cudaMalloc(&dml,4*(size_t)nv); cudaMalloc(&dout,4*(size_t)nv);
    u8 *hs=(u8*)malloc(64*(size_t)nv),*hp=(u8*)malloc(32*(size_t)nv),*hm=(u8*)malloc(128*(size_t)nv);
    int *hml=(int*)malloc(4*(size_t)nv),*gpu=(int*)malloc(4*(size_t)nv);
    for(int i=0;i<nv;i++){ memcpy(hs+64*(size_t)i,v[i].sig,64); memcpy(hp+32*(size_t)i,v[i].pk,32);
        memcpy(hm+128*(size_t)i,v[i].msg,(size_t)v[i].msglen); hml[i]=v[i].msglen; }
    cudaMemcpy(dsigs,hs,64*(size_t)nv,cudaMemcpyHostToDevice);
    cudaMemcpy(dpks,hp,32*(size_t)nv,cudaMemcpyHostToDevice);
    cudaMemcpy(dmsgs,hm,128*(size_t)nv,cudaMemcpyHostToDevice);
    cudaMemcpy(dml,hml,4*(size_t)nv,cudaMemcpyHostToDevice);
    schnorr_verify_batch<<<(nv+255)/256,256>>>(dout,dsigs,dpks,dmsgs,dml,nv);
    cudaDeviceSynchronize();
    cudaMemcpy(gpu,dout,4*(size_t)nv,cudaMemcpyDeviceToHost);
    int gfail=0;
    for(int i=0;i<nv;i++){
        if(gpu[i]!=v[i].want){ gfail++; printf("  GPU MISMATCH row %d want=%d got=%d\n",i,v[i].want,gpu[i]); }
    }
    printf("GPU: %d vectors, %d mismatches\n",nv,gfail);

    /* ---- scale gate: replicate the official vectors across a large batch,
       every result must equal the authoritative column (concurrent threads) ---- */
    int BN = nv*28;   /* 532 sigs when nv==19 */
    u8 *bs=(u8*)malloc(64*(size_t)BN),*bp=(u8*)malloc(32*(size_t)BN),*bm=(u8*)malloc(128*(size_t)BN);
    int *bml=(int*)malloc(4*(size_t)BN),*bwant=(int*)malloc(4*(size_t)BN),*bgpu=(int*)malloc(4*(size_t)BN),*bref=(int*)malloc(4*(size_t)BN);
    for(int i=0;i<BN;i++){ int j=i%nv;
        memcpy(bs+64*(size_t)i,v[j].sig,64); memcpy(bp+32*(size_t)i,v[j].pk,32);
        memcpy(bm+128*(size_t)i,v[j].msg,(size_t)v[j].msglen); bml[i]=v[j].msglen; bwant[i]=v[j].want;
        bref[i]=schnorr_verify_ref(v[j].sig,v[j].pk,v[j].msg,v[j].msglen); }
    u8 *db1,*db2,*db3; int *dm1,*do1;
    cudaMalloc(&db1,64*(size_t)BN); cudaMalloc(&db2,32*(size_t)BN); cudaMalloc(&db3,128*(size_t)BN);
    cudaMalloc(&dm1,4*(size_t)BN); cudaMalloc(&do1,4*(size_t)BN);
    cudaMemcpy(db1,bs,64*(size_t)BN,cudaMemcpyHostToDevice);
    cudaMemcpy(db2,bp,32*(size_t)BN,cudaMemcpyHostToDevice);
    cudaMemcpy(db3,bm,128*(size_t)BN,cudaMemcpyHostToDevice);
    cudaMemcpy(dm1,bml,4*(size_t)BN,cudaMemcpyHostToDevice);
    schnorr_verify_batch<<<(BN+255)/256,256>>>(do1,db1,db2,db3,dm1,BN);
    cudaDeviceSynchronize();
    cudaMemcpy(bgpu,do1,4*(size_t)BN,cudaMemcpyDeviceToHost);
    int brefBad=0, bgpuBad=0, bgpuVsRef=0;
    for(int i=0;i<BN;i++){
        if(bref[i]!=bwant[i]) brefBad++;
        if(bgpu[i]!=bwant[i]) bgpuBad++;
        if(bgpu[i]!=bref[i]) bgpuVsRef++;
    }
    printf("SCALE batch n=%d | host==expected: %d/%d | gpu==expected: %d/%d | gpu==host: %d/%d\n",
           BN, BN-brefBad,BN, BN-bgpuBad,BN, BN-bgpuVsRef,BN);
    printf("SCALE result: %s\n",(brefBad==0&&bgpuBad==0&&bgpuVsRef==0)?"ALL CORRECT":"FAILURES");
    return (cfail||gfail||brefBad||bgpuBad||bgpuVsRef)?1:0;
#else
    (void)0; return cfail?1:0;
#endif
}
