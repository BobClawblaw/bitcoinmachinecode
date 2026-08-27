#!/usr/bin/env python3
"""fuzz_chainwork.py -- differential fuzz of bitcoin_chainwork.S vs a pure
Python big-int oracle (u256_div / block_work / chainwork_add / chainwork_cmp /
store_chainwork_* persistence incl. truncate+rollback).

Usage: python3 fuzz_chainwork.py [seeds] [n_per_seed]
Requires: host aarch64 gcc + bitcoin_chainwork.S in this dir.
"""
import subprocess, sys, tempfile, os, hashlib, pathlib

HERE = pathlib.Path(__file__).resolve().parent
DRIVER = r"""
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned char u8;
extern void u256_div(u8 q[32], const u8 a[32], const u8 b[32]);
extern void block_work(u8 work[16], unsigned int bits);
extern void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16]);
extern long chainwork_cmp(const u8 a[16], const u8 b[16]);
extern int  store_chainwork_init(void* st);
extern int  store_chainwork_append(void* st, long h, const u8 w[16]);
extern int  store_chainwork_get_tip(void* st, u8 out[16]);
extern long store_chainwork_reload(void* st);
extern long store_chainwork_truncate(void* st, long target);
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
static void seed_rng(uint64_t s){ rng_state = s ^ 0x9e3779b97f4a7c15ULL; }
static uint64_t rnd(void){
    uint64_t z = (rng_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
static void rand256(u8* p){ for(int i=0;i<32;i++) p[i]=(u8)rnd(); }
static void rand128(u8* p){ for(int i=0;i<16;i++) p[i]=(u8)rnd(); }
static void hex256(const u8* p){ for(int i=31;i>=0;i--) printf("%02x",p[i]); }
static void hex128(const u8* p){ for(int i=15;i>=0;i--) printf("%02x",p[i]); }
int main(int argc, char** argv){
    int n = argc>1? atoi(argv[1]) : 6000;
    if(argc>2) seed_rng(strtoull(argv[2],0,10)+1);
    for(int i=0;i<n;i++){
        u8 a[32],b[32],q[32]; rand256(a); rand256(b);
        switch(i%5){
            case 0: for(int z=25;z<32;z++) b[z]=0; b[24]=(u8)((rnd()&0x0f)|1); if(b[24]==0)b[24]=1; break;
            case 1: memcpy(b,a,32); break;
            case 2: memset(b,0,32); b[0]=(i&1)?1:(i&2)?7:(i&4)?3:256; break;
            case 3: memset(b,0,32); b[31]=(u8)(rnd()|1); break;
            default: break;
        }
        if(memcmp(b,"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",32)==0) b[0]=1;
        u256_div(q,a,b);
        printf("u256d "); hex256(a); printf(" "); hex256(b); printf(" "); hex256(q); printf("\n");
    }
    unsigned int reals[] = {0x1d00ffff,0x1b0404cb,0x170e0408,0x1c00ffff,0x1f00ffff,0x207fffff,
                            0x1a0e0408,0x1d00ffff,0x1b0a0000,0x1c0e0000,0x1800ffff,0x1e00ffff,
                            0x1b01e240,0x1d0170a8};
    for(unsigned k=0;k<sizeof(reals)/sizeof(reals[0]);k++){ u8 w[16]; block_work(w,reals[k]); printf("bw %08x ", reals[k]); hex128(w); printf("\n"); }
    for(int i=0;i<n;i++){ unsigned e=1+(unsigned)(rnd()%30); unsigned m=(unsigned)(rnd()&0x00ffffffu); u8 w[16]; block_work(w,(e<<24)|m); printf("bw %08x ", (e<<24)|m); hex128(w); printf("\n"); }
    for(int i=0;i<n;i++){ u8 a[16],b[16],o[16]; rand128(a); rand128(b); chainwork_add(o,a,b); printf("cwa "); hex128(a); printf(" "); hex128(b); printf(" "); hex128(o); printf("\n"); printf("cwc "); hex128(a); printf(" "); hex128(b); printf(" %ld\n", chainwork_cmp(a,b)); }
    {
        unsigned char st[256]; memset(st,0,sizeof st);
        if(store_chainwork_init(st)!=1){ printf("store init fail\n"); return 2; }
        long last=-1;
        for(int s=0;s<120;s++){
            long h=last+1; unsigned e=1+(unsigned)(rnd()%30); unsigned m=(unsigned)rnd()&0xffffffu;
            u8 w[16]; block_work(w,(e<<24)|m);
            printf("stA %ld ", h); hex128(w); printf("\n");
            if(store_chainwork_append(st,h,w)!=1){ printf("append fail h=%ld\n",h); return 2; }
            last=h; u8 t[16]; store_chainwork_get_tip(st,t); printf("stT %ld ", last); hex128(t); printf("\n");
            if(s%5==0){ long cnt=store_chainwork_reload(st); if(cnt<0){ printf("reload fail\n"); return 2; } u8 t2[16]; store_chainwork_get_tip(st,t2); printf("stR %ld %ld ", last, cnt); hex128(t2); printf("\n"); }
            if(s>2 && s%7==3){ long target=last-1-(long)(rnd()%(last>4?4:1)); if(target<-1)target=-1; printf("stX %ld\n", target); if(store_chainwork_truncate(st,target)!=1){ printf("truncate fail %ld\n",target); return 2; } last=target; }
        }
        store_chainwork_reload(st); printf("stFINAL %ld\n", last);
    }
    return 0;
}
"""

def diff_target(bits):
    e=(bits>>24)&0xff; m=bits&0x00ffffff
    return 0 if e<3 else m<<(8*(e-3))
def block_work(bits):
    t=diff_target(bits)
    if t==0: return 0
    if t==(1<<256)-1: return 1
    return ((((1<<256)-1-t)//(t+1))+1) & ((1<<128)-1)

def oracle(out):
    fail=0; M=(1<<128)-1; store={}; last=-1
    lines=out.splitlines()
    for ln in lines:
        p=ln.split()
        if not p: continue
        op=p[0]
        if op=='u256d':
            if int(p[3],16)!=int(p[1],16)//int(p[2],16): fail+=1
        elif op=='bw':
            if int(p[2],16)!=block_work(int(p[1],16)): fail+=1
        elif op=='cwa':
            if int(p[3],16)!=((int(p[1],16)+int(p[2],16))&M): fail+=1
        elif op=='cwc':
            a,b=int(p[1],16),int(p[2],16); exp=1 if a>b else(-1 if a<b else 0)
            if int(p[3])!=exp: fail+=1
        elif op=='stA':
            h=int(p[1]); w=int(p[2],16); prev=store.get(h-1,0) if h>0 else 0
            store[h]=(prev+w)&M; last=h
        elif op=='stT':
            if int(p[2],16)!=store.get(last,0): fail+=1
        elif op=='stR':
            if int(p[2])!=int(p[1])+1: fail+=1
            if int(p[3],16)!=store.get(int(p[1]),0): fail+=1
        elif op=='stX':
            tgt=int(p[1])
            for h in [k for k in store if k>tgt]: del store[h]
            last=tgt
    return fail

def main():
    nseeds=int(sys.argv[1]) if len(sys.argv)>1 else 8
    n=int(sys.argv[2]) if len(sys.argv)>2 else 6000
    with tempfile.TemporaryDirectory() as d:
        drv=os.path.join(d,'cw_driver.c'); open(drv,'w').write(DRIVER)
        subprocess.run(['gcc','-O2','-o',os.path.join(d,'cw_driver'),drv,
                        os.path.join(HERE,'bitcoin_chainwork.S')],check=True)
        tot=0
        for seed in range(1,nseeds+1):
            sd=os.path.join(d,f's{seed}'); os.makedirs(sd)
            r=subprocess.run([os.path.join(d,'cw_driver'),str(n),str(seed)],
                             cwd=sd,capture_output=True,text=True)
            if r.returncode!=0: print(f'seed {seed}: DRIVER ERROR rc={r.returncode}'); sys.exit(2)
            f=oracle(r.stdout); tot+=f
            print(f'seed {seed}: {["FAIL="+str(f),"0 fail"][f==0]}')
        print(f'TOTAL failures across {nseeds} seeds: {tot}')
        sys.exit(1 if tot else 0)

if __name__=='__main__':
    main()
