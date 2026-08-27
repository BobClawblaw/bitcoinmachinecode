#!/usr/bin/env python3
"""fuzz_muhash.py -- differential fuzz of bitcoin_muhash.S (MuHash3072) vs a
pure Python big-int oracle for the core operation num3072_mul (a = a*b mod p,
p = 2^3072 - 1103717), over thousands of random full-width 3072-bit operands.

The repo test_muhash.c already checks ChaCha20/ToNum3072/Mul/Finalize against
Bitcoin Core's OWN MuHash3072 output (Core-generated, never hand-transcribed),
but its MUL layer is only 6 FIXED vectors -- it never exercises the 48x48
schoolbook + 2-pass reduction across the value space. This fuzzer drives
num3072_mul with random 384-byte LE operands -- canonical (< p) AND raw
full-width (stress the reduce) -- and compares against an INDEPENDENT big-int
computation (a*b % p). This is the same generated-vs-transcribed discipline as
the repo's validation scripts (ENGINEERING_RULES.md 1).

Usage: python3 fuzz_muhash.py [seeds] [n_per_seed]
Requires: host aarch64 gcc + bitcoin_muhash.S in this dir.
"""
import subprocess, sys, tempfile, os, pathlib

HERE = pathlib.Path(__file__).resolve().parent

# MuHash3072 modulus p = 2^3072 - 1103717.
PRIME_DIFF = 1103717
P = (1 << 3072) - PRIME_DIFF

DRIVER = r"""
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned char u8;
extern void num3072_mul(void* a, const void* b);   /* a = a*b mod p */
extern void num3072_set_one(void* a);
static uint64_t rng_state = 0x9e3779b97f4a7c15ULL;
static void seed_rng(uint64_t s){ rng_state = s ^ 0x9e3779b97f4a7c15ULL; }
static uint64_t rnd(void){
    uint64_t z = (rng_state += 0x9e3779b97f4a7c15ULL);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
    return z ^ (z >> 31);
}
static void rand384(u8* p){ for(int i=0;i<48;i++){ uint64_t v=rnd(); memcpy(p+8*i,&v,8);} }
/* Clear the top 5 bits of the top limb -> value < 2^3072 (canonical-ish). */
static void canonicalize(u8* p){ p[47] &= 0x07; }
static void hex384(const u8* p){ for(int i=47;i>=0;i--) for(int j=7;j>=0;j--) printf("%02x", p[i*8+j]); }
int main(int argc, char** argv){
    int n = argc>1? atoi(argv[1]) : 2000;
    if(argc>2) seed_rng(strtoull(argv[2],0,10)+1);
    for(int i=0;i<n;i++){
        u8 a[384], b[384];
        rand384(a); rand384(b);
        if(i%3==0){ canonicalize(a); canonicalize(b); }   /* canonical operands */
        if(i%7==0) num3072_set_one(b);                    /* x*1 == x */
        if(i%11==0) memcpy(b,a,384);                      /* x*x   */
        printf("mul "); hex384(a); printf(" "); hex384(b); printf(" ");
        num3072_mul(a, b);
        hex384(a); printf("\n");
    }
    return 0;
}
"""

def to_int(hexle):
    # hex384 prints limb 47 (most significant) first with its most significant
    # byte first -- i.e. the conventional MSB-first hex of the integer the 48
    # LE u64 limbs represent. So the value is int(hex,16), NOT byte-swapped.
    return int(hexle, 16)

def oracle(out):
    fail = 0
    for ln in out.splitlines():
        p = ln.split()
        if not p or p[0] != 'mul':
            continue
        ai, bi, r = to_int(p[1]), to_int(p[2]), to_int(p[3])
        exp = (ai * bi) % P
        if r != exp:
            fail += 1
    return fail

def main():
    nseeds = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    with tempfile.TemporaryDirectory() as d:
        drv = os.path.join(d, 'mh_driver.c'); open(drv, 'w').write(DRIVER)
        subprocess.run(['gcc', '-O2', '-o', os.path.join(d, 'mh_driver'), drv,
                        os.path.join(HERE, 'bitcoin_muhash.S'),
                        os.path.join(HERE, 'sha256.S')], check=True)
        tot = 0
        for seed in range(1, nseeds + 1):
            r = subprocess.run([os.path.join(d, 'mh_driver'), str(n), str(seed)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                print(f'seed {seed}: DRIVER ERROR rc={r.returncode}'); sys.exit(2)
            f = oracle(r.stdout); tot += f
            print(f'seed {seed} ({n} mults): {"FAIL="+str(f) if f else "0 fail"}')
        print(f'TOTAL num3072_mul failures across {nseeds} seeds: {tot}')
        sys.exit(1 if tot else 0)

if __name__ == '__main__':
    main()
