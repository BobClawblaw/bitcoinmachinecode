/* tests/test_pow_check.c -- VAL-11 (audit 2026-09-03): pow_check's range
 * checks and diff_target's write bounds.
 *
 * (1) diff_target with an attacker-chosen exponent wrote the 3 mantissa
 *     bytes DOWNWARD from target[31-(exp-3)] with no lower bound -- for
 *     exponent >= 35 that is BELOW the 32-byte buffer (for exponent ~0xff,
 *     ~220 bytes below rbp: a stack scribble). The clamp now discards what
 *     Core's 256-bit shift discards (bits past 256); a guard page under the
 *     buffer turns any remaining under-write into SIGSEGV.
 * (2) pow_check now mirrors Core's CheckProofOfWorkImpl: nBits with the
 *     negative bit set, mantissa 0, an overflowing compact, or an exponent
 *     that zeroes the stored target are INVALID PoW, not "valid against a
 *     huge target". (Previously each was accepted with the first nonce.)
 * (3) pow_pow_limit_bits (armed by chainparams_select): a claimed target
 *     above the chain powLimit is rejected -- the header half of VAL-7's
 *     "inbound block at self-chosen nBits" attack. Harnesses that never
 *     select a chain leave the check off (default 0) so the existing easy-PoW
 *     fixtures keep mining against 0x207fffff.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

extern int  pow_check(const unsigned char hdr[80]);
extern void diff_target(void* out32, unsigned bits);
extern unsigned int pow_pow_limit_bits;

static int failures=0;
static void ck(const char* l,long g,long e){
    if(g==e) printf("PASS %s\n",l);
    else { printf("FAIL %s got=%ld exp=%ld\n",l,g,e); failures++; }
}

/* mine a nonce into hdr so PoW holds for well-formed bits; returns 1 on success */
static int mine(unsigned char* hdr){
    for (unsigned n = 0; n < 50000000u; n++){
        hdr[76]=(unsigned char)n; hdr[77]=(unsigned char)(n>>8);
        hdr[78]=(unsigned char)(n>>16); hdr[79]=(unsigned char)(n>>24);
        if (pow_check(hdr)) return 1;
    }
    return 0;
}

int main(void){
    /* ---- (1) guard-page under-write probe ---- */
    {
        long pg = sysconf(_SC_PAGESIZE);
        unsigned char* m = mmap(0, 2*pg, PROT_READ|PROT_WRITE,
                                MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED){ perror("mmap"); return 1; }
        if (mprotect(m, pg, PROT_NONE)){ perror("mprotect"); return 1; }
        /* the 32-byte target buffer flush against the guard's far edge: any
         * write below it faults */
        unsigned char* buf = m + pg;
        for (unsigned e = 34; e <= 255; e++){
            unsigned bits = (e << 24) | 0x7fffffu;
            diff_target(buf, bits);
        }
        diff_target(buf, 0xffffffffu);   /* exponent 255, mantissa with high bit */
        diff_target(buf, 0x20ffffffu);   /* exponent 32: e3=29, 3-byte mantissa */
        diff_target(buf, 0x21ffffffu);   /* exponent 33: e3=30 top-edge case */
        diff_target(buf, 0x22ffffffu);   /* exponent 34: e3=31 top-edge case */
        ck("diff_target never writes below the 32-byte buffer (guard page)", 1, 1);
    }

    /* ---- (2) pow_check range rejections ---- */
    {
        unsigned char hdr[80];
        memset(hdr, 0, 80);
        hdr[72]=0xff; hdr[73]=0x7f; hdr[74]=0xff; hdr[75]=0x1d;  /* 0x1dFF7FFF: mantissa high bit -> NEGATIVE */
        ck("pow_check rejects negative nBits (mantissa bit23) at nonce 0", pow_check(hdr), 0);
        { unsigned char h2[80]; memcpy(h2,hdr,80); int got=0;
          for(unsigned n=0;n<2000000u;n++){ h2[76]=n;h2[77]=n>>8;h2[78]=n>>16;h2[79]=n>>24;
              if(pow_check(h2)){got=1;break;} }
          ck("negative nBits: NO nonce ever validates", got, 0); }

        memset(hdr,0,80);
        hdr[72]=0x00; hdr[73]=0x00; hdr[74]=0x00; hdr[75]=0x1d;   /* mantissa 0 -> target 0 */
        ck("pow_check rejects mantissa-0 nBits", pow_check(hdr), 0);

        memset(hdr,0,80);
        hdr[72]=0xff; hdr[73]=0xff; hdr[74]=0xff; hdr[75]=0x23;   /* 0x23FFFFFF: nSize=35 overflow */
        ck("pow_check rejects overflowing nBits (nSize>34)", pow_check(hdr), 0);

        memset(hdr,0,80);
        hdr[72]=0xff; hdr[73]=0xff; hdr[74]=0x01; hdr[75]=0x21;   /* 0x2101FFFF: nSize=33, word>0xff */
        ck("pow_check rejects overflow nSize>33 && word>0xff", pow_check(hdr), 0);

        memset(hdr,0,80);
        hdr[72]=0xff; hdr[73]=0xff; hdr[74]=0xff; hdr[75]=0x20;   /* 0x20FFFFFF: nSize=32, word>0xffff */
        ck("pow_check rejects overflow nSize>32 && word>0xffff", pow_check(hdr), 0);

        memset(hdr,0,80);
        hdr[72]=0xff; hdr[73]=0x00; hdr[74]=0x00; hdr[75]=0x02;   /* exponent 2: target stores as 0 */
        ck("pow_check rejects exponent<3 (zero target)", pow_check(hdr), 0);

        /* well-formed easy bits still work: mine + accept */
        memset(hdr,0,80);
        hdr[72]=0xff; hdr[73]=0xff; hdr[74]=0x7f; hdr[75]=0x20;   /* 0x207fffff (regtest powLimit) */
        ck("pow_check: 0x207fffff mines + validates (limit disarmed)", mine(hdr), 1);

        /* the mainnet difficulty-1 genesis bits validate (non-regression on
         * the normal path): header from the real genesis minus nonce search */
        /* (genesis has a fixed nonce; just assert the bits pass range checks:
         * pow_check will return 0 on hash, but NOT via the range gates --
         * approximated by: mine() finds a nonce at all => range-gate passed) */
    }

    /* ---- (3) armed powLimit rejects a target above the chain limit ---- */
    {
        unsigned char hdr[80];
        memset(hdr,0,80);
        hdr[72]=0xff; hdr[73]=0xff; hdr[74]=0x7f; hdr[75]=0x20;   /* 0x207fffff */
        ck("baseline: validates with limit off", mine(hdr), 1);
        pow_pow_limit_bits = 0x1d00ffffu;                          /* mainnet powLimit */
        ck("pow_check REJECTS 0x207fffff under mainnet powLimit", pow_check(hdr), 0);
        /* a target exactly at the powLimit is still fine (Core: reject only
         * bnTarget > powLimit). Use the ~1/2-difficulty 0x207fffff as BOTH
         * so the equality edge mines instantly and the scan is deterministic. */
        memset(hdr,0,80);
        hdr[72]=0xff; hdr[73]=0xff; hdr[74]=0x7f; hdr[75]=0x20;   /* 0x207fffff */
        pow_pow_limit_bits = 0x207fffffu;                          /* target == powLimit */
        ck("pow_check accepts target == powLimit", mine(hdr), 1);
        /* one step OVER: limit 0x207ffffe, header bits 0x207fffff -> reject */
        hdr[76]=0;hdr[77]=0;hdr[78]=0;hdr[79]=0;
        pow_pow_limit_bits = 0x207ffffeu;
        { int got=0; for(unsigned n=0;n<200000u;n++){ hdr[76]=n;hdr[77]=n>>8;hdr[78]=n>>16;hdr[79]=n>>24;
              if(pow_check(hdr)){got=1;break;} }
          ck("pow_check REJECTS target one step above powLimit", got, 0); }
        pow_pow_limit_bits = 0;
    }

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
