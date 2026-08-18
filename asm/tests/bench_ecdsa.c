/* bench_ecdsa.c -- signature verifications per second, single core.
 * Scoping input for block script verification: the chain needs roughly a
 * billion of these, so this rate decides whether assumevalid is optional. */
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
typedef unsigned long long u64;
extern int ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
                        const u64 Qx[4], const u64 Qy[4]);
int main(int argc, char** argv){
    long n = (argc>1)? atol(argv[1]) : 20000;
    u64 z[4] = {0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL};
    u64 r[4] = {0x2af4a71489e9f1dbULL,0xc0cb2fd43c3b6e75ULL,0x5fbff28aa15cced7ULL,0x592cb214ca60184fULL};
    u64 s[4] = {0xc4a2c025aa14e92aULL,0x010761c8cf1d4450ULL,0x812cf05ef8411d64ULL,0x23d627acd53ebcd7ULL};
    u64 Qx[4]= {0xfd723873aa170695ULL,0xe7bcc89470d63e1aULL,0x8947c271ac274529ULL,0x9651c463c001f731ULL};
    u64 Qy[4]= {0x21837fb0e654eaf7ULL,0x3b16ba7a5a9b154dULL,0x73d6d17fe8b63c99ULL,0x4e362e7fe8ff06daULL};
    if (ecdsa_verify(z,r,s,Qx,Qy)!=1){ printf("FAIL: fixture sig does not verify\n"); return 1; }
    struct timespec a,b; clock_gettime(CLOCK_MONOTONIC,&a);
    long acc=0;
    for(long i=0;i<n;i++) acc += ecdsa_verify(z,r,s,Qx,Qy);
    clock_gettime(CLOCK_MONOTONIC,&b);
    double el = (b.tv_sec-a.tv_sec) + (b.tv_nsec-a.tv_nsec)/1e9;
    if (acc != n){ printf("FAIL: %ld of %ld verifications did not accept\n", n-acc, n); return 1; }
    printf("%ld verifications in %.3fs -> %.0f/s per core (%.1f us each)\n",
           n, el, n/el, el/n*1e6);
    printf("1e9 signatures at this rate: %.1f core-hours (%.1f h on 16 cores)\n",
           1e9/(n/el)/3600.0, 1e9/(n/el)/3600.0/16.0);
    return 0;
}
