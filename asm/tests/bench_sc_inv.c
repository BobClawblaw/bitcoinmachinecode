/* bench_sc_inv.c -- sc_inv_var (s^{-1} mod n, variable-time) per call, single
 * core. ecdsa_verify calls it once per signature, so its cost is a straight
 * share of bench_ecdsa's number; libsecp256k1's own figure is
 * `bench_internal scalar` -> scalar_inverse_var.
 *
 * MEASUREMENT: thread CPU time, min over ROUNDS repetitions, same discipline
 * as tests/bench_ecdsa.c (interference can only add time). The inputs are a
 * fixed pseudo-random set in [1,n), and each result is folded into a checksum
 * that is printed so the loop cannot be optimised away.
 *   argv[1] = inversions per round (default 200000)
 *   argv[2] = rounds (default 7) */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
typedef unsigned long long u64;
extern int sc_inv_var(u64 r[4], const u64 a[4]);
static double cpu_s(void){
    struct timespec ts; clock_gettime(CLOCK_THREAD_CPUTIME_ID,&ts);
    return ts.tv_sec + ts.tv_nsec*1e-9;
}
#define NIN 1024
int main(int argc, char** argv){
    long n = (argc>1)? atol(argv[1]) : 200000;
    int rounds = (argc>2)? atoi(argv[2]) : 7;
    static u64 in[NIN][4];
    u64 x = 0x9E3779B97F4A7C15ULL;
    for (int i=0;i<NIN;i++){
        for (int k=0;k<4;k++){ x^=x<<13; x^=x>>7; x^=x<<17; in[i][k]=x; }
        in[i][3] >>= 1;                      /* < 2^255 < n, never 0 */
        in[i][0] |= 1;
    }
    double best=1e9, worst=0; u64 sum=0;
    for (int r=0;r<rounds;r++){
        double t0=cpu_s();
        for (long i=0;i<n;i++){ u64 o[4]; sc_inv_var(o, in[i&(NIN-1)]); sum+=o[0]^o[3]; }
        double t=cpu_s()-t0;
        if (t < best) best = t;
        if (t > worst) worst = t;
    }
    printf("sc_inv_var: %ld calls, min-of-%d CPU-time rounds: %.3fs -> %.3f us each (worst round %.3f us) [checksum %016llx]\n",
           n, rounds, best, best/n*1e6, worst/n*1e6, sum);
    return 0;
}
