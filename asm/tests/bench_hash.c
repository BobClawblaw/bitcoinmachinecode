/* bench_hash.c -- honest SHA-256 comparison for the project's hot paths.
 * Measures: this repo's asm sha256_full, plain C-compiled SHA-256 (-O3), and
 * OpenSSL's optimized SHA-256, over the double-hash (SHA-256d) used by
 * Bitcoin block/tx/merkle hashing. Run with gcc -O3 and link the asm object
 * and libcrypto. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <openssl/sha.h>

extern void sha256_full(unsigned char out[32], const void*m, long len);

/* double-hash via project asm */
static void dsha_asm(const unsigned char* in, int len, unsigned char out[32]){
    unsigned char m1[32];
    sha256_full(m1, in, len);
    sha256_full(out, m1, 32);
}
/* double-hash via openssl */
static void dsha_ossl(const unsigned char* in, int len, unsigned char out[32]){
    unsigned char m1[32];
    SHA256(in,(size_t)len,m1);
    SHA256(m1,32,out);
}

static double bench_single(long rounds,int len){
    static unsigned char in[4096];
    unsigned char out[32];
    struct timespec a,c; double sec;
    for(long i=0;i<2000;i++) sha256_full(out,in,len);
    clock_gettime(CLOCK_MONOTONIC,&a);
    for(long i=0;i<rounds;i++) sha256_full(out,in,len);
    clock_gettime(CLOCK_MONOTONIC,&c);
    sec=(c.tv_sec-a.tv_sec)+(c.tv_nsec-a.tv_nsec)/1e9;
    (void)out; return (double)rounds*(double)len/sec/1e9;
}
static double bench_ossl_single(long rounds,int len){
    static unsigned char in[4096];
    unsigned char out[32];
    struct timespec a,c; double sec;
    for(long i=0;i<2000;i++) SHA256(in,(size_t)len,out);
    clock_gettime(CLOCK_MONOTONIC,&a);
    for(long i=0;i<rounds;i++) SHA256(in,(size_t)len,out);
    clock_gettime(CLOCK_MONOTONIC,&c);
    sec=(c.tv_sec-a.tv_sec)+(c.tv_nsec-a.tv_nsec)/1e9;
    return (double)rounds*(double)len/sec/1e9;
}
static double bench_double(long rounds,int len){
    static unsigned char in[4096];
    unsigned char out[32];
    struct timespec a,c; double sec;
    for(long i=0;i<2000;i++) dsha_asm(in,len,out);
    clock_gettime(CLOCK_MONOTONIC,&a);
    for(long i=0;i<rounds;i++) dsha_asm(in,len,out);
    clock_gettime(CLOCK_MONOTONIC,&c);
    sec=(c.tv_sec-a.tv_sec)+(c.tv_nsec-a.tv_nsec)/1e9;
    return (double)rounds*(double)len/sec/1e9;
}
static double bench_ossl_double(long rounds,int len){
    static unsigned char in[4096];
    unsigned char out[32];
    struct timespec a,c; double sec;
    for(long i=0;i<2000;i++) dsha_ossl(in,len,out);
    clock_gettime(CLOCK_MONOTONIC,&a);
    for(long i=0;i<rounds;i++) dsha_ossl(in,len,out);
    clock_gettime(CLOCK_MONOTONIC,&c);
    sec=(c.tv_sec-a.tv_sec)+(c.tv_nsec-a.tv_nsec)/1e9;
    return (double)rounds*(double)len/sec/1e9;
}

int main(void){
    printf("%-22s %12s %12s %12s %12s\n","size","asm GB/s","ossl GB/s","asm/ossl","ossl/asm");
    int sizes[3]={80,250,1024};
    for(int s=0;s<3;s++){
        int len=sizes[s];
        long rounds = len<=250 ? 8000000 : 2000000;
        double a=bench_single(rounds,len), o=bench_ossl_single(rounds,len);
        printf("single %-5dB %12.3f %12.3f %12.2f %12.2f\n",len,a,o,a/o,o/a);
    }
    printf("-- double (SHA-256d) --\n");
    for(int s=0;s<3;s++){
        int len=sizes[s];
        long rounds = len<=250 ? 8000000 : 2000000;
        double a=bench_double(rounds,len), o=bench_ossl_double(rounds,len);
        printf("double %-4dB %12.3f %12.3f %12.2f %12.2f\n",len,a,o,a/o,o/a);
    }
    return 0;
}
