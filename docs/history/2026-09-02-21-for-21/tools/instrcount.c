/* REPRODUCE: cd /storage/bitcoinmachinecode/asm && gcc -O2 -no-pie -o /storage/bmc-book/tools/instrcount /storage/bmc-book/tools/instrcount.c sha256.o secp256k1_fe.o secp256k1_scalar.o secp256k1_point.o secp256k1_point_ct.o secp256k1_ecdsa.o secp256k1_glv_c.o
 * RUN: /storage/bmc-book/tools/instrcount 2000 5   -> 360,030 per verification (deterministic to 5 digits). */
/* instrcount.c -- dynamic x86-64 instruction count for ecdsa_verify,
 * measured with PERF_COUNT_HW_INSTRUCTIONS (user-space, exclude_kernel).
 * Method note for the book: retired instructions, user space, this binary
 * only (statically linked deps; libc rand excluded by exclude_kernel only,
 * so a few % of overhead is in the loop itself, NOT in the kernel). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <errno.h>
typedef unsigned long long u64;
extern int ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
                        const u64 Qx[4], const u64 Qy[4]);
static long pfd;
static void perf_open(void){
    struct perf_event_attr pe; memset(&pe,0,sizeof(pe));
    pe.type=PERF_TYPE_HARDWARE; pe.size=sizeof(pe);
    pe.config=PERF_COUNT_HW_INSTRUCTIONS;
    pe.disabled=1; pe.exclude_kernel=1; pe.exclude_hv=1;
    pfd=syscall(__NR_perf_event_open,&pe,0,-1,-1,0);
    if(pfd<0){ fprintf(stderr,"perf_event_open: %s\n",strerror(errno)); exit(2);}
}
static long long perf_rd(void){
    ioctl(pfd,PERF_EVENT_IOC_ENABLE,0);
    unsigned long long v=0;
    if(read(pfd,&v,sizeof(v))!=sizeof(v)){perror("read");exit(2);}
    ioctl(pfd,PERF_EVENT_IOC_DISABLE,0);
    return (long long)v;
}
int main(int argc,char**argv){
    long n=(argc>1)?atol(argv[1]):1000;
    u64 z[4]={0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL,0x0123456789abcdefULL};
    u64 r[4]={0x2af4a71489e9f1dbULL,0xc0cb2fd43c3b6e75ULL,0x5fbff28aa15cced7ULL,0x592cb214ca60184fULL};
    u64 s[4]={0xc4a2c025aa14e92aULL,0x010761c8cf1d4450ULL,0x812cf05ef8411d64ULL,0x23d627acd53ebcd7ULL};
    u64 Qx[4]={0xfd723873aa170695ULL,0xe7bcc89470d63e1aULL,0x8947c271ac274529ULL,0x9651c463c001f731ULL};
    u64 Qy[4]={0x21837fb0e654eaf7ULL,0x3b16ba7a5a9b154dULL,0x73d6d17fe8b63c99ULL,0x4e362e7fe8ff06daULL};
    if(ecdsa_verify(z,r,s,Qx,Qy)!=1){printf("FAIL fixture\n");return 1;}
    perf_open();
    long long base=0;
    long acc=0;
    long long delta=0;
    int rounds=(argc>2)?atoi(argv[2]):3;
    for(int k=0;k<rounds;k++){
        /* enable-with-reset atomically: PERF_EVENT_IOC_ENABLE does NOT
         * reset; reset first with a zeroed read (perf_rd's enable starts
         * the counter; disable stops it, so the read after enable-without-
         * prior-disable is the true enable-to-disable delta). */
        ioctl(pfd,PERF_EVENT_IOC_RESET,0);
        ioctl(pfd,PERF_EVENT_IOC_ENABLE,0);
        acc=0;
        for(long i=0;i<n;i++) acc+=ecdsa_verify(z,r,s,Qx,Qy);
        long long tot=perf_rd();
        if(acc!=n){printf("FAIL verify count\n");return 1;}
        long long d=tot-base;
        if(k==0||d<delta) delta=d;
    }
    (void)0;
    printf("%ld ecdsa_verify calls (min of %d rounds): %lld retired user-space instructions, %.0f per verification\n",
           n, rounds, delta, (double)delta/n);
    printf("one signature verification = %.1f instructions\n",(double)delta/n);
    return 0;
}
