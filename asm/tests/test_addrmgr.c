/* test_addrmgr.c -- harness for the ASM address-book manager + addr v1 codec.
 * Verifies amr_init/count/add/lookup/get_i and p2p_addr_v1/count byte-exact
 * against a reference built here with the same wire layout (Bitcoin `addr` v1:
 * count varint + [time u32][services u64][ip16 v4][port u16 BE] * n).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>

extern int  amr_init(void* ab);
extern long amr_count(void* ab);
extern int  amr_add  (void* ab, unsigned ip, unsigned short port, unsigned long long services, unsigned lastseen);
extern int  amr_get_i(void* ab, long i, void* out);
extern long amr_lookup(void* ab, unsigned ip);
extern long p2p_addr_v1(void* out, const void* src, long n);
extern long p2p_addr_count(const void* pl, long plen);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else {printf("FAIL %s got=%ld exp=%ld\n",l,g,e); failures++;} }

int main(void){
    mkdir("/tmp/amrtest",0777); chdir("/tmp/amrtest");
    unlink("peers.dat"); unlink("index.dat"); unlink("blk00000.dat");
    static unsigned char ab[64];
    cki("amr_init", amr_init(ab), 1);
    cki("amr_count empty", amr_count(ab), 0);

    /* ip 1.2.3.4 = 0x04030201 LE; port 8333 BE = 0x208D; services=1; seen=1000 */
    unsigned ip0 = 0x04030201u;
    cki("amr_add new", amr_add(ab, ip0, 0x208D, 1, 1000), 1);
    cki("amr_add dup", amr_add(ab, ip0, 0x208D, 1, 1001), 0);
    unsigned ip1 = 0x08070605u;   /* 5.6.7.8 */
    cki("amr_add ip1", amr_add(ab, ip1, 0x208D, 1, 2000), 1);
    cki("amr_count", amr_count(ab), 2);
    cki("amr_lookup ip0 idx", amr_lookup(ab, ip0), 0);
    cki("amr_lookup ip1 idx", amr_lookup(ab, ip1), 1);
    cki("amr_lookup missing", amr_lookup(ab, 0xAAAAAAAAu), -1);

    /* read record 0 and check 18-byte layout */
    unsigned char rec[18];
    cki("amr_get_i 0", amr_get_i(ab, 0, rec), 1);
    unsigned ipr; memcpy(&ipr, rec, 4); cki("rec0 ip", ipr, ip0);
    unsigned short pr; memcpy(&pr, rec+4, 2); cki("rec0 port BE", pr, 0x208D);
    unsigned long long sv; memcpy(&sv, rec+6, 8); cki("rec0 services", sv, 1);
    unsigned ls; memcpy(&ls, rec+14, 4); cki("rec0 lastseen", ls, 1000);

    /* p2p_addr_v1: build 2-record wire payload and compare byte-exact */
    static unsigned char src[2*18];
    amr_get_i(ab, 0, src);
    amr_get_i(ab, 1, src+18);
    static unsigned char out[2*30+1];
    long n = p2p_addr_v1(out, src, 2);
    cki("p2p_addr_v1 len", n, 1+2*30);
    /* reference build */
    unsigned char ref[1+2*30];
    ref[0]=2;
    for(int k=0;k<2;k++){
        unsigned char* s=src+k*18;
        unsigned char* r=ref+1+k*30;
        /* time = lastseen LE */
        r[0]=s[14];r[1]=s[15];r[2]=s[16];r[3]=s[17];
        /* services LE */
        memcpy(r+4, s+6, 8);
        /* ip (v4) into 16-byte at 12 */
        memset(r+12,0,16); r[12]=s[0];r[13]=s[1];r[14]=s[2];r[15]=s[3];
        /* port BE already BE */
        r[28]=s[4];r[29]=s[5];
    }
    cki("p2p_addr_v1 payload byte-exact", memcmp(out, ref, 1+2*30)==0, 1);

    /* p2p_addr_count parses it back */
    cki("p2p_addr_count 2", p2p_addr_count(out, 1+2*30), 2);
    /* truncated -> -1 */
    cki("p2p_addr_count truncated", p2p_addr_count(out, 10), -1);

    unlink("peers.dat");
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
