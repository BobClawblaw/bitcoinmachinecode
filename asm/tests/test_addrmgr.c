/* test_addrmgr.c -- harness for the ASM address-book manager + addr codecs.
 * Verifies amr_init/count/add/lookup/get_i, and p2p_addr_v1 / p2p_addr_v2 /
 * p2p_addr_count byte-exact against BITCOIN CORE's serializer
 * (test/functional/test_framework/messages.py: msg_addr / msg_addrv2 over
 * CAddress.serialize / serialize_v2), not against a reference built here.
 *
 * Until 2026-08-28 the v1 reference WAS built here, from the same mistaken
 * layout as the encoder: the IPv4 at bytes 12..15 of the 16-byte field with
 * no ::ffff: marker (so every address went out as the IPv6 address
 * a.b.c.d::), and a one-byte count for up to 1000 entries. The test passed
 * for as long as the encoder was wrong in exactly the way the test was.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

extern int  amr_init(void* ab);
extern long amr_count(void* ab);
extern int  amr_add  (void* ab, unsigned ip, unsigned short port, unsigned long long services, unsigned lastseen);
extern int  amr_get_i(void* ab, long i, void* out);
extern long amr_lookup(void* ab, unsigned ip);
extern long p2p_addr_v1(void* out, const void* src, long n);
extern long p2p_addr_v2(void* out, const void* src, long n);
extern long p2p_addr_count(const void* pl, long plen);

static int failures=0;
static void cki(const char*l,long g,long e){ if(g==e)printf("PASS %s (got %ld)\n",l,g); else {printf("FAIL %s got=%ld exp=%ld\n",l,g,e); failures++;} }

int main(void){
    /* fixed /tmp/amrtest was shared by every concurrent run */
    tt_isolate();
    unlink("peers.dat"); unlink("index.dat"); unlink("blk00000.dat");
    static unsigned char ab[64];
    cki("amr_init", amr_init(ab), 1);
    cki("amr_count empty", amr_count(ab), 0);

    /* ip 1.2.3.4 as network-order bytes; port 8333 passed as htons() = 0x8D20 (BE on disk); services=1; seen=1000 */
    unsigned ip0 = 0x04030201u;
    cki("amr_add new", amr_add(ab, ip0, 0x8D20 /* htons(8333): the book stores the port BE on disk */, 1, 1000), 1);
    cki("amr_add dup", amr_add(ab, ip0, 0x8D20 /* htons(8333): the book stores the port BE on disk */, 1, 1001), 0);
    unsigned ip1 = 0x08070605u;   /* 5.6.7.8 */
    cki("amr_add ip1", amr_add(ab, ip1, 0x8D20 /* htons(8333): the book stores the port BE on disk */, 1, 2000), 1);
    cki("amr_count", amr_count(ab), 2);
    cki("amr_lookup ip0 idx", amr_lookup(ab, ip0), 0);
    cki("amr_lookup ip1 idx", amr_lookup(ab, ip1), 1);
    cki("amr_lookup missing", amr_lookup(ab, 0xAAAAAAAAu), -1);

    /* read record 0 and check 18-byte layout */
    unsigned char rec[18];
    cki("amr_get_i 0", amr_get_i(ab, 0, rec), 1);
    unsigned ipr; memcpy(&ipr, rec, 4); cki("rec0 ip", ipr, ip0);
    cki("rec0 port bytes 20 8d (big-endian on disk, verbatim wire form)", rec[4]==0x20 && rec[5]==0x8d, 1);
    unsigned long long sv; memcpy(&sv, rec+6, 8); cki("rec0 services", sv, 1);
    unsigned ls; memcpy(&ls, rec+14, 4); cki("rec0 lastseen", ls, 1000);

    /* p2p_addr_v1: 2-record wire payload; the IPv4 must land at bytes 24..27
     * of the 16-byte field behind ten zero bytes and ff ff (::ffff:a.b.c.d) */
    static unsigned char src[2*18];
    amr_get_i(ab, 0, src);
    amr_get_i(ab, 1, src+18);
    static unsigned char out[2*30+1];
    long n = p2p_addr_v1(out, src, 2);
    cki("p2p_addr_v1 len", n, 1+2*30);
    unsigned char ref[1+2*30];
    ref[0]=2;
    for(int k=0;k<2;k++){
        unsigned char* s=src+k*18;
        unsigned char* r=ref+1+k*30;
        r[0]=s[14];r[1]=s[15];r[2]=s[16];r[3]=s[17];      /* time = lastseen LE */
        memcpy(r+4, s+6, 8);                               /* services LE */
        memset(r+12,0,10); r[22]=0xff; r[23]=0xff;         /* ::ffff: */
        r[24]=s[0];r[25]=s[1];r[26]=s[2];r[27]=s[3];       /* a.b.c.d */
        r[28]=s[4];r[29]=s[5];                             /* port BE */
    }
    cki("p2p_addr_v1 payload (IPv4-mapped) byte-exact", memcmp(out, ref, 1+2*30)==0, 1);
    cki("p2p_addr_count 2", p2p_addr_count(out, 1+2*30), 2);
    cki("p2p_addr_count truncated", p2p_addr_count(out, 10), -1);

    /* ---- against Bitcoin Core's own serializer ----
     * Three records: (5.6.7.8:8333 svc 9 t 1700000000) (9.10.11.12:8333 svc 1
     * t 1700000001) (200.1.2.3:8334 svc 0x409 t 1700000002). The expected
     * bytes are what Core's messages.py msg_addr / msg_addrv2 emit for them. */
    static const unsigned char CORE_V1_3[] = {
      0x03,
      0x00,0xf1,0x53,0x65, 0x09,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0xff,0xff, 5,6,7,8, 0x20,0x8d,
      0x01,0xf1,0x53,0x65, 0x01,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0xff,0xff, 9,10,11,12, 0x20,0x8d,
      0x02,0xf1,0x53,0x65, 0x09,0x04,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0xff,0xff, 200,1,2,3, 0x20,0x8e };
    static const unsigned char CORE_V2_3[] = {
      0x03,
      0x00,0xf1,0x53,0x65, 0x09, 0x01, 0x04, 5,6,7,8, 0x20,0x8d,
      0x01,0xf1,0x53,0x65, 0x01, 0x01, 0x04, 9,10,11,12, 0x20,0x8d,
      0x02,0xf1,0x53,0x65, 0xfd,0x09,0x04, 0x01, 0x04, 200,1,2,3, 0x20,0x8e };
    static unsigned char src3[3*18];
    { struct { unsigned char ip[4]; unsigned short port_h; unsigned long long svc; unsigned t; } R[3] = {
        {{5,6,7,8},8333,9,1700000000u}, {{9,10,11,12},8333,1,1700000001u}, {{200,1,2,3},8334,0x409,1700000002u} };
      for(int k=0;k<3;k++){ unsigned char* r=src3+k*18;
        memcpy(r, R[k].ip, 4);                              /* ip as stored: network order */
        r[4]=(unsigned char)(R[k].port_h>>8); r[5]=(unsigned char)R[k].port_h;   /* port BE */
        memcpy(r+6, &R[k].svc, 8); memcpy(r+14, &R[k].t, 4); } }
    static unsigned char o1[4+3*30], o2[4+3*21];
    long n1 = p2p_addr_v1(o1, src3, 3), n2 = p2p_addr_v2(o2, src3, 3);
    cki("v1 len == Core's", n1, (long)sizeof CORE_V1_3);
    cki("v1 bytes == Core msg_addr", n1==(long)sizeof CORE_V1_3 && memcmp(o1, CORE_V1_3, n1)==0, 1);
    cki("v2 len == Core's", n2, (long)sizeof CORE_V2_3);
    cki("v2 bytes == Core msg_addrv2 (services CompactSize, net 1, len 4)", n2==(long)sizeof CORE_V2_3 && memcmp(o2, CORE_V2_3, n2)==0, 1);

    /* count is a CompactSize: 300 records -> fd 2c 01 (Core: 9003 / 3903 bytes) */
    static unsigned char src300[300*18]; for(int k=0;k<300;k++) memcpy(src300+k*18, src3, 18);
    static unsigned char big1[3+300*30], big2[3+300*21];
    long b1 = p2p_addr_v1(big1, src300, 300), b2 = p2p_addr_v2(big2, src300, 300);
    cki("v1 300-record length == Core's 9003", b1, 9003);
    cki("v1 300 count prefix fd 2c 01", big1[0]==0xfd && big1[1]==0x2c && big1[2]==0x01, 1);
    cki("v2 300-record length == Core's 3903", b2, 3903);
    cki("v2 300 count prefix fd 2c 01", big2[0]==0xfd && big2[1]==0x2c && big2[2]==0x01, 1);
    cki("p2p_addr_count reads a 3-byte count", p2p_addr_count(big1, b1), 300);

    /* services CompactSize edges (Core: 253 -> fd fd 00, 0x10000 -> fe 00 00 01 00) */
    static const unsigned char CORE_V2_EDGES[] = {
      0x02, 0x07,0,0,0, 0xfd,0xfd,0x00, 0x01,0x04, 1,2,3,4, 0x00,0x01,
            0x07,0,0,0, 0xfe,0x00,0x00,0x01,0x00, 0x01,0x04, 1,2,3,4, 0x00,0x01 };
    static unsigned char srce[2*18];
    { unsigned char ip[4]={1,2,3,4}; unsigned long long s0=253, s1=0x10000; unsigned t=7;
      memcpy(srce, ip, 4); srce[4]=0; srce[5]=1; memcpy(srce+6,&s0,8); memcpy(srce+14,&t,4);
      memcpy(srce+18, ip, 4); srce[22]=0; srce[23]=1; memcpy(srce+24,&s1,8); memcpy(srce+32,&t,4); }
    static unsigned char oe[64];
    long ne = p2p_addr_v2(oe, srce, 2);
    cki("v2 services CompactSize edges == Core", ne==(long)sizeof CORE_V2_EDGES && memcmp(oe, CORE_V2_EDGES, ne)==0, 1);

    unlink("peers.dat");
    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
