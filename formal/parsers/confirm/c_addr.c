/* confirm X-ADDR1-core / X-ADDRV2-core on the compiled addr_ingest.c +
 * netaddr.c + bitcoin_addrmgr.o (the real NASM p2p_addr_count):
 *  (a) addr whose count is ff 01 00 00 00 01 00 00 00 (2^32 + 1): Core's
 *      ReadCompactSize throws "size too large"; the asm counter reads 4 bytes
 *      (1) and the record is taken;
 *  (b) addr whose count is the non-canonical fd 01 00: Core throws
 *      "non-canonical ReadCompactSize()"; the record is taken;
 *  (c) addrv2 with count 2 and only ONE record present (truncated): Core's
 *      vector read throws at the end of data and takes nothing; bmc takes 1;
 *  (d) addrv2 whose second record is net 1 (IPv4) with length 5: Core throws
 *      "BIP155 IPv4 address with length 5"; bmc skips it and takes the first.
 * The book is a counting stub (the parse is the subject, not the book). */
#include <stdio.h>
#include <string.h>
#include "netaddr.h"
#include "addrbook.h"
#include "node_config.h"
node_config_t g_cfg;
static int g_added;
ab2_t* ab2_open(const char* d, int rw){ (void)d; (void)rw; static char x; return (ab2_t*)&x; }
int ab2_add_from(ab2_t* b, const bmc_addr_t* a, unsigned long long s, unsigned t, unsigned g){ (void)b; (void)a; (void)s; (void)t; (void)g; g_added++; return 1; }
long ab2_count(const ab2_t* b){ (void)b; return 0; }
int asmap_active(void){ return 0; }
unsigned asmap_lookup_net(int n, const unsigned char* a, int l){ (void)n; (void)a; (void)l; return 0; }
void sha3_256(unsigned char o[32], const void* d, unsigned long l){ (void)o; (void)d; (void)l; }
int tcp_connect_ip(unsigned ip, unsigned short p){ (void)ip; (void)p; return -1; }
long p2p_write(int f, const char* c, unsigned cl, const void* p, unsigned pl){ (void)f; (void)c; (void)cl; (void)p; (void)pl; return -1; }
int p2p_read(int f, char c[12], void* p, unsigned cap, unsigned* pl){ (void)f; (void)c; (void)p; (void)cap; (void)pl; return -1; }
void fd_close(int f){ (void)f; }
unsigned net_netgroup_v4(unsigned ip){ return ip >> 16; }
void dial_gate_wait(void){}
long addr_ingest_msg_v(void* ab, const char* cmd, const unsigned char* pl, long plen, long limit, int* viol);
static long rec_v1(unsigned char* o, int ip3){ memset(o, 0, 30); o[0] = 0x00; o[1] = 0x50; o[2] = 0x3b; o[3] = 0x66; o[4] = 1;
    o[22] = 0xff; o[23] = 0xff; o[24] = 8; o[25] = 8; o[26] = 4; o[27] = (unsigned char)ip3; o[28] = 0x20; o[29] = 0x8d; return 30; }
static long rec_v2(unsigned char* o, int net, int alen, int ip3){ long n = 0; o[n++] = 0x00; o[n++] = 0x50; o[n++] = 0x3b; o[n++] = 0x66; o[n++] = 1;
    o[n++] = (unsigned char)net; o[n++] = (unsigned char)alen; for (int i = 0; i < alen; i++) o[n++] = (unsigned char)(i == 0 ? 8 : i == 3 ? ip3 : 8); o[n++] = 0x20; o[n++] = 0x8d; return n; }
static int run(const char* what, const char* cmd, const unsigned char* p, long n){
    g_added = 0; int viol = -1; long r = addr_ingest_msg_v(0, cmd, p, n, 0, &viol);
    printf("  %-58s added=%ld viol=%d -> %s\n", what, r, viol, r > 0 ? "CONFIRMED (Core takes nothing)" : "not reproduced");
    return r > 0;
}
int main(int argc, char** argv){
    (void)argc; (void)argv;
    g_cfg.addr_max_per_response = 1000; g_cfg.addr_max_per_netgroup = 1000;
    unsigned char b[128]; long n; int ok = 0;
    n = 0; b[n++] = 0xff; b[n++] = 1; b[n++] = 0; b[n++] = 0; b[n++] = 0; b[n++] = 1; b[n++] = 0; b[n++] = 0; b[n++] = 0; n += rec_v1(b + n, 4);
    ok += run("(a) addr, count ff 0100000001000000 (2^32+1)", "addr", b, n);
    n = 0; b[n++] = 0xfd; b[n++] = 1; b[n++] = 0; n += rec_v1(b + n, 5);
    ok += run("(b) addr, non-canonical count fd 0100", "addr", b, n);
    n = 0; b[n++] = 2; n += rec_v2(b + n, 1, 4, 6);
    ok += run("(c) addrv2, count 2, one record (truncated)", "addrv2", b, n);
    n = 0; b[n++] = 2; n += rec_v2(b + n, 1, 4, 7); n += rec_v2(b + n, 1, 5, 9);
    ok += run("(d) addrv2, second record IPv4 with length 5", "addrv2", b, n);
    return ok == 4 ? 0 : 1;
}
