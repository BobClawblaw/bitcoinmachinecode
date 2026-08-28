/* tests/test_addr_ingest_parse.c -- the addr / addrv2 INGEST parsers
 * (daemon/addr_ingest.c) on Bitcoin Core's own bytes, hermetically.
 *
 * Until 2026-08-28 the v1 parser read the IPv4 from record offset 12 (the
 * first four bytes of the ip16 field, always zero for a ::ffff:-mapped
 * address) and "fell back" to offset 0 -- the timestamp -- so a Core-format
 * v1 reply yielded either nothing or a FABRICATED address built from time
 * bytes, written to the book with the real port. Both parsers also stored
 * the port host-order while the book's contract (and the DNS-seed writers)
 * is big-endian on disk. Neither parser had a hermetic test; the only test
 * needed a live peer. Found by an adversarial review that executed the
 * parser on the bytes Core's msg_addr produces.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "test_tmpdir.h"

extern int  amr_init(void* ab);
extern long amr_count(void* ab);
extern int  amr_get_i(void* ab, long i, void* out);
extern long addr_ingest_msg(void* ab, const char* cmd, const unsigned char* pl, long plen);

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

/* Core's msg_addr / msg_addrv2 for (5.6.7.8:8333 svc 9 t 1700000000)
 * (9.10.11.12:8333 svc 1 t 1700000001) (200.1.2.3:8334 svc 0x409 t 1700000002) */
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

static void check_book(void* ab, const char* tag){
    char l[160];
    snprintf(l, sizeof l, "%s: 3 records in the book", tag); ck(l, amr_count(ab) == 3);
    struct { unsigned char ip[4]; unsigned char port[2]; unsigned long long svc; } want[3] = {
        {{5,6,7,8},{0x20,0x8d},9}, {{9,10,11,12},{0x20,0x8d},1}, {{200,1,2,3},{0x20,0x8e},0x409} };
    for (int i = 0; i < 3; i++){
        unsigned char r[18]; if (amr_get_i(ab, i, r) != 1){ snprintf(l,sizeof l,"%s: read rec %d",tag,i); ck(l,0); continue; }
        unsigned long long svc; memcpy(&svc, r+6, 8);
        snprintf(l, sizeof l, "%s: rec %d ip %u.%u.%u.%u (network order, from offset 24)", tag, i, r[0],r[1],r[2],r[3]);
        ck(l, memcmp(r, want[i].ip, 4) == 0);
        snprintf(l, sizeof l, "%s: rec %d port bytes %02x %02x (big-endian on disk)", tag, i, r[4], r[5]);
        ck(l, r[4] == want[i].port[0] && r[5] == want[i].port[1]);
        snprintf(l, sizeof l, "%s: rec %d services 0x%llx", tag, i, svc);
        ck(l, svc == want[i].svc);
    }
}

int main(void){
    tt_isolate();
    static unsigned char ab[64];

    printf("== legacy addr (Core msg_addr bytes) ==\n");
    unlink("peers.dat"); ck("amr_init", amr_init(ab) == 1);
    ck("3 added", addr_ingest_msg(ab, "addr", CORE_V1_3, (long)sizeof CORE_V1_3) == 3);
    check_book(ab, "v1");
    close(*(int*)ab);

    printf("\n== addrv2 (Core msg_addrv2 bytes) ==\n");
    unlink("peers.dat"); ck("amr_init", amr_init(ab) == 1);
    ck("3 added", addr_ingest_msg(ab, "addrv2", CORE_V2_3, (long)sizeof CORE_V2_3) == 3);
    check_book(ab, "v2");
    close(*(int*)ab);

    printf("\n== regression: a v1 record that is NOT IPv4-mapped must be skipped, never fabricated ==\n");
    /* time 0x68b09a3c, a native IPv6 address in the ip16 field: the old code
     * ended up adding 60.154.176.104 (the time bytes) with port 8333 */
    static unsigned char one[31];
    one[0] = 1; unsigned t = 0x68b09a3cu; memcpy(one+1, &t, 4); one[5] = 9;
    static const unsigned char v6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    memcpy(one+13, v6, 16); one[29] = 0x20; one[30] = 0x8d;
    unlink("peers.dat"); ck("amr_init", amr_init(ab) == 1);
    ck("0 added from a native-IPv6 v1 record", addr_ingest_msg(ab, "addr", one, 31) == 0);
    ck("book stays empty (no address fabricated from the timestamp)", amr_count(ab) == 0);
    close(*(int*)ab);

    unlink("peers.dat");
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
