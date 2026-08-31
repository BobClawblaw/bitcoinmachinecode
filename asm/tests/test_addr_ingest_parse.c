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

#include "../daemon/addrbook.h"
extern long addr_ingest_msg(void* ab, const char* cmd, const unsigned char* pl, long plen);
extern ab2_t* addr_book(void);
static void book_reset(void){ unlink("peers.dat"); unlink("peers2.dat"); }

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

static void check_book(const char* tag){
    char l[160];
    ab2_t* b = addr_book();
    snprintf(l, sizeof l, "%s: 3 records in the book", tag); ck(l, b && ab2_count(b) == 3);
    struct { const char* hp; unsigned long long svc; } want[3] = {
        {"5.6.7.8:8333", 9}, {"9.10.11.12:8333", 1}, {"200.1.2.3:8334", 0x409} };
    for (int i = 0; i < 3 && b; i++){
        bmc_addr_t a; bmc_addr_from_string_port(&a, want[i].hp, 0);
        long idx = ab2_find(b, &a); ab2_rec_t r;
        snprintf(l, sizeof l, "%s: %s in the book (address + port)", tag, want[i].hp);
        ck(l, idx >= 0 && ab2_get(b, idx, &r));
        snprintf(l, sizeof l, "%s: %s services 0x%llx", tag, want[i].hp, want[i].svc);
        ck(l, idx >= 0 && r.services == want[i].svc);
    }
}

int main(void){
    tt_isolate();

    printf("== legacy addr (Core msg_addr bytes) ==\n");
    book_reset();
    ck("3 added", addr_ingest_msg(NULL, "addr", CORE_V1_3, (long)sizeof CORE_V1_3) == 3);
    check_book("v1");

    printf("\n== addrv2 (Core msg_addrv2 bytes): the same three again are duplicates ==\n");
    ck("0 added (all three already present)", addr_ingest_msg(NULL, "addrv2", CORE_V2_3, (long)sizeof CORE_V2_3) == 0);
    check_book("v2");

    printf("\n== regression: a v1 record that is NOT IPv4-mapped must be skipped, never fabricated ==\n");
    /* time 0x68b09a3c, a native IPv6 address in the ip16 field: the old code
     * ended up adding 60.154.176.104 (the time bytes) with port 8333 */
    static unsigned char one[31];
    one[0] = 1; unsigned t = 0x68b09a3cu; memcpy(one+1, &t, 4); one[5] = 9;
    static const unsigned char v6[16] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    memcpy(one+13, v6, 16); one[29] = 0x20; one[30] = 0x8d;
    /* 2001:db8::/32 is documentation space: unroutable, so the record must
     * be skipped -- and never turned into an IPv4 made of time bytes */
    long before = ab2_count(addr_book());
    ck("0 added from an unroutable native-IPv6 v1 record", addr_ingest_msg(NULL, "addr", one, 31) == 0);
    ck("book unchanged (no address fabricated from the timestamp)", ab2_count(addr_book()) == before);
    { bmc_addr_t fab; bmc_addr_from_string_port(&fab, "60.154.176.104:8333", 0);
      ck("the old fabricated address 60.154.176.104 is NOT in the book", ab2_find(addr_book(), &fab) < 0); }

    printf("\n== a ROUTABLE native IPv6 v1 record is kept as ipv6 ==\n");
    { static const unsigned char v6r[16] = {0x2a,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
      memcpy(one+13, v6r, 16);
      ck("1 added", addr_ingest_msg(NULL, "addr", one, 31) == 1);
      bmc_addr_t a; bmc_addr_from_string_port(&a, "[2a01::1]:8333", 0); ab2_rec_t r;
      ck("stored as network ipv6 with port 8333", ab2_find(addr_book(), &a) >= 0 && ab2_get(addr_book(), ab2_find(addr_book(), &a), &r) && r.a.net == BMC_NET_IPV6); }

    printf("\n== addrv2 with onion + i2p + cjdns entries (Core's mixed message) ==\n");
    { static const unsigned char MIXED[] = {0x05,0x00,0xf1,0x53,0x65,0x09,0x01,0x04,0x7b,0x7b,0x7b,0x01,0x20,0x8d,0x01,0xf1,0x53,0x65,0x01,0x02,0x10,0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,0x01,0x20,0x8e,0x02,0xf1,0x53,0x65,0x09,0x04,0x20,0x79,0xbc,0xc6,0x25,0x18,0x4b,0x05,0x19,0x49,0x75,0xc2,0x8b,0x66,0xb6,0x6b,0x04,0x69,0xf7,0xf6,0x55,0x6f,0xb1,0xac,0x31,0x89,0xa7,0x9b,0x40,0xdd,0xa3,0x2f,0x1f,0x20,0x8f,0x03,0xf1,0x53,0x65,0x09,0x05,0x20,0x17,0x0c,0x56,0xce,0x72,0xa5,0xa0,0xe6,0x23,0x06,0xa3,0xc7,0x08,0x43,0x18,0xee,0x3a,0x46,0x35,0x5d,0x17,0xf6,0x78,0x96,0xa0,0x9c,0x51,0xef,0xbe,0x23,0xfd,0x71,0x00,0x00,0x04,0xf1,0x53,0x65,0xfd,0x09,0x04,0x06,0x10,0xfc,0x00,0x00,0x01,0x00,0x02,0x00,0x03,0,0,0,0,0,0,0,0x04,0x20,0x91};
      long n = addr_ingest_msg(NULL, "addrv2", MIXED, (long)sizeof MIXED);
      ck("4 of 5 added (the 2001:db8:: documentation address is unroutable)", n == 4);
      bmc_addr_t a; ab2_rec_t r;
      bmc_addr_from_string_port(&a, "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:8335", 0);
      ck("onion stored", ab2_find(addr_book(), &a) >= 0 && ab2_get(addr_book(), ab2_find(addr_book(), &a), &r) && r.a.net == BMC_NET_TORV3);
      bmc_addr_from_string_port(&a, "c4gfnttsuwqomiygupdqqqyy5y5emnk5c73hrfvatri67prd7vyq.b32.i2p", 0);
      ck("i2p stored (port 0)", ab2_find(addr_book(), &a) >= 0);
      bmc_addr_from_string_port(&a, "[fc00:1:2:3::4]:8337", 0);
      ck("cjdns stored with services 0x409", ab2_find(addr_book(), &a) >= 0 && ab2_get(addr_book(), ab2_find(addr_book(), &a), &r) && r.services == 0x409); }

    book_reset();
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
