/* tests/test_addrbook.c -- the version-2 address book: every network, dedup
 * by (net, addr, port), refresh of an existing entry, persistence across
 * reopen, migration from the legacy 18-byte IPv4 book, eviction when full. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "../daemon/addrbook.h"
#include "test_tmpdir.h"
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static const char* ONION = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion";
static const char* I2P = "c4gfnttsuwqomiygupdqqqyy5y5emnk5c73hrfvatri67prd7vyq.b32.i2p";
int main(void){
    tt_isolate();
    bmc_addr_t a; ab2_rec_t r;
    printf("== legacy migration ==\n");
    /* a legacy book: 5.6.7.8:8333 svc 9 seen 100; 10.0.0.1 (unroutable); 9.10.11.12:8334 svc 1 */
    { FILE* f = fopen("peers.dat", "wb");
      unsigned char rec[18];
      memset(rec, 0, 18); rec[0]=5;rec[1]=6;rec[2]=7;rec[3]=8; rec[4]=0x20;rec[5]=0x8d; rec[6]=9; rec[14]=100; fwrite(rec,1,18,f);
      memset(rec, 0, 18); rec[0]=10;rec[1]=0;rec[2]=0;rec[3]=1; rec[4]=0x20;rec[5]=0x8d; rec[6]=9; rec[14]=100; fwrite(rec,1,18,f);
      memset(rec, 0, 18); rec[0]=9;rec[1]=10;rec[2]=11;rec[3]=12; rec[4]=0x20;rec[5]=0x8e; rec[6]=1; rec[14]=101; fwrite(rec,1,18,f);
      fclose(f); }
    ab2_t* b = ab2_open(".", 1);
    ck("open creates peers2.dat and migrates", b && access("peers2.dat", F_OK) == 0);
    ck("2 routable legacy entries migrated (10/8 dropped)", ab2_count(b) == 2);
    bmc_addr_from_string_port(&a, "9.10.11.12:8334", 0);
    ck("migrated entry found with its port and services", ab2_find(b, &a) >= 0 && ab2_get(b, ab2_find(b, &a), &r) && r.services == 1 && r.last_seen == 101);

    printf("\n== add every network, dedup by (net, addr, port) ==\n");
    bmc_addr_from_string_port(&a, ONION, 8333);            ck("add onion", ab2_add(b, &a, 9, 200) == 1);
    bmc_addr_from_string_port(&a, I2P, 0);                 ck("add i2p", ab2_add(b, &a, 9, 201) == 1);
    bmc_addr_from_string_port(&a, "[fc00:1:2:3::4]:8337", 0); ck("add cjdns", ab2_add(b, &a, 0x409, 202) == 1);
    bmc_addr_from_string_port(&a, "[2a01::1]:8333", 0);     ck("add ipv6", ab2_add(b, &a, 9, 203) == 1);
    bmc_addr_from_string_port(&a, ONION, 8333);            ck("same onion again = dup (0)", ab2_add(b, &a, 9, 150) == 0);
    bmc_addr_from_string_port(&a, ONION, 8334);            ck("same onion, other port = new", ab2_add(b, &a, 9, 204) == 1);
    ck("count 7", ab2_count(b) == 7);
    ck("per-network counts", ab2_count_net(b, BMC_NET_IPV4) == 2 && ab2_count_net(b, BMC_NET_TORV3) == 2 && ab2_count_net(b, BMC_NET_I2P) == 1 && ab2_count_net(b, BMC_NET_CJDNS) == 1 && ab2_count_net(b, BMC_NET_IPV6) == 1);
    bmc_addr_from_string_port(&a, ONION, 8333);
    ck("refresh: a NEWER last_seen updates the entry", ab2_add(b, &a, 9, 999) == 0 && ab2_get(b, ab2_find(b, &a), &r) && r.last_seen == 999);
    ck("refresh: an OLDER last_seen does not", ab2_add(b, &a, 9, 5) == 0 && ab2_get(b, ab2_find(b, &a), &r) && r.last_seen == 999);
    ab2_close(b);

    printf("\n== persistence: reopen read-only ==\n");
    b = ab2_open(".", 0);
    ck("reopened with 7 records", b && ab2_count(b) == 7);
    bmc_addr_from_string_port(&a, I2P, 0);
    ck("i2p entry intact after reopen", ab2_find(b, &a) >= 0 && ab2_get(b, ab2_find(b, &a), &r) && r.a.net == BMC_NET_I2P && r.last_seen == 201);
    ck("read-only refuses add", ab2_add(b, &a, 9, 1) == -1);
    ck("a second open does NOT re-migrate (still 7)", ab2_count(b) == 7);
    ab2_close(b);

    printf("\n== a reader sees IN-PLACE rewrites, not just growth ==\n");
    { ab2_t* w = ab2_open(".", 1); ab2_t* rdr = ab2_open(".", 0);
      bmc_addr_from_string_port(&a, "5.6.7.8:8333", 0);
      long i = ab2_find(rdr, &a); ab2_rec_t before; ab2_get(rdr, i, &before);
      sleep(1);                                   /* mtime has 1s granularity */
      ab2_add(w, &a, 9, before.last_seen + 500);  /* same record, newer last_seen: no size change */
      ck("before refresh the reader still has the old value", ab2_get(rdr, i, &r) && r.last_seen == before.last_seen);
      ab2_refresh(rdr);
      ck("after refresh the reader sees the rewrite", ab2_get(rdr, ab2_find(rdr, &a), &r) && r.last_seen == before.last_seen + 500);
      ab2_close(w); ab2_close(rdr); }

    printf("\n== a truncated peers2.dat is rebuilt, not fatal for ever ==\n");
    { ab2_close(ab2_open(".", 1));
      FILE* f = fopen("peers2.dat", "wb"); fclose(f);          /* 0 bytes, as a kill between creat and header would leave */
      ab2_t* b2 = ab2_open(".", 0);
      ck("a READER refuses a corrupt book (it must not rewrite it)", b2 == NULL);
      b2 = ab2_open(".", 1);
      ck("a WRITER rebuilds it and re-migrates the legacy book", b2 != NULL && ab2_count(b2) == 2);
      ck("the corrupt file is kept aside as peers2.dat.bad", access("peers2.dat.bad", F_OK) == 0);
      ab2_close(b2); }

    printf("\n== eviction when full ==\n");
    unlink("peers2.dat"); unlink("peers.dat");
    b = ab2_open(".", 1);
    for (long k = 0; k < AB2_MAX; k++){
        memset(&a, 0, sizeof a); a.net = BMC_NET_IPV4; a.len = 4;
        a.addr[0] = 11; a.addr[1] = (unsigned char)(k >> 16); a.addr[2] = (unsigned char)(k >> 8); a.addr[3] = (unsigned char)k; a.port = 8333;
        ab2_add(b, &a, 9, (unsigned)(1000 + k));
    }
    ck("filled to AB2_MAX", ab2_count(b) == AB2_MAX);
    bmc_addr_from_string_port(&a, ONION, 8333);
    ck("one more evicts the oldest instead of failing", ab2_add(b, &a, 9, 5000000) == 1 && ab2_count(b) == AB2_MAX && ab2_find(b, &a) >= 0);
    { bmc_addr_t old; memset(&old, 0, sizeof old); old.net = BMC_NET_IPV4; old.len = 4; old.addr[0] = 11; old.port = 8333;  /* k = 0, seen 1000 */
      ck("the evicted one was the oldest (k=0)", ab2_find(b, &old) < 0); }
    ab2_close(b);
    printf(fails ? "\nFAILURES %d\n" : "\nALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
