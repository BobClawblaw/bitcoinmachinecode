/* tests/test_addr_ingest_violation.c -- which addr/addrv2 payloads are taken,
 * dropped, or scored (daemon/addr_ingest.c, bitcoin_addrmgr.asm
 * p2p_addr_count, daemon/netaddr.c bmc_addr_decode_v2).
 *
 * Core's rule (net_processing.cpp ADDR/ADDRV2, v31.1): the whole vector is
 * deserialized first. Any deserialization failure -- a non-canonical or
 * over-MAX_SIZE CompactSize, fewer records than the count, a KNOWN BIP155
 * network id with the wrong address length -- throws; ProcessMessages
 * catches it and the message is dropped whole, unscored. A vector that
 * deserialized and holds more than MAX_ADDR_TO_SEND (1000) entries is
 * Misbehaving ("addr message size = %u"). Everything else is processed.
 *
 * History. Audit 2026-09-02 N3 made a count above 1000, or a malformed
 * payload, a violation (`viol`), so the worker could score the peer. That
 * test asserted three cases Core does not score: a truncated count, a count
 * the payload does not hold, and a count of 1001 with no records behind it
 * -- each a payload Core's deserializer throws on, dropped without a score.
 * They pinned the over-scoring and are inverted below. formal/parsers F2
 * (2026-10-23) then found payloads Core drops whole that this node took
 * addresses from:
 *   (a) addr count ff 01000000 01000000 (2^32 + 1): p2p_addr_count read 4 of
 *       the 8 count bytes, so the count was 1;
 *   (b) a non-canonical count (fd 0100 for 1);
 *   (c) addrv2 with fewer records than its count (the present ones kept);
 *   (d) addrv2 whose second record is a known network (IPv4) with length 5
 *       (skipped as "unknown", the first kept).
 * Each is asserted to add nothing and score nothing, beside the
 * Core-matching cases that must still work: a well-formed 1000-entry addr
 * and addrv2 (taken, up to the per-response quota), a 1001-entry one (scored,
 * nothing taken), an unknown network id skipped with the rest kept. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "test_tmpdir.h"
extern long addr_ingest_msg_v(void* ab, const char* cmd, const unsigned char* pl, long plen, long limit, int* viol);
extern long addr_msg_records(const char* cmd, const unsigned char* pl, long plen) __attribute__((weak));   /* weak: the build without it still runs every other case */
extern long p2p_addr_count(const void* pl, long plen);
static int fails = 0;
static void ck(const char* l, int c){ printf("  %s %s\n", c ? "ok  " : "FAIL", l); if (!c) fails++; }
/* The book stays open in this process (addr_book() opens it once), so
 * removing its files does not empty it: every case uses addresses no other
 * case uses, and counts what it adds. */
static void book_reset(void){ unlink("peers.dat"); unlink("peers2.dat"); }

/* routable IPv4 i: a distinct /16 per index (11.0/16 and up), so the
 * per-netgroup quota never decides a count */
static void ip_of(unsigned i, unsigned char ip[4]){ ip[0] = (unsigned char)(11 + i / 200); ip[1] = (unsigned char)(i % 200); ip[2] = 1; ip[3] = 1; }
static const unsigned T = 1700000000u;
static long v1_rec(unsigned char* o, unsigned i){
    o[0]=(unsigned char)T; o[1]=(unsigned char)(T>>8); o[2]=(unsigned char)(T>>16); o[3]=(unsigned char)(T>>24);
    memset(o + 4, 0, 8); o[4] = 9;                                  /* services NETWORK|WITNESS */
    memset(o + 12, 0, 10); o[22] = 0xff; o[23] = 0xff; ip_of(i, o + 24);
    o[28] = 0x20; o[29] = 0x8d;                                     /* 8333 */
    return 30;
}
static long v2_rec(unsigned char* o, unsigned i, int net, int alen){
    long p = 0;
    o[p++]=(unsigned char)T; o[p++]=(unsigned char)(T>>8); o[p++]=(unsigned char)(T>>16); o[p++]=(unsigned char)(T>>24);
    o[p++] = 9;                                                     /* services, CompactSize */
    o[p++] = (unsigned char)net; o[p++] = (unsigned char)alen;
    unsigned char ip[4]; ip_of(i, ip);
    for (int k = 0; k < alen; k++) o[p++] = k < 4 ? ip[k] : 0;
    o[p++] = 0x20; o[p++] = 0x8d;
    return p;
}
static long csz(unsigned char* o, unsigned long n){
    if (n < 0xfd){ o[0] = (unsigned char)n; return 1; }
    o[0] = 0xfd; o[1] = (unsigned char)n; o[2] = (unsigned char)(n >> 8); return 3;
}
static unsigned char big[64 << 10];

int main(void){
    tt_isolate();   /* the ingest writes peers2.dat by bare name */
    int v; long n; unsigned char pl[96];

    printf("== addrv2: only a well-formed vector above 1000 is a violation ==\n");
    book_reset();
    memset(pl, 0, sizeof pl); pl[0] = 0xfd; pl[1] = 0xe9; pl[2] = 0x03;        /* count 1001, no records */
    v = -1; n = addr_ingest_msg_v(NULL, "addrv2", pl, 3, 0, &v);
    ck("count 1001 with no records behind it: dropped, NOT a violation (Core: end of data, unscored)", v == 0 && n == 0);
    { long p = csz(big, 1001); for (unsigned i = 0; i < 1001; i++) p += v2_rec(big + p, i, 1, 4);
      v = -1; n = addr_ingest_msg_v(NULL, "addrv2", big, p, 0, &v);
      ck("1001 well-formed records: a violation, nothing taken (Core: Misbehaving)", v == 1 && n == 0); }
    { long p = csz(big, 1000); for (unsigned i = 0; i < 1000; i++) p += v2_rec(big + p, i, 1, 4);
      v = -1; n = addr_ingest_msg_v(NULL, "addrv2", big, p, 0, &v);
      ck("1000 well-formed records: taken up to the per-response quota (256), no violation", v == 0 && n == 256); }
    book_reset();
    pl[0] = 0xfd;                                                                /* CompactSize marker with no bytes behind it */
    v = -1; addr_ingest_msg_v(NULL, "addrv2", pl, 1, 0, &v);
    ck("a truncated count is dropped, not a violation", v == 0);
    pl[0] = 0;
    v = -1; addr_ingest_msg_v(NULL, "addrv2", pl, 1, 0, &v);
    ck("an empty addrv2 is not a violation", v == 0);

    printf("== addrv2: a payload Core drops whole adds nothing (F2b, c, d) ==\n");
    book_reset();
    { long p = 0; pl[p++] = 0xfd; pl[p++] = 1; pl[p++] = 0; p += v2_rec(pl + p, 3001, 1, 4);   /* (b) count 1, 3-byte spelling */
      v = -1; n = addr_ingest_msg_v(NULL, "addrv2", pl, p, 0, &v);
      ck("F2b a non-canonical count (fd 0100) adds nothing, no violation", n == 0 && v == 0);
      p = 0; pl[p++] = 1; p += v2_rec(pl + p, 3001, 1, 4);
      ck("  ...and the canonical spelling of the same record is taken", addr_ingest_msg_v(NULL, "addrv2", pl, p, 0, &v) == 1 && v == 0); }
    book_reset();
    { long p = 0; pl[p++] = 2; p += v2_rec(pl + p, 3002, 1, 4);                                 /* (c) count 2, one record */
      v = -1; n = addr_ingest_msg_v(NULL, "addrv2", pl, p, 0, &v);
      ck("F2c count 2 with one record present adds nothing, no violation", n == 0 && v == 0); }
    { long p = 0; pl[p++] = 2; p += v2_rec(pl + p, 3003, 1, 4); p += v2_rec(pl + p, 3004, 1, 5);   /* (d) IPv4 with length 5 */
      v = -1; n = addr_ingest_msg_v(NULL, "addrv2", pl, p, 0, &v);
      ck("F2d a known network (IPv4) with length 5 adds nothing from the whole message, no violation", n == 0 && v == 0); }
    { long p = 0; pl[p++] = 1; long r0 = p; p += v2_rec(pl + p, 3005, 1, 4);
      memmove(pl + r0 + 7, pl + r0 + 5, (size_t)(p - r0 - 5)); pl[r0 + 4] = 0xfd; pl[r0 + 5] = 9; pl[r0 + 6] = 0; p += 2;   /* services 9 as fd 0900 */
      v = -1; n = addr_ingest_msg_v(NULL, "addrv2", pl, p, 0, &v);
      ck("a non-canonical services CompactSize adds nothing (Core: non-canonical ReadCompactSize)", n == 0 && v == 0); }
    { long p = 0; pl[p++] = 3; p += v2_rec(pl + p, 3006, 1, 4); p += v2_rec(pl + p, 3007, 9, 5); p += v2_rec(pl + p, 3008, 3, 7);
      v = -1; n = addr_ingest_msg_v(NULL, "addrv2", pl, p, 0, &v);
      ck("unknown ids (9, and TORv2's 3, which Core v31 no longer decodes) are skipped, the rest kept", n == 1 && v == 0); }

    printf("== legacy addr ==\n");
    book_reset();
    memset(pl, 0, sizeof pl); pl[0] = 5;                                         /* declares 5 records, carries 30 bytes */
    v = -1; addr_ingest_msg_v(NULL, "addr", pl, 31, 0, &v);
    ck("a count that does not fit the payload is dropped, not a violation", v == 0);
    pl[0] = 1;                                                                   /* 1 record, 30 bytes: legal shape */
    v = -1; addr_ingest_msg_v(NULL, "addr", pl, 31, 0, &v);
    ck("one well-formed record is not a violation", v == 0);
    pl[0] = 0;
    v = -1; addr_ingest_msg_v(NULL, "addr", pl, 1, 0, &v);
    ck("an empty addr is not a violation", v == 0);
    { long p = 0; pl[p++] = 0xff; pl[p++] = 1; pl[p++] = 0; pl[p++] = 0; pl[p++] = 0; pl[p++] = 1; pl[p++] = 0; pl[p++] = 0; pl[p++] = 0;
      p += v1_rec(pl + p, 3009);                                                    /* (a) count 2^32 + 1, one record */
      ck("F2a p2p_addr_count reads all 8 bytes of an ff count (2^32 + 1 does not fit: -1)", p2p_addr_count(pl, p) == -1);
      v = -1; n = addr_ingest_msg_v(NULL, "addr", pl, p, 0, &v);
      ck("F2a addr count ff 01000000 01000000 adds nothing, no violation", n == 0 && v == 0); }
    { long p = 0; pl[p++] = 0xfd; pl[p++] = 1; pl[p++] = 0; p += v1_rec(pl + p, 3010);       /* (b) */
      ck("F2b p2p_addr_count refuses fd 0100", p2p_addr_count(pl, p) == -1);
      v = -1; n = addr_ingest_msg_v(NULL, "addr", pl, p, 0, &v);
      ck("F2b addr count fd 0100 adds nothing, no violation", n == 0 && v == 0); }
    { long p = 0; pl[p++] = 0xfe; pl[p++] = 0x89; pl[p++] = 0x88; pl[p++] = 0x88; pl[p++] = 0x08;   /* 0x08888889: *30 wraps 32 bits to 14 */
      p += v1_rec(pl + p, 3011);
      ck("p2p_addr_count: a 4-byte count whose *30 wraps 32 bits does not fit (-1)", p2p_addr_count(pl, p) == -1); }
    { long p = csz(big, 1001); for (unsigned i = 0; i < 1001; i++) p += v1_rec(big + p, i);
      v = -1; n = addr_ingest_msg_v(NULL, "addr", big, p, 0, &v);
      ck("1001 well-formed records: a violation, nothing taken", v == 1 && n == 0);
      ck("p2p_addr_count reads the 3-byte count 1001", p2p_addr_count(big, p) == 1001); }
    book_reset();
    { long p = csz(big, 1000); for (unsigned i = 0; i < 1000; i++) p += v1_rec(big + p, 1000 + i);   /* not the addrv2 case's addresses */
      v = -1; n = addr_ingest_msg_v(NULL, "addr", big, p, 0, &v);
      ck("1000 well-formed records: taken up to the per-response quota (256), no violation", v == 0 && n == 256);
      ck("addr_msg_records counts them", addr_msg_records && addr_msg_records("addr", big, p) == 1000); }

    printf("== the old entry points still answer ==\n");
    extern long addr_ingest_msg_n(void*, const char*, const unsigned char*, long, long);
    ck("addr_ingest_msg_n on a malformed payload returns 0 without a viol pointer", addr_ingest_msg_n(NULL, "addrv2", (unsigned char*)"\xfd\xe9\x03", 3, 0) == 0);
    book_reset();
    printf("%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL PASS", fails);
    return fails ? 1 : 0;
}
