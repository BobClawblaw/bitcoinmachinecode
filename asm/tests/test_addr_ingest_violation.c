/* tests/test_addr_ingest_violation.c -- audit 2026-09-02 N3: a malformed
 * addr/addrv2 payload, or one declaring more than MAX_ADDR_TO_SEND (1000)
 * entries, is reported as a protocol violation through the `viol` out-param
 * of addr_ingest_msg_v, so the worker can score the peer (Core: Misbehaving
 * "addr message size = %u"). A legal payload never sets it. */
#include <stdio.h>
#include <string.h>
extern long addr_ingest_msg_v(void* ab, const char* cmd, const unsigned char* pl, long plen, long limit, int* viol);
static int fails = 0;
static void ck(const char* l, int c){ printf("  %s %s\n", c ? "ok  " : "FAIL", l); if (!c) fails++; }
int main(void){
    int v; unsigned char pl[64];
    printf("== addrv2 ==\n");
    memset(pl, 0, sizeof pl); pl[0] = 0xfd; pl[1] = 0xe9; pl[2] = 0x03;        /* count 1001, no records */
    v = -1; addr_ingest_msg_v(NULL, "addrv2", pl, 3, 0, &v);
    ck("count 1001 (> MAX_ADDR_TO_SEND) is a violation", v == 1);
    pl[0] = 0xfd; pl[1] = 0xe8; pl[2] = 0x03;                                    /* count 1000, no records: legal, just empty */
    v = -1; addr_ingest_msg_v(NULL, "addrv2", pl, 3, 0, &v);
    ck("count 1000 is not a violation", v == 0);
    pl[0] = 0xfd;                                                                /* CompactSize marker with no bytes behind it */
    v = -1; addr_ingest_msg_v(NULL, "addrv2", pl, 1, 0, &v);
    ck("a truncated count is a violation", v == 1);
    pl[0] = 0;
    v = -1; addr_ingest_msg_v(NULL, "addrv2", pl, 1, 0, &v);
    ck("an empty addrv2 is not a violation", v == 0);
    printf("== legacy addr ==\n");
    memset(pl, 0, sizeof pl); pl[0] = 5;                                         /* declares 5 records, carries 30 bytes */
    v = -1; addr_ingest_msg_v(NULL, "addr", pl, 31, 0, &v);
    ck("a count that does not fit the payload is a violation", v == 1);
    pl[0] = 1;                                                                   /* 1 record, 30 bytes: legal shape */
    v = -1; addr_ingest_msg_v(NULL, "addr", pl, 31, 0, &v);
    ck("one well-formed record is not a violation", v == 0);
    pl[0] = 0;
    v = -1; addr_ingest_msg_v(NULL, "addr", pl, 1, 0, &v);
    ck("an empty addr is not a violation", v == 0);
    printf("== the old entry points still answer ==\n");
    extern long addr_ingest_msg_n(void*, const char*, const unsigned char*, long, long);
    ck("addr_ingest_msg_n on a violating payload returns 0 without a viol pointer", addr_ingest_msg_n(NULL, "addrv2", (unsigned char*)"\xfd\xe9\x03", 3, 0) == 0);
    printf("%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL PASS", fails);
    return fails ? 1 : 0;
}
