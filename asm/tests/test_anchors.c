/* tests/test_anchors.c -- CC-4: anchors.dat round trip in Core's format; block-only legs excluded from relay. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "anchors.h"
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);
static int checks, fails; static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
#define P "anchors_test.dat"
int main(void){
    unlink(P); const char* hosts[] = { "203.0.113.7:8333", "[2001:db8::1]:8333", "not a host", "198.51.100.9:18333" };
    printf("== write / read round trip ==\n");
    long w = anchors_write(P, hosts, 4, 0xd9b4bef9u, 0x409ULL, 1700000000u);
    ok(w == 3, "three parseable hosts written, the unparseable one skipped");
    unsigned char buf[4096]; FILE* f = fopen(P, "rb"); long len = (long)fread(buf, 1, sizeof buf, f); fclose(f);
    ok(buf[0]==0xf9 && buf[1]==0xbe && buf[2]==0xb4 && buf[3]==0xd9, "starts with the mainnet message-start, LE dword as Core writes it");
    ok(buf[4]==3, "then CompactSize count 3");
    { unsigned char h[32]; sha256d(h, buf, (unsigned long)(len-32)); ok(!memcmp(h, buf+len-32, 32), "ends with sha256d of everything before (Core SerializeFileDB)"); }
    char got[8][128]; long r = anchors_read(P, got, 8, 0xd9b4bef9u);
    ok(r == 3, "read back three");
    ok(!strcmp(got[0], hosts[0]) && !strcmp(got[2], hosts[3]), "hosts survive: first and last identical");
    printf("      %s | %s | %s\n", got[0], got[1], got[2]);
    ok(access(P, F_OK) != 0, "the file is deleted on read (a crash loop does not pin the same peers)");
    printf("== a bad file is refused and removed ==\n");
    anchors_write(P, hosts, 2, 0xd9b4bef9u, 0x409ULL, 1700000000u);
    f = fopen(P, "r+b"); fseek(f, 6, SEEK_SET); fputc(0x55, f); fclose(f);    /* corrupt a body byte */
    ok(anchors_read(P, got, 8, 0xd9b4bef9u) == -1 && access(P, F_OK) != 0, "checksum mismatch -> -1, file gone");
    anchors_write(P, hosts, 2, 0xd9b4bef9u, 0x409ULL, 1700000000u);
    ok(anchors_read(P, got, 8, 0x0709110bu) == -1, "wrong network magic (testnet) -> -1");
    ok(anchors_read(P, got, 8, 0xd9b4bef9u) == 0, "no file -> 0");
    printf("== relay fd list: block-only legs are excluded ==\n");
    int fds[5] = { 10, 11, 12, 13, -1 }; unsigned char kinds[5] = { LEG_FULL, LEG_BLOCK_ONLY, LEG_FULL, LEG_BLOCK_ONLY, LEG_FULL }; int out[5];
    int k = legs_relay_fds(fds, kinds, 5, out);
    ok(k == 2 && out[0]==10 && out[1]==-1 && out[2]==12 && out[3]==-1 && out[4]==-1, "fds 11 and 13 (block-only) become -1; two relay legs remain");
    printf("== negative control: every leg full-relay (the pre-CC-4 node) ==\n");
    unsigned char allfull[5] = {0,0,0,0,0}; k = legs_relay_fds(fds, allfull, 5, out);
    ok(k == 4 && out[1]==11 && out[3]==13, "control: nothing excluded, every leg announces transactions");
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails); return fails?1:0;
}
