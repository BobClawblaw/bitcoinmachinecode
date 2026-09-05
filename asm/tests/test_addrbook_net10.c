/* tests/test_addrbook_net10.c -- NET-10 (audit 2026-09-03, scoped in
 * docs/audits/NET-10_ADDRMAN_SCOPE.md): the address book evicted the record
 * with the smallest last_seen, and last_seen is chosen by the peer that
 * gossiped the address. So a flood did not merely dilute the book -- it
 * preferentially destroyed the once-connected entries the dialer draws from,
 * because those carry the oldest honest timestamps while attacker addresses
 * arrive looking fresh.
 *
 * The three rules, each with the control that shows it is doing the work:
 *   1. a source netgroup may hold at most ab2_set_src_cap() live entries;
 *   2. a tried entry is never evicted to make room;
 *   3. among untried entries eviction prefers terrible (unseen for a
 *      fortnight), then oldest -- not the gossiped timestamp order.
 * Plus: a version-2 file upgrades in place with every record intact.
 *
 * The book is shrunk with ab2_set_capacity() so eviction is reachable; a real
 * full-book flood rebuilds the hash per insert (~4e9 operations). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "../daemon/addrbook.h"
#include "test_tmpdir.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static bmc_addr_t v4(unsigned a, unsigned b, unsigned c, unsigned d, unsigned short port){
    bmc_addr_t x; memset(&x, 0, sizeof x);
    x.net = BMC_NET_IPV4; x.len = 4;
    x.addr[0]=(unsigned char)a; x.addr[1]=(unsigned char)b; x.addr[2]=(unsigned char)c; x.addr[3]=(unsigned char)d;
    x.port = port; return x;
}
static unsigned NOW;
#define OLD  (NOW - 30u*24*3600)      /* terrible: unseen for a month */
#define FRESH (NOW - 60u)

int main(void){
    tt_isolate_named("addrbook_net10");
    NOW = (unsigned)time(NULL);

    /* ---- rule 1: one source netgroup is capped ---------------------- */
    {
        ab2_t* b = ab2_open(".", 1); if (!b){ printf("FAIL: open\n"); return 1; }
        ab2_set_src_cap(10);
        long added = 0;
        for (int i = 0; i < 200; i++){ bmc_addr_t a = v4(51, 15, (unsigned)(i>>8), (unsigned)(i&255), 8333);
            if (ab2_add_from(b, &a, 1, FRESH, 0xAAAA0001u) == 1) added++; }
        ck("rule 1: a 200-address flood from one source netgroup stops at the cap", added == 10);
        ck("rule 1: ...and the book agrees how many that source holds", ab2_count_src(b, 0xAAAA0001u) == 10);
        long other = 0;
        for (int i = 0; i < 20; i++){ bmc_addr_t a = v4(77, 20, (unsigned)(i>>8), (unsigned)(i&255), 8333);
            if (ab2_add_from(b, &a, 1, FRESH, 0xBBBB0002u) == 1) other++; }
        ck("rule 1: a different source netgroup is unaffected", other == 10);
        long unknown = 0;
        for (int i = 0; i < 40; i++){ bmc_addr_t a = v4(99, 30, (unsigned)(i>>8), (unsigned)(i&255), 8333);
            if (ab2_add_from(b, &a, 1, FRESH, 0) == 1) unknown++; }
        ck("rule 1: an unknown source (0) is never capped", unknown == 40);
        ab2_set_src_cap(0); ab2_close(b);
    }
    /* ---- rules 2 and 3: who gets evicted ---------------------------- */
    unlink("peers2.dat");
    {
        ab2_t* b = ab2_open(".", 1); if (!b){ printf("FAIL: open 2\n"); return 1; }
        ab2_set_capacity(20);
        /* 5 tried entries with OLD timestamps -- the once-connected set the
         * dialer needs, and exactly what min(last_seen) would evict first. */
        for (int i = 0; i < 5; i++){ bmc_addr_t a = v4(10, 0, 0, (unsigned)i, 8333);
            ab2_add_from(b, &a, 1, OLD, 0); ab2_mark_tried(b, &a); }
        /* 15 untried fillers, all FRESH, so the book is exactly full */
        for (int i = 0; i < 15; i++){ bmc_addr_t a = v4(20, 0, 0, (unsigned)i, 8333);
            ab2_add_from(b, &a, 1, FRESH, 0xCCCC0003u); }
        ck("setup: the book is full", ab2_count(b) == 20);
        /* flood with fresh gossip: every insert must evict an untried filler */
        for (int i = 0; i < 100; i++){ bmc_addr_t a = v4(30, (unsigned)(i>>8), 0, (unsigned)(i&255), 8333);
            ab2_add_from(b, &a, 1, NOW, 0); }
        int tried_alive = 0;
        for (int i = 0; i < 5; i++){ bmc_addr_t a = v4(10, 0, 0, (unsigned)i, 8333); if (ab2_find(b, &a) >= 0) tried_alive++; }
        ck("rule 2: all 5 tried entries survive a 100-address flood", tried_alive == 5);
        ck("rule 2: ...even though their last_seen is the oldest in the book", tried_alive == 5);
        ab2_close(b);
    }
    /* ---- rule 3: untried-terrible goes before untried-fresh --------- */
    unlink("peers2.dat");
    {
        ab2_t* b = ab2_open(".", 1); if (!b){ printf("FAIL: open 3\n"); return 1; }
        ab2_set_capacity(4);
        bmc_addr_t stale = v4(40,0,0,1,8333), fresh1 = v4(40,0,0,2,8333);
        bmc_addr_t fresh2 = v4(40,0,0,3,8333), fresh3 = v4(40,0,0,4,8333);
        ab2_add_from(b, &fresh1, 1, FRESH, 0); ab2_add_from(b, &stale, 1, OLD, 0);
        ab2_add_from(b, &fresh2, 1, FRESH, 0); ab2_add_from(b, &fresh3, 1, FRESH, 0);
        bmc_addr_t nw = v4(50,0,0,1,8333);
        ab2_add_from(b, &nw, 1, NOW, 0);
        ck("rule 3: the terrible (month-old) entry is the one evicted", ab2_find(b, &stale) < 0);
        ck("rule 3: ...and the fresh untried ones stay", ab2_find(b, &fresh1) >= 0 && ab2_find(b, &fresh2) >= 0 && ab2_find(b, &fresh3) >= 0);
        ab2_close(b);
    }
    /* ---- the NEGATIVE CONTROL: without the cap, the flood wins ------ */
    unlink("peers2.dat");
    {
        ab2_t* b = ab2_open(".", 1); if (!b){ printf("FAIL: open 4\n"); return 1; }
        ab2_set_capacity(20);
        ab2_set_src_cap(1000000);            /* rule 1 disabled */
        for (int i = 0; i < 20; i++){ bmc_addr_t a = v4(60, 0, 0, (unsigned)i, 8333);
            ab2_add_from(b, &a, 1, OLD, 0); }   /* honest, untried, old */
        long before = ab2_count(b);
        for (int i = 0; i < 100; i++){ bmc_addr_t a = v4(70, (unsigned)(i>>8), 0, (unsigned)(i&255), 8333);
            ab2_add_from(b, &a, 1, NOW, 0xDDDD0004u); }
        int honest_alive = 0;
        for (int i = 0; i < 20; i++){ bmc_addr_t a = v4(60, 0, 0, (unsigned)i, 8333); if (ab2_find(b, &a) >= 0) honest_alive++; }
        ck("control: with rule 1 off and nothing tried, the flood DOES evict the honest set (the finding)",
           before == 20 && honest_alive == 0);
        /* the same flood with the cap on, and the honest set marked tried */
        ab2_set_src_cap(8);
        ab2_close(b); unlink("peers2.dat");
        b = ab2_open(".", 1); ab2_set_capacity(20);
        for (int i = 0; i < 20; i++){ bmc_addr_t a = v4(60, 0, 0, (unsigned)i, 8333);
            ab2_add_from(b, &a, 1, OLD, 0); ab2_mark_tried(b, &a); }
        for (int i = 0; i < 100; i++){ bmc_addr_t a = v4(70, (unsigned)(i>>8), 0, (unsigned)(i&255), 8333);
            ab2_add_from(b, &a, 1, NOW, 0xDDDD0004u); }
        honest_alive = 0;
        for (int i = 0; i < 20; i++){ bmc_addr_t a = v4(60, 0, 0, (unsigned)i, 8333); if (ab2_find(b, &a) >= 0) honest_alive++; }
        ck("control: with the rules on, the same flood evicts none of them", honest_alive == 20);
        ab2_set_src_cap(0); ab2_set_capacity(0); ab2_close(b);
    }
    /* ---- version-2 file upgrades in place -------------------------- */
    unlink("peers2.dat");
    {
        /* hand-build a BMCADBK2 file: 16-byte header + 48-byte records */
        int fd = open("peers2.dat", O_RDWR|O_CREAT|O_TRUNC, 0644);
        unsigned char h[16]; memset(h, 0, sizeof h); memcpy(h, "BMCADBK2", 8);
        const int N = 7; h[8] = (unsigned char)N;
        if (write(fd, h, 16) != 16){ printf("FAIL: v2 header\n"); return 1; }
        for (int i = 0; i < N; i++){
            unsigned char o[48]; memset(o, 0, sizeof o);
            o[0] = BMC_NET_IPV4; o[1] = 4; o[2] = 8; o[3] = 8; o[4] = 0; o[5] = (unsigned char)i;
            o[34] = 0x20; o[35] = 0x8d;                       /* port 8333 BE */
            o[36] = 1;
            for (int k = 0; k < 4; k++) o[44+k] = (unsigned char)(FRESH >> (8*k));
            if (write(fd, o, 48) != 48){ printf("FAIL: v2 record\n"); return 1; }
        }
        close(fd);
        ab2_t* b = ab2_open(".", 1);
        ck("upgrade: a BMCADBK2 file opens", b != NULL);
        if (b){
            ck("upgrade: every record survives", ab2_count(b) == N);
            int found = 0, tried = 0;
            for (int i = 0; i < N; i++){ bmc_addr_t a = v4(8,8,0,(unsigned)i,8333);
                long ix = ab2_find(b, &a); if (ix >= 0){ found++; ab2_rec_t r; if (ab2_get(b, ix, &r) && (r.flags & AB2_F_TRIED)) tried++; } }
            ck("upgrade: every address is still findable", found == N);
            ck("upgrade: the head is marked tried (it is the once-connected set)", tried == N);
            ab2_close(b);
            /* reopening must now see a v3 file and change nothing */
            ab2_t* b2 = ab2_open(".", 1);
            ck("upgrade: reopening reads BMCADBK3 with the same count", b2 && ab2_count(b2) == N);
            ab2_close(b2);
        }
    }
    /* ---- a READ-ONLY opener of a v2 file must still work -------------- */
    unlink("peers2.dat");
    {
        int fd = open("peers2.dat", O_RDWR|O_CREAT|O_TRUNC, 0644);
        unsigned char h[16]; memset(h, 0, sizeof h); memcpy(h, "BMCADBK2", 8);
        const int N = 5; h[8] = (unsigned char)N;
        if (write(fd, h, 16) != 16){ printf("FAIL: ro v2 header\n"); return 1; }
        for (int i = 0; i < N; i++){
            unsigned char o[48]; memset(o, 0, sizeof o);
            o[0] = BMC_NET_IPV4; o[1] = 4; o[2] = 9; o[3] = 9; o[4] = 0; o[5] = (unsigned char)i;
            o[34] = 0x20; o[35] = 0x8d; o[36] = 1;
            for (int k = 0; k < 4; k++) o[44+k] = (unsigned char)(FRESH >> (8*k));
            if (write(fd, o, 48) != 48){ printf("FAIL: ro v2 record\n"); return 1; }
        }
        close(fd);
        ab2_t* ro = ab2_open(".", 0);          /* read-only, file still v2 */
        ck("read-only: a v2 file still opens (no upgrade, no NULL)", ro != NULL);
        ck("read-only: every record is visible", ro && ab2_count(ro) == N);
        if (ro){ bmc_addr_t a = v4(9,9,0,2,8333); ck("read-only: addresses are findable", ab2_find(ro, &a) >= 0); ab2_close(ro); }
        /* and the file was NOT rewritten by the reader */
        int fd2 = open("peers2.dat", O_RDONLY); unsigned char m[8];
        ck("read-only: the reader left the file at v2", fd2 >= 0 && read(fd2, m, 8) == 8 && !memcmp(m, "BMCADBK2", 8));
        if (fd2 >= 0) close(fd2);
    }
    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
