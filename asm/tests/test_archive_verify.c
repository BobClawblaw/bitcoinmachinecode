/* Integration test for the boot-time archive self-heal, run against a COPY of
 * the genuinely corrupt production index (1,003,675 entries / 944,039 unique /
 * first bad height 479,658) rather than a synthetic fake, so it exercises the
 * real damage shape: an early-block duplicate spliced onto the tail. */
#include <stdio.h>
#include <unistd.h>

extern long store_init(void* st);
extern long store_reload(void* st);
extern long archive_scan(long* entries, long* unique, long* dups);
extern int  archive_verify_and_repair(void* store_buf, int repair);

static unsigned char store_buf[4096];

int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr,"usage: %s <datadir>\n", argv[0]); return 2; }
    if (chdir(argv[1])){ perror("chdir"); return 2; }
    int failures = 0;
    printf("---- archive self-heal ----\n");

    if (store_init(store_buf)!=1 || store_reload(store_buf)!=1){ printf("FAIL: store init\n"); return 1; }

    long e=0,u=0,d=0;
    long first = archive_scan(&e,&u,&d);
    printf("scan: entries=%ld unique=%ld dups=%ld first_bad=%ld\n", e,u,d,first);
    if (first == 479658) printf("PASS: detected first bad height 479658\n");
    else { printf("FAIL: expected first bad height 479658, got %ld\n", first); failures++; }
    if (d == 59636) printf("PASS: counted all 59636 duplicate entries\n");
    else { printf("FAIL: expected 59636 dups, got %ld\n", d); failures++; }

    /* report-only must NOT modify anything */
    int ro = archive_verify_and_repair(store_buf, 0);
    long e2=0,u2=0,d2=0; archive_scan(&e2,&u2,&d2);
    if (ro < 0 && e2 == e) printf("PASS: report-only left the archive untouched\n");
    else { printf("FAIL: report-only changed the archive or misreported (%d, %ld vs %ld)\n", ro, e2, e); failures++; }

    /* repair must truncate to first_bad-1 and leave a CLEAN archive */
    int rr = archive_verify_and_repair(store_buf, 1);
    if (rr == 0) printf("PASS: repair reported success\n");
    else { printf("FAIL: repair returned %d\n", rr); failures++; }

    long e3=0,u3=0,d3=0;
    long first3 = archive_scan(&e3,&u3,&d3);
    printf("post-repair: entries=%ld unique=%ld dups=%ld first_bad=%ld\n", e3,u3,d3,first3);
    if (first3 < 0 && d3 == 0) printf("PASS: archive is CLEAN after repair (no duplicates remain)\n");
    else { printf("FAIL: still corrupt after repair (first_bad=%ld dups=%ld)\n", first3, d3); failures++; }
    if (e3 == 479658) printf("PASS: truncated to exactly 479658 entries (heights 0..479657)\n");
    else { printf("FAIL: expected 479658 entries after repair, got %ld\n", e3); failures++; }

    /* a clean archive must verify clean and be left alone */
    int again = archive_verify_and_repair(store_buf, 1);
    if (again == 1) printf("PASS: re-verify on the repaired archive reports CLEAN (idempotent)\n");
    else { printf("FAIL: re-verify returned %d on a clean archive\n", again); failures++; }

    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
