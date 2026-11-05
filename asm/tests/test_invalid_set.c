/* tests/test_invalid_set.c -- CC-10: the invalidateblock set persists, dedups, removes, and refuses junk. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "invalid_set.h"
static int checks, fails; static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
#define P "invalid_test.dat"
int main(void){
    unsigned char a[32], b[32], c[32]; memset(a,1,32); memset(b,2,32); memset(c,3,32); unlink(P);
    printf("== add / has / dedup / remove ==\n");
    invset_clear(); ok(invset_add(a) == 1 && invset_add(b) == 1 && invset_count() == 2, "two added");
    ok(invset_add(a) == 0 && invset_count() == 2, "adding a again: already present, count unchanged");
    ok(invset_has(a) && invset_has(b) && !invset_has(c), "has a, has b, not c");
    ok(invset_remove(a) == 1 && !invset_has(a) && invset_has(b) && invset_count() == 1, "remove a: gone, b remains");
    ok(invset_remove(c) == 0, "removing an absent hash: 0");
    printf("== persistence ==\n");
    invset_add(c); ok(invset_save(P) == 0, "saved");
    invset_clear(); ok(invset_load(P) == 2 && invset_has(b) && invset_has(c) && !invset_has(a), "reloaded: b and c, not a");
    invset_clear(); ok(invset_save(P) == 0 && access(P, F_OK) != 0, "an empty set removes the file");
    ok(invset_load(P) == 0 && invset_count() == 0, "no file: empty, 0");
    printf("== junk on disk ==\n");
    FILE* f = fopen(P, "wb"); fwrite("abc", 1, 3, f); fclose(f);
    ok(invset_load(P) == -1 && invset_count() == 0, "a file that is not a multiple of 32 bytes: -1 and empty");
    unlink(P);
    printf("== capacity (CON-11: the set grows; it was a fixed 64) ==\n");
    invset_clear(); int added = 0; for (int i = 0; i < 1000; i++){ unsigned char h[32]; memset(h, 0, 32); h[0] = (unsigned char)i; h[1] = (unsigned char)(i>>8); h[2] = 0xc1; if (invset_add(h) == 1) added++; }
    ok(added == 1000 && invset_count() == 1000, "CON-11: 1,000 marks are all held (no -1 at 65)");
    { unsigned char h[32]; memset(h, 0, 32); h[0] = (unsigned char)(999 & 0xff); h[1] = (unsigned char)(999 >> 8); h[2] = 0xc1;
      ok(invset_has(h), "CON-11: the 1,000th mark is found"); }
    ok(invset_save(P) == 0, "CON-11: 1,000 marks saved");
    invset_clear(); ok(invset_load(P) == 1000 && invset_count() == 1000, "CON-11: ...and all 1,000 reloaded");
    unlink(P);
    printf("== negative control: nothing marked means nothing refused ==\n");
    invset_clear(); ok(!invset_has(a) && !invset_has(b), "control: an empty set matches no hash (the pre-CC-10 node had no marks at all)");
    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails); return fails?1:0;
}
