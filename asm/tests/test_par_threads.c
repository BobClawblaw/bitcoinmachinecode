/* tests/test_par_threads.c -- -par means what Core's -par means.
 *
 * Core (node/chainstatemanager_args.cpp):
 *     script_threads = -par;                      // default 0
 *     if (script_threads <= 0) script_threads += GetNumCores();
 *     worker_threads_num = script_threads - 1;    // the main thread counts too
 * So -par is the TOTAL number of threads doing script checks, the caller
 * included: 0 = every core, -n = leave n cores free, 1 = single-threaded.
 *
 * The finding (2026-09-06): this node parsed `par`, printed it at boot, and
 * then used it for the DOWNLOAD chunk-worker count, while both script-verify
 * pools sized themselves from sysconf() and never read it. An operator asking
 * for par=8 got a node that still verified on every core AND halved its
 * download parallelism. Naming a writer without a reader is exactly how that
 * hid, so this test asserts the READER.
 *
 * Watched to fail first: with par_script_threads() returning sysconf() as it
 * used to, every check below fails except the auto one.
 */
#include <stdio.h>
#include <unistd.h>
#include "par_threads.h"

static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }

int main(void){
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN); if (ncpu < 1) ncpu = 1;
    printf("== -par is the script-verification thread count (this box: %ld cores) ==\n", ncpu);

    par_set(0);
    ok(par_get() == 0, "the configured value is kept verbatim");
    ok(par_script_threads() == (int)ncpu, "par=0 -> every core, as Core's autodetect does");

    par_set(8);
    ok(par_script_threads() == 8, "par=8 -> exactly 8 threads, whatever the box has");
    par_set(1);
    ok(par_script_threads() == 1, "par=1 -> single-threaded (the caller alone)");

    printf("== negative means LEAVE THAT MANY CORES FREE ==\n");
    par_set(-1);
    ok(par_script_threads() == (int)ncpu - 1, "par=-1 -> one core left free");
    par_set(-4);
    ok(par_script_threads() == (int)ncpu - 4, "par=-4 -> four cores left free");

    printf("== the floor: a node always has one script-checking thread ==\n");
    par_set((int)-ncpu);
    ok(par_script_threads() == 1, "par=-<cores> cannot go below one thread");
    par_set((int)-ncpu - 100);
    ok(par_script_threads() == 1, "an absurd negative still leaves one thread");

    printf("== a fixed value does NOT track the machine ==\n");
    par_set(2);
    int a = par_script_threads();
    par_set(0);
    int b = par_script_threads();
    ok(a == 2 && b == (int)ncpu && a != b,
       "par=2 and par=0 differ on a multi-core box -- the setting is read, not ignored");

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
