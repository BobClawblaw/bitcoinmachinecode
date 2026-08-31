/* Regression test for utxo_live_recover() -- the in-place recovery that makes
 * a failed catch-up survivable instead of terminal.
 *
 * Before this existed, a catch-up failure set utxo_live_ok=0 and the node ran
 * with NO UTXO tracking until a human restarted it (observed twice on
 * 2026-08-18). The dominant cause is a full manifest, which a compaction
 * clears -- so recovery must actually reduce manifest_n to be worth anything.
 *
 * We replay a real (truncated) archive to build several runs, then assert:
 *   1. recover() on a multi-run store reports >0 successful compaction rounds
 *   2. recover() again is a clean no-op (nothing left to merge), NOT a spin
 * Run count is observed via recover()'s own return, since manifest_n is
 * private to utxo_live.c.
 *
 * FIXTURE. This needs a datadir whose UTXO store already holds SEVERAL runs,
 * which in practice means an archive replayed deep enough to have compacted
 * at least once (the 160k-180k stretch is what this was written against). A
 * short chain reloads with manifest_n=0 and assertion 1 cannot fire -- it
 * reports "recover() did nothing", which is the fixture being inadequate
 * rather than the code being wrong.
 *
 * NEVER point it at the production datadir: utxo_live_recover() COMPACTS in
 * place, so it mutates whatever store it is given. Use a copy.
 *
 * Not in `make test` for that reason; see MANUAL in
 * scripts/makefile_runlist_audit.py.
 *
 * CHAIN. Takes the chain as a second argument because the fixture decides it,
 * not the default. Pointed at a signet store while defaulting to mainnet, the
 * replay rejects every block as "unexpected-witness" -- mainnet's activation
 * schedule gates on HEIGHT, and a signet height is a small number, so real
 * signet blocks look pre-segwit. That is the same trap that made signet
 * itself reject block 1 (see daemon/chainparams.c), and it fails here in a
 * way that looks like the store is broken when it is the harness. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

extern long store_init(void* st);
extern long store_reload(void* st);
extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_applied_height(void);
extern long utxo_live_recover(void);
extern void utxo_live_set_undo_enabled(int on);

static unsigned char store_buf[4096];

extern int chainparams_select(const char* name);

int main(int argc, char** argv){
    if (argc < 2) {
        fprintf(stderr, "usage: %s <datadir> [chain]\n"
                        "  chain defaults to main; pass the chain the fixture\n"
                        "  came from (signet/testnet4/regtest) or every block\n"
                        "  is judged under mainnet's activation heights.\n", argv[0]);
        return 2;
    }
    const char* chain = (argc > 2) ? argv[2] : "main";
    if (!chainparams_select(chain)) {
        fprintf(stderr, "unknown chain: %s\n", chain); return 2;
    }
    printf("chain=%s fixture=%s\n", chain, argv[1]);
    if (chdir(argv[1]) != 0) { perror("chdir"); return 2; }

    int failures = 0;
    printf("---- utxo_live_recover ----\n");

    if (store_init(store_buf) != 1 || store_reload(store_buf) != 1) {
        printf("FAIL: store init/reload\n"); return 1;
    }
    if (!utxo_live_init(argv[1])) { printf("FAIL: utxo_live_init\n"); return 1; }

    /* Undo capture off for this test. It is not what we are testing, and it
     * dominates the runtime: every spend does a full utxo_lsm_get plus an
     * append to undo_<height>.dat before the delete. Leaving it on made the
     * 160k-180k stretch take 5.5 MINUTES here, against seconds for the same
     * range in daemon/build_utxo (which has no undo capture) -- the clearest
     * measurement yet of what undo capture costs on a bulk replay. */
    utxo_live_set_undo_enabled(0);

    long applied = 0, r;
    while ((r = utxo_live_catchup(store_buf)) > 0) applied += r;
    if (r < 0) { printf("FAIL: catch-up errored before we could build runs\n"); return 1; }
    printf("PASS: replayed to height %ld (%ld blocks)\n", utxo_live_applied_height(), applied);

    /* 1. multi-run store -> recovery must actually merge something */
    long rounds = utxo_live_recover();
    if (rounds > 0) printf("PASS: recover() compacted (%ld round(s) reduced manifest_n)\n", rounds);
    else { printf("FAIL: recover() did nothing (%ld) -- it cannot clear a full manifest\n", rounds); failures++; }

    /* 2. already-collapsed store -> clean no-op, must not spin or error */
    long again = utxo_live_recover();
    if (again == 0) printf("PASS: second recover() is a clean no-op\n");
    else { printf("FAIL: second recover() reported %ld rounds; expected 0\n", again); failures++; }

    /* 3. the store must still be usable afterwards */
    if (utxo_live_catchup(store_buf) >= 0) printf("PASS: catch-up still healthy after recovery\n");
    else { printf("FAIL: catch-up broken after recovery\n"); failures++; }

    if (failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
