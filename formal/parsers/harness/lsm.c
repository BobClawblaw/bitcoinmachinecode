/* P-LSMMAN: the UTXO LSM manifest reader (daemon/lsm_manifest.c
 * lsm_manifest_read_file, lsm_manifest_persisted_live_file) on a manifest
 * of nondeterministic content and size <= FP_FSZ (a torn or corrupt
 * utxo_manifest.dat at boot).
 * Environment: the file (fileio.h). The in-memory manifest buffer holds
 * manifest_cap <= 3 entries of 16 bytes (the caller's allocation).
 * Claims:
 *   - memory safety, no leak, file closed on every path,
 *   - success => manifest_n <= manifest_cap and every entry came from the file,
 *   - the entry count is refused above 2^20 before the allocation it sizes,
 *   - X-LSM-gen (FP_CORE_STRICT): after a successful read, next_gen and
 *     next_run_no exceed every entry's gen and run number (what
 *     advance_counters is for), even for an entry of 2^64 - 1. */
#include <stdlib.h>
#include <string.h>
#include "nd.h"
#include "fileio.h"
#include SRC
int main(void){
    fio_init();
    struct lsm_state st; memset(&st, 0, sizeof st);
    st.manifest_cap = nondet_ull(); ASSUME(st.manifest_cap <= 3);
    st.manifest_buf = nd_buf(st.manifest_cap * 16);
    st.next_gen = nondet_ull(); st.next_run_no = nondet_ull();
    uint64_t live = 0;
    int r = nondet_int() ? lsm_manifest_read_file("m", &st, &live) : (live = lsm_manifest_persisted_live_file("m"), -2);
    CHECK(g_fopen_n == 0, "file closed on every path");
    if (r == 0){
        CHECK(st.manifest_n <= st.manifest_cap, "entries within the buffer");
#ifdef FP_CORE_STRICT
        for (uint64_t i = 0; i < st.manifest_n; i++){ uint64_t g, rn; memcpy(&g, (unsigned char*)st.manifest_buf + i*16, 8); memcpy(&rn, (unsigned char*)st.manifest_buf + i*16 + 8, 8);
            CHECK(st.next_gen > g && st.next_run_no > rn, "CORE: next_gen/next_run_no exceed every entry"); }
#endif
    }
    free(st.manifest_buf); free(g_f);
    COVER(r == 0 && st.manifest_n == 2, "a two-entry manifest read");
    COVER(r == -2 && live != ~0ULL, "a v2 header's live count read");
    return 0;
}
