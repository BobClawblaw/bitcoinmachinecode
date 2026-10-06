/* tests/test_benchlog.c -- the [bench] and [ready] lines' exact text
 * (2026-10-04; worklog/2026-10-04-logged-ibd-runs-plan.md parts 2 and 3).
 *
 * A benchmark report is a parser over these lines, so their FORMAT is the
 * contract: field order, separators, units, two decimals. Pinned here:
 *   - benchlog_fmt_index: the choke point's per-block index line;
 *   - dlc_benchlog_fmt_chunk: the download-chunk line (the rate is bytes over
 *     wall; a zero wall prints a zero rate, never inf/nan);
 *   - dlc_benchlog_chunk: prints exactly that line, timestamped, with
 *     bmc.benchlog=1 and NOTHING with it off (the gate is the point: the
 *     default node writes no [bench] line);
 *   - benchlog_ready_eval: the finish condition, one unmet condition at a
 *     time -- IBD, no tip, UTXO behind, txindex behind, the filter for the
 *     tip itself missing (count == tip is one short), the coinstats fold
 *     behind, the history base not complete -- each refuses and names
 *     itself; all met prints the line; disabled indexes are named as
 *     skipped and never waited on.
 * The per-block UTXO line and the flush line are driven through a real
 * catch-up in tests/test_utxo_catchup_timing.c (section C). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include "../daemon/node_config.h"
#include "../daemon/benchlog.h"
#include "../daemon/dlc_benchlog.h"
#include "test_tmpdir.h"

static int failures = 0;
static void ckm(const char* l, int cond){
    if (cond) printf("PASS %s\n", l); else { printf("FAIL %s\n", l); failures++; }
}
static void cks(const char* l, const char* got, const char* exp){
    if (!strcmp(got, exp)) printf("PASS %s\n", l);
    else { printf("FAIL %s\n  got: %s\n  exp: %s\n", l, got, exp); failures++; }
}

/* stderr -> a file around one call */
static char* capture(void (*fn)(void)){
    char path[] = "test_benchlog_cap.XXXXXX";
    int fd = mkstemp(path); if (fd < 0){ perror("mkstemp"); exit(1); }
    fflush(stderr); int saved = dup(2); dup2(fd, 2);
    fn();
    fflush(stderr); dup2(saved, 2); close(saved);
    off_t n = lseek(fd, 0, SEEK_END); lseek(fd, 0, SEEK_SET);
    char* buf = calloc(1, (size_t)n + 1);
    if (buf && n > 0 && read(fd, buf, (size_t)n) != n){ free(buf); buf = 0; }
    close(fd); unlink(path);
    return buf;
}
static void emit_chunk(void){ dlc_benchlog_chunk(3, "203.0.113.7:8333", 800000, 16, 1234, 56, 12340000, 16); }

static benchlog_ready_t all_ready(void){
    benchlog_ready_t r; memset(&r, 0, sizeof r);
    r.ibd_over = 1; r.tip = 900;
    r.utxo_on = 1; r.utxo_applied = 900;
    r.txindex_on = 1; r.txindex_covered = 900;
    r.bfilter_on = 1; r.bfilter_count = 901;        /* filters for 0..900 */
    r.coinstats_on = 1; r.coinstats_hist_ok = 1; r.coinstats_height = 900;
    r.secs = 81234.56;
    return r;
}

int main(void){
    tt_isolate();   /* the capture file lands in a private directory */
    char out[512];

    /* ---- the index line ---- */
    { unsigned long long ns[BL_IX_N] = { 1234567ULL, 20000ULL, 3000000ULL, 0ULL, 45678ULL };
      int n = benchlog_fmt_index(out, sizeof out, 812345, ns);
      cks("index line: format", out, "[bench] index 812345: txindex 1.23 | txospender 0.02 | bfilter 3.00 | addr 0.00 | zmq 0.05 ms");
      ckm("index line: return is the length", n == (int)strlen(out)); }

    /* ---- the chunk line ---- */
    dlc_benchlog_fmt_chunk(out, sizeof out, 3, "203.0.113.7:8333", 800000, 16, 1234, 56, 12340000, 16);
    cks("chunk line: format", out, "[bench] chunk w3 peer 203.0.113.7:8333: blocks 800000..800015 (16) | wall 1234 ms | wait 56 ms | 12.34 MB (10.00 MB/s) | inflight max 16");
    dlc_benchlog_fmt_chunk(out, sizeof out, 0, "", 5, 1, 0, 0, 285, 1);
    cks("chunk line: zero wall -> zero rate, empty peer -> ?", out, "[bench] chunk w0 peer ?: blocks 5..5 (1) | wall 0 ms | wait 0 ms | 0.00 MB (0.00 MB/s) | inflight max 1");

    /* ---- the gate ---- */
    g_cfg.benchlog = 0;
    { char* got = capture(emit_chunk);
      ckm("chunk print: bmc.benchlog=0 writes nothing", got && got[0] == 0); free(got); }
    g_cfg.benchlog = 1;
    { char* got = capture(emit_chunk);
      const char* want = "[bench] chunk w3 peer 203.0.113.7:8333: blocks 800000..800015 (16) | wall 1234 ms | wait 56 ms | 12.34 MB (10.00 MB/s) | inflight max 16\n";
      const char* at = got ? strstr(got, "[bench] chunk") : 0;
      ckm("chunk print: bmc.benchlog=1 writes the line", at && !strcmp(at, want));
      ckm("chunk print: one line, timestamp first", got && at && at > got && got[0] == '2' && strchr(got, '\n') == got + strlen(got) - 1);
      free(got); }
    g_cfg.benchlog = 0;

    /* ---- the finish line ---- */
    { benchlog_ready_t r = all_ready();
      ckm("ready: every enabled index at the tip -> 1", benchlog_ready_eval(&r, out, sizeof out) == 1);
      cks("ready: the line", out, "[ready] all indexes at height 900 (utxo, txindex, bfilter, coinstats history) -- 81234.6s"); }
    { benchlog_ready_t r = all_ready(); r.ibd_over = 0;
      ckm("ready: still in IBD -> 0", benchlog_ready_eval(&r, out, sizeof out) == 0);
      cks("ready: ...and says so", out, "waiting: initial block download"); }
    { benchlog_ready_t r = all_ready(); r.tip = -1;
      ckm("ready: no archive tip -> 0", benchlog_ready_eval(&r, out, sizeof out) == 0); }
    { benchlog_ready_t r = all_ready(); r.utxo_applied = 899;
      ckm("ready: utxo one block behind -> 0", benchlog_ready_eval(&r, out, sizeof out) == 0);
      cks("ready: ...named", out, "waiting: utxo at 899 of 900"); }
    { benchlog_ready_t r = all_ready(); r.txindex_covered = 812;
      ckm("ready: txindex behind -> 0", benchlog_ready_eval(&r, out, sizeof out) == 0);
      cks("ready: ...named", out, "waiting: txindex at 812 of 900"); }
    { benchlog_ready_t r = all_ready(); r.bfilter_count = 900;   /* filters 0..899: the tip's own is missing */
      ckm("ready: the tip's filter missing (count == tip) -> 0", benchlog_ready_eval(&r, out, sizeof out) == 0);
      cks("ready: ...named", out, "waiting: bfilter at 899 of 900"); }
    { benchlog_ready_t r = all_ready(); r.bfilter_count = -1;    /* the index closed itself */
      ckm("ready: filter index inactive while enabled -> 0", benchlog_ready_eval(&r, out, sizeof out) == 0); }
    { benchlog_ready_t r = all_ready(); r.coinstats_height = 880;
      ckm("ready: coinstats fold behind -> 0", benchlog_ready_eval(&r, out, sizeof out) == 0);
      cks("ready: ...named", out, "waiting: coinstats at 880 of 900"); }
    { benchlog_ready_t r = all_ready(); r.coinstats_hist_ok = 0;
      ckm("ready: coinstats history base not complete -> 0 (the post-IBD rebuild counts)", benchlog_ready_eval(&r, out, sizeof out) == 0);
      cks("ready: ...named", out, "waiting: coinstats history base"); }
    { benchlog_ready_t r = all_ready();
      r.bfilter_on = 0; r.bfilter_count = -1;
      r.coinstats_on = 0; r.coinstats_hist_ok = 0; r.coinstats_height = -1;
      ckm("ready: disabled indexes are not waited on -> 1", benchlog_ready_eval(&r, out, sizeof out) == 1);
      cks("ready: ...and are named as skipped", out, "[ready] all indexes at height 900 (utxo, txindex; skipped: bfilter, coinstats history) -- 81234.6s"); }
    { benchlog_ready_t r = all_ready();
      r.txindex_on = 0; r.txindex_covered = -1; r.bfilter_on = 0; r.coinstats_on = 0; r.coinstats_hist_ok = 0;
      ckm("ready: utxo alone -> 1", benchlog_ready_eval(&r, out, sizeof out) == 1);
      cks("ready: ...line", out, "[ready] all indexes at height 900 (utxo; skipped: txindex, bfilter, coinstats history) -- 81234.6s"); }

    /* ---- the [mem] line (M1, 2026-10-06): a 48 MB anonymous region, touched
     * and named, must appear under its name with its size; the totals come
     * from smaps_rollup. The name check is skipped on a kernel without
     * PR_SET_VMA_ANON_NAME (maps shows no "[anon:bl_probe]"). */
    printf("\n-- the [mem] line\n");
    {
        size_t len = 48u << 20;
        unsigned char* p = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        ckm("mem: mmap 48 MB", p != MAP_FAILED);
        memset(p, 0x5a, len);
        benchlog_mem_name_region(p, len, "bl_probe");
        int named = 0;
        { FILE* mf = fopen("/proc/self/maps", "r"); char l[512];
          while (mf && fgets(l, sizeof l, mf)) if (strstr(l, "[anon:bl_probe]")) named = 1;
          if (mf) fclose(mf); }
        char big[2048];
        int n = benchlog_mem_line(big, sizeof big, "test");
        printf("     %s\n", big);
        ckm("mem: the line is non-empty and bounded", n > 0 && n < (int)sizeof big);
        ckm("mem: starts with the tag and the totals", strncmp(big, "[mem] test: pss ", 16) == 0 && strstr(big, " MB (anon ") != NULL);
        ckm("mem: the totals are non-zero (smaps_rollup read)", strstr(big, "pss 0 MB") == NULL);
        if (named){
            const char* e = strstr(big, "| bl_probe ");
            long mb = e ? strtol(e + 11, NULL, 10) : -1;
            printf("     bl_probe entry: %ld MB\n", mb);
            ckm("mem: the named region is listed by name with its size (48 MB, +/-1)", mb >= 47 && mb <= 49);
        } else printf("     (kernel has no PR_SET_VMA_ANON_NAME: name check skipped)\n");
        ckm("mem: entries under 16 MB fold into 'other'", strstr(big, "| other ") != NULL);
        /* a cap too small for the list still yields a bounded, NUL-terminated prefix */
        char small[40]; int m = benchlog_mem_line(small, sizeof small, "t");
        ckm("mem: a small cap is honoured", m < (int)sizeof small && strlen(small) < sizeof small && strncmp(small, "[mem] t: pss ", 13) == 0);
        munmap(p, len);
    }

    printf("\n%s (%d failures)\n", failures == 0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
