/* daemon/benchlog.c -- see benchlog.h (2026-10-04). Formatting only: no
 * clock, no I/O, no globals, so the daemon pays nothing it does not print. */
#include <stdio.h>
#include <string.h>
#include "benchlog.h"

int benchlog_fmt_index(char* out, size_t cap, long h, const unsigned long long ns[BL_IX_N]){
    return snprintf(out, cap, "[bench] index %ld: txindex %.2f | txospender %.2f | bfilter %.2f | addr %.2f | zmq %.2f ms",
                    h, (double)ns[BL_IX_TXINDEX] / 1e6, (double)ns[BL_IX_TXOSPENDER] / 1e6,
                    (double)ns[BL_IX_BFILTER] / 1e6, (double)ns[BL_IX_ADDR] / 1e6, (double)ns[BL_IX_ZMQ] / 1e6);
}

/* append "name" to one of the two lists, comma-separated */
static void ready_add(char* list, size_t cap, const char* name){
    size_t n = strlen(list);
    if (n + 2 >= cap) return;
    snprintf(list + n, cap - n, "%s%s", n ? ", " : "", name);
}

int benchlog_ready_eval(const benchlog_ready_t* r, char* out, size_t cap){
    if (!r->ibd_over){ snprintf(out, cap, "waiting: initial block download"); return 0; }
    if (r->tip < 0){ snprintf(out, cap, "waiting: no archive tip"); return 0; }
    /* the first unmet condition, in the order the stages finish on a sync */
    if (r->utxo_on && r->utxo_applied < r->tip){
        snprintf(out, cap, "waiting: utxo at %ld of %ld", r->utxo_applied, r->tip); return 0; }
    if (r->txindex_on && r->txindex_covered < r->tip){
        snprintf(out, cap, "waiting: txindex at %ld of %ld", r->txindex_covered, r->tip); return 0; }
    if (r->bfilter_on && r->bfilter_count - 1 < r->tip){
        snprintf(out, cap, "waiting: bfilter at %ld of %ld", r->bfilter_count - 1, r->tip); return 0; }
    if (r->coinstats_on && r->coinstats_height < r->tip){
        snprintf(out, cap, "waiting: coinstats at %ld of %ld", r->coinstats_height, r->tip); return 0; }
    if (r->coinstats_on && !r->coinstats_hist_ok){
        snprintf(out, cap, "waiting: coinstats history base"); return 0; }
    char on[96] = "", off[96] = "";
    ready_add(r->utxo_on ? on : off, sizeof on, "utxo");
    ready_add(r->txindex_on ? on : off, sizeof on, "txindex");
    ready_add(r->bfilter_on ? on : off, sizeof on, "bfilter");
    ready_add(r->coinstats_on ? on : off, sizeof on, "coinstats history");
    snprintf(out, cap, "[ready] all indexes at height %ld (%s%s%s) -- %.1fs",
             r->tip, on[0] ? on : "none enabled", off[0] ? "; skipped: " : "", off, r->secs);
    return 1;
}
