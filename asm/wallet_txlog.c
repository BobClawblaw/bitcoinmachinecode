/*
 * wallet_txlog.c -- persistent transaction journal for the ASM wallet CLI.
 *
 * WHY: the wallet CLI signs/sends transactions but never records them, so there
 * is no history of "all our transactions" (no listtransactions / gettransaction).
 * This module adds a tiny, own-format, versioned, append-only journal of every
 * wallet transaction the CLI sends -- consistent with the project's "no BDB, own
 * format" philosophy (see wallet_store.c and wallet_book.c).
 *
 * FILE FORMAT (textual, auditable, versioned, append-only):
 *   BMCTX v1
 *   <unix_ts> sent <txid_hex64> <amount_sat> <fee_sat> <dest_h160_hex40> <inputs_used> <rawlen>
 *   # comments and blank lines ignored; one record per line. The journal stores
 *   sent-record metadata (not the raw bytes, to keep it small); the raw signed
 *   transaction bytes the CLI printed are intentionally not re-serialized here
 *   (reconstruction from inputs is out of scope for this store).
 *
 * ABI (plain C, stdio-only, no new deps):
 *   char* txlog_path_for(const char* wallet_path, char* buf, int cap);
 *     -> "<wallet_path>.txlog" (e.g. config/wallet.dat -> config/wallet.dat.txlog),
 *        or a default "config/wallet.dat.txlog" if wallet_path is NULL.
 *   int   txlog_append(const char* path, unsigned long long ts,
 *                      const unsigned char txid[32], long long amount,
 *                      long long fee, const unsigned char dest_h160[20],
 *                      unsigned long inputs_used, long rawlen);
 *     -> appends one "sent" record. Returns 0 on success, -1 on error.
 *   int   txlog_append_sent(const char* wallet_path, const unsigned char txid[32],
 *                           long long amount, long long fee,
 *                           const unsigned char dest_h160[20],
 *                           unsigned long inputs_used, long rawlen);
 *     -> convenience: resolves the path via txlog_path_for() then appends.
 *   int   txlog_list(const char* path, char* out, int cap);
 *     -> renders the whole journal as human-readable history ("the header line
 *        plus one '<ts>  <direction>  <amount>  <fee>  <dest>' per record").
 *        Returns 0 on success (or if the file does not exist yet -> empty),
 *        -1 on error.
 * All return 0 on success, -1 on failure.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#define BMCTX_MAGIC "BMCTX v1"

/* default wallet store path, must match wallet_cli.c's default_wallet_path() */
#define DEFAULT_WALLET_PATH "config/wallet.dat"

/* ---- helpers ---------------------------------------------------------- */

char* txlog_path_for(const char* wallet_path, char* buf, int cap) {
    const char* w = wallet_path ? wallet_path : DEFAULT_WALLET_PATH;
    snprintf(buf, cap, "%s.txlog", w);
    return buf;
}

/* Write a file with 0600 perms (mirrors the wallet secret-file convention). */
static int write_0600(const char* path, const char* data, long len, int create) {
    FILE* f = fopen(path, create ? "w" : "a");
    if (!f) return -1;
    if (fwrite(data, 1, (size_t)len, f) != (size_t)len) { fclose(f); return -1; }
    fclose(f);
    chmod(path, 0600);
    return 0;
}

/* Ensure the journal exists with the magic header (no-op if already present). */
static int txlog_ensure_header(const char* path) {
    FILE* f = fopen(path, "r");
    if (f) {
        char buf[64];
        size_t n = fread(buf, 1, sizeof buf - 1, f);
        fclose(f);
        buf[n] = 0;
        if (strstr(buf, BMCTX_MAGIC)) return 0; /* already initialized */
    }
    /* create with header (0600) */
    return write_0600(path, BMCTX_MAGIC "\n", (long)(strlen(BMCTX_MAGIC) + 1), 1);
}

/* ---- public API ------------------------------------------------------- */

int txlog_append(const char* path, unsigned long long ts,
                 const unsigned char txid[32], long long amount,
                 long long fee, const unsigned char dest_h160[20],
                 unsigned long inputs_used, long rawlen) {
    if (!path) return -1;
    if (txlog_ensure_header(path) != 0) return -1;
    char line[512];
    char txh[65], dest[41];
    for (int i = 0; i < 32; i++) snprintf(txh + 2 * i, 3, "%02x", txid[i]);
    for (int i = 0; i < 20; i++) snprintf(dest + 2 * i, 3, "%02x", dest_h160[i]);
    snprintf(line, sizeof line,
             "%llu sent %s %lld %lld %s %lu %ld\n",
             ts, txh, amount, fee, dest, inputs_used, rawlen);
    return write_0600(path, line, (long)strlen(line), 0);
}

int txlog_append_sent(const char* wallet_path, const unsigned char txid[32],
                      long long amount, long long fee,
                      const unsigned char dest_h160[20],
                      unsigned long inputs_used, long rawlen) {
    char path[1024];
    txlog_path_for(wallet_path, path, sizeof path);
    return txlog_append(path, (unsigned long long)time(NULL),
                        txid, amount, fee, dest_h160, inputs_used, rawlen);
}

int txlog_list(const char* path, char* out, int cap) {
    if (!out || cap <= 0) return -1;
    out[0] = 0;
    int n = 0;
    n += snprintf(out + n, (size_t)(cap - n),
                  "%-12s %-5s %-64s %-10s %-10s %s\n",
                  "time", "dir", "txid", "amount-sat", "fee-sat", "dest-h160");
    FILE* f = fopen(path, "r");
    if (!f) return 0; /* no history yet is not an error */
    char line[512];
    while (fgets(line, sizeof line, f)) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;
        if (strncmp(line, BMCTX_MAGIC, strlen(BMCTX_MAGIC)) == 0) continue;
        /* one record:  ts dir txid_hex amount fee dest_h160_hex inputs rawlen */
        unsigned long long ts; long long amt, fee; unsigned long ins; long raw;
        char dir[16], txh[65], dest[41];
        int got = sscanf(line, "%llu %15s %64s %lld %lld %40s %lu %ld",
                         &ts, dir, txh, &amt, &fee, dest, &ins, &raw);
        if (got != 8) continue;
        txh[64] = 0; dest[40] = 0;
        n += snprintf(out + n, (size_t)(cap - n),
                      "%-12llu %-5s %-64s %-10lld %-10lld %s\n",
                      ts, dir, txh, amt, fee, dest);
    }
    fclose(f);
    return 0;
}
