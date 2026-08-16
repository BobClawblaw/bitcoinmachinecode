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
#include <unistd.h>

#define BMCTX_MAGIC "BMCTX v1"

/* default wallet store path, must match wallet_cli.c's default_wallet_path() */
#define DEFAULT_WALLET_PATH "config/wallet.dat"

/* ---- helpers ---------------------------------------------------------- */

char* txlog_path_for(const char* wallet_path, char* buf, int cap) {
    const char* w = wallet_path ? wallet_path : DEFAULT_WALLET_PATH;
    snprintf(buf, cap, "%s.txlog", w);
    return buf;
}

/* FNV-1a 32-bit over a byte span. Dependency-free, deterministic, good enough
 * to detect a torn (partially-written) journal record -- NOT a collision-proof
 * checksum. The journal is own-format and low-stakes (history only). */
static unsigned long txlog_crc(const char* s, long n) {
    unsigned long h = 2166136261UL;
    for (long i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 16777619UL;
    }
    return h;
}

/* Append bytes to a file as 0600, and fsync them to stable storage so a durable
 * write is reported before the caller advertises success (FINDING P2-1).
 * Returns 0 on success, -1 on error. */
static int append_sync0600(const char* path, const char* data, long len) {
    FILE* f = fopen(path, "a");
    if (!f) return -1;
    int ok = 1;
    if (fwrite(data, 1, (size_t)len, f) != (size_t)len) ok = 0;
    if (ok && fflush(f) != 0) ok = 0;
    if (ok && fsync(fileno(f)) != 0) ok = 0;   /* durability gate */
    if (fclose(f) != 0) ok = 0;
    chmod(path, 0600);
    return ok ? 0 : -1;
}

/* Create (truncate) a file with 0600 perms and fsync it. Used only for the
 * journal header. Returns 0 on success, -1 on error. */
static int create_sync0600(const char* path, const char* data, long len) {
    FILE* f = fopen(path, "w");
    if (!f) return -1;
    int ok = 1;
    if (fwrite(data, 1, (size_t)len, f) != (size_t)len) ok = 0;
    if (ok && fflush(f) != 0) ok = 0;
    if (ok && fsync(fileno(f)) != 0) ok = 0;
    if (fclose(f) != 0) ok = 0;
    chmod(path, 0600);
    return ok ? 0 : -1;
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
    /* create with header (0600, fsynced) */
    return create_sync0600(path, BMCTX_MAGIC "\n", (long)(strlen(BMCTX_MAGIC) + 1));
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
    /* 8 data fields; a trailing 32-bit FNV-1a checksum (8 hex) guards against
     * accepting a torn (partially-written) record on reload. Compute the crc
     * over the exact 8-field prefix (no newline, no checksum field). */
    int p = snprintf(line, sizeof line,
                     "%llu sent %s %lld %lld %s %lu %ld",
                     ts, txh, amount, fee, dest, inputs_used, rawlen);
    char rec[520];
    int r = snprintf(rec, sizeof rec, "%s %08lx\n", line, txlog_crc(line, p));
    return append_sync0600(path, rec, (long)r);
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
        /* tokenize the record: 8 data fields + an optional 9th checksum field.
         * A checksummed record with a mismatched crc is a TORN write -> reject. */
        char toks[16][72];
        char* tok[16];
        int nt = 0;
        char* save = NULL;
        for (char* t = strtok_r(line, " \t\r\n", &save); t && nt < 16;
             t = strtok_r(NULL, " \t\r\n", &save)) {
            snprintf(toks[nt], sizeof toks[nt], "%s", t);
            tok[nt] = toks[nt];
            nt++;
        }
        if (nt < 8 || nt > 9) continue;            /* malformed -> skip */
        unsigned long long ts = strtoull(tok[0], NULL, 10);
        long long amt = strtoll(tok[3], NULL, 10);
        long long fee = strtoll(tok[4], NULL, 10);
        if (nt == 9) {
            /* verify checksum over the 8 data fields */
            char prefix[512];
            int pp = snprintf(prefix, sizeof prefix,
                              "%s %s %s %s %s %s %s %s",
                              tok[0], tok[1], tok[2], tok[3],
                              tok[4], tok[5], tok[6], tok[7]);
            char want[24];
            snprintf(want, sizeof want, "%08lx", txlog_crc(prefix, pp));
            if (strcmp(tok[8], want) != 0) continue; /* TORN -> reject */
        }
        n += snprintf(out + n, (size_t)(cap - n),
                      "%-12llu %-5s %-64s %-10lld %-10lld %s\n",
                      ts, tok[1], tok[2], amt, fee, tok[5]);
    }
    fclose(f);
    return 0;
}
