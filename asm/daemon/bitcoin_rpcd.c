/* daemon/bitcoin_rpcd.c -- standalone HTTP JSON-RPC server daemon.
 *
 * The production server endpoint for the RPC wire-up. Loads rpcport /
 * rpcuser / rpcpassword from config/bitcoin.conf (like bitcoind), builds a
 * deterministic in-memory wallet (rpc_wallet), and serves JSON-RPC 2.0
 * requests over an HTTP endpoint -- bit-exact vs bitcoin-cli via the shared
 * rpc_dispatch() render path.
 *
 *   usage:
 *     bitcoin_rpcd [-conf=<path>] [-rpcport=<n>] [-rpcuser=<u>] [-rpcpassword=<p>]
 *
 * The daemon blocks serving requests until SIGINT/SIGTERM. For integration
 * tests the TEST_RPC_PORT env overrides the port so the harness can bind the
 * real server on an ephemeral port and exec the real bmc_cli against it.
 */
#include "../rpc_server.h"
#include "../rpc_json.h"
#include "../rpc_commands.h"
#include "../rpc_chain.h"

#include <stdio.h>
#include "log_ts.h"
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/* ---- long-lived LSM UTXO store for gettxout (asm/bitcoin_utxo_lsm.asm) ----
 * See rpc_commands_set_utxo_store's doc comment: a separate handle from the
 * wallet, reloaded once at startup and never re-reloaded, so it goes stale
 * exactly as far as the on-disk store drifts after boot -- an accepted
 * tradeoff per the LSM store's own "periodically rebuilt, not incrementally
 * live-maintained" design (avoids touching the live daemon's already-proven
 * UTXO-application code at all). Restart bitcoin_rpcd to pick up new data. */
typedef unsigned long long u64;
extern long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_reload(void* lst, void* u);
struct lsm_state {
    long log_fd, idx_fd;
    u64 log_len, ckpt_log_off, ckpt_n;
    u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen;
    void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap;
    u64 next_run_no;
    void* tomb_hash_buf; u64 tomb_hash_mask; /* LSM-owned, see bitcoin_utxo_lsm.asm */
};
#define BLOOM_MAX_BYTES  (4*1024*1024)
#define SCRIPT_MAX_BYTES 65536
static struct lsm_state g_utxo_lst;

static void* mmap_file(const char* path, u64 size){
    int fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) { fprintf(stderr, "bitcoin_rpcd: open(%s): %s\n", path, strerror(errno)); return 0; }
    if (ftruncate(fd, (off_t)size) != 0) { fprintf(stderr, "bitcoin_rpcd: ftruncate(%s): %s\n", path, strerror(errno)); close(fd); return 0; }
    void* p = mmap(0, size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (p == MAP_FAILED) { fprintf(stderr, "bitcoin_rpcd: mmap(%s): %s\n", path, strerror(errno)); return 0; }
    return p;
}

/* Same slots_log2 as build_utxo.c/build_migrate_compact.c, NOT a smaller
 * "modest" size (an earlier version of this code tried slots_log2=16 and
 * was reliably pathological: the memtable's linear-probe hash table has a
 * bounded-but-O(slots) probe on a full/overfull table, and a WAL tail's
 * live-entry count is whatever was unflushed when the writer stopped --
 * for the real store that was ~953K entries, ~15x too many for 65536
 * slots. Matching the production sizing costs more memory/startup time but
 * is correct regardless of how large the tail turns out to be. */
static int init_utxo_store(const char* datadir) {
    if (chdir(datadir)) { fprintf(stderr, "bitcoin_rpcd: chdir(%s): %s\n", datadir, strerror(errno)); return 0; }
    int slots_log2 = 22;
    unsigned long slots = 1UL << slots_log2;
    u64 blob_cap = 2UL*1024*1024*1024;
    long ustruct = utxo_struct_size(slots);
    u64 fill_threshold = (u64)slots * 3 / 4;
    u64 op_threshold    = (u64)slots * 2;
    u64 tomb_cap         = op_threshold;
    u64 desc_cap         = (u64)slots * 3;
    u64 scratch_cap       = desc_cap*128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    u64 manifest_cap       = 8192;

    void* u = mmap_file("utxo_lsm_rpcd_table.map", (u64)ustruct);
    void* blob = mmap_file("utxo_lsm_rpcd_blob.map", blob_cap);
    if (!u || !blob) return 0;
    utxo_init(u, slots, blob, blob_cap);

    void* tomb_buf = malloc(tomb_cap*36);
    void* manifest_buf = malloc(manifest_cap*16);
    void* scratch_buf = malloc(scratch_cap);
    if (!tomb_buf || !manifest_buf || !scratch_buf) { fprintf(stderr, "bitcoin_rpcd: malloc failed\n"); return 0; }

    memset(&g_utxo_lst, 0, sizeof g_utxo_lst);
    g_utxo_lst.op_threshold = op_threshold;
    g_utxo_lst.fill_threshold = fill_threshold;
    g_utxo_lst.tomb_buf = tomb_buf; g_utxo_lst.tomb_cap = tomb_cap;
    g_utxo_lst.manifest_buf = manifest_buf; g_utxo_lst.manifest_cap = manifest_cap;
    g_utxo_lst.scratch_buf = scratch_buf; g_utxo_lst.scratch_cap = scratch_cap;

    long replayed = utxo_lsm_reload(&g_utxo_lst, u);
    if (replayed < 0) { fprintf(stderr, "bitcoin_rpcd: utxo_lsm_reload failed\n"); return 0; }
    fprintf(stderr, "bitcoin_rpcd: UTXO store loaded (manifest_n=%llu, %ld WAL-tail ops replayed)\n",
            g_utxo_lst.manifest_n, replayed);
    rpc_commands_set_utxo_store(&g_utxo_lst, u);
    return 1;
}

/* mmap the address index (asm/daemon/build_addr_index.c's output,
 * "addr_index.dat" in the data directory) read-only, for listunspent/
 * getbalance. Optional: if the file doesn't exist yet (the index hasn't
 * been built), those commands just report "owns nothing" rather than
 * failing the whole daemon -- matches gettxout's "not configured" story.
 * Must run AFTER init_utxo_store's chdir(datadir), since this opens a
 * relative filename in the same directory. */
static int init_addr_index(void) {
    int fd = open("addr_index.dat", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "bitcoin_rpcd: no addr_index.dat (listunspent/getbalance will report empty) -- %s\n", strerror(errno));
        return 1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0) { fprintf(stderr, "bitcoin_rpcd: fstat(addr_index.dat): %s\n", strerror(errno)); close(fd); return 0; }
    u64 size = (u64)st.st_size;
    void* base = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (base == MAP_FAILED) { fprintf(stderr, "bitcoin_rpcd: mmap(addr_index.dat): %s\n", strerror(errno)); return 0; }
    rpc_commands_set_addr_index(base, size);
    fprintf(stderr, "bitcoin_rpcd: address index loaded (%llu bytes)\n", size);
    return 1;
}

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* ---- minimal bitcoin.conf reader (key=value, '#' comments, empty lines) ---- */
static long g_prune_mib = 0;
static void load_config(const char* path, int* port,
                        char* user, size_t usercap,
                        char* pass, size_t passcap) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char line[1024];
    while (fgets(line, sizeof line, f)) {
        char* p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == 0) continue;
        char* eq = strchr(p, '=');
        if (!eq) continue;
        *eq = 0;
        char* key = p;
        char* val = eq + 1;
        /* strip trailing whitespace/CR/LF from val */
        size_t vl = strlen(val);
        while (vl && (val[vl-1] == '\n' || val[vl-1] == '\r' || val[vl-1] == ' ' || val[vl-1] == '\t')) val[--vl] = 0;
        /* strip trailing whitespace from key */
        size_t kl = strlen(key);
        while (kl && (key[kl-1] == ' ' || key[kl-1] == '\t')) key[--kl] = 0;
        if (strcmp(key, "rpcport") == 0) *port = atoi(val);
        else if (strcmp(key, "rpcuser") == 0) snprintf(user, usercap, "%s", val);
        else if (strcmp(key, "rpcpassword") == 0) snprintf(pass, passcap, "%s", val);
        else if (strcmp(key, "prune") == 0) g_prune_mib = atol(val);
    }
    fclose(f);
}

/* ---- deterministic wallet for the daemon (fixed seed + a small UTXO set) ----
 * The address the wallet reports is derived from this seed via the verified
 * wallet_core command layer, exactly as the RPC harness does. */
static unsigned char g_seed[64];
static unsigned char g_utxo_txid[2][32];
static unsigned long  g_utxo_idx[2]  = {0, 1};
static unsigned long long g_utxo_val[2] = {25000000ULL, 500000ULL}; /* 0.25 + 0.005 */
static const char* g_utxo_script[2] = {
    "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
    "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
};
static rpc_wallet g_wallet;

static void init_wallet(void) {
    for (int i = 0; i < 64; i++) g_seed[i] = (unsigned char)(0x10 + i);
    for (int i = 0; i < 32; i++) { g_utxo_txid[0][i] = (unsigned char)(0xa0 + i); g_utxo_txid[1][i] = (unsigned char)(0x50 + i); }
    g_wallet.seed = g_seed;
    g_wallet.utxo_txid = (const unsigned char (*)[32])g_utxo_txid;
    g_wallet.utxo_idx = g_utxo_idx;
    g_wallet.utxo_val = g_utxo_val;
    g_wallet.utxo_script = (const unsigned char* const*)g_utxo_script;
    g_wallet.utxo_n = 2;
}

int main(int argc, char** argv) {
    const char* conf = "config/bitcoin.conf";
    const char* datadir = NULL;
    int port = 8332;
    char user[128] = "bitcoin";
    char pass[128] = "bitcoin";

    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "-conf=", 6)) conf = argv[i] + 6;
        else if (!strncmp(argv[i], "-datadir=", 9)) datadir = argv[i] + 9;
        else if (!strncmp(argv[i], "-rpcport=", 9)) port = atoi(argv[i] + 9);
        else if (!strncmp(argv[i], "-rpcuser=", 9)) snprintf(user, sizeof user, "%s", argv[i] + 9);
        else if (!strncmp(argv[i], "-rpcpassword=", 13)) snprintf(pass, sizeof pass, "%s", argv[i] + 13);
        else if (!strncmp(argv[i], "-h", 2)) {
            fprintf(stderr,
                "Bitcoin Core RPC server\n\n"
                "usage: bitcoin_rpcd [-conf=<path>] [-datadir=<path>] [-rpcport=<n>] [-rpcuser=<u>] [-rpcpassword=<p>]\n"
                "  -datadir=<path>  enables real gettxout against the LSM UTXO store in <path>,\n"
                "                   and (if <path>/addr_index.dat exists, see daemon/build_\n"
                "                   addr_index.c) real listunspent/getbalance\n"
                "                   (omit to serve those as \"not found\"/empty for everything),\n"
                "                   and the blockchain-query RPCs (getblock*, getblockchaininfo,\n"
                "                   getrawtransaction <txid> <verbosity> <blockhash>) against its archive\n");
            return 0;
        }
    }

    load_config(conf, &port, user, sizeof user, pass, sizeof pass);

    /* allow the test harness to override the port via env for ephemeral bind */
    const char* env = getenv("TEST_RPC_PORT");
    if (env && *env) port = atoi(env);

    init_wallet();

    if (datadir) {
        if (!init_utxo_store(datadir)) {
            fprintf(stderr, "bitcoin_rpcd: UTXO store init failed for -datadir=%s\n", datadir);
            return 1;
        }
        if (!init_addr_index()) {
            fprintf(stderr, "bitcoin_rpcd: address index init failed\n");
            return 1;
        }
        /* Blockchain-query RPCs (getblock*, getblockchaininfo, getrawtransaction
         * with a block hash) read the archive in this same directory. Optional:
         * without index.dat those methods answer -28 "Loading block index...". */
        rpc_chain_set_prune_mib(g_prune_mib);
        if (rpc_chain_open(NULL))
            fprintf(stderr, "bitcoin_rpcd: block archive opened (blockchain-query RPCs live)\n");
        else
            fprintf(stderr, "bitcoin_rpcd: no block archive in datadir (blockchain-query RPCs will report -28)\n");
    }

    /* ZERO-INITIALISED. The struct grows fields (bind_addr, allows), and a
     * caller that sets members one by one leaves the new ones as garbage --
     * for `allows` that is a garbage FUNCTION POINTER. Adding a field must not
     * be able to break a caller that never mentioned it. */
    rpc_server_cfg cfg = {0};
    cfg.port = port;
    cfg.user = user;
    cfg.pass = pass;
    cfg.wallet = &g_wallet;
    /* test hooks for the 2026-09-01 server options (the daemon reads them
     * from bitcoin.conf; this tool has no config file) */
    { const char* e;
      if ((e = getenv("TEST_RPC_THREADS")) && *e)   cfg.threads   = atoi(e);
      if ((e = getenv("TEST_RPC_WORKQUEUE")) && *e) cfg.workqueue = atoi(e);
      if ((e = getenv("TEST_RPC_TIMEOUT")) && *e)   cfg.timeout_s = atoi(e);
      if ((e = getenv("TEST_RPC_WHITELIST")) && *e){          /* "user:m1,m2;user2:m3" */
          char buf[1024]; snprintf(buf, sizeof buf, "%s", e);
          char* save = NULL;
          for (char* t = strtok_r(buf, ";", &save); t; t = strtok_r(NULL, ";", &save))
              if (!rpc_whitelist_add(t)) fprintf(stderr, "bitcoin_rpcd: bad TEST_RPC_WHITELIST entry %s\n", t);
      }
      if ((e = getenv("TEST_RPC_WHITELIST_DEFAULT")) && *e) rpc_whitelist_set_default(atoi(e)); }

    int actual = 0;
    char errmsg[256];
    if (rpc_server_start(&cfg, &actual, errmsg, sizeof errmsg) != 0) {
        fprintf(stderr, "bitcoin_rpcd: %s\n", errmsg);
        return 1;
    }
    fprintf(stderr, "bitcoin_rpcd: JSON-RPC server listening on 127.0.0.1:%d (user=%s)\n", actual, user);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    while (!g_stop) sleep(1);

    rpc_server_stop();
    return 0;
}
