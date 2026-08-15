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
 * real server on an ephemeral port and exec the real bitcoin_cli against it.
 */
#include "../rpc_server.h"
#include "../rpc_json.h"
#include "../rpc_commands.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;
static void on_signal(int sig) { (void)sig; g_stop = 1; }

/* ---- minimal bitcoin.conf reader (key=value, '#' comments, empty lines) ---- */
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
    int port = 8332;
    char user[128] = "bitcoin";
    char pass[128] = "bitcoin";

    for (int i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "-conf=", 6)) conf = argv[i] + 6;
        else if (!strncmp(argv[i], "-rpcport=", 9)) port = atoi(argv[i] + 9);
        else if (!strncmp(argv[i], "-rpcuser=", 9)) snprintf(user, sizeof user, "%s", argv[i] + 9);
        else if (!strncmp(argv[i], "-rpcpassword=", 13)) snprintf(pass, sizeof pass, "%s", argv[i] + 13);
        else if (!strncmp(argv[i], "-h", 2)) {
            fprintf(stderr,
                "Bitcoin Core RPC server\n\n"
                "usage: bitcoin_rpcd [-conf=<path>] [-rpcport=<n>] [-rpcuser=<u>] [-rpcpassword=<p>]\n");
            return 0;
        }
    }

    load_config(conf, &port, user, sizeof user, pass, sizeof pass);

    /* allow the test harness to override the port via env for ephemeral bind */
    const char* env = getenv("TEST_RPC_PORT");
    if (env && *env) port = atoi(env);

    init_wallet();

    rpc_server_cfg cfg;
    cfg.port = port;
    cfg.user = user;
    cfg.pass = pass;
    cfg.wallet = &g_wallet;

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
