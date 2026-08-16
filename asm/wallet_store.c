/*
 * wallet_store.c -- minimal persistent wallet store for the ASM wallet CLI.
 *
 * WHY: the wallet CLI generates/imports mnemonic+seed but never persists it, so
 * a "wallet" cannot outlive a single invocation. This module adds the minimal
 * persistence needed to actually manage a wallet across sessions (the prerequisite
 * for testing real small-amount sends). It does NOT replicate Bitcoin Core's
 * wallet.dat (BerkeleyDB) -- that is a BDB-database rabbit hole with no payoff
 * here. Instead we store the RECOVERABLE SECRET (a BIP39 mnemonic + optional
 * passphrase) in a small versioned file of our own format. Everything else
 * (the 64-byte seed, all BIP44 addresses/keys) is deterministically derived from
 * the mnemonic at load time via the verified wallet_core API.
 *
 * FILE FORMAT (own, not BDB; textual, auditable, versioned):
 *   BMCWAL v1
 *   <mnemonic words, space-separated, on one line>
 *   pass=PASS        (only if a non-empty passphrase is set)
 *   # optional comment lines (#) and trailing blank lines are ignored
 *
 * Security note: this is plaintext (matches Core when the wallet has no BIP38
 * passphrase-encryption of the seed). It stores the mnemonic that can derive all
 * keys, so protect the file perms (0600) -- the module enforces that on create.
 *
 * ABI (plain C, stdio-only):
 *   int wallet_store_create(const char* path, const char* mnemonic, const char* pass);
 *   int wallet_store_load(const char* path, char* mnemonic_out, int cap,
 *                         char* pass_out, int pcap);
 *   int wallet_store_mnemonic_validate_line(const char* line); // convenience
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BMCWAL_MAGIC "BMCWAL v1"

/* Create (or overwrite) a wallet file at `path` holding `mnemonic` and optional
 * `pass` (may be NULL/empty). Enforces 0600 perms. Returns 0 on success. */
int wallet_store_create(const char* path, const char* mnemonic, const char* pass) {
    if (!path || !mnemonic) return -1;
    FILE* f = fopen(path, "w");
    if (!f) return -1;
    fprintf(f, BMCWAL_MAGIC "\n");
    fprintf(f, "%s\n", mnemonic);
    if (pass && pass[0]) fprintf(f, "pass=%s\n", pass);
    fclose(f);
    chmod(path, 0600);
    return 0;
}

/* Load a wallet file. On success 0, fills mnemonic_out (NUL-terminated) and
 * pass_out (empty string if none). Buffer sizes cap/pcap must include NUL. */
int wallet_store_load(const char* path, char* mnemonic_out, int cap,
                      char* pass_out, int pcap) {
    if (!path || !mnemonic_out || cap <= 1) return -1;
    mnemonic_out[0] = 0;
    if (pass_out && pcap > 0) pass_out[0] = 0;
    FILE* f = fopen(path, "r");
    if (!f) return -1;

    char line[1024];
    int got_seed_word = 0;   /* the first non-#, non-magic line = the mnemonic */
    int first = 1;
    while (fgets(line, sizeof line, f)) {
        /* strip trailing newline/CR */
        size_t l = strlen(line);
        while (l && (line[l-1]=='\n' || line[l-1]=='\r')) line[--l]=0;

        if (first) {
            /* skip the magic header line if present */
            first = 0;
            if (!strncmp(line, BMCWAL_MAGIC, strlen(BMCWAL_MAGIC))) continue;
        }
        if (line[0] == '#' || line[0] == 0) continue;   /* comment / blank */
        if (!strncmp(line, "pass=", 5)) {
            if (pass_out && pcap > 0) {
                snprintf(pass_out, pcap, "%s", line + 5);
            }
            continue;
        }
        if (!got_seed_word) {
            snprintf(mnemonic_out, cap, "%s", line);
            got_seed_word = 1;
        }
    }
    fclose(f);
    return got_seed_word ? 0 : -1;   /* must have found the mnemonic */
}
