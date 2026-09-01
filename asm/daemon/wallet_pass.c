/* daemon/wallet_pass.c -- the daemon's wallet passphrase source.
 *
 * WHY <store>.pass IS GONE (audit 2026-08-29 finding 2).
 *
 * The old boot path read the passphrase from `<store>.pass`, a 0600 file
 * beside the wallet. The stated intent was to avoid pairing ciphertext and
 * key in ONE FILE -- but it put them in one DIRECTORY, under a guessable
 * name. Any read primitive over the datadir yields both, and so does any
 * backup of it: the two halves travel together in the tar. That is not a
 * weaker version of key separation, it is the absence of it.
 *
 * The daemon now takes the passphrase from, in order:
 *
 *   1. $BMC_WALLET_PASS -- but note an environment variable is readable via
 *      /proc/<pid>/environ by the same user and by root, and systemd's
 *      Environment= is visible in `systemctl show`. Convenient, not secret.
 *   2. `walletpassfile=` in bitcoin.conf: an ABSOLUTE path outside the
 *      datadir. The intended deployment is a root-owned file the service
 *      account can read but not write -- root:<service group>, mode 0640 --
 *      so it is excluded from datadir backups and from anything the daemon
 *      itself could be tricked into rewriting.
 *
 * The file is REFUSED rather than used if it is world-accessible, group
 * writable, or inside the datadir, because each of those puts it back in
 * reach of exactly what the separation is for. A refusal is logged loudly:
 * a passphrase file that is silently ignored is worse than none, since the
 * operator believes the wallet will unlock and only finds out otherwise when
 * something needs a key.
 *
 * The CLI keeps its <store>.pass convenience for development. That is a
 * human running a command on a box they are sitting at, not an unattended
 * service holding a spendable key.
 */
#include <stdio.h>
#include "log_ts.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "wallet_pass.h"

/* Deliberately NOT read out of g_cfg. rpc_wallet_ops.o calls into here and is
 * part of RPCLIBS, which 31 targets link WITHOUT node_config.o -- reaching
 * for the config here makes every one of them fail to link. The config pushes
 * the path in instead, so this module has no external dependencies at all. */
static char g_passfile[256];

void wallet_pass_set_file(const char* path){
    if (!path) { g_passfile[0] = 0; return; }
    snprintf(g_passfile, sizeof g_passfile, "%s", path);
}

static int read_secret_file(const char* path, char* out, int cap, const char** why){
    struct stat sb;
    if (stat(path, &sb) != 0){ if (why) *why = "no such file"; return 0; }
    if (!S_ISREG(sb.st_mode)){ if (why) *why = "not a regular file"; return 0; }
    /* 0640 root:<group> is the intended shape; 0600 is fine too. Anything
     * world-readable, world-writable or group-writable is refused. */
    if (sb.st_mode & 0007){ if (why) *why = "world-accessible (need mode 0640 or stricter)"; return 0; }
    if (sb.st_mode & 0020){ if (why) *why = "group-writable (need mode 0640 or stricter)"; return 0; }

    FILE* f = fopen(path, "r");
    if (!f){ if (why) *why = "unreadable by the service account"; return 0; }
    out[0] = 0;
    if (!fgets(out, cap, f)){ fclose(f); out[0] = 0; if (why) *why = "empty"; return 0; }
    fclose(f);
    size_t l = strlen(out);
    while (l && (out[l-1] == '\n' || out[l-1] == '\r')) out[--l] = 0;
    if (!out[0]){ if (why) *why = "empty"; return 0; }
    return 1;
}

int wallet_pass_load(char* out, int cap, const char** why){
    if (!out || cap <= 1) return 0;
    out[0] = 0;
    if (why) *why = 0;

    const char* env = getenv("BMC_WALLET_PASS");
    if (env && env[0]){ snprintf(out, (size_t)cap, "%s", env); return 1; }

    const char* pf = g_passfile;
    if (!pf[0]) return 0;

    if (pf[0] != '/'){
        fprintf(stderr, "[wallet] walletpassfile must be an absolute path -- ignoring \"%s\"\n", pf);
        if (why) *why = "not an absolute path";
        return 0;
    }
    /* Inside the datadir it would be swept up by any backup of the datadir,
     * which is the whole failure this replaces. The daemon has already
     * chdir'd into the datadir, so its realpath is the comparison. */
    { char dd[4096];
      if (getcwd(dd, sizeof dd)){
          size_t n = strlen(dd);
          if (!strncmp(pf, dd, n) && (pf[n] == '/' || pf[n] == 0)){
              fprintf(stderr, "[wallet] walletpassfile \"%s\" is inside the datadir -- refusing; "
                              "put it somewhere a datadir backup will not carry it\n", pf);
              if (why) *why = "inside the datadir";
              return 0;
          }
      } }

    const char* w = 0;
    if (read_secret_file(pf, out, cap, &w)) return 1;
    fprintf(stderr, "[wallet] walletpassfile \"%s\" not usable: %s\n", pf, w ? w : "unknown");
    if (why) *why = w;
    return 0;
}

void wallet_pass_warn_legacy(const char* store_path){
    if (!store_path || !store_path[0]) return;
    char pf[1100];
    snprintf(pf, sizeof pf, "%s.pass", store_path);
    struct stat sb;
    if (stat(pf, &sb) != 0) return;
    fprintf(stderr,
        "[wallet] WARNING: %s exists but is NO LONGER READ by the daemon.\n"
        "[wallet]          It pairs the wallet's key with its ciphertext in one\n"
        "[wallet]          directory -- and in every backup of that directory.\n"
        "[wallet]          Move the secret to walletpassfile= (absolute path,\n"
        "[wallet]          outside the datadir, root-owned, mode 0640) and delete it.\n", pf);
}
