/* test_dumptxoutset_path.c -- ST2-3 (audit 2026-10-23): dumptxoutset's runner
 * (daemon/utxo_setinfo_rpc.c utxo_dump_rpc_run) never writes over an existing
 * file, and never writes through a planted symlink.
 *
 * THE BUG. The runner fopen("<path>.tmp", "wb")'d -- truncating whatever was
 * there, through symlinks -- and at the end rename()d it over <path> with no
 * existence check, the path being relative to the chain directory. So
 * `dumptxoutset utxo_manifest.dat` replaced the live chainstate's manifest,
 * and a symlink at <path>.tmp truncated its target before anything else ran.
 *
 * Core v31.1 (rpc/blockchain.cpp dumptxoutset) refuses a path that exists
 * ("<path> already exists. If you are sure this is what you want, move it out
 * of the way first", RPC_INVALID_PARAMETER), writes "<path>.incomplete" and
 * renames it on completion. The runner now does the same, creates the temp
 * file O_CREAT|O_EXCL|O_NOFOLLOW, and renames without replacing.
 *
 * The runner is driven here in an empty directory: there is no UTXO set, so a
 * call that gets past the path checks fails later (-1) -- what matters is
 * what it did to the files first. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "test_tmpdir.h"

extern long utxo_dump_rpc_run(const char* path, int (*hash_at)(long, unsigned char*),
                              long* out_height, unsigned long long* out_coins,
                              char* msg, unsigned long mcap);

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }
static int no_hash(long h, unsigned char out[32]){ (void)h; (void)out; return 0; }
static void put_file(const char* p, const char* body){
    FILE* f = fopen(p, "wb"); if (!f || fputs(body, f) < 0){ perror(p); exit(2); } fclose(f);
}
static int file_is(const char* p, const char* body){
    char buf[256] = {0}; FILE* f = fopen(p, "rb"); if (!f) return 0;
    size_t n = fread(buf, 1, sizeof buf - 1, f); fclose(f);
    return n == strlen(body) && !memcmp(buf, body, n);
}
static int exists(const char* p){ struct stat st; return lstat(p, &st) == 0; }

int main(void){
    tt_isolate();
    char cwd[1024]; if (!getcwd(cwd, sizeof cwd)){ perror("getcwd"); return 2; }
    char path[1200], msg[1400], want[1400];
    long h = 0; unsigned long long coins = 0;

    /* 1. the live chainstate's manifest as the target: refused, untouched */
    put_file("utxo_manifest.dat", "LIVE MANIFEST");
    snprintf(path, sizeof path, "%s/utxo_manifest.dat", cwd);
    long r = utxo_dump_rpc_run(path, no_hash, &h, &coins, msg, sizeof msg);
    snprintf(want, sizeof want, "%s already exists. If you are sure this is what you want, move it out of the way first", path);
    ck("an existing target is refused (-2, RPC_INVALID_PARAMETER)", r == -2);
    ck("...with Core's message", !strcmp(msg, want));
    if (strcmp(msg, want)) printf("      got [%s]\n", msg);
    ck("...and the file is untouched", file_is("utxo_manifest.dat", "LIVE MANIFEST"));
    ck("...and no temp file was left", !exists("utxo_manifest.dat.incomplete") && !exists("utxo_manifest.dat.tmp"));

    /* 2. a symlink planted at the temp name: refused, its target untouched */
    put_file("victim.dat", "VICTIM");
    if (symlink("victim.dat", "snap.dat.incomplete") || symlink("victim.dat", "snap.dat.tmp")){ perror("symlink"); return 2; }
    snprintf(path, sizeof path, "%s/snap.dat", cwd);
    r = utxo_dump_rpc_run(path, no_hash, &h, &coins, msg, sizeof msg);
    snprintf(want, sizeof want, "Couldn't open file %s.incomplete for writing.", path);
    ck("a symlink at <path>.incomplete is refused (-2)", r == -2);
    ck("...with Core's open-failure message", !strcmp(msg, want));
    if (strcmp(msg, want)) printf("      got [%s]\n", msg);
    ck("...and the symlink's target is untouched", file_is("victim.dat", "VICTIM"));
    ck("...and nothing appeared at the path", !exists("snap.dat"));
    unlink("snap.dat.incomplete"); unlink("snap.dat.tmp");

    /* 3. a clean path gets past the checks (and fails later: no UTXO set),
     * leaving nothing behind */
    snprintf(path, sizeof path, "%s/clean.dat", cwd);
    r = utxo_dump_rpc_run(path, no_hash, &h, &coins, msg, sizeof msg);
    ck("a fresh path passes the path checks (fails later without a UTXO set: -1)", r == -1);
    ck("...and its temp file is removed", !exists("clean.dat.incomplete") && !exists("clean.dat"));

    if (fails){ printf("\nTESTS FAILED (%d failures)\n", fails); return 1; }
    printf("\nALL TESTS PASSED (0 failures)\n");
    return 0;
}
