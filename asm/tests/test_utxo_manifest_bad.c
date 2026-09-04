/* tests/test_utxo_manifest_bad.c -- UTX-6 (audit 2026-09-03): a manifest that
 * EXISTS but cannot be read must fail the reload, not read as "no runs".
 *
 * THE BUG. mac_lsm_reload_impl's .rl_manifest_bad path was reached from four
 * places -- a short read of the 12-byte prefix, an unrecognised magic, a
 * manifest_n larger than the caller's manifest_cap, and a short read of the
 * entry array -- and all four zeroed manifest_n / next_gen / next_run_no and
 * fell through to success, returning the WAL replay count. The store then
 * believed it had no runs at all, which is indistinguishable from a fresh
 * store. An open() that failed for any reason other than ENOENT took the
 * neighbouring "no manifest" path and did the same.
 *
 * Why that is worse than a wrong answer: in the daemon, boot's ghost rollback
 * issues puts and dels that can cross fill_threshold and trigger mac_flush,
 * which publishes a manifest naming only the new run. Every real run becomes
 * an orphan, and the next boot's lsm_manifest_sweep_orphans -- which requires
 * on-disk and in-memory to agree, and now they do -- deletes them for real.
 * In the read-only tools it answers from the WAL tail and says
 * "consistent: true".
 *
 * The over-capacity case is the most likely in practice: the daemon passes
 * manifest_cap 256, the tools pass 4096, and build_utxo/migrate write up to
 * 8192 entries.
 *
 * WHAT IS ASSERTED. Each corruption is applied to a manifest the SAME harness
 * has just written and reloaded successfully, so a failure cannot be blamed
 * on the fixture. The absent-manifest case is asserted to still succeed --
 * without it, "fail on anything" would pass this file and break every fresh
 * store.
 *
 * Usage: ./test_utxo_manifest_bad
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef unsigned long long u64;
typedef unsigned char u8;

struct lsm_state { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; u64 op_count, op_threshold, fill_threshold;
    void* tomb_buf; u64 tomb_cap, tomb_n, total_live, next_gen; void* manifest_buf; u64 manifest_cap, manifest_n;
    void* scratch_buf; u64 scratch_cap; u64 next_run_no; void* tomb_hash_buf; u64 tomb_hash_mask; };

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const u8* txid, unsigned index, u64 value,
                         unsigned long height, unsigned long cb, const u8* script, unsigned slen);
extern long utxo_lsm_reload(void* lst, void* u);
extern void utxo_lsm_close(void* lst);

#define MANIFEST "utxo_manifest.dat"
#define MAGIC2   0x324E4D55u

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("ok  : %s\n", l); else { printf("FAIL: %s\n", l); fails++; } }
static void mk(u8* t, unsigned i){ for (int j=0;j<32;j++) t[j]=(u8)(0x30+j); t[0]=(u8)i; t[1]=(u8)(i>>8); }

static void state_init(struct lsm_state* lst, unsigned long slots, unsigned long tombs, unsigned long mcap){
    memset(lst, 0, sizeof *lst);
    lst->op_threshold   = 100000000ULL;
    lst->fill_threshold = slots;
    lst->tomb_buf = malloc(tombs * 36); lst->tomb_cap = tombs;
    lst->manifest_buf = malloc(mcap * 16); lst->manifest_cap = mcap;
    lst->scratch_cap = (u64)(slots + tombs) * 128 + 8ULL*1024*1024 + 65536;
    lst->scratch_buf = malloc(lst->scratch_cap);
}

/* Reload into a fresh state and return what utxo_lsm_reload said. */
static long try_reload(unsigned long mcap, u64* out_n){
    void* blob = malloc(4u<<20);
    void* u = malloc(utxo_struct_size(4096));
    utxo_init(u, 4096, blob, 4u<<20);
    struct lsm_state lst; state_init(&lst, 4096, 512, mcap);
    long r = utxo_lsm_reload(&lst, u);
    if (out_n) *out_n = lst.manifest_n;
    utxo_lsm_close(&lst);
    free(u); free(blob);
    return r;
}

/* Restore the captured, genuinely valid manifest. */
static void restore_good(const unsigned char* good, long len){
    int fd = open(MANIFEST, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    (void)!write(fd, good, (size_t)len); close(fd);
}

/* Write a syntactically valid v2 manifest naming `n` runs that do NOT exist.
 * Only used for the capacity check, which must reject BEFORE any run file is
 * opened -- so the missing files never come into it. */
static void write_manifest(u64 n){
    int fd = open(MANIFEST, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    unsigned char h[20]; memset(h, 0, sizeof h);
    unsigned magic = MAGIC2;
    memcpy(h, &magic, 4); memcpy(h+4, &n, 8);
    u64 live = 7; memcpy(h+12, &live, 8);
    (void)!write(fd, h, 20);
    for (u64 i = 0; i < n; i++){
        unsigned char e[16]; u64 g = i, r = i;
        memcpy(e, &g, 8); memcpy(e+8, &r, 8);
        (void)!write(fd, e, 16);
    }
    close(fd);
}

int main(void){
    char tmpl[] = "/tmp/utxmanXXXXXX"; char* dir = mkdtemp(tmpl);
    if (!dir || chdir(dir) != 0){ printf("FAIL: tmpdir\n"); return 1; }

    /* ---- a REAL store: enough records, with a low fill_threshold, that
     * mac_flush writes an actual run file and publishes a real manifest.
     * A hand-written manifest naming runs that do not exist fails the reload
     * for an unrelated reason (the run files cannot be opened), so the
     * "valid manifest" controls below must use a manifest the store itself
     * produced. ------------------------------------------------------- */
    {
        void* blob = malloc(8u<<20);
        void* u = malloc(utxo_struct_size(4096));
        utxo_init(u, 4096, blob, 8u<<20);
        struct lsm_state lst; state_init(&lst, 4096, 512, 512);
        lst.fill_threshold = 64;                 /* flush early and often */
        ck("harness init", utxo_lsm_init(&lst) == 1);
        u8 script[24]; for (int j=0;j<24;j++) script[j]=(u8)(0x90+j);
        for (unsigned i = 0; i < 400; i++){ u8 t[32]; mk(t,i);
            if (utxo_lsm_put(&lst, u, t, 0, 1000+i, 100+i, 0, script, 24) != 1){ ck("wal write", 0); break; } }
        utxo_lsm_close(&lst);
        free(u); free(blob);
    }
    ck("the store published a real manifest", access(MANIFEST, F_OK) == 0);
    /* Keep the good bytes so every corruption below starts from a manifest
     * this same harness has just reloaded successfully. */
    static unsigned char good[64*1024]; long goodlen = 0;
    { int fd = open(MANIFEST, O_RDONLY); goodlen = read(fd, good, sizeof good); close(fd); }
    ck("good manifest captured", goodlen > 12);

    printf("== control: an ABSENT manifest is a fresh store, still a success ==\n");
    unlink(MANIFEST);
    { u64 n = 99; long r = try_reload(512, &n);
      ck("no manifest file -> reload succeeds", r >= 0);
      ck("...with zero runs", n == 0); }

    printf("== control: the store's OWN manifest reloads and is not rejected ==\n");
    restore_good(good, goodlen);
    u64 good_n = 0;
    { long r = try_reload(512, &good_n);
      printf("      (real manifest reload returned %ld, manifest_n %llu)\n", r, (unsigned long long)good_n);
      ck("a real published manifest -> reload succeeds", r >= 0);
      ck("...and its run entries are in memory", good_n >= 1); }

    printf("== UTX-6: an unrecognised magic FAILS the reload ==\n");
    restore_good(good, goodlen);
    { int fd = open(MANIFEST, O_WRONLY); unsigned bad = 0xdeadbeefu;
      (void)!pwrite(fd, &bad, 4, 0); close(fd); }
    { u64 n = 0; long r = try_reload(512, &n);
      ck("bad magic -> reload returns -1", r == -1);
      ck("...and it is NOT reported as an empty manifest", !(r >= 0 && n == 0)); }

    printf("== UTX-6: a manifest truncated mid-header FAILS ==\n");
    restore_good(good, goodlen);
    { (void)!truncate(MANIFEST, 6); }
    ck("6-byte manifest -> reload returns -1", try_reload(512, NULL) == -1);

    printf("== UTX-6: a manifest truncated mid-entry-array FAILS ==\n");
    restore_good(good, goodlen);
    { (void)!truncate(MANIFEST, goodlen - 5); }
    ck("short entry array -> reload returns -1", try_reload(512, NULL) == -1);

    printf("== UTX-6: manifest_n > manifest_cap FAILS (the daemon-vs-tools case) ==\n");
    write_manifest(300);          /* build_utxo-sized manifest ... */
    { u64 n = 0; long r = try_reload(256, &n);   /* ... read with the daemon's cap */
      ck("300 runs into a 256-entry cap -> reload returns -1", r == -1);
      ck("...and does NOT read as a store with no runs", !(r >= 0 && n == 0)); }
    restore_good(good, goodlen);
    { u64 n = 0; long r = try_reload(512, &n);
      ck("the real manifest with a large enough cap still loads", r >= 0 && n == good_n); }

    printf("== UTX-6: an open() failure that is not ENOENT FAILS ==\n");
    unlink(MANIFEST);
    /* A symlink to itself: open() gives ELOOP for every uid, so this behaves
     * the same whether the suite runs as root or not (a chmod 000 file would
     * not). It is not ENOENT, so it must not read as a fresh store. */
    ck("symlink loop created", symlink(MANIFEST, MANIFEST) == 0);
    { u64 n = 0; long r = try_reload(512, &n);
      ck("manifest that exists but cannot be opened -> reload returns -1", r == -1);
      ck("...and is NOT mistaken for an absent manifest", !(r >= 0 && n == 0)); }
    unlink(MANIFEST);

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
