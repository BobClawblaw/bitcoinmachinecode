/* tests/test_utxo_async_flush.c -- plan B3 (2026-10-06): the memtable flush
 * off the applier, at the LSM layer (bitcoin_utxo_lsm.asm's freeze, the
 * frozen consult in get, the run writer, the retired WAL bytes).
 *
 *   1. a freeze keeps every read right: keys put before it are found
 *      (from the copy, before any run exists), a del after it shadows a
 *      frozen key, a put after it is found; the run written from the copy
 *      and adopted gives the same answers, and so does a reload.
 *   2. the reload's tombstone pass starts at the checkpoint offset: with
 *      the retired bytes zeroed (a punched hole), a DEL appended above the
 *      offset must still shadow the run after a reload.
 *   3. a crash before the adopt loses nothing: the generation replays from
 *      the WAL, the unadopted run is an orphan.
 *   4. the freeze hook replaces mac_flush at the threshold crossing.
 *   5. a second freeze while one is frozen is refused.
 *
 * Revert checks (each was watched to FAIL against the unfixed code): 1
 * without the frozen consult in utxo_lsm_get (the frozen keys read as
 * absent), 2 with the tombstone pass from byte 0 (the del is lost: the key
 * reads as live from the run), 3 if the freeze truncated the WAL as
 * mac_flush does, 4 without the hook (mac_flush runs: manifest_n grows). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "test_tmpdir.h"
#include "../daemon/lsm_state.h"

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_count(void* u);
extern long utxo_lsm_init(void* lst);
extern long utxo_lsm_put(void* lst, void* u, const unsigned char txid[32], unsigned index, unsigned long long value,
                         unsigned long height, unsigned long is_coinbase, const unsigned char* script, unsigned slen);
extern long utxo_lsm_del(void* lst, void* u, const unsigned char txid[32], unsigned index);
extern long utxo_lsm_flush(void* lst, void* u);
extern long utxo_lsm_get(void* lst, void* u, const unsigned char txid[32], unsigned index, unsigned long long* value,
                         unsigned long* height, unsigned long* is_coinbase, const unsigned char** script, unsigned long* slen);
extern long utxo_lsm_count(void* lst);
extern long utxo_lsm_reload(void* lst, void* u);
extern void utxo_lsm_close(void* lst);
extern long utxo_lsm_freeze(void* lst, void* u, void* fz);
extern long utxo_lsm_build_run(void* lst, void* u, void* tomb_buf, unsigned long long tomb_n, unsigned long long gen, unsigned long long run_no);
extern void utxo_lsm_set_freeze_hook(long (*fn)(void*, void*));
extern void utxo_lsm_fz_enable(long on);

#define BLOOM_MAX_BYTES   (4*1024*1024)
#define SCRIPT_MAX_BYTES  65536
#define SLOTS 64
#define BLOBCAP (64*1024)

static int fails = 0;
static void ck(const char* l, long g, long e){
    if (g == e) printf("ok  : %-56s (got %ld)\n", l, g);
    else { printf("FAIL: %-56s (got %ld exp %ld)\n", l, g, e); fails++; }
}
static void key(unsigned char* t, unsigned i){ memset(t, 0x40, 32); t[0] = (unsigned char)i; t[1] = (unsigned char)(i >> 8); }
static long get1(struct lsm_state* lst, void* u, unsigned i, unsigned long long* v){
    unsigned char t[32]; key(t, i);
    unsigned long long value = 0; unsigned long h = 0, cb = 0, sl = 0; const unsigned char* sc = 0;
    long r = utxo_lsm_get(lst, u, t, 0, &value, &h, &cb, &sc, &sl);
    if (v) *v = value;
    return r;
}
static long put1(struct lsm_state* lst, void* u, unsigned i){
    unsigned char t[32]; key(t, i); unsigned char s[4] = { 0x51, (unsigned char)i, 0, 0 };
    return utxo_lsm_put(lst, u, t, 0, 1000ULL + i, 100 + i, 0, s, 4);
}
static long del1(struct lsm_state* lst, void* u, unsigned i){ unsigned char t[32]; key(t, i); return utxo_lsm_del(lst, u, t, 0); }

static void* mk_table(void){
    unsigned long sz = utxo_struct_size(SLOTS);
    void* u = calloc(1, sz); void* b = calloc(1, BLOBCAP);
    utxo_init(u, SLOTS, b, BLOBCAP);
    return u;
}
static void mk_lst(struct lsm_state* lst, void* fz){
    memset(lst, 0, sizeof *lst);
    lst->op_threshold = 1000000; lst->fill_threshold = 1000000;   /* no flush on its own */
    lst->tomb_cap = 4096; lst->tomb_buf = calloc(4096, 36);
    lst->manifest_cap = 64; lst->manifest_buf = calloc(64, 16);
    lst->scratch_cap = (unsigned long long)(SLOTS * 3) * 128 + BLOOM_MAX_BYTES + SCRIPT_MAX_BYTES;
    lst->scratch_buf = malloc(lst->scratch_cap);
    lst->fz_u = fz; lst->fz_tomb_buf = calloc(4096, 36);
}
/* the daemon's adopt, by hand: the manifest entry and a MAGIC_MANIFEST2 publish */
static void adopt(struct lsm_state* lst){
    unsigned char* e = (unsigned char*)lst->manifest_buf + lst->manifest_n * 16;
    memcpy(e, &lst->fz_gen, 8); memcpy(e + 8, &lst->fz_run_no, 8); lst->manifest_n++;
    unsigned char h[20]; unsigned magic = 0x324E4D55u; unsigned long long live = lst->total_live;
    memcpy(h, &magic, 4); memcpy(h + 4, &lst->manifest_n, 8); memcpy(h + 12, &live, 8);
    int fd = open("utxo_manifest.tmp", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || write(fd, h, 20) != 20 || write(fd, lst->manifest_buf, (size_t)lst->manifest_n * 16) != (ssize_t)(lst->manifest_n * 16)){ perror("publish"); exit(2); }
    fsync(fd); close(fd);
    if (rename("utxo_manifest.tmp", "utxo_manifest.dat") != 0){ perror("rename"); exit(2); }
    lst->fz_active = 0; lst->fz_tomb_n = 0;
}
/* the daemon's retire, by hand: utxo.idx {log_off, n=0} and the dead bytes zeroed (what a punched hole reads as) */
static void retire(struct lsm_state* lst){
    unsigned char h[20]; unsigned magic = 0x55545849u; unsigned long long off = lst->fz_wal_end, n = 0;
    memcpy(h, &magic, 4); memcpy(h + 4, &off, 8); memcpy(h + 12, &n, 8);
    int fd = open("utxo.idx", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || write(fd, h, 20) != 20){ perror("idx"); exit(2); }
    close(fd);
    unsigned char* z = calloc(1, (size_t)off);
    if (pwrite((int)lst->log_fd, z, (size_t)off, 0) != (ssize_t)off){ perror("zero"); exit(2); }
    free(z);
    lst->ckpt_log_off = off;
}
static long g_hook_calls = 0;
static long hook_count_only(void* lst, void* u){ (void)lst; (void)u; g_hook_calls++; return 1; }

int main(void){
    tt_isolate();
    utxo_lsm_fz_enable(1);
    void* u = mk_table(); void* fz = mk_table();
    struct lsm_state lst; mk_lst(&lst, fz);
    ck("utxo_lsm_init", utxo_lsm_init(&lst), 1);

    /* ---- 1. the freeze keeps every read right ---- */
    for (unsigned i = 1; i <= 10; i++) ck("put", put1(&lst, u, i), 1);
    ck("del K2 before the freeze", del1(&lst, u, 2), 1);
    ck("tombstones before the freeze", (long)lst.tomb_n, 1);
    ck("freeze", utxo_lsm_freeze(&lst, u, fz), 1);
    ck("live table empty after the freeze", utxo_count(u), 0);
    ck("op_count reset", (long)lst.op_count, 0);
    ck("fz_active", (long)lst.fz_active, 1);
    ck("frozen tombstones", (long)lst.fz_tomb_n, 1);
    ck("live tombstones", (long)lst.tomb_n, 0);
    ck("fz_gen reserved", (long)lst.fz_gen, 0); ck("next_gen advanced", (long)lst.next_gen, 1);
    ck("fz_run_no reserved", (long)lst.fz_run_no, 0); ck("next_run_no advanced", (long)lst.next_run_no, 1);
    ck("fz_wal_end = log_len", (long)(lst.fz_wal_end == lst.log_len), 1);
    ck("the copy holds the generation", utxo_count(fz), 9);
    { unsigned long long v = 0; ck("get K1 through the copy", get1(&lst, u, 1, &v), 1); ck("K1's value", (long)v, 1001); }
    ck("get K10 through the copy", get1(&lst, u, 10, 0), 1);
    ck("get K2 (deleted before the freeze)", get1(&lst, u, 2, 0), 0);
    ck("del K3 after the freeze", del1(&lst, u, 3), 1);
    ck("K3 shadowed by the live tombstone", get1(&lst, u, 3, 0), 0);
    ck("put K11 after the freeze", put1(&lst, u, 11), 1);
    ck("get K11 (live)", get1(&lst, u, 11, 0), 1);
    ck("a second freeze while frozen is refused", utxo_lsm_freeze(&lst, u, fz), -1);
    /* the writer */
    ck("build_run from the copy", utxo_lsm_build_run(&lst, fz, lst.fz_tomb_buf, lst.fz_tomb_n, lst.fz_gen, lst.fz_run_no), 1);
    { struct stat sb; ck("run file exists", stat("utxo_run_000000.dat", &sb) == 0, 1); }
    ck("manifest untouched by the writer", (long)lst.manifest_n, 0);
    adopt(&lst);
    ck("adopted: manifest_n", (long)lst.manifest_n, 1);
    ck("get K1 from the run", get1(&lst, u, 1, 0), 1);
    ck("get K2 absent (its tombstone is in the run)", get1(&lst, u, 2, 0), 0);
    ck("get K3 absent (live tombstone)", get1(&lst, u, 3, 0), 0);
    ck("get K11 (live)", get1(&lst, u, 11, 0), 1);
    retire(&lst);
    ck("retired: ckpt_log_off = fz_wal_end", (long)(lst.ckpt_log_off == lst.fz_wal_end), 1);
    /* ---- 2. the reload's tombstone pass starts at the checkpoint offset ---- */
    ck("del K4 above the retired bytes", del1(&lst, u, 4), 1);
    utxo_lsm_close(&lst);
    { struct lsm_state l2; void* u2 = mk_table(); void* fz2 = mk_table(); mk_lst(&l2, fz2);
      ck("reload", utxo_lsm_reload(&l2, u2) >= 0, 1);
      ck("reload: ckpt_log_off restored", (long)(l2.ckpt_log_off == lst.fz_wal_end), 1);
      ck("reload: the live generation replayed (K11)", get1(&l2, u2, 11, 0), 1);
      ck("reload: K3's tombstone rebuilt", get1(&l2, u2, 3, 0), 0);
      ck("reload: K4's tombstone rebuilt (pass from the checkpoint)", get1(&l2, u2, 4, 0), 0);
      ck("reload: K1 from the run", get1(&l2, u2, 1, 0), 1);
      ck("reload: K5 from the run", get1(&l2, u2, 5, 0), 1);
      utxo_lsm_close(&l2); }

    /* ---- 3. a crash before the adopt ---- */
    if (mkdir("crash", 0755) != 0 || chdir("crash") != 0) return 2;
    { void* u3 = mk_table(); void* fz3 = mk_table(); struct lsm_state l3; mk_lst(&l3, fz3);
      ck("init (crash dir)", utxo_lsm_init(&l3), 1);
      for (unsigned i = 1; i <= 5; i++) put1(&l3, u3, i);
      ck("freeze (crash)", utxo_lsm_freeze(&l3, u3, fz3), 1);
      ck("the writer wrote the run", utxo_lsm_build_run(&l3, fz3, l3.fz_tomb_buf, l3.fz_tomb_n, l3.fz_gen, l3.fz_run_no), 1);
      ck("WAL not truncated by the freeze", (long)(l3.log_len > 0), 1);
      utxo_lsm_close(&l3);                                      /* no adopt: the parent died here */
      void* u4 = mk_table(); void* fz4 = mk_table(); struct lsm_state l4; mk_lst(&l4, fz4);
      ck("reload after the crash", utxo_lsm_reload(&l4, u4) >= 0, 1);
      ck("every key of the generation replayed", utxo_count(u4), 5);
      for (unsigned i = 1; i <= 5; i++) ck("get after the crash", get1(&l4, u4, i, 0), 1);
      ck("no run adopted", (long)l4.manifest_n, 0);
      utxo_lsm_close(&l4); }

    /* ---- 4. the hook replaces mac_flush at the threshold crossing ---- */
    if (chdir("..") != 0 || mkdir("hook", 0755) != 0 || chdir("hook") != 0) return 2;
    { void* u5 = mk_table(); void* fz5 = mk_table(); struct lsm_state l5; mk_lst(&l5, fz5);
      ck("init (hook dir)", utxo_lsm_init(&l5), 1);
      l5.op_threshold = 4;
      utxo_lsm_set_freeze_hook(hook_count_only);
      for (unsigned i = 1; i <= 4; i++) put1(&l5, u5, i);
      ck("hook called at the crossing", g_hook_calls, 1);
      ck("mac_flush did not run (manifest_n)", (long)l5.manifest_n, 0);
      ck("the memtable still holds the generation", utxo_count(u5), 4);
      utxo_lsm_set_freeze_hook(0);
      l5.op_count = 0;
      for (unsigned i = 5; i <= 8; i++) put1(&l5, u5, i);
      ck("without the hook mac_flush runs (manifest_n)", (long)l5.manifest_n, 1);
      ck("hook not called again", g_hook_calls, 1);
      utxo_lsm_close(&l5); }

    printf("%s (%d failure%s)\n", fails ? "FAILED" : "ALL TESTS PASSED", fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
