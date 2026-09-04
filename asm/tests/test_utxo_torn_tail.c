/* tests/test_utxo_torn_tail.c -- UTX-4 (audit 2026-09-03), second half: a
 * torn WAL tail must be truncated, not left to poison every future reload.
 *
 * THE BUG. utxo_store_reload sets log_len from SEEK_END -- the physical file
 * size -- and stops replaying at the first record it cannot read: a short
 * prefix, a short body, or an unrecognised op byte. All three mean the bytes
 * from that point to the end are a PARTIALLY WRITTEN record, the tail of a
 * write that power loss or a kernel crash cut in half.
 *
 * Nothing was done about it. The daemon went on appending AFTER the torn
 * record, and every future reload stopped at that same record -- silently
 * dropping everything appended since. One torn write made the WAL permanently
 * unreplayable past that point, and the store went on looking healthy because
 * reload returned a plausible count.
 *
 * WHAT IS ASSERTED, in order, because each step depends on the last:
 *   1. a clean WAL replays completely (the control: without it, a reload that
 *      truncated everything would pass the rest);
 *   2. after appending garbage that cannot be a record, reload replays
 *      exactly the good records and no more;
 *   3. it TRUNCATES the file to the good length -- this is the fix;
 *   4. records written AFTER that reload survive the NEXT reload, which is
 *      the property the bug actually destroyed and the reason truncating
 *      matters rather than merely stopping early.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

typedef unsigned long long u64;
typedef unsigned char u8;

struct ustate { long log_fd, idx_fd; u64 log_len, ckpt_log_off, ckpt_n; };

extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_store_init(void* st);
extern long utxo_store_reload(void* st, void* u);
extern long utxo_store_put(void* st, void* u, const u8 txid[32], unsigned index,
                           u64 value, unsigned height, unsigned is_coinbase,
                           const u8* script, unsigned slen);
extern long utxo_store_close(void* st);
extern long utxo_count(void* u);

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

static void mk(u8* t, unsigned i){ memset(t, 0x40, 32); t[0]=(u8)i; t[1]=(u8)(i>>8); }

static long file_size(const char* p){
    struct stat sb;
    return stat(p, &sb) == 0 ? (long)sb.st_size : -1;
}

/* A fresh in-memory table + state, reloaded from whatever is on disk. */
static long reload_count(long* out_replayed){
    static void* blob; static void* u;
    if (!blob) blob = malloc(8u<<20);
    if (!u) u = malloc(utxo_struct_size(4096));
    utxo_init(u, 4096, blob, 8u<<20);
    struct ustate st; memset(&st, 0, sizeof st);
    /* utxo_store_reload does not open the fds itself -- it assumes
     * st->log_fd/idx_fd are already valid, mirroring the store's own
     * init-then-reload convention. It also needs the WRITABLE log fd to
     * truncate a torn tail. */
    if (utxo_store_init(&st) != 1){ if (out_replayed) *out_replayed = -99; return -1; }
    long r = utxo_store_reload(&st, u);
    if (out_replayed) *out_replayed = r;
    long n = utxo_count(u);
    utxo_store_close(&st);
    return n;
}

int main(void){
    char tmpl[] = "/tmp/utxtornXXXXXX"; char* dir = mkdtemp(tmpl);
    if (!dir || chdir(dir) != 0){ printf("FAIL: tmpdir\n"); return 1; }

    enum { NREC = 40 };
    u8 script[24]; for (int i=0;i<24;i++) script[i] = (u8)(0x90+i);

    printf("== control: a clean WAL replays completely ==\n");
    {
        void* blob = malloc(8u<<20);
        void* u = malloc(utxo_struct_size(4096));
        utxo_init(u, 4096, blob, 8u<<20);
        struct ustate st; memset(&st, 0, sizeof st);
        ck("store init", utxo_store_init(&st) == 1);
        for (unsigned i = 0; i < NREC; i++){
            u8 t[32]; mk(t, i);
            if (utxo_store_put(&st, u, t, 0, 1000+i, 100+i, 0, script, 24) != 1){ ck("put", 0); break; }
        }
        utxo_store_close(&st);
        free(u); free(blob);
    }
    long clean_size = file_size("utxo.dat");
    { long r = 0; long n = reload_count(&r);
      printf("      (clean: %ld bytes, replayed %ld, count %ld)\n", clean_size, r, n);
      ck("all records replay from a clean WAL", n == NREC);
      ck("...and the reload reports them", r == NREC); }

    printf("\n== a torn record at the end stops the replay ==\n");
    /* Append bytes that cannot begin a record: a valid-looking 8-byte prefix
     * with an op byte no version of this format defines, then nothing. This
     * is what a write cut in half leaves behind. */
    {
        int fd = open("utxo.dat", O_WRONLY|O_APPEND);
        u8 torn[8] = { 0,0,0,0, 0x7f, 0,0,0 };
        (void)!write(fd, torn, sizeof torn);
        close(fd);
    }
    long torn_size = file_size("utxo.dat");
    ck("the file really did grow", torn_size == clean_size + 8);
    { long r = 0; long n = reload_count(&r);
      printf("      (torn: %ld bytes before reload, replayed %ld, count %ld)\n", torn_size, r, n);
      ck("the good records still replay", n == NREC); }

    printf("\n== UTX-4: the torn tail is TRUNCATED away ==\n");
    { long after = file_size("utxo.dat");
      printf("      (%ld bytes after reload; clean was %ld)\n", after, clean_size);
      ck("the file is back to the good length", after == clean_size); }

    printf("\n== and records written after that reload SURVIVE the next one ==\n");
    /* This is the property the bug destroyed: with the torn record left in
     * place, these appends land after it and the next reload never reaches
     * them. */
    {
        void* blob = malloc(8u<<20);
        void* u = malloc(utxo_struct_size(4096));
        utxo_init(u, 4096, blob, 8u<<20);
        struct ustate st; memset(&st, 0, sizeof st);
        ck("re-init over the truncated WAL", utxo_store_init(&st) == 1);
        long pre = utxo_store_reload(&st, u);
        ck("reload before appending sees the good records", pre == NREC);
        for (unsigned i = NREC; i < NREC + 10; i++){
            u8 t[32]; mk(t, i);
            if (utxo_store_put(&st, u, t, 0, 1000+i, 100+i, 0, script, 24) != 1){ ck("append", 0); break; }
        }
        utxo_store_close(&st);
        free(u); free(blob);
    }
    { long r = 0; long n = reload_count(&r);
      printf("      (final: replayed %ld, count %ld, expected %d)\n", r, n, NREC + 10);
      ck("the later records are reachable on the next reload", n == NREC + 10); }

    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
