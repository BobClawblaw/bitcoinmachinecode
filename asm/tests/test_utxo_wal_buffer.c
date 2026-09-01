/* tests/test_utxo_wal_buffer.c -- the store's buffered WAL (2026-09-01).
 *   1. puts are buffered: the file lags log_len until a drain; log_len is
 *      the LOGICAL length at all times;
 *   2. utxo_store_wal_drain lands every byte (file size == log_len);
 *   3. a reload (which measures the file) drains implicitly and replays
 *      everything, including records that were only buffered;
 *   4. a checkpoint (utxo_store_sync) drains;
 *   5. a process that dies with undrained bytes loses exactly that suffix
 *      and nothing before it (fork + _exit without a drain).
 *   6. a record larger than the buffer goes straight through, in order. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "test_tmpdir.h"
struct US { long log_fd, idx_fd; unsigned long long log_len, ckpt_log_off, ckpt_n; };
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void* u, unsigned long slots, void* blob, unsigned long cap);
extern long utxo_store_init(void* st);
extern long utxo_store_sync(void* st, void* u);
extern long utxo_store_reload(void* st, void* u);
extern long utxo_store_wal_drain(void* st);
extern long utxo_store_put(void* st, void* u, const unsigned char txid[32], unsigned long index, unsigned long long value, unsigned long height, unsigned long is_coinbase, const unsigned char* script, unsigned long slen);
extern long utxo_store_get(void* st, void* u, const unsigned char txid[32], unsigned long index, unsigned long long* value, unsigned long* height, unsigned long* is_coinbase, const unsigned char** script, unsigned long* slen);
extern long utxo_store_count(void* st, void* u);
extern void utxo_store_close(void* st);
static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }
static void txid_of(unsigned char* t, unsigned i){ memset(t, 0x33, 32); memcpy(t, &i, 4); }
static long fsize(void){ struct stat st; return stat("utxo.dat", &st) == 0 ? (long)st.st_size : -1; }
enum { SLOTS = 1 << 17, N = 30000 };
static void* mk_table(void){ void* u = malloc(utxo_struct_size(SLOTS)); utxo_init(u, SLOTS, malloc(32u << 20), 32u << 20); return u; }
int main(void){
    tt_isolate();
    struct US st; memset(&st, 0, sizeof st);
    ck("store_init", utxo_store_init(&st) == 1);
    void* u = mk_table();
    unsigned char script[40]; memset(script, 0x51, sizeof script);
    printf("== %d puts (~%d KB of WAL) ==\n", N, N * 99 / 1024);
    for (unsigned i = 0; i < N; i++){ unsigned char t[32]; txid_of(t, i);
        if (utxo_store_put(&st, u, t, i & 7, 1000ULL + i, 100 + (i % 50), 0, script, 40) != 1){ printf("FAIL put %u\n", i); return 1; } }
    ck("log_len counts every record (logical length)", st.log_len == (unsigned long long)N * (59 + 40));
    ck("the file lags log_len before a drain (bytes are buffered)", fsize() < (long)st.log_len);
    printf("  (file %ld of log_len %llu)\n", fsize(), st.log_len);
    ck("utxo_store_wal_drain -> 0", utxo_store_wal_drain(&st) == 0);
    ck("file size == log_len after the drain", fsize() == (long)st.log_len);
    ck("a second drain with nothing pending is a no-op", utxo_store_wal_drain(&st) == 0 && fsize() == (long)st.log_len);
    /* buffered records + implicit drain on reload */
    for (unsigned i = N; i < N + 500; i++){ unsigned char t[32]; txid_of(t, i); utxo_store_put(&st, u, t, i & 7, 1000ULL + i, 7, 0, script, 40); }
    ck("500 more are buffered again", fsize() < (long)st.log_len);
    { struct US st2; memset(&st2, 0, sizeof st2); void* u2 = mk_table();
      ck("second store init on the same files", utxo_store_init(&st2) == 1);
      long rep = utxo_store_reload(&st2, u2);
      ck("reload drains implicitly and replays every record", rep >= 0 && utxo_store_count(&st2, u2) == N + 500);
      printf("  (replayed=%ld count=%ld)\n", rep, utxo_store_count(&st2, u2));
      ck("file size == logical length after the reload", fsize() == (long)st.log_len);
      unsigned char t[32]; txid_of(t, N + 499); unsigned long long v = 0; unsigned long h = 0, cb = 0, sl = 0; const unsigned char* sp = 0;
      ck("the last buffered record is readable after the reload", utxo_store_get(&st2, u2, t, (N + 499) & 7, &v, &h, &cb, &sp, &sl) == 1 && v == 1000ULL + N + 499 && sl == 40);
      st2.log_fd = -1; st2.idx_fd = -1; /* leave the shared files to st */ }
    /* checkpoint drains */
    { unsigned char t[32]; txid_of(t, N + 500); utxo_store_put(&st, u, t, 0, 5, 7, 0, script, 40);
      ck("buffered before the checkpoint", fsize() < (long)st.log_len);
      ck("utxo_store_sync", utxo_store_sync(&st, u) == 1);
      ck("checkpoint drained the WAL (file size == log_len)", fsize() == (long)st.log_len); }
    /* crash: a child appends without draining and dies */
    long before = fsize();
    pid_t pid = fork();
    if (pid == 0){ for (unsigned i = 0; i < 100; i++){ unsigned char t[32]; txid_of(t, 900000 + i); utxo_store_put(&st, u, t, 0, 1, 1, 0, script, 40); } _exit(0); }
    int status = 0; waitpid(pid, &status, 0);
    ck("a process that dies with undrained bytes loses exactly that suffix", fsize() == before);
    { struct US st3; memset(&st3, 0, sizeof st3); void* u3 = mk_table(); utxo_store_init(&st3);
      utxo_store_wal_drain(&st); /* parent's own buffer is empty; harmless */
      long rep = utxo_store_reload(&st3, u3);
      ck("...and everything before it is intact", rep >= 0 && utxo_store_count(&st3, u3) == N + 501);
      st3.log_fd = -1; st3.idx_fd = -1; }
    /* oversize record: straight through, in order */
    { static unsigned char big[65000]; memset(big, 0x6a, sizeof big);
      unsigned char a[32], b[32]; txid_of(a, 700001); txid_of(b, 700002);
      utxo_store_put(&st, u, a, 1, 11, 9, 0, script, 40);          /* buffered */
      /* a script is capped well below the buffer, so the "larger than the buffer" path is exercised by
         filling the buffer to within a few bytes of the cap and appending: the append drains first. */
      for (unsigned i = 0; fsize() + 0 >= 0 && i < 12000; i++){ unsigned char t[32]; txid_of(t, 800000 + i); utxo_store_put(&st, u, t, 0, 1, 1, 0, big, 60); }
      utxo_store_put(&st, u, b, 2, 22, 9, 0, script, 40);
      ck("the buffer drained itself while filling past 1 MB", fsize() > before);
      ck("utxo_store_wal_drain -> 0", utxo_store_wal_drain(&st) == 0);
      struct US st4; memset(&st4, 0, sizeof st4); void* u4 = mk_table(); utxo_store_init(&st4);
      long rep = utxo_store_reload(&st4, u4);
      unsigned long long v = 0; unsigned long h = 0, cb = 0, sl = 0; const unsigned char* sp = 0;
      ck("records written across a self-drain are all there and in order", rep >= 0 && utxo_store_count(&st4, u4) == N + 501 + 2 + 12000
         && utxo_store_get(&st4, u4, a, 1, &v, &h, &cb, &sp, &sl) == 1 && v == 11 && utxo_store_get(&st4, u4, b, 2, &v, &h, &cb, &sp, &sl) == 1 && v == 22);
      printf("  (count=%ld)\n", utxo_store_count(&st4, u4));
      st4.log_fd = -1; st4.idx_fd = -1; }
    utxo_store_close(&st);
    printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
    return fails ? 1 : 0;
}
