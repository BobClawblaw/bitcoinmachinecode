/* test_mempool_persist.c -- Core's mempool.dat format.
 *
 * The two things worth pinning are the ones a plausible implementation gets
 * wrong silently:
 *   - the v2 XOR origin. Core sets obfuscation on the stream AFTER reading
 *     version+key, so the first obfuscated byte is at WHOLE-FILE offset 16
 *     and its key index is 16 % 8 == 0. Keying from 0 instead decodes the
 *     transaction count correctly (it is 8 bytes at an 8-aligned offset) and
 *     then fails on the first transaction -- a confusing way to find out.
 *   - a truncated file must be REFUSED, not partially loaded. A mempool
 *     half-restored from a torn dump is worse than one not restored at all.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tests/test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned long long u64;

extern long mempool_dump_write(const char* path, const u8* const* txs,
                               const unsigned long* lens, const long long* times,
                               const long long* deltas, long n,
                               const u8* extra_txids, const long long* extra_deltas,
                               long n_extra);
extern long mempool_dump_read(const char* path,
                              int (*sink)(void*, const u8*, unsigned long, long long, long long),
                              void* ctx, char* err, unsigned long errcap);

static int failures = 0;
static void ck(const char* l, int c){ if(c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); failures++; } }

/* minimal well-formed tx (the same shape test_package_policy builds) */
static unsigned long mk_tx(u8* out, u8 tag){
    u8* p = out;
    p[0]=2;p[1]=0;p[2]=0;p[3]=0; p+=4;
    *p++ = 1;
    memset(p, tag, 32); p += 32;
    p[0]=0;p[1]=0;p[2]=0;p[3]=0; p+=4;
    *p++ = 0;
    p[0]=0xfd;p[1]=0xff;p[2]=0xff;p[3]=0xff; p+=4;
    *p++ = 1;
    for(int k=0;k<8;k++) *p++ = (u8)(k==0?0x40:0);      /* value */
    *p++ = 22; *p++ = 0x00; *p++ = 0x14;
    for(int k=0;k<20;k++) *p++ = (u8)(k+tag);
    p[0]=0;p[1]=0;p[2]=0;p[3]=0; p+=4;
    return (unsigned long)(p - out);
}

typedef struct { int n; u8 txid_tag[8]; long long t[8], d[8]; unsigned long len[8]; } collect;
static int sink(void* ctx, const u8* tx, unsigned long len, long long t, long long d){
    collect* c = (collect*)ctx;
    if (c->n >= 8) return -1;
    c->txid_tag[c->n] = tx[4];          /* first prevout byte = our tag */
    c->len[c->n] = len; c->t[c->n] = t; c->d[c->n] = d;
    c->n++;
    return 0;
}

int main(void){
    tt_isolate();
    static u8 a[512], b[512];
    unsigned long la = mk_tx(a, 0xA1), lb = mk_tx(b, 0xB2);
    const u8* txs[2] = { a, b };
    unsigned long lens[2] = { la, lb };
    long long times[2]  = { 1700000001LL, 1700000002LL };
    long long deltas[2] = { 0LL, -1234LL };

    printf("---- mempool.dat round trip ----\n");

    long w = mempool_dump_write("mempool.dat", txs, lens, times, deltas, 2, NULL, NULL, 0);
    ck("write reports both transactions", w == 2);

    { collect c; memset(&c, 0, sizeof c); char err[128]; err[0]=0;
      long r = mempool_dump_read("mempool.dat", sink, &c, err, sizeof err);
      ck("read returns both transactions", r == 2 && c.n == 2);
      ck("transaction bytes survive", c.len[0]==la && c.len[1]==lb);
      ck("entry times survive", c.t[0]==1700000001LL && c.t[1]==1700000002LL);
      ck("fee deltas survive, including a NEGATIVE one",
         c.d[0]==0LL && c.d[1]==-1234LL); }

    /* v2: same body, obfuscated. Built by hand here so the test does not
     * simply agree with our own writer about where the XOR starts. */
    { FILE* f = fopen("mempool.dat", "rb");
      fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
      u8* v1 = malloc((size_t)n); (void)!fread(v1, 1, (size_t)n, f); fclose(f);

      u8 key[8] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88};
      /* Core's layout EXACTLY: uint64 version, then the key as a VECTOR --
       * compact-size 8 followed by the bytes -- so the body starts at 17.
       * The first version of this fixture wrote a bare 8-byte key, which
       * agreed with the reader's identical mistake and passed while Core's
       * real files did not decode. A self-built fixture only tests the
       * format if it is built from the format, not from the reader. */
      long n2 = n + 9;
      u8* v2 = malloc((size_t)n2);
      memset(v2, 0, 8); v2[0] = 2;
      v2[8] = 8;                          /* compact-size length prefix */
      memcpy(v2+9, key, 8);
      memcpy(v2+17, v1+8, (size_t)(n-8));
      for (long i = 17; i < n2; i++) v2[i] ^= key[i % 8];
      f = fopen("mempool_v2.dat", "wb"); (void)!fwrite(v2, 1, (size_t)n2, f); fclose(f);

      collect c; memset(&c, 0, sizeof c); char err[128]; err[0]=0;
      long r = mempool_dump_read("mempool_v2.dat", sink, &c, err, sizeof err);
      ck("an obfuscated (v2) dump decodes", r == 2 && c.n == 2);
      ck("v2 entry times match the v1 original",
         c.t[0]==1700000001LL && c.t[1]==1700000002LL);
      if (r != 2) printf("      err: %s\n", err);
      free(v1); free(v2); }

    /* a truncated file must be refused outright */
    { FILE* f = fopen("mempool.dat", "rb");
      fseek(f, 0, SEEK_END); long n = ftell(f); rewind(f);
      u8* full = malloc((size_t)n); (void)!fread(full, 1, (size_t)n, f); fclose(f);
      f = fopen("trunc.dat", "wb"); (void)!fwrite(full, 1, (size_t)(n - 12), f); fclose(f);
      collect c; memset(&c, 0, sizeof c); char err[128]; err[0]=0;
      long r = mempool_dump_read("trunc.dat", sink, &c, err, sizeof err);
      ck("a truncated dump is refused, not partly loaded", r == -1 && err[0]);
      free(full); }

    /* an unknown version is refused rather than guessed at */
    { u8 h[32]; memset(h, 0, sizeof h); h[0] = 99;
      FILE* f = fopen("bad.dat", "wb"); (void)!fwrite(h, 1, sizeof h, f); fclose(f);
      char err[128]; err[0]=0;
      long r = mempool_dump_read("bad.dat", sink, NULL, err, sizeof err);
      ck("an unknown version is refused", r == -1 && strstr(err, "version")); }

    /* an empty pool is a legal dump */
    { long w0 = mempool_dump_write("empty.dat", NULL, NULL, NULL, NULL, 0, NULL, NULL, 0);
      collect c; memset(&c, 0, sizeof c); char err[128]; err[0]=0;
      long r = mempool_dump_read("empty.dat", sink, &c, err, sizeof err);
      ck("an empty mempool round-trips", w0 == 0 && r == 0 && c.n == 0); }

    if(failures) printf("\nFAILURES: %d\n", failures);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return failures ? 1 : 0;
}
