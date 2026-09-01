/* tests/test_mempool_persist_wiring.c -- -persistmempool is a real option.
 *
 * The machinery to read and write Core's mempool.dat existed and was tested
 * for a long time while NOTHING CALLED IT, so the option was accepted from
 * bitcoin.conf and did nothing. That is the failure mode this project treats
 * as worse than an absent feature: the operator believes the mempool survives
 * a restart, and only finds out otherwise after one.
 *
 * This pins the two halves that made it inert:
 *   - the config key is honoured and no longer on the unimplemented list;
 *   - a dump written by the save path is readable by the load path, with the
 *     transactions and their metadata intact.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "../daemon/node_config.h"

extern node_config_t g_cfg;
extern int  nodecfg_unimplemented(const char* key);
typedef unsigned char u8;
extern long mempool_dump_write(const char* path, const u8* const* txs,
                               const unsigned long* lens, const long long* times,
                               const long long* deltas, long n,
                               const u8* extra_txids, const long long* extra_deltas,
                               long n_extra);
extern long mempool_dump_read(const char* path,
                              int (*sink)(void*, const u8*, unsigned long, long long, long long),
                              void* ctx, char* err, unsigned long errcap);

/* A minimal but VALID transaction, tagged so entries stay distinguishable --
 * same shape tests/test_mempool_persist.c uses. */
static unsigned long mk_tx(u8* out, u8 tag){
    u8* p = out;
    p[0]=2;p[1]=0;p[2]=0;p[3]=0; p+=4;
    *p++ = 1;
    memset(p, tag, 32); p += 32;
    p[0]=0;p[1]=0;p[2]=0;p[3]=0; p+=4;
    *p++ = 0;
    p[0]=0xfd;p[1]=0xff;p[2]=0xff;p[3]=0xff; p+=4;
    *p++ = 1;
    for(int k=0;k<8;k++) *p++ = (u8)(k==0?0x40:0);
    *p++ = 22; *p++ = 0x00; *p++ = 0x14;
    for(int k=0;k<20;k++) *p++ = (u8)(k+tag);
    p[0]=0;p[1]=0;p[2]=0;p[3]=0; p+=4;
    return (unsigned long)(p - out);
}

static int fails = 0;
static void ck(const char* l, int c){ if (c) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); fails++; } }

typedef struct { long n; unsigned long lens[4]; long long times[4], deltas[4]; u8 first[8]; } sink_ctx;
static int sink(void* vc, const u8* tx, unsigned long len, long long time, long long delta){
    sink_ctx* c = (sink_ctx*)vc;
    if (c->n < 4){
        c->lens[c->n] = len; c->times[c->n] = time; c->deltas[c->n] = delta;
        if (c->n == 0 && len >= 8) memcpy(c->first, tx, 8);
    }
    c->n++;
    return 1;
}

int main(void){
    printf("== the config key is honoured ==\n");
    /* g_cfg carries static initialisers, so the default is in effect without
     * loading any file -- which is the state a node starts in. */
    ck("persistmempool defaults to 1, as in Core", g_cfg.persistmempool == 1);
    ck("  and it is no longer on the unimplemented list",
       nodecfg_unimplemented("persistmempool") == 0);
    ck("  a key that really is unimplemented still warns",
       nodecfg_unimplemented("txreconciliation") == 1);   /* bytespersigop is implemented now */

    printf("== a dump round-trips through the save and load paths ==\n");
    /* Two transactions with distinguishable lengths, times and fee deltas, so
     * a load that silently dropped or reordered metadata would show. */
    { char path[256];
      snprintf(path, sizeof path, "/tmp/mpd_wiring_%d.dat", (int)getpid());
      /* Real serialised transactions: the reader runs tx_parse over each
       * entry, so random bytes are rejected as malformed and the round trip
       * proves nothing. (My first cut used filler and failed exactly there.) */
      static u8 tx1[256], tx2[256];
      unsigned long l1 = mk_tx(tx1, 0xA1), l2 = mk_tx(tx2, 0xB2);
      const u8* txs[2]  = { tx1, tx2 };
      unsigned long lens[2] = { l1, l2 };
      long long times[2]  = { 1700000001LL, 1700000002LL };
      long long deltas[2] = { 0, -1234 };

      long w = mempool_dump_write(path, txs, lens, times, deltas, 2, NULL, NULL, 0);
      ck("the save path writes both transactions", w == 2);

      sink_ctx c; memset(&c, 0, sizeof c);
      char err[160]; err[0] = 0;
      long r = mempool_dump_read(path, sink, &c, err, sizeof err);
      ck("the load path reads them back", r == 2 && c.n == 2);
      ck("  lengths survive", c.lens[0] == l1 && c.lens[1] == l2);
      ck("  entry times survive", c.times[0] == 1700000001LL && c.times[1] == 1700000002LL);
      ck("  and the fee deltas, including a NEGATIVE one",
         c.deltas[0] == 0 && c.deltas[1] == -1234);
      /* offset 0..3 = version, 4 = input count, 5.. = the tagged prevout */
      ck("  the transaction bytes are unchanged",
         c.first[0] == 2 && c.first[4] == 1 && c.first[5] == 0xA1);
      unlink(path); }

    printf("== a missing dump is not an error ==\n");
    /* A fresh datadir has no mempool.dat. Treating that as a failure would
     * make every first boot log an error it cannot act on. */
    { sink_ctx c; memset(&c, 0, sizeof c);
      char err[160]; err[0] = 0;
      long r = mempool_dump_read("/tmp/definitely_no_such_mempool_dump.dat", sink, &c, err, sizeof err);
      ck("reading an absent file reports -1 with a reason", r == -1 && err[0] != 0);
      ck("  and admits nothing", c.n == 0); }

    printf("== an empty mempool still writes a valid dump ==\n");
    /* A node with nothing in its pool must not write a file the next boot
     * refuses -- that would turn a quiet restart into a logged failure. */
    { char path[256];
      snprintf(path, sizeof path, "/tmp/mpd_empty_%d.dat", (int)getpid());
      long w = mempool_dump_write(path, NULL, NULL, NULL, NULL, 0, NULL, NULL, 0);
      ck("writing an empty pool succeeds", w == 0);
      sink_ctx c; memset(&c, 0, sizeof c);
      char err[160]; err[0] = 0;
      long r = mempool_dump_read(path, sink, &c, err, sizeof err);
      ck("  and it reads back as zero transactions, not as corruption",
         r == 0 && c.n == 0);
      unlink(path); }

    /* ---- the serve process's reload yields to SIGTERM and does not block
     * the serve loop (2026-09-01: the shutdown-flag hook was installed only
     * in the download worker; the serve's inline boot reload ignored
     * systemd's SIGTERM for 184 s and, SIGKILLed, saved no mempool.dat) ---- */
    { FILE* f = fopen("daemon/main.c", "r");
      ck("daemon/main.c is readable for the structure check", f != NULL);
      if (f){
          fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
          char* src = malloc((size_t)n + 1); size_t got = fread(src, 1, (size_t)n, f); src[got] = 0; fclose(f);
          const char* boot = strstr(src, "rpc_node_set_shutdown_flag(&g_shutdown_requested); }\n            if(pthread_create(&g_mempool_reload_thread");
          ck("reload yields to SIGTERM in the serve process: the hook is installed right before the reload thread starts", boot != NULL);
          ck("the reload runs on a thread, not inline in the boot path", strstr(src, "static void* mempool_reload_thread(void* arg)") != NULL
             && strstr(src, "            long acc = rpc_node_mempool_load(\"mempool.dat\");\n            if(acc < 0)") == NULL);
          const char* sd = strstr(src, "mempool_reload_join();\n            if(CFG_PERSISTMEMPOOL()){\n                long w = rpc_node_mempool_save");
          ck("the shutdown dump waits for a still-running reload to abort first", sd != NULL);
          free(src);
      } }

    if (fails) printf("\nFAILURES: %d\n", fails);
    else printf("\nALL TESTS PASSED (0 failures)\n");
    return fails ? 1 : 0;
}
