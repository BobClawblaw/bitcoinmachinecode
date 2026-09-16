/* test_rpc_chain_growth.c -- by-hash lookups must keep working as the archive
 * GROWS under a live rpc_chain view.
 *
 * Run 24 (2026-09-16) exposed this on a syncing node: getblock served every
 * height up to a fixed cut and answered "-5 Block not found" for everything
 * above it, at every verbosity, while the tip kept advancing. The cut did not
 * move as the tip went 159,440 -> 193,360. getblockhash worked at every
 * height, so only the hash->height lookup was affected. Production never
 * showed it because production opened its store when the chain was already
 * complete, so the boot-time fold covered everything.
 *
 * This test reproduces the shape: open the chain view at a LOW tip, append
 * more blocks the way the daemon does, then look the new blocks up by hash.
 * The blocks are synthetic 81-byte stubs -- the assertion is purely about the
 * hash->height index, so a header that would not pass consensus is fine. A
 * lookup that resolves is the pass; "-5 Block not found" is the defect.
 */
#include "../rpc_json.h"
#include "../rpc_chain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test_tmpdir.h"
#include <sys/wait.h>
#include <unistd.h>

extern int  store_init(void* st);
extern long store_append(void* st, const unsigned char* hash32, const void* blk, long len);
extern void store_reload(void* st);
extern void sha256d(unsigned char out[32], const void* data, unsigned long len);

/* the mempool policy layer wants this resolver; this test never exercises
 * mempool acceptance, so a refusing stub is the honest shape. */
long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script,
                     unsigned long* slen);
long mempool_resolve_confirmed_utxo(void* u, const unsigned char txid[32], unsigned long index,
                     unsigned long long* value, const unsigned char** script,
                     unsigned long* slen){
    (void)u; (void)txid; (void)index; (void)value; (void)script; (void)slen;
    return 0;
}

static int fails = 0;
static void ck(const char* l, int c){ printf("%s %s\n", c ? "ok  :" : "FAIL:", l); if (!c) fails++; }

static unsigned char g_st[4096];

/* An 81-byte block whose header is just the height painted into the nonce
 * area: unique per height, which is all the index cares about. */
static long mk_block(unsigned char* blk, unsigned h){
    memset(blk, 0, 81);
    blk[0] = 1;
    for (int i = 0; i < 4; i++) blk[76+i] = (unsigned char)(h >> (8*i));
    blk[80] = 0;                      /* tx count 0 */
    return 81;
}
static void tohex_rev(char* out, const unsigned char* b, int n){
    static const char* H = "0123456789abcdef";
    for (int i = 0; i < n; i++){ unsigned char c = b[n-1-i]; out[i*2]=H[c>>4]; out[i*2+1]=H[c&15]; }
    out[n*2] = 0;
}

/* getblock <hash> 1 -- returns 1 if the node RESOLVED the hash. Anything other
 * than -5 counts as resolved: a stub block may fail to render, but rendering
 * is not what this test is about. */
static int resolves(const char* hash_disp){
    rj_val* p = rj_arr();
    rj_arr_push(p, rj_str(hash_disp));
    rj_arr_push(p, rj_numf("%d", 1));
    rj_val* res = NULL; long ec = 0; const char* em = NULL;
    int r = rpc_chain_dispatch("getblock", p, &res, &ec, &em);
    rj_free(p); if (res) rj_free(res);
    if (r == 1) return 1;
    return ec != -5;
}

int main(void){
    tt_isolate();

    enum { AT_OPEN = 64, GROWN = 8192 };
    char hash_at_open[65], hash_grown[65], hash_low[65];

    memset(g_st, 0, sizeof g_st);
    if (store_init(g_st) != 1){ printf("FAIL store_init\n"); return 1; }

    /* the chain as it stands when the RPC view opens */
    for (unsigned h = 0; h <= AT_OPEN; h++){
        unsigned char blk[128]; long n = mk_block(blk, h);
        unsigned char id[32]; sha256d(id, blk, (unsigned long)n);
        if (store_append(g_st, id, blk, n) < 0){ printf("FAIL append %u\n", h); return 1; }
        if (h == 1) tohex_rev(hash_low, id, 32);
        if (h == AT_OPEN) tohex_rev(hash_at_open, id, 32);
    }

    ck("rpc_chain_open on the short chain", rpc_chain_open(NULL) == 1);
    ck("a block present at open resolves", resolves(hash_at_open));

    /* Now the daemon keeps syncing underneath the open view. This MUST happen
     * in another process with its own store handle: that is the real shape on
     * a node (the RPC reader refreshes via store_reload off index.dat), and it
     * is the part an in-process append does not model -- sharing one handle
     * makes the reader see the writer's appends for free. */
    { unsigned char last[32];
      for (unsigned h = AT_OPEN + 1; h <= GROWN; h++){
          unsigned char blk[128]; long n = mk_block(blk, h);
          sha256d(last, blk, (unsigned long)n);
          if (h == GROWN) tohex_rev(hash_grown, last, 32);
      } }
    { pid_t pid = fork();
      if (pid == 0){
          static unsigned char st2[4096];
          memset(st2, 0, sizeof st2);
          if (store_init(st2) != 1) _exit(2);
          store_reload(st2);   /* learn the tip already on disk, as rpc_chain_open does -- without this the writer appends from height 0 and overwrites the chain the reader opened on */
          for (unsigned h = AT_OPEN + 1; h <= GROWN; h++){
              unsigned char blk[128]; long n = mk_block(blk, h);
              unsigned char id[32]; sha256d(id, blk, (unsigned long)n);
              if (store_append(st2, id, blk, n) < 0) _exit(3);
          }
          _exit(0);
      }
      int ws = 0; waitpid(pid, &ws, 0);
      ck("writer process appended the new blocks",
         WIFEXITED(ws) && WEXITSTATUS(ws) == 0);
    }

    /* the tip advances for the RPC view (this is what getblockcount reports
     * and what drives the index fold) */
    { rj_val* res = NULL; long ec; const char* em;
      rpc_chain_dispatch("getblockcount", NULL, &res, &ec, &em);
      if (res){ printf("      getblockcount after growth: %s\n", res->str ? res->str : "?"); rj_free(res); } }

    ck("a block appended AFTER open resolves by hash", resolves(hash_grown));
    ck("an early block still resolves after growth", resolves(hash_low));

    printf(fails ? "\nFAILURES: %d\n" : "\nall good\n", fails);
    return fails ? 1 : 0;
}
