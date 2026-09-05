/* tests/test_txaccept_corpus.c -- real MINED transactions must verify.
 *
 * Every vector in txaccept_vec.h was mined into the main chain, so it is
 * consensus-valid under the script flags active AT ITS OWN HEIGHT. That is
 * the whole claim: this is the full-archive replay reduced to a unit test
 * that runs in milliseconds, over transactions chosen because they broke
 * someone's assumption rather than because they are common.
 *
 * WHY HEIGHT MATTERS. The flags are not fixed: DERSIG at 363,725, CLTV at
 * 388,381, CSV at 419,328, segwit at 481,824, taproot at 709,632. A
 * transaction from 2011 must verify under 2011's rules, and several of these
 * would be REJECTED under today's -- which is the point. Passing the wrong
 * height would turn this corpus into a test of nothing, so each vector
 * carries its own.
 *
 * WHAT THIS IS NOT: a standardness corpus. Several of these are
 * consensus-valid and non-standard today -- bare multisig, uncompressed keys,
 * high-S signatures. Core cannot even be asked for a standardness verdict on
 * a transaction whose inputs are long spent. Mempool policy is tested
 * separately (test_scr9_policy_flags, test_mempool_policy); conflating the
 * two would produce a confident wrong answer.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "txaccept_vec.h"

typedef unsigned char u8;
typedef unsigned long long u64;

extern int tx_verify_at_height(const u8* tx, u64 txlen, long height,
                               int (*rf)(void*, const u8[36], unsigned,
                                         u64*, u64*, u64*, const u8**, unsigned long*),
                               void* rctx, const char** reason);
extern int tx_dispatch_init(void);

static int fails = 0, checks = 0;
static void ck(const char* label, int cond){
    checks++;
    printf("%s %s\n", cond ? "ok  :" : "FAIL:", label);
    if (!cond) fails++;
}

static long unhex(const char* s, u8* out, long cap){
    long n = 0;
    for (const char* p = s; p[0] && p[1]; p += 2){
        if (n >= cap) return -1;
        int hi, lo; char a = p[0], b = p[1];
        hi = (a>='0'&&a<='9')?a-'0':(a>='a'&&a<='f')?a-'a'+10:-1;
        lo = (b>='0'&&b<='9')?b-'0':(b>='a'&&b<='f')?b-'a'+10:-1;
        if (hi < 0 || lo < 0) return -1;
        out[n++] = (u8)((hi<<4)|lo);
    }
    return n;
}

/* The resolver hands back the frozen prevouts IN INPUT ORDER. The corpus
 * stores them that way (the generator walks tx.vin), so the Nth call answers
 * the Nth input -- the verifier resolves inputs in order, and asserting that
 * is itself worth something. */
typedef struct { const txacc_vec_t* v; int next; u8 spk[16][520]; unsigned long spklen[16]; } rctx_t;

static int resolve_frozen(void* vctx, const u8 outpoint[36], unsigned index,
                          u64* value, u64* height, u64* is_coinbase,
                          const u8** spk, unsigned long* spklen){
    (void)outpoint; (void)index;
    rctx_t* c = (rctx_t*)vctx;
    if (c->next >= c->v->n_prev) return 0;
    const txacc_prev_t* p = &c->v->prev[c->next];
    *value = p->value; *height = (u64)p->height; *is_coinbase = (u64)p->coinbase;
    *spk = c->spk[c->next]; *spklen = c->spklen[c->next];
    c->next++;
    return 1;
}

int main(void){
    tx_dispatch_init();
    printf("== %d real mined transactions, each at its own height ==\n\n", TXACC_VEC_N);

    static u8 txbuf[400000];
    int accepted = 0;

    for (int i = 0; i < TXACC_VEC_N; i++){
        const txacc_vec_t* v = &TXACC_VEC[i];
        long tl = unhex(v->tx_hex, txbuf, sizeof txbuf);
        char label[240];

        snprintf(label, sizeof label, "[%d] decodes: %s", i, v->why);
        ck(label, tl > 0);
        if (tl <= 0) continue;

        rctx_t ctx; memset(&ctx, 0, sizeof ctx);
        ctx.v = v; ctx.next = 0;
        int too_many = (v->n_prev > 16);
        if (!too_many){
            for (int k = 0; k < v->n_prev; k++){
                long l = unhex(v->prev[k].spk_hex, ctx.spk[k], (long)sizeof ctx.spk[k]);
                if (l < 0){ too_many = 1; break; }
                ctx.spklen[k] = (unsigned long)l;
            }
        }
        snprintf(label, sizeof label, "[%d] prevouts decode (%d)", i, v->n_prev);
        ck(label, !too_many);
        if (too_many) continue;

        const char* reason = NULL;
        int rc = tx_verify_at_height(txbuf, (u64)tl, v->height,
                                     resolve_frozen, &ctx, &reason);
        snprintf(label, sizeof label, "[%d] ACCEPTED at h=%ld", i, v->height);
        ck(label, rc == 1);
        if (rc != 1)
            printf("      rejected: %s\n", reason ? reason : "(no reason)");
        else accepted++;

        snprintf(label, sizeof label, "[%d] every input was resolved", i);
        ck(label, ctx.next == v->n_prev);
    }

    printf("\n%d of %d transactions accepted at their own heights\n",
           accepted, TXACC_VEC_N);
    printf("%s (%d checks, %d failures)\n",
           fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
