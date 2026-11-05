/* cs_txparse_diff.c -- differential test of the REAL assembled tx_parse
 * (bitcoin_tx.o: the block-path transaction splitter used by cons_verify
 * and apply_block_inner's Phase 0) against a C port of Core v31.1's
 * UnserializeTransaction (primitives/transaction.h) over ReadCompactSize
 * (serialize.h, range_check = true), on transactions whose every CompactSize
 * field (input count, scriptSig lengths, output count, scriptPubKey
 * lengths, witness stack sizes and item lengths) is drawn from: canonical,
 * a WIDER (non-canonical) encoding of the same value, a canonical value
 * above MAX_SIZE, or the 9-byte form. Each tx is followed by random trailing
 * bytes (tx_parse runs on the rest of a block buffer); a byte-exact
 * truncation is also tried. Compared: accept/reject and, on accept, the
 * consumed length. Generated segwit transactions always carry a non-empty
 * first witness stack (the "superfluous witness" rule is bw_walk_tx's, not
 * a CompactSize rule) and n_in >= 1 (no 00-xx marker ambiguity).
 * usage: cs_txparse_diff N SEED [canonical]   exit 0 iff no unexpected
 * divergence. Without "canonical", 1 in 10 CompactSize fields uses a wider
 * encoding; tx_parse accepts those and Core rejects them (counted, not a
 * failure: the block path re-reads every field with a canonical reader, see
 * NOTES.md). With "canonical" no wider encoding is generated and any
 * divergence fails. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "../core_cs.h"
extern int tx_parse(void* info, const uint8_t* tx, unsigned long txlen);

static uint64_t rs;
static uint64_t rnd(void){ rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

/* write v with a chosen encoding; returns bytes written */
static size_t put_enc(uint8_t* p, uint64_t v, int mode){
    int w;               /* 1, 3, 5, 9 */
    if (mode == 0) w = v < 0xfd ? 1 : v <= 0xffff ? 3 : v <= 0xffffffffULL ? 5 : 9;
    else { int c = v < 0xfd ? 1 : v <= 0xffff ? 3 : v <= 0xffffffffULL ? 5 : 9;
           static const int W[] = {1,3,5,9}; int k = 0; while (W[k] != c) k++;
           k += 1 + (int)(rnd() % 3); if (k > 3) k = 3; w = W[k]; }
    if (w == 1){ p[0] = (uint8_t)v; return 1; }
    p[0] = w == 3 ? 0xfd : w == 5 ? 0xfe : 0xff;
    for (int i = 0; i < w - 1; i++) p[1+i] = (uint8_t)(v >> (8*i));
    return (size_t)w;
}
/* a count/length field: returns the value the generator will then honour */
static int g_noncanon;            /* this case carries a non-canonical CompactSize */
static int g_allow_noncanon = 1;
static uint64_t pick_len(uint64_t want, int* mode, uint64_t* enc_v){
    unsigned k = rnd() % 10;
    *mode = 0; *enc_v = want;
    if (k == 0 && g_allow_noncanon){ *mode = 1; g_noncanon = 1; } /* non-canonical */
    else if (k == 1){ *enc_v = 0x02000001ULL + rnd() % 1000; } /* > MAX_SIZE, canonical */
    else if (k == 2){ *enc_v = 0x100000000ULL + rnd() % 1000; }/* 9-byte form */
    return want;
}

/* Core port: returns consumed length, or 0 if Core throws. */
static size_t core_tx(const uint8_t* b, size_t n){
    size_t p = 0; uint64_t v; unsigned u;
#define CS(dst) do { if (!core_read_compact_size(b + p, (unsigned)((n - p) > 9 ? 9 : (n - p)), 1, &v, &u)) return 0; p += u; dst = v; } while (0)
#define NEED(k) do { if (n - p < (k)) return 0; } while (0)
    NEED(4); p += 4;
    uint64_t nin, nout; int flags = 0;
    CS(nin);
    if (nin == 0){
        NEED(1); flags = b[p++];
        if (flags != 0){ CS(nin); goto read_vin; }
        nout = 0; goto after;
    }
read_vin:
    for (uint64_t i = 0; i < nin; i++){
        NEED(36); p += 36; uint64_t sl; CS(sl); NEED(sl); p += sl; NEED(4); p += 4;
    }
    CS(nout);
    for (uint64_t i = 0; i < nout; i++){
        NEED(8); p += 8; uint64_t sl; CS(sl); NEED(sl); p += sl;
    }
after:
    if (flags & 1){
        flags ^= 1; int has = 0;
        for (uint64_t i = 0; i < nin; i++){
            uint64_t items; CS(items); if (items) has = 1;
            for (uint64_t k = 0; k < items; k++){ uint64_t il; CS(il); NEED(il); p += il; }
        }
        if (!has) return 0;                                  /* superfluous witness record */
    }
    if (flags) return 0;                                     /* unknown optional data */
    NEED(4); p += 4;
    return p;
#undef CS
#undef NEED
}

static uint8_t buf[1 << 20];
int main(int argc, char** argv){
    long N = argc > 1 ? atol(argv[1]) : 1000000;
    rs = argc > 2 ? strtoull(argv[2], 0, 0) : 0xabcdef;
    if (!rs) rs = 1;
    if (argc > 3 && !strcmp(argv[3], "canonical")) g_allow_noncanon = 0;
    long fails = 0, acc = 0, rej = 0, nc_div = 0;
    for (long it = 0; it < N; it++){
        size_t p = 0; int mode; uint64_t ev;
        g_noncanon = 0;
        int segwit = rnd() % 3 == 0;
        for (int i = 0; i < 4; i++) buf[p++] = (uint8_t)rnd();
        if (segwit){ buf[p++] = 0; buf[p++] = 1; }
        uint64_t nin = 1 + rnd() % 3;
        pick_len(nin, &mode, &ev); p += put_enc(buf + p, ev, mode);
        for (uint64_t i = 0; i < nin; i++){
            for (int j = 0; j < 36; j++) buf[p++] = (uint8_t)rnd();
            uint64_t sl = (rnd() % 8 == 0) ? 253 + rnd() % 50 : rnd() % 12;
            pick_len(sl, &mode, &ev); p += put_enc(buf + p, ev, mode);
            for (uint64_t j = 0; j < sl; j++) buf[p++] = (uint8_t)rnd();
            for (int j = 0; j < 4; j++) buf[p++] = (uint8_t)rnd();
        }
        uint64_t nout = 1 + rnd() % 3;
        pick_len(nout, &mode, &ev); p += put_enc(buf + p, ev, mode);
        for (uint64_t i = 0; i < nout; i++){
            for (int j = 0; j < 8; j++) buf[p++] = (uint8_t)rnd();
            uint64_t sl = (rnd() % 8 == 0) ? 253 + rnd() % 50 : rnd() % 30;
            pick_len(sl, &mode, &ev); p += put_enc(buf + p, ev, mode);
            for (uint64_t j = 0; j < sl; j++) buf[p++] = (uint8_t)rnd();
        }
        if (segwit){
            for (uint64_t i = 0; i < nin; i++){
                uint64_t items = (i == 0) ? 1 + rnd() % 3 : rnd() % 3;
                pick_len(items, &mode, &ev); p += put_enc(buf + p, ev, mode);
                for (uint64_t k = 0; k < items; k++){
                    uint64_t il = (rnd() % 10 == 0) ? 253 + rnd() % 20 : rnd() % 40;
                    pick_len(il, &mode, &ev); p += put_enc(buf + p, ev, mode);
                    for (uint64_t j = 0; j < il; j++) buf[p++] = (uint8_t)rnd();
                }
            }
        }
        for (int j = 0; j < 4; j++) buf[p++] = (uint8_t)rnd();
        size_t txlen = p;
        size_t tail = rnd() % 64;
        for (size_t j = 0; j < tail; j++) buf[p++] = (uint8_t)rnd();
        size_t avail = (rnd() % 8 == 0) ? (txlen > 0 ? txlen - 1 - rnd() % (txlen < 4 ? txlen : 4) : 0) : p;
        size_t c = core_tx(buf, avail);
        uint8_t info[64]; memset(info, 0, sizeof info);
        int ok = tx_parse(info, buf, avail);
        uint64_t blen; memcpy(&blen, info, 8);
        int same = (ok ? 1 : 0) == (c ? 1 : 0) && (!ok || blen == c);
        if (c) acc++; else rej++;
        if (!same && g_noncanon && ok && !c){ nc_div++; continue; }  /* the known class: see NOTES */
        if (!same){
            if (fails < 10){
                printf("DIVERGE segwit=%d avail=%zu core=%zu bmc ok=%d len=%llu :", segwit, avail, c, ok, (unsigned long long)blen);
                for (size_t k = 0; k < (avail < 80 ? avail : 80); k++) printf("%02x", buf[k]);
                printf("\n");
            }
            fails++;
        }
    }
    printf("tx_parse: %ld cases (%ld Core-accepted, %ld Core-rejected), %ld unexpected divergences, "
           "%ld non-canonical encodings accepted by tx_parse and rejected by Core\n", N, acc, rej, fails, nc_div);
    return fails ? 1 : 0;
}
