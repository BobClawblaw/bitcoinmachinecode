/* sg_diff.c -- differential test of the REAL assembled sigop counters
 * (bitcoin_sigops.o over bitcoin_scriptcodec.o's get_op) against a C port of
 * Core v31.1:
 *   script_sigops_ex(s, n, accurate) vs CScript::GetSigOpCount(fAccurate)
 *       (script/script.cpp), GetScriptOp's push parsing, break on a bad op
 *   tx_legacy_sigops(tx, len)        vs GetLegacySigOpCount(tx)
 *       (consensus/tx_verify.cpp): sum over every scriptSig and every
 *       scriptPubKey with fAccurate = false; the witness is not counted.
 * Scripts are random byte strings of length 0..120 drawn from an
 * opcode-heavy alphabet (CHECKSIG/CHECKMULTISIG and their VERIFY forms,
 * OP_0..OP_16, OP_1NEGATE, OP_RESERVED, direct pushes, PUSHDATA1/2/4 with
 * short and over-long lengths) plus uniform bytes; transactions are
 * well-formed legacy or segwit serializations carrying such scripts.
 * Plus EXHAUSTIVE: every script of length <= 2 (65,793 scripts) both modes.
 * usage: sg_diff N SEED   exit 0 iff no divergence. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
extern long script_sigops_ex(const uint8_t* s, unsigned long n, long accurate);
extern long tx_legacy_sigops(const uint8_t* tx, unsigned long n);

static unsigned core_getsigopcount(const uint8_t* s, unsigned long n, int fAccurate){
    unsigned cnt = 0; unsigned long pc = 0; unsigned last = 0xff;   /* OP_INVALIDOPCODE */
    while (pc < n){
        unsigned op = s[pc++];
        if (op <= 0x4e){
            unsigned long sz;
            if (op < 0x4c) sz = op;
            else if (op == 0x4c){ if (n - pc < 1) break; sz = s[pc++]; }
            else if (op == 0x4d){ if (n - pc < 2) break; sz = s[pc] | ((unsigned long)s[pc+1] << 8); pc += 2; }
            else { if (n - pc < 4) break; sz = (unsigned long)s[pc] | ((unsigned long)s[pc+1] << 8) | ((unsigned long)s[pc+2] << 16) | ((unsigned long)s[pc+3] << 24); pc += 4; }
            if (n - pc < sz) break;
            pc += sz;
        }
        if (op == 0xac || op == 0xad) cnt++;
        else if (op == 0xae || op == 0xaf){
            if (fAccurate && last >= 0x51 && last <= 0x60) cnt += last - 0x50;
            else cnt += 20;
        }
        last = op;
    }
    return cnt;
}

static uint64_t rs;
static uint64_t rnd(void){ rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }
static size_t rnd_script(uint8_t* s, size_t cap){
    size_t n = rnd() % 121; if (n > cap) n = cap;
    size_t i = 0;
    while (i < n){
        unsigned k = rnd() % 16;
        uint8_t b;
        if (k < 4) b = 0xac + (rnd() % 4);
        else if (k < 7) b = 0x50 + (rnd() % 17);
        else if (k < 8) b = 0x00;
        else if (k < 9) b = 0x4f;
        else if (k < 11){                     /* a short direct push */
            b = 1 + rnd() % 8; s[i++] = b;
            for (unsigned j = 0; j < b && i < n; j++) s[i++] = (uint8_t)rnd();
            continue;
        } else if (k < 12){                   /* PUSHDATA1/2/4 with a length */
            b = 0x4c + rnd() % 3; s[i++] = b;
            unsigned len = (rnd() & 1) ? rnd() % 6 : (unsigned)rnd();
            unsigned w = b == 0x4c ? 1 : b == 0x4d ? 2 : 4;
            for (unsigned j = 0; j < w && i < n; j++) s[i++] = (uint8_t)(len >> (8 * j));
            continue;
        } else b = (uint8_t)rnd();
        s[i++] = b;
    }
    return n;
}
static size_t put_cs(uint8_t* p, uint64_t v){
    if (v < 0xfd){ p[0] = (uint8_t)v; return 1; }
    p[0] = 0xfd; p[1] = (uint8_t)v; p[2] = (uint8_t)(v >> 8); return 3;
}

int main(int argc, char** argv){
    long N = argc > 1 ? atol(argv[1]) : 1000000;
    rs = argc > 2 ? strtoull(argv[2], 0, 0) : 0x1234567;
    if (!rs) rs = 1;
    long fails = 0, cases = 0;
    uint8_t s[1024];
    /* exhaustive: every script of length <= 2 */
    for (int len = 0; len <= 2; len++){
        unsigned long lim = 1UL << (8 * len);
        for (unsigned long v = 0; v < lim; v++){
            for (int i = 0; i < len; i++) s[i] = (uint8_t)(v >> (8 * i));
            for (int acc = 0; acc < 2; acc++){
                cases++;
                if ((unsigned long)script_sigops_ex(s, len, acc) != core_getsigopcount(s, len, acc)){
                    if (fails < 5) printf("DIVERGE script len=%d v=%lx acc=%d\n", len, v, acc);
                    fails++;
                }
            }
        }
    }
    printf("exhaustive scripts (len<=2): %ld cases, %ld divergences\n", cases, fails);
    long sc = 0;
    for (long i = 0; i < N; i++){
        size_t n = rnd_script(s, sizeof s);
        for (int acc = 0; acc < 2; acc++){
            sc++;
            if ((unsigned long)script_sigops_ex(s, n, acc) != core_getsigopcount(s, n, acc)){
                if (fails < 10){ printf("DIVERGE script acc=%d n=%zu:", acc, n); for (size_t k = 0; k < n; k++) printf("%02x", s[k]); printf("\n"); }
                fails++;
            }
        }
    }
    printf("random scripts: %ld cases, %ld divergences (total)\n", sc, fails);
    /* transactions */
    static uint8_t tx[1 << 16];
    long tc = 0;
    for (long i = 0; i < N / 4; i++){
        size_t p = 0; unsigned expect = 0;
        int segwit = rnd() & 1;
        tx[p++] = 2; tx[p++] = 0; tx[p++] = 0; tx[p++] = 0;
        if (segwit){ tx[p++] = 0; tx[p++] = 1; }
        unsigned nin = 1 + rnd() % 4, nout = 1 + rnd() % 4;
        if (rnd() % 16 == 0) nin = 0xfd + rnd() % 8;          /* a 3-byte count */
        p += put_cs(tx + p, nin);
        for (unsigned k = 0; k < nin; k++){
            for (int j = 0; j < 36; j++) tx[p++] = (uint8_t)rnd();
            size_t n = (k < 8) ? rnd_script(s, 200) : 0;
            p += put_cs(tx + p, n); memcpy(tx + p, s, n); p += n;
            expect += core_getsigopcount(s, n, 0);
            for (int j = 0; j < 4; j++) tx[p++] = (uint8_t)rnd();
        }
        p += put_cs(tx + p, nout);
        for (unsigned k = 0; k < nout; k++){
            for (int j = 0; j < 8; j++) tx[p++] = (uint8_t)rnd();
            size_t n = rnd_script(s, 200);
            p += put_cs(tx + p, n); memcpy(tx + p, s, n); p += n;
            expect += core_getsigopcount(s, n, 0);
        }
        if (segwit){
            for (unsigned k = 0; k < nin; k++){
                unsigned items = 1 + rnd() % 3; p += put_cs(tx + p, items);
                for (unsigned j = 0; j < items; j++){
                    size_t n = rnd_script(s, 100);       /* witness bytes: NOT counted */
                    p += put_cs(tx + p, n); memcpy(tx + p, s, n); p += n;
                }
            }
        }
        for (int j = 0; j < 4; j++) tx[p++] = 0;
        tc++;
        long got = tx_legacy_sigops(tx, p);
        if (got != (long)expect){
            if (fails < 15) printf("DIVERGE tx segwit=%d len=%zu got=%ld want=%u\n", segwit, p, got, expect);
            fails++;
        }
    }
    printf("random txs: %ld cases, %ld divergences (total)\n", tc, fails);
    return fails ? 1 : 0;
}
