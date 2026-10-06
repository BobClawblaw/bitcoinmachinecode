/* tests/test_utxo_snapshot_diff.c -- the coin-by-coin snapshot diff over
 * files written by this node's own encoder (asm/utxo_snapshot.c, which is
 * pinned against a real Core snapshot), with every kind of divergence
 * planted: a coin only on one side, a coin only on the other, the same
 * outpoint with a different amount / height / script, vouts of one txid in
 * a different order (NOT a difference), a different coin count, and an
 * out-of-order file (refused). Each case fails with the comparison
 * disabled, so the assertions are on the tool and not on the fixtures. */
#define USNAP_DIFF_NO_MAIN
#include "../daemon/utxo_snapshot_diff.c"
#include "../utxo_snapshot.h"
#include "test_tmpdir.h"
#include <unistd.h>

static int failures = 0;
static void ck(const char* l, int cond){ if (cond) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); failures++; } }

typedef struct { unsigned char txid[32]; unsigned vout; unsigned long height; int cb; unsigned long long value; unsigned char spk[40]; unsigned long spklen; } tcoin;
static void p2pkh(unsigned char* s, unsigned char fill){ s[0]=0x76; s[1]=0xa9; s[2]=0x14; memset(s+3, fill, 20); s[23]=0x88; s[24]=0xac; }
static void p2wpkh(unsigned char* s, unsigned char fill){ s[0]=0x00; s[1]=0x14; memset(s+2, fill, 20); }
/* writes coins (already grouped by txid, in the given order) as a snapshot */
static void write_snap(const char* path, const unsigned char base[32], const tcoin* c, int n, unsigned long long count_override){
    FILE* f = fopen(path, "wb"); unsigned char h[51]; usnap_header(base, count_override ? count_override : (unsigned long long)n, h); fwrite(h, 1, 51, f);
    int i = 0;
    while (i < n){
        int j = i; while (j < n && !memcmp(c[j].txid, c[i].txid, 32)) j++;
        fwrite(c[i].txid, 1, 32, f); unsigned char cs = (unsigned char)(j - i); fwrite(&cs, 1, 1, f);
        for (int k = i; k < j; k++){ unsigned char o[256]; long l = usnap_coin(c[k].vout, c[k].height, c[k].cb, c[k].value, c[k].spk, c[k].spklen, o, sizeof o); fwrite(o, 1, l, f); }
        i = j;
    }
    fclose(f);
}
static long run_diff(const char* a, const char* b, char* out, unsigned long cap){
    FILE* m = fmemopen(out, cap, "w"); long d = usnap_diff(a, b, m, 50); fclose(m); return d;
}

int main(void){
    tt_isolate();
    unsigned char base[32]; memset(base, 0xAB, 32);
    tcoin c[6]; memset(c, 0, sizeof c);
    for (int i = 0; i < 6; i++){ memset(c[i].txid, 0x10 * (i / 2 + 1), 32); c[i].vout = i % 2; c[i].height = 100 + i; c[i].cb = i == 0; c[i].value = 1000000ULL * (i + 1); }
    for (int i = 0; i < 6; i++){ if (i & 1) p2wpkh(c[i].spk, (unsigned char)i), c[i].spklen = 22; else p2pkh(c[i].spk, (unsigned char)i), c[i].spklen = 25; }
    c[5].vout = 300;   /* a vout past 255: a two-byte compactsize, and the kind of vout two writers may order differently */
    char out[8192]; long d;

    write_snap("a.dat", base, c, 6, 0); write_snap("b.dat", base, c, 6, 0);
    d = run_diff("a.dat", "b.dat", out, sizeof out);
    ck("identical files: 0 differences, says IDENTICAL with the coin count", d == 0 && strstr(out, "IDENTICAL: A 6 coins, B 6 coins"));

    /* the vouts of one txid in the other order: not a difference */
    { tcoin s[6]; memcpy(s, c, sizeof s); tcoin t = s[4]; s[4] = s[5]; s[5] = t; write_snap("b.dat", base, s, 6, 0);
      d = run_diff("a.dat", "b.dat", out, sizeof out);
      ck("vouts of one txid in a different order are the same set", d == 0); }

    /* a coin only in A (B lacks c[3]) */
    { tcoin s[5]; memcpy(s, c, 3 * sizeof *s); memcpy(s + 3, c + 4, 2 * sizeof *s); write_snap("b.dat", base, s, 5, 0);
      d = run_diff("a.dat", "b.dat", out, sizeof out);
      ck("a coin missing from B is named only-in-A with its outpoint and amount", d >= 1 && strstr(out, "only-in-A 2020") && strstr(out, ":1 height=103 cb=0 amount=4000000"));
      ck("... and the coin count mismatch is reported too", strstr(out, "coin-count differs: A 6 | B 5") != 0); }

    /* a coin only in B */
    { tcoin s[7]; memcpy(s, c, sizeof c); s[6] = c[5]; s[6].vout = 301; write_snap("b.dat", base, s, 7, 0);
      d = run_diff("a.dat", "b.dat", out, sizeof out);
      ck("an extra coin in B is named only-in-B", d >= 1 && strstr(out, "only-in-B 3030") && strstr(out, ":301 ")); }

    /* the same outpoint, a different amount; then a different height; then a different script */
    { tcoin s[6]; memcpy(s, c, sizeof s); s[2].value += 1; write_snap("b.dat", base, s, 6, 0);
      d = run_diff("a.dat", "b.dat", out, sizeof out);
      ck("a different amount at the same outpoint: 'differs' with both amounts", d == 1 && strstr(out, "differs   2020") && strstr(out, "amount=3000000") && strstr(out, "amount=3000001"));
      memcpy(s, c, sizeof s); s[2].height = 999; write_snap("b.dat", base, s, 6, 0);
      d = run_diff("a.dat", "b.dat", out, sizeof out);
      ck("a different height: 'differs' with both heights", d == 1 && strstr(out, "height=102") && strstr(out, "height=999"));
      memcpy(s, c, sizeof s); p2wpkh(s[2].spk, 0x77); s[2].spklen = 22; write_snap("b.dat", base, s, 6, 0);
      d = run_diff("a.dat", "b.dat", out, sizeof out);
      ck("a different script: 'differs' with both scripts", d == 1 && strstr(out, "differs") && strstr(out, "script=00") && strstr(out, "script=")); }

    /* a different base block: reported, coins still compared */
    { unsigned char b2[32]; memset(b2, 0xCD, 32); write_snap("b.dat", b2, c, 6, 0);
      d = run_diff("a.dat", "b.dat", out, sizeof out);
      ck("a different base block is reported and counted", d == 1 && strstr(out, "base-block differs")); }

    /* an out-of-order file is refused, never mis-diffed */
    { tcoin s[6]; memcpy(s, c, sizeof s); tcoin g[2] = { s[4], s[5] }; memmove(s + 2, s, 4 * sizeof *s); s[0] = g[0]; s[1] = g[1]; write_snap("b.dat", base, s, 6, 0);
      d = run_diff("a.dat", "b.dat", out, sizeof out);
      ck("txids out of order: the file is refused (MALFORMED), not compared", d == -2 && strstr(out, "MALFORMED")); }

    /* the amount decoder against the encoder, over awkward values */
    { unsigned long long vals[] = { 0, 1, 330, 546, 100000000ULL, 2099999997690000ULL, 123456789ULL, 10ULL, 1000000000000ULL };
      int ok = 1; for (unsigned i = 0; i < sizeof vals / sizeof *vals; i++) if (usd_decompress_amount(usnap_compress_amount(vals[i])) != vals[i]) ok = 0;
      ck("DecompressAmount inverts CompressAmount on 9 values incl. 0, dust, 1 BTC and the supply cap", ok); }

    printf("%s (%d failure(s))\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
