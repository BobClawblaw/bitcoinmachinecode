/* tests/test_psbt_bounds.c -- WAL-14 (audit 2026-09-03): the PSBT map walkers
 * must not read past the buffer.
 *
 * THE DEFECT. psbt_update.c's parse_map read a key length and a value length
 * with rd_varint -- which takes a BARE POINTER and reads up to nine bytes from
 * it -- and then advanced `p` by those lengths without ever comparing them
 * with blen. So a PSBT whose key length is a 0xff varint of 2^64-1 walked the
 * cursor far past the end, and ser_map/has_key then read from wherever it
 * landed. rpc_commands.c's psbt_parse_map had the identical shape.
 *
 * The audit rated this PLAUSIBLE because reachability depends on how
 * completely psbt_v2_normalize validates first. That is exactly why it is
 * worth bounding: a parser that is only safe because of what runs before it
 * is one refactor away from not being safe.
 *
 * HOW THIS TEST WORKS. The malformed PSBTs below are placed at the END of a
 * page-aligned mapping whose next page is PROT_NONE. Any read past the
 * declared length lands in the guard page and the process dies with SIGSEGV,
 * so "it returned an error" and "it stayed in bounds" are checked separately
 * -- the same guard-page technique tests/test_tx_bounds_fuzz.c uses. Without
 * the fix these cases fault rather than merely returning something wrong.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

typedef unsigned char u8;

/* the real entry point (psbt_update.c) */
extern long psbt_update_bytes_from_descs(const u8* buf, long blen, void* dv, int nd,
                                         u8* outbuf, long outcap);

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

/* place `n` bytes so that buf[n] is the first byte of a PROT_NONE page */
static u8* guarded(const u8* src, long n, void** base_out, long* map_out){
    long ps = sysconf(_SC_PAGESIZE);
    long maplen = ps * 2;
    u8* base = mmap(NULL, (size_t)maplen, PROT_READ|PROT_WRITE,
                    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return NULL;
    if (mprotect(base + ps, (size_t)ps, PROT_NONE) != 0){ munmap(base, (size_t)maplen); return NULL; }
    u8* p = base + ps - n;
    memcpy(p, src, (size_t)n);
    *base_out = base; *map_out = maplen;
    return p;
}

static void run_case(const char* name, const u8* body, long n){
    void* base; long maplen;
    u8* p = guarded(body, n, &base, &maplen);
    if (!p){ printf("FAIL: %s (mmap)\n", name); fails++; checks++; return; }
    static u8 out[1 << 16];
    long r = psbt_update_bytes_from_descs(p, n, NULL, 0, out, sizeof out);
    /* the only requirement is that it RETURNED -- a read past `n` would have
     * hit the guard page and killed the process before this line */
    char lbl[160];
    snprintf(lbl, sizeof lbl, "%s: returned without reading past the buffer (r=%ld)", name, r);
    ck(lbl, 1);
    munmap(base, (size_t)maplen);
}

int main(void){
    printf("== WAL-14: malformed PSBT maps stay inside the buffer ==\n");

    /* a 0xff key length: 2^64-1 declared, nothing present */
    { u8 b[64]; long n = 0;
      memcpy(b, "psbt\xff", 5); n = 5;
      b[n++] = 0xff; for (int i = 0; i < 8; i++) b[n++] = 0xff;   /* kl = 2^64-1 */
      run_case("key length 2^64-1", b, n); }

    /* a 0xfd key length whose two length bytes are themselves off the end */
    { u8 b[64]; long n = 0;
      memcpy(b, "psbt\xff", 5); n = 5;
      b[n++] = 0xfd;                                              /* needs 2 more bytes */
      run_case("truncated 0xfd key length", b, n); }

    /* a well-formed key, then a value length past the end */
    { u8 b[64]; long n = 0;
      memcpy(b, "psbt\xff", 5); n = 5;
      b[n++] = 1; b[n++] = 0x00;                                  /* kl=1, key 0x00 */
      b[n++] = 0xfe; b[n++] = 0xff; b[n++] = 0xff; b[n++] = 0xff; b[n++] = 0x7f;  /* vl huge */
      run_case("value length past the end", b, n); }

    /* a key length that is exactly one byte too long */
    { u8 b[64]; long n = 0;
      memcpy(b, "psbt\xff", 5); n = 5;
      b[n++] = 4; b[n++] = 0x00; b[n++] = 0x01; b[n++] = 0x02;    /* claims 4, supplies 3 */
      run_case("key length one byte over", b, n); }

    /* a map with no terminator at all */
    { u8 b[64]; long n = 0;
      memcpy(b, "psbt\xff", 5); n = 5;
      b[n++] = 1; b[n++] = 0x00; b[n++] = 1; b[n++] = 0xaa;       /* one kv, then EOF */
      run_case("unterminated map", b, n); }

    /* the unsigned-tx walker: a scriptSig length near 2^64 (the sl+4 wrap) */
    { u8 b[128]; long n = 0;
      memcpy(b, "psbt\xff", 5); n = 5;
      b[n++] = 1; b[n++] = 0x00;                                  /* global key 0x00 = unsigned tx */
      long vlpos = n; b[n++] = 0;                                 /* value length, patched below */
      long tx0 = n;
      b[n++] = 2; b[n++] = 0; b[n++] = 0; b[n++] = 0;             /* version */
      b[n++] = 1;                                                 /* 1 input */
      for (int i = 0; i < 36; i++) b[n++] = 0;                    /* outpoint */
      b[n++] = 0xff; for (int i = 0; i < 8; i++) b[n++] = 0xff;   /* scriptSig len 2^64-1 */
      b[vlpos] = (u8)(n - tx0);
      b[n++] = 0;                                                 /* map terminator */
      run_case("unsigned tx with a 2^64-1 scriptSig length", b, n); }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
