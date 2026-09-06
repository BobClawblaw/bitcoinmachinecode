/* tests/test_archive_seed.c -- the archive's slot 0 is genesis, on EVERY chain.
 *
 * The finding (2026-09-06, found by a fresh-sync benchmark): main() seeded
 * genesis only when the chain was not mainnet, so a fresh MAINNET datadir
 * whose first block came from the serial leg (peers relay block 1, never
 * genesis) built an archive shifted by one for its whole life. Reading height
 * h then returns block h+1, so block h+1's coins are inserted under height h,
 * and the next apply of h+1 is refused with a false `bad-txns-BIP30` --
 * "output 0 already unspent" against a coin the node itself mis-filed.
 *
 * Watched to fail first: with the pre-fix condition restored inside
 * archive_seed_genesis_if_empty (skip when mainnet), checks 1-4 fail.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "archive_seed.h"
#include "test_tmpdir.h"
extern int  store_init(void* st);
extern long store_append(void* st, const unsigned char hash[32], const unsigned char* blk, unsigned long len);
extern long store_read_at(void* st, unsigned long h, void* out, long cap);
extern void block_hash(unsigned char out[32], const unsigned char* hdr80);

static int checks, fails;
static void ok(int c, const char* m){ checks++; if(!c) fails++; printf("  %s %s\n", c?"ok  :":"FAIL:", m); }
static void hex32(char* out, const unsigned char h[32]){ for(int i=0;i<32;i++) sprintf(out+i*2, "%02x", h[31-i]); }

/* mainnet genesis, exactly as the chain table carries it (80-byte header + the
 * 1-tx body); only the header is hashed, the body is stored verbatim. */
static const unsigned char GENESIS[] = {
 0x01,0x00,0x00,0x00, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
 0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a,
 0x29,0xab,0x5f,0x49, 0xff,0xff,0x00,0x1d, 0x1d,0xac,0x2b,0x7c,
 0x01,
 0x01,0x00,0x00,0x00,0x01,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0xff,0xff,0xff,0xff,0x4d,0x04,0xff,0xff,0x00,0x1d,0x01,0x04,0x45,0x54,0x68,0x65,0x20,
 0x54,0x69,0x6d,0x65,0x73,0x20,0x30,0x33,0x2f,0x4a,0x61,0x6e,0x2f,0x32,0x30,0x30,0x39,
 0x20,0x43,0x68,0x61,0x6e,0x63,0x65,0x6c,0x6c,0x6f,0x72,0x20,0x6f,0x6e,0x20,0x62,0x72,
 0x69,0x6e,0x6b,0x20,0x6f,0x66,0x20,0x73,0x65,0x63,0x6f,0x6e,0x64,0x20,0x62,0x61,0x69,
 0x6c,0x6f,0x75,0x74,0x20,0x66,0x6f,0x72,0x20,0x62,0x61,0x6e,0x6b,0x73,0xff,0xff,0xff,
 0xff,0x01,0x00,0xf2,0x05,0x2a,0x01,0x00,0x00,0x00,0x43,0x41,0x04,0x67,0x8a,0xfd,0xb0,
 0xfe,0x55,0x48,0x27,0x19,0x67,0xf1,0xa6,0x71,0x30,0xb7,0x10,0x5c,0xd6,0xa8,0x28,0xe0,
 0x39,0x09,0xa6,0x79,0x62,0xe0,0xea,0x1f,0x61,0xde,0xb6,0x49,0xf6,0xbc,0x3f,0x4c,0xef,
 0x38,0xc4,0xf3,0x55,0x04,0xe5,0x1e,0xc1,0x12,0xde,0x5c,0x38,0x4d,0xf7,0xba,0x0b,0x8d,
 0x57,0x8a,0x4c,0x70,0x2b,0x6b,0xf1,0x1d,0x5f,0xac,0x00,0x00,0x00,0x00 };
#define GENESIS_HASH "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"

int main(void){
    tt_isolate();
    static unsigned char store[1<<16];
    if (store_init(store) != 1){ printf("FAIL: store_init\n"); return 1; }

    printf("== the finding: a FRESH MAINNET archive seeds genesis at slot 0 ==\n");
    ok(*(int*)(store+24) == -1, "a fresh archive has no blocks (tip -1)");
    int r = archive_seed_genesis_if_empty(store, GENESIS, (unsigned long)sizeof GENESIS);
    ok(r == 1, "seeding an empty archive reports that it seeded");
    ok(*(int*)(store+24) == 0, "the tip is height 0 -- genesis IS a block in the archive");
    { static unsigned char buf[4096];
      long n = store_read_at(store, 0, buf, sizeof buf);
      unsigned char h[32]; char hex[65];
      ok(n >= 80, "height 0 reads back");
      block_hash(h, buf); hex32(hex, h);
      ok(n >= 80 && strcmp(hex, GENESIS_HASH) == 0, "height 0 IS genesis (the whole archive's height==index rests on it)");
      if (n >= 80 && strcmp(hex, GENESIS_HASH) != 0) printf("      got %s\n", hex); }

    printf("== a second boot does not seed again ==\n");
    r = archive_seed_genesis_if_empty(store, GENESIS, (unsigned long)sizeof GENESIS);
    ok(r == 0, "a non-empty archive is left alone");
    ok(*(int*)(store+24) == 0, "the tip did not move");

    printf("== the shift this prevents: block 1 must not land in slot 0 ==\n");
    { /* the serial leg's first append is block 1; with genesis seeded it lands
       * at height 1, and heights and slots agree from then on. */
      static unsigned char blk1[81]; memset(blk1, 0, sizeof blk1);
      blk1[0] = 1; memcpy(blk1 + 4, "\x6f\xe2\x8c\x0a\xb6\xf1\xb3\x72\xc1\xa6\xa2\x46\xae\x63\xf7\x4f\x93\x1e\x83\x65\xe1\x5a\x08\x9c\x68\xd6\x19\x00\x00\x00\x00\x00", 32);
      unsigned char bh[32]; block_hash(bh, blk1);
      long h1 = store_append(store, bh, blk1, sizeof blk1);
      ok(h1 == 1, "the first peer-relayed block appends at height 1, not 0");
      static unsigned char buf[4096];
      unsigned char g[32]; char hex[65];
      long n = store_read_at(store, 0, buf, sizeof buf);
      block_hash(g, buf); hex32(hex, g);
      ok(n >= 80 && strcmp(hex, GENESIS_HASH) == 0, "height 0 still reads genesis after that append"); }

    printf("\n%s (%d checks, %d failures)\n", fails?"TESTS FAILED":"ALL TESTS PASSED", checks, fails);
    return fails?1:0;
}
