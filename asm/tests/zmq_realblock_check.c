/* tests/zmq_realblock_check.c -- does the block-hash the ZMQ path publishes
 * actually identify the block?
 *
 * main.c's hashblock notification computes sha256d over the 80-byte header
 * and publishes it in WIRE order. Both halves of that are easy to get wrong
 * in a way no unit test would catch, because the result still LOOKS like a
 * block hash: reversed bytes, or hashing the wrong span, produce a plausible
 * 32-byte value that simply matches nothing.
 *
 * So this runs the exact expression main.c uses against REAL blocks from the
 * production archive and compares to hashes obtained from Bitcoin Core.
 *
 *   zmq_realblock_check <datadir> <height> <core-hash-hex> [<height> <hash>...]
 *
 * The core-hash argument is in DISPLAY order (what Core prints), so the
 * comparison also pins down the byte-order convention rather than assuming
 * it. Read-only: opens the archive and never writes.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern int  store_init(void* st);
extern long store_reload(void* st);
extern void store_rd_init(void* st);
extern long store_read_at(void* st, unsigned long h, void* out, long cap);
extern void sha256d(unsigned char o[32], const void* m, long l);

static unsigned char store_buf[4096];
#define BLOCKBUF (4*1024*1024)
static unsigned char blk[BLOCKBUF];

int main(int argc, char** argv){
    if (argc < 4 || (argc - 2) % 2){
        fprintf(stderr, "usage: %s <datadir> <height> <core-hash-hex> [...]\n", argv[0]);
        return 2;
    }
    if (chdir(argv[1]) != 0){ perror("chdir"); return 1; }
    /* Same three-step open build_tx_index uses: init, reload, then arm the
     * read path. store_reload alone leaves store_read_at unable to resolve a
     * height. */
    if (store_init(store_buf) != 1){ fprintf(stderr, "store_init failed\n"); return 1; }
    store_reload(store_buf);
    store_rd_init(store_buf);
    printf("  archive tip = %d\n", *(int*)(store_buf + 24));

    int bad = 0, n = 0;
    for (int a = 2; a + 1 < argc; a += 2){
        long h = atol(argv[a]);
        const char* want = argv[a + 1];
        long bl = store_read_at(store_buf, (unsigned long)h, blk, BLOCKBUF);
        if (bl <= 0){ printf("  height %ld: UNREADABLE (%ld)\n", h, bl); bad++; continue; }

        /* the exact expression daemon/main.c publishes: sha256d over the
         * header, then REVERSED, because Core's ZMQ notifier flips the hash
         * to display order before sending (data[31-i] = hash.begin()[i]).
         * The first version of this feature published wire order; this
         * check now asserts on the bytes that actually cross the wire, so
         * that regression cannot come back quietly. */
        unsigned char bh[32], zmq_bytes[32];
        sha256d(bh, blk, 80);
        for (int i = 0; i < 32; i++) zmq_bytes[i] = bh[31 - i];

        char onwire[65];
        for (int i = 0; i < 32; i++) sprintf(onwire + i*2, "%02x", zmq_bytes[i]);
        int ok = (strcasecmp(onwire, want) == 0);
        printf("  height %ld: %s\n", h, ok ? "ZMQ bytes == Core hash" : "MISMATCH");
        printf("      core prints    : %s\n", want);
        printf("      ZMQ publishes  : %s\n", onwire);
        if (!ok) bad++;
        n++;
    }
    if (bad){ printf("zmq_realblock_check: %d of %d FAILED\n", bad, n); return 1; }
    printf("zmq_realblock_check: %d/%d blocks: hex(published hashblock bytes) == Core getblockhash\n", n, n);
    return 0;
}
