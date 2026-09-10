/* dnet.c -- batched p2p_frame differential driver (file-based, no popen).
 * Same driver compiles on x86-64 (against asm/bitcoin_net.o) and macOS/AArch64
 * (against port/osx/net_twin.c). Reads vector records, appends the built
 * frames to the output file; `cmp` the two output streams byte-for-byte.
 *
 * Record: u32 cmdlen | u32 plen | cmd[cmdlen] | payload[plen]
 * Output: for each record, the raw 24+plen frame (no framing of its own --
 * sizes are derivable from the record stream).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;
typedef unsigned char u8;

extern u64 p2p_frame(u8 *out, const char *cmd, u32 cmdlen, const void *payload,
                     u64 plen);

int main(int argc, char **argv)
{
    if (argc != 3) { fprintf(stderr, "usage: dnet <vectors> <out>\n"); return 2; }
    FILE *fv = fopen(argv[1], "rb");
    if (!fv) { perror("vectors"); return 2; }
    FILE *fo = fopen(argv[2], "wb");
    if (!fo) { perror("out"); return 2; }

    u32 hdr[2];
    u8 cmd[64];
    static u8 pay[4u * 1000 * 1000 + 24];
    u8 *frame = malloc(sizeof pay + 24);
    if (!frame) { fprintf(stderr, "oom\n"); return 2; }

    unsigned n = 0;
    while (fread(hdr, 4, 2, fv) == 2) {
        u32 cmdlen = hdr[0], plen = hdr[1];
        if (cmdlen > 16 || plen > 4000000u) { fprintf(stderr, "bad record %u\n", n); return 2; }
        if (cmdlen && fread(cmd, 1, cmdlen, fv) != cmdlen) break;
        if (plen && fread(pay, 1, plen, fv) != plen) break;
        u64 total = p2p_frame(frame, (const char *)cmd, cmdlen, pay, plen);
        if (total != (u64)plen + 24) { fprintf(stderr, "frame len wrong rec %u\n", n); return 2; }
        fwrite(frame, 1, total, fo);
        n++;
    }
    fclose(fv);
    if (fflush(fo) != 0 || fclose(fo) != 0) { perror("write out"); return 2; }
    printf("dnet: %u frames written\n", n);
    return 0;
}
