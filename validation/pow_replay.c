/* validation/pow_replay.c -- prove bitcoin_pow_rules.c against a REAL chain
 * before it is allowed anywhere near the accept path.
 *
 * Reads a headers.dat mirror (112-byte records: 80-byte header + 32-byte
 * hash, position == height, record 0 == genesis -- both mirrors verified
 * genesis-first before this tool was written) READ-ONLY, and asserts that
 * for EVERY height h >= 1 the stored header's nBits equals
 * pow_expected_bits(h) computed from its ancestors alone. A single mismatch
 * prints the height, expected and actual bits, and exits 1.
 *
 *   ./pow_replay <headers.dat> main       # 964k+ heights, 478 boundaries
 *   ./pow_replay <headers.dat> testnet4   # min-difficulty + BIP94 paths
 *   ./pow_replay <headers.dat> regtest
 *
 * This is the mainnet/testnet4 acceptance proof demanded before wiring the
 * check into validation (LOG.md 2026-08-27): if Core accepted every one of
 * these headers and our rule agrees with every one of them, our rule is
 * Core's rule over every input the real world has ever produced.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "../asm/bitcoin_pow_rules.h"

typedef unsigned char u8;
typedef unsigned int u32;

static const u8* g_recs; static long g_n;
static int get_hdr(void* ctx, long h, u8 hdr[80]){
    (void)ctx;
    if (h < 0 || h >= g_n) return 0;
    memcpy(hdr, g_recs + (size_t)h * 112, 80);
    return 1;
}
static u32 rd32(const u8* p){ return (u32)p[0]|((u32)p[1]<<8)|((u32)p[2]<<16)|((u32)p[3]<<24); }

int main(int argc, char** argv){
    if (argc != 3){ fprintf(stderr, "usage: %s <headers.dat> main|testnet4|regtest\n", argv[0]); return 2; }
    int no_rt = 0, min_diff = 0, bip94 = 0; u32 lim = 0x1d00ffff;
    if      (!strcmp(argv[2], "main"))     { }
    else if (!strcmp(argv[2], "testnet4")) { min_diff = 1; bip94 = 1; }
    else if (!strcmp(argv[2], "regtest"))  { no_rt = 1; lim = 0x207fffff; }
    else { fprintf(stderr, "unknown chain %s\n", argv[2]); return 2; }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0){ perror("open"); return 2; }
    struct stat sb; fstat(fd, &sb);
    long n = sb.st_size / 112;
    const u8* m = mmap(NULL, (size_t)n * 112, PROT_READ, MAP_PRIVATE, fd, 0);
    if (m == MAP_FAILED){ perror("mmap"); return 2; }
    g_recs = m; g_n = n;

    long boundaries = 0, mindiff_used = 0, walkbacks = 0, bad = 0;
    for (long h = 1; h < n; h++){
        const u8* hdr = g_recs + (size_t)h * 112;
        long btime = (long)rd32(hdr + 68);
        u32 want = pow_expected_bits(h, btime, get_hdr, NULL, no_rt, min_diff, bip94, lim);
        u32 got  = rd32(hdr + 72);
        if (want == 0){ fprintf(stderr, "h=%ld: ancestor unavailable\n", h); return 1; }
        if (h % 2016 == 0) boundaries++;
        if (min_diff && got == lim && (h % 2016) != 0) mindiff_used++;
        if (min_diff && (h % 2016) != 0 && got != lim){
            const u8* ph = g_recs + (size_t)(h-1) * 112;
            if (rd32(ph + 72) == lim) walkbacks++;   /* real-bits block after min-diff run */
        }
        if (want != got){
            fprintf(stderr, "MISMATCH h=%ld expected=%08x actual=%08x (boundary=%s)\n",
                    h, want, got, (h % 2016 == 0) ? "yes" : "no");
            if (++bad >= 10){ fprintf(stderr, "(stopping after 10)\n"); break; }
        }
    }
    if (bad){ printf("FAILED: %ld mismatch(es) over %ld heights\n", bad, n-1); return 1; }
    printf("OK: %ld heights validated (%s), %ld retarget boundaries, "
           "%ld min-difficulty blocks, %ld walk-back re-anchors -- every nBits matches\n",
           n-1, argv[2], boundaries, mindiff_used, walkbacks);
    return 0;
}
