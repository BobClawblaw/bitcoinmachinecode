/* chainwork_build.c -- regenerate <datadir>/chainwork.dat from headers.dat.
 *
 * chainwork.dat is a positional table of 16-byte little-endian cumulative work,
 * one record per height. It was found CORRUPT from ~height 481824 (segwit
 * activation / the witness-stripped-archive repair episode): getblockheader
 * chainwork diverged from Bitcoin Core for the entire post-segwit chain, while
 * matching through 481824. Root-caused (tests/../scratch cwdiag): the per-block
 * work primitive block_work() is CORRECT -- recomputing cumulative work from
 * headers.dat's nBits matches Core byte-for-byte at every height -- so the fix
 * is to rewrite the file, not the computation.
 *
 * headers.dat is 112-byte records in height order; the 80-byte block header
 * starts each record, nBits at offset 72. This tool sums block_work(nBits) with
 * chainwork_add() and writes chainwork.dat.rebuild (caller verifies, then
 * atomically renames over chainwork.dat).
 *
 * Usage: chainwork_build <datadir>
 *   writes <datadir>/chainwork.dat.rebuild and prints checkpoints.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

typedef unsigned char u8;
typedef unsigned int  u32;
extern void block_work(u8 w[16], unsigned bits);
extern void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16]);

static u32 rd32(const u8* p){ return (u32)p[0]|((u32)p[1]<<8)|((u32)p[2]<<16)|((u32)p[3]<<24); }

int main(int argc, char** argv){
    if (argc < 2){ fprintf(stderr, "usage: chainwork_build <datadir>\n"); return 2; }
    char hp[4096], op[4096];
    snprintf(hp, sizeof hp, "%s/headers.dat", argv[1]);
    snprintf(op, sizeof op, "%s/chainwork.dat.rebuild", argv[1]);
    int hf = open(hp, O_RDONLY);
    if (hf < 0){ fprintf(stderr, "chainwork_build: cannot open %s\n", hp); return 1; }
    struct stat sb; if (fstat(hf, &sb) != 0){ perror("fstat"); return 1; }
    long nrec = sb.st_size / 112;
    if (nrec <= 0){ fprintf(stderr, "chainwork_build: headers.dat has no records\n"); return 1; }

    int of = open(op, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (of < 0){ fprintf(stderr, "chainwork_build: cannot create %s\n", op); return 1; }

    u8 cw[16]; memset(cw, 0, 16);
    u8* obuf = malloc((size_t)nrec * 16);
    if (!obuf){ fprintf(stderr, "chainwork_build: oom\n"); return 1; }

    for (long h = 0; h < nrec; h++){
        u8 rec[112];
        if (pread(hf, rec, 112, (long)h * 112) != 112){ fprintf(stderr, "chainwork_build: short read at h=%ld\n", h); return 1; }
        u8 w[16]; block_work(w, rd32(rec + 72));
        if (h == 0) memcpy(cw, w, 16);
        else chainwork_add(cw, cw, w);
        memcpy(obuf + (size_t)h * 16, cw, 16);
    }
    long total = nrec * 16, wr = 0; ssize_t k;
    while (wr < total && (k = write(of, obuf + wr, (size_t)(total - wr))) > 0) wr += k;
    if (wr != total){ fprintf(stderr, "chainwork_build: short write (%ld/%ld)\n", wr, total); return 1; }
    fsync(of); close(of); close(hf); free(obuf);

    /* checkpoints for the caller to eyeball against Core */
    printf("chainwork_build: wrote %ld records to %s\n", nrec, op);
    return 0;
}
