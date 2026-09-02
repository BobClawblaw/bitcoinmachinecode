/* tests/tool_archive_relayout.c -- rewrite a block archive in HEIGHT ORDER
 * (manual tool, not a test). Archives filled by the parallel downloader have
 * their frames laid down in chunk-completion order; nothing is wrong with
 * them except that truncation and pruning refuse to run ("block data is NOT
 * laid out monotonically"). This reads index.dat (48-byte records: hash 32,
 * file_no u32@32, data_pos u64@36, data_size u32@44), copies every frame
 * ([u32 len][u32 magic] + block bytes) verbatim into new blk files in height
 * order (128 MiB rotation, same as the writer), writes a matching new
 * index.dat, verifies every block's sha256d against the index hash, and
 * leaves the result in <out-dir>. Swapping is the operator's explicit step:
 *   stop daemon; mv blk*.dat index.dat to <backup>/; move <out-dir>'s files into
 *   <archive>/; start.
 * Usage: tool_archive_relayout <archive-dir> <out-dir> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
extern void sha256d(u8 out[32], const void* p, unsigned long n);
#define BLK_ROTATE (128u<<20)
int main(int argc, char** argv){
    if (argc != 3){ fprintf(stderr, "usage: %s <archive-dir> <out-dir>\n", argv[0]); return 2; }
    char path[4096];
    snprintf(path, sizeof path, "%s/index.dat", argv[1]);
    FILE* ix = fopen(path, "rb");
    if (!ix){ perror("index.dat"); return 1; }
    fseek(ix, 0, SEEK_END); long isz = ftell(ix); fseek(ix, 0, SEEK_SET);
    long nrec = isz / 48;
    u8* idx = malloc((size_t)isz);
    if (fread(idx, 1, (size_t)isz, ix) != (size_t)isz){ fprintf(stderr, "short index read\n"); return 1; }
    fclose(ix);
    mkdir(argv[2], 0755);
    u8* nidx = calloc((size_t)nrec, 48);
    int cur_in_no = -1; FILE* fin = 0;
    int out_no = 0; u64 out_pos = 0;
    snprintf(path, sizeof path, "%s/blk%05u.dat", argv[2], out_no);
    FILE* fo = fopen(path, "wb"); if (!fo){ perror(path); return 1; }
    static u8 buf[9 << 20];
    long holes = 0, done = 0, bad = 0;
    for (long h = 0; h < nrec; h++){
        const u8* r = idx + h*48;
        u8 zero[48] = {0};
        if (!memcmp(r, zero, 48)){ holes++; continue; }             /* hole stays a zero record */
        u32 fno; u64 pos; u32 size;
        memcpy(&fno, r+32, 4); memcpy(&pos, r+36, 8); memcpy(&size, r+44, 4);
        if (size + 8u > sizeof buf){ fprintf(stderr, "h=%ld frame too big (%u)\n", h, size); return 1; }
        if ((int)fno != cur_in_no){
            if (fin) fclose(fin);
            snprintf(path, sizeof path, "%s/blk%05u.dat", argv[1], fno);
            fin = fopen(path, "rb"); if (!fin){ perror(path); return 1; }
            cur_in_no = (int)fno;
        }
        if (fseek(fin, (long)pos, SEEK_SET) != 0 || fread(buf, 1, size + 8u, fin) != size + 8u){
            fprintf(stderr, "h=%ld short frame read\n", h); return 1; }
        u8 hh[32]; sha256d(hh, buf + 8, 80);            /* a block hash is the HEADER's sha256d */
        if (memcmp(hh, r, 32) != 0){ fprintf(stderr, "h=%ld HASH MISMATCH reading the old archive\n", h); bad++; continue; }
        if (out_pos + size + 8u > BLK_ROTATE){
            fflush(fo); fsync(fileno(fo)); fclose(fo);
            out_no++; out_pos = 0;
            snprintf(path, sizeof path, "%s/blk%05u.dat", argv[2], out_no);
            fo = fopen(path, "wb"); if (!fo){ perror(path); return 1; }
        }
        if (fwrite(buf, 1, size + 8u, fo) != size + 8u){ perror("write"); return 1; }
        u8* nr = nidx + h*48;
        memcpy(nr, r, 32);
        u32 ono = (u32)out_no; memcpy(nr+32, &ono, 4);
        memcpy(nr+36, &out_pos, 8); memcpy(nr+44, &size, 4);
        out_pos += size + 8u;
        done++;
    }
    if (fin) fclose(fin);
    fflush(fo); fsync(fileno(fo)); fclose(fo);
    snprintf(path, sizeof path, "%s/index.dat", argv[2]);
    FILE* no_ = fopen(path, "wb"); fwrite(nidx, 48, (size_t)nrec, no_); fflush(no_); fsync(fileno(no_)); fclose(no_);
    /* verification pass over the NEW layout */
    long vbad = 0; cur_in_no = -1; fin = 0;
    for (long h = 0; h < nrec; h++){
        const u8* r = nidx + h*48; u8 zero[48] = {0};
        if (!memcmp(r, zero, 48)) continue;
        u32 fno; u64 pos; u32 size; memcpy(&fno, r+32, 4); memcpy(&pos, r+36, 8); memcpy(&size, r+44, 4);
        if ((int)fno != cur_in_no){ if (fin) fclose(fin);
            snprintf(path, sizeof path, "%s/blk%05u.dat", argv[2], fno);
            fin = fopen(path, "rb"); if (!fin){ perror(path); return 1; } cur_in_no = (int)fno; }
        fseek(fin, (long)pos, SEEK_SET);
        if (fread(buf, 1, size + 8u, fin) != size + 8u){ vbad++; continue; }
        u8 hh[32]; sha256d(hh, buf + 8, 80);            /* a block hash is the HEADER's sha256d */
        if (memcmp(hh, r, 32) != 0) vbad++;
    }
    if (fin) fclose(fin);
    fprintf(stderr, "relayout: %ld blocks rewritten in height order (%ld holes kept, %ld unreadable in the OLD archive), "
                    "verification of the new layout: %ld bad\n", done, holes, bad, vbad);
    return (vbad || bad) ? 1 : 0;
}
