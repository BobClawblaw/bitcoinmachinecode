#define _GNU_SOURCE
/* daemon/archive_reindex.c -- Bitcoin Core's -reindex for this node's archive.
 *
 * Core's -reindex throws away the block index and chain state and rebuilds
 * both by walking the blk*.dat files: every block found on disk is re-linked
 * by its prev-hash into a tree from genesis, the best chain by cumulative
 * work becomes the active chain, and the UTXO set is then rebuilt by
 * re-applying it. This is the same thing for this node's own on-disk shape:
 *
 *   blk*.dat      frames [u32 len][u32 magic][block], appended in whatever
 *                 order the downloader finished them; 128 MiB rotation
 *   index.dat     positional by HEIGHT: [hash 32][file u32][pos u64][size u32]
 *   headers.dat   positional by height: [80-byte header][32-byte hash]
 *   chainwork.dat positional by height: 16-byte little-endian cumulative work
 *
 * The three derived files are rebuilt from the frames alone. Nothing in the
 * frames is trusted beyond its shape: a frame is only used if its magic and
 * length are sane, its header's hash satisfies its own nBits target, and it
 * links, through prev-hashes, back to the chain's genesis. Duplicates (the
 * same block appended twice) collapse to the LAST copy; orphans (a prev-hash
 * no frame carries) and stale forks (less cumulative work than the best tip)
 * are left on disk and simply not indexed -- exactly what Core does with
 * out-of-chain blocks in its block files.
 *
 * APPEND SAFETY. The store derives its append position from the TIP record
 * (file_no, pos + 8 + size) when it reloads. In a normally grown archive the
 * tip is also the last frame written, so that is correct; after a rebuild it
 * need not be (the last frame on disk might be a stale fork). Appending there
 * would overwrite whatever frame follows. So when the rebuilt tip is not the
 * physically last frame of the highest-numbered file, its frame is copied to
 * that file's end and the tip record points at the copy: one block of extra
 * disk, and the invariant holds by construction.
 *
 * The rebuilt files are written beside the originals (*.reindex), fsynced,
 * and renamed into place in one pass; the originals are kept as
 * *.pre-reindex. The chain state is NOT touched here: the caller drops the
 * UTXO set and the height-positional indexes afterwards (a height may have
 * moved), which is the -reindex-chainstate machinery this node already has.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include "archive_reindex.h"

typedef unsigned char u8; typedef unsigned int u32; typedef unsigned long long u64;
extern void sha256d(u8 out[32], const void* p, unsigned long n);
extern void block_work(u8 w[16], unsigned bits);
extern void chainwork_add(u8 out[16], const u8 a[16], const u8 b[16]);

#define RX_MAX_FRAME   (8u << 20)      /* a serialized block is < 4 MB; 8 MB is generous */
#define RX_MAX_MISSING 8               /* stop after this many consecutive absent blk files */

typedef struct {
    u8  hash[32], prev[32];
    u32 bits, file, size;
    u64 pos;
    u8  work[16];
    long height;
    int parent, child, sibling;        /* tree links (indices), -1 = none */
    u8  onchain, visited;
} rx_ent;

static u32 rd32(const u8* p){ return (u32)p[0] | ((u32)p[1] << 8) | ((u32)p[2] << 16) | ((u32)p[3] << 24); }

/* hash <= target(nBits), both as 256-bit little-endian numbers. A compact
 * target with the sign bit, a zero mantissa or an exponent past 34 is invalid
 * and fails every hash, as in Core's CheckProofOfWork. */
static int rx_pow_ok(const u8 hash[32], u32 bits){
    u32 exp = bits >> 24, mant = bits & 0x007fffffu;
    if ((bits & 0x00800000u) || mant == 0 || exp > 34) return 0;
    u8 target[32]; memset(target, 0, 32);
    if (exp <= 3){
        mant >>= 8 * (3 - exp);
        target[0] = (u8)mant; target[1] = (u8)(mant >> 8); target[2] = (u8)(mant >> 16);
    } else {
        u32 sh = exp - 3;
        if (sh + 3 > 32) return 0;
        target[sh] = (u8)mant; target[sh + 1] = (u8)(mant >> 8); target[sh + 2] = (u8)(mant >> 16);
    }
    for (int i = 31; i >= 0; i--){
        if (hash[i] < target[i]) return 1;
        if (hash[i] > target[i]) return 0;
    }
    return 1;
}

/* open-addressing map: hash prefix -> entry index */
static int*  rx_map; static u64 rx_mask;
static u64 rx_key(const u8* h){ u64 k; memcpy(&k, h, 8); return k ? k : 1; }
static int rx_map_find(const rx_ent* e, const u8* h){
    for (u64 i = rx_key(h) & rx_mask;; i = (i + 1) & rx_mask){
        int v = rx_map[i];
        if (v < 0) return -1;
        if (!memcmp(e[v].hash, h, 32)) return v;
    }
}
static void rx_map_put(int idx, const rx_ent* e){
    for (u64 i = rx_key(e[idx].hash) & rx_mask;; i = (i + 1) & rx_mask)
        if (rx_map[i] < 0){ rx_map[i] = idx; return; }
}
static int rx_work_gt(const u8 a[16], const u8 b[16]){
    for (int i = 15; i >= 0; i--){ if (a[i] > b[i]) return 1; if (a[i] < b[i]) return 0; }
    return 0;
}
static int rx_write_all(int fd, const void* p, size_t n){
    const u8* q = p; while (n){ ssize_t k = write(fd, q, n); if (k <= 0) return -1; q += k; n -= (size_t)k; }
    return 0;
}
static int rx_pread_all(int fd, void* p, size_t n, u64 off){
    u8* q = p; while (n){ ssize_t k = pread(fd, q, n, (off_t)off); if (k <= 0) return -1; q += k; n -= (size_t)k; off += (u64)k; }
    return 0;
}

int archive_reindex(const char* dir, const unsigned char genesis[32], unsigned magic,
                    archive_reindex_stats* st, char* err, unsigned long errcap){
    archive_reindex_stats zs; memset(&zs, 0, sizeof zs); if (!st) st = &zs; memset(st, 0, sizeof *st);
    #define RX_FAIL(...) do { if (err && errcap) snprintf(err, errcap, __VA_ARGS__); return -1; } while (0)
    char path[4096];
    rx_ent* e = 0; long n = 0, cap = 0;
    u64 file_end[65536]; int max_file = -1;
    /* ---- 1. scan every frame of every blk file ------------------------------- */
    for (u32 fno = 0, missing = 0; fno < 65536; fno++){
        snprintf(path, sizeof path, "%s/blk%05u.dat", dir, fno);
        int fd = open(path, O_RDONLY);
        if (fd < 0){ if (++missing >= RX_MAX_MISSING) break; continue; }
        missing = 0;
        struct stat sb; if (fstat(fd, &sb) != 0){ close(fd); RX_FAIL("fstat %s: %s", path, strerror(errno)); }
        u64 fsz = (u64)sb.st_size, pos = 0, junk = 0, lost_at = 0; int lost = 0;
        file_end[fno] = fsz; max_file = (int)fno; st->files++;
        while (pos + 8 + 80 <= fsz){
            u8 fh[88];
            if (rx_pread_all(fd, fh, 88, pos) != 0) break;
            u32 len = rd32(fh), mg = rd32(fh + 4);
            int sane = (mg == magic && len >= 80 && len <= RX_MAX_FRAME && pos + 8 + len <= fsz);
            u8 hh[32]; if (sane) sha256d(hh, fh + 8, 80);
            /* A frame boundary is trusted only if what follows LOOKS like a
             * frame: right magic, sane length, and a header that clears its
             * own nBits -- garbage cannot forge the last one. Otherwise slide
             * forward a byte at a time until one reappears (a torn write, or
             * junk after the last frame), so the frames beyond it are still
             * found and a rebuild is repeatable. */
            if (!sane || !rx_pow_ok(hh, rd32(fh + 8 + 72))){
                if (sane){ st->bad_pow++; pos += 8 + len; st->frames++; continue; }   /* real frame, invalid block: skip it whole */
                if (!lost){ lost = 1; lost_at = pos; }
                /* resync by searching for the next magic dword in bulk: a
                 * per-byte probe would cost hours on a file that is junk from
                 * its first byte (or one written with a different magic). */
                { static u8 chunk[4u << 20]; u64 want = fsz - pos; if (want > sizeof chunk) want = sizeof chunk;
                  if (want < 88 || rx_pread_all(fd, chunk, (size_t)want, pos) != 0){ junk += fsz - pos; pos = fsz; break; }
                  u8 mg4[4] = { (u8)magic, (u8)(magic >> 8), (u8)(magic >> 16), (u8)(magic >> 24) };
                  u64 off = 4, found = 0;
                  while (off + 4 <= want){
                      u8* hit = memmem(chunk + off, (size_t)(want - off), mg4, 4);
                      if (!hit){ break; }
                      u64 cand = pos + (u64)(hit - chunk) - 4;
                      u32 clen = rd32(chunk + (hit - chunk) - 4);
                      if (clen >= 80 && clen <= RX_MAX_FRAME && cand + 8 + clen <= fsz){ found = 1; junk += cand - pos; pos = cand; break; }
                      off = (u64)(hit - chunk) + 1;
                  }
                  if (!found){ u64 adv = want > 8 ? want - 8 : want; junk += adv; pos += adv; }
                }
                continue;
            }
            if (lost){ fprintf(stderr, "[reindex] blk%05u.dat: frame boundary lost at byte %llu, resynced after %llu junk byte(s)\n", fno, lost_at, junk); lost = 0; }
            if (n == cap){ cap = cap ? cap * 2 : 4096; rx_ent* ne = realloc(e, (size_t)cap * sizeof *ne); if (!ne){ close(fd); free(e); RX_FAIL("out of memory"); } e = ne; }
            rx_ent* x = &e[n]; memset(x, 0, sizeof *x);
            memcpy(x->hash, hh, 32);
            memcpy(x->prev, fh + 8 + 4, 32);
            x->bits = rd32(fh + 8 + 72); x->file = fno; x->pos = pos; x->size = len;
            x->parent = x->child = x->sibling = -1;
            n++;
            pos += 8 + len;
            st->frames++;
        }
        if (pos < fsz){ junk += fsz - pos; if (!lost){ lost = 1; lost_at = pos; } }
        if (lost){ fprintf(stderr, "[reindex] blk%05u.dat: %llu junk byte(s) from byte %llu to the end of the file\n", fno, junk, lost_at); }
        if (junk){ st->truncated_files++; st->junk_bytes += junk; }
        close(fd);
    }
    if (n == 0 || max_file < 0) { free(e); RX_FAIL("no block frames found under %s", dir); }
    /* ---- 2. link by prev-hash into a tree from genesis ------------------------ */
    u64 msz = 1; while (msz < (u64)n * 2) msz <<= 1;
    rx_map = malloc(msz * sizeof(int)); if (!rx_map){ free(e); RX_FAIL("out of memory"); }
    for (u64 i = 0; i < msz; i++){ rx_map[i] = -1; }
    rx_mask = msz - 1;
    long kept = 0;
    for (long i = 0; i < n; i++){
        int ex = rx_map_find(e, e[i].hash);
        if (ex >= 0){
            /* LAST copy wins: a block appended twice is a block re-fetched
             * (a witness-stripped frame superseded by the complete one), and
             * the tip copy this function appends for safety must be the one
             * the rebuilt index points at, or a rebuild would never converge. */
            st->duplicates++; e[ex] = e[i]; e[ex].parent = e[ex].child = e[ex].sibling = -1; continue;
        }
        if (kept != i) e[kept] = e[i];
        rx_map_put((int)kept, e); kept++;
    }
    n = kept;
    int g = rx_map_find(e, genesis);
    if (g < 0){ free(rx_map); free(e); RX_FAIL("the genesis block is not among the %ld frame(s) on disk", n); }
    for (long i = 0; i < n; i++){
        if (i == g) continue;
        int p = rx_map_find(e, e[i].prev);
        if (p < 0){ st->orphans++; continue; }
        e[i].parent = p; e[i].sibling = e[p].child; e[p].child = (int)i;
    }
    /* ---- 3. walk the tree: heights, cumulative work, best tip ----------------- */
    int* stack = malloc((size_t)n * sizeof(int)); if (!stack){ free(rx_map); free(e); RX_FAIL("out of memory"); }
    long sp = 0; stack[sp++] = g;
    block_work(e[g].work, e[g].bits); e[g].height = 0; e[g].visited = 1;
    int best = g;
    while (sp > 0){
        int cur = stack[--sp];
        if (rx_work_gt(e[cur].work, e[best].work)) best = cur;
        for (int c = e[cur].child; c >= 0; c = e[c].sibling){
            u8 w[16]; block_work(w, e[c].bits);
            chainwork_add(e[c].work, e[cur].work, w);
            e[c].height = e[cur].height + 1; e[c].visited = 1;
            stack[sp++] = c;
        }
    }
    free(stack);
    long tip = e[best].height;
    for (int c = best; c >= 0; c = e[c].parent) e[c].onchain = 1;
    for (long i = 0; i < n; i++) if (e[i].visited && !e[i].onchain && e[i].parent >= 0) st->stale++;
    /* ---- 4. append safety: the tip frame must be physically last -------------- */
    {
        rx_ent* t = &e[best];
        u64 last_end = file_end[max_file];
        if (!((int)t->file == max_file && t->pos + 8 + t->size == last_end)){
            snprintf(path, sizeof path, "%s/blk%05u.dat", dir, (unsigned)t->file);
            int in = open(path, O_RDONLY);
            u8* buf = malloc((size_t)t->size + 8);
            if (in < 0 || !buf || rx_pread_all(in, buf, (size_t)t->size + 8, t->pos) != 0){ if (in >= 0) close(in); free(buf); free(rx_map); free(e); RX_FAIL("cannot read the tip frame"); }
            close(in);
            snprintf(path, sizeof path, "%s/blk%05u.dat", dir, (unsigned)max_file);
            int out = open(path, O_WRONLY | O_APPEND);
            if (out < 0 || rx_write_all(out, buf, (size_t)t->size + 8) != 0 || fsync(out) != 0){ if (out >= 0) close(out); free(buf); free(rx_map); free(e); RX_FAIL("cannot re-append the tip frame to %s", path); }
            close(out); free(buf);
            t->file = (u32)max_file; t->pos = last_end;
            st->tip_reappended = 1;
        }
    }
    /* ---- 5. write index.dat / headers.dat / chainwork.dat beside the originals -- */
    u8* idx = calloc((size_t)(tip + 1), 48);
    u8* hdr = malloc((size_t)(tip + 1) * 112);
    u8* cw  = malloc((size_t)(tip + 1) * 16);
    if (!idx || !hdr || !cw){ free(idx); free(hdr); free(cw); free(rx_map); free(e); RX_FAIL("out of memory"); }
    for (int c = best; c >= 0; c = e[c].parent){
        long h = e[c].height; u8* r = idx + h * 48;
        memcpy(r, e[c].hash, 32); memcpy(r + 32, &e[c].file, 4); memcpy(r + 36, &e[c].pos, 8); memcpy(r + 44, &e[c].size, 4);
        memcpy(cw + h * 16, e[c].work, 16);
        snprintf(path, sizeof path, "%s/blk%05u.dat", dir, (unsigned)e[c].file);
        int in = open(path, O_RDONLY);
        if (in < 0 || rx_pread_all(in, hdr + h * 112, 80, e[c].pos + 8) != 0){ if (in >= 0) close(in); free(idx); free(hdr); free(cw); free(rx_map); free(e); RX_FAIL("cannot re-read header at height %ld", h); }
        close(in);
        memcpy(hdr + h * 112 + 80, e[c].hash, 32);
    }
    free(rx_map); free(e);
    const char* names[3] = { "index.dat", "headers.dat", "chainwork.dat" };
    const u8*   bufs[3]  = { idx, hdr, cw };
    size_t      lens[3]  = { (size_t)(tip + 1) * 48, (size_t)(tip + 1) * 112, (size_t)(tip + 1) * 16 };
    for (int k = 0; k < 3; k++){
        snprintf(path, sizeof path, "%s/%s.reindex", dir, names[k]);
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0 || rx_write_all(fd, bufs[k], lens[k]) != 0 || fsync(fd) != 0){ if (fd >= 0) close(fd); free(idx); free(hdr); free(cw); RX_FAIL("cannot write %s", path); }
        close(fd);
    }
    free(idx); free(hdr); free(cw);
    for (int k = 0; k < 3; k++){
        char cur[4096], old[4096];
        snprintf(cur, sizeof cur, "%s/%s", dir, names[k]);
        snprintf(old, sizeof old, "%s/%s.pre-reindex", dir, names[k]);
        snprintf(path, sizeof path, "%s/%s.reindex", dir, names[k]);
        struct stat sb;
        if (stat(cur, &sb) == 0 && rename(cur, old) != 0) RX_FAIL("cannot set aside %s: %s", cur, strerror(errno));
        if (rename(path, cur) != 0) RX_FAIL("cannot install %s: %s", cur, strerror(errno));
    }
    st->tip = tip;
    return 0;
    #undef RX_FAIL
}
