/* daemon/undo_store.h -- the on-disk shape of undo data (2026-09-08): kept
 * for EVERY block, like Core's rev*.dat files, instead of one file per height
 * pruned behind a 200-block window.
 *
 * Why. The window made every "fee" and "prevout" answer, the address-index
 * backfill and any deeper reorg impossible past 200 blocks, and mempool.space
 * wants all of them for the whole chain. Core keeps undo for every block
 * unless the node prunes; so do we now.
 *
 * Layout (chain directory, next to blk*.dat):
 *   rev%05u.dat  append-only runs of records, one run per block, rotated at
 *                UNDO_REV_MAX bytes (the block store's own file size). A run
 *                is the block's records in spend order, each
 *                  txid[32] | index u32 | value u64 | height u32 |
 *                  is_coinbase u8 | slen u16 | script[slen]
 *                (the record undo_log.c always wrote), closed by an END
 *                marker: a header whose txid is all 0xFF, index 0xFFFFFFFF,
 *                is_coinbase 0xFF, slen 0, value = the block height.
 *   undo.idx     16 bytes per height at (h+1)*16: file u32 | off u64 | tag u32
 *                (tag UNDO_TAG = present; 0 = none). Slot 0 is the header:
 *                magic UNDO_MAGIC | current rev file u32.
 *
 * The semantics every consumer relied on with one-file-per-height survive:
 *  - "undo exists for h" is now an index entry; it appears with the FIRST
 *    record of the block (or with the END marker of a block that spent
 *    nothing), so a block whose spends were durable before its checkpoint
 *    still shows up above the applied height and boot recovery rolls it back;
 *  - a run without END is torn (the process died mid-block): the tolerant
 *    replay stops there, the strict one refuses, exactly as a short file did;
 *  - discard clears the entry; the bytes stay as unreachable orphans, so a
 *    block reconnected at the same height starts a fresh run and can never
 *    have a stale file prepended to it (the old O_APPEND hazard);
 *  - pruning follows the BLOCK STORE: rev files wholly below the store's
 *    prune height go, nothing else does.
 *
 * Header-only, static: undo_log.c (the writer and the reorg readers) and
 * rpc_chain.c (the RPC readers) each carry their own copy, and nothing new
 * has to be linked anywhere. Writer state lives only in undo_log.c. */
#ifndef UNDO_STORE_H
#define UNDO_STORE_H
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>

#define UNDO_IDX_FILE   "undo.idx"
#define UNDO_REV_FMT    "rev%05u.dat"
#define UNDO_REV_MAX    (128u << 20)
#define UNDO_MAGIC      0x58444955u      /* 'UIDX' */
#define UNDO_TAG        0x4f444e55u      /* 'UNDO' */
#define UNDO_REC_HDR    51
#define UNDO_REC_MAXSCRIPT 10000

typedef struct { unsigned file; unsigned long long off; } undo_slot_t;

static inline int us_is_end(const unsigned char* hdr){
    unsigned idx; unsigned short slen; memcpy(&idx, hdr + 32, 4); memcpy(&slen, hdr + 49, 2);
    if (idx != 0xFFFFFFFFu || hdr[48] != 0xFF || slen != 0) return 0;
    for (int i = 0; i < 32; i++) if (hdr[i] != 0xFF) return 0;
    return 1;
}
static inline void us_make_end(unsigned char hdr[UNDO_REC_HDR], long height){
    memset(hdr, 0xFF, 32);
    unsigned idx = 0xFFFFFFFFu; unsigned long long v = (unsigned long long)height; unsigned uh = 0; unsigned short slen = 0;
    memcpy(hdr + 32, &idx, 4); memcpy(hdr + 36, &v, 8); memcpy(hdr + 44, &uh, 4); hdr[48] = 0xFF; memcpy(hdr + 49, &slen, 2);
}
static inline void us_rev_name(char out[32], unsigned file){ snprintf(out, 32, UNDO_REV_FMT, file); }

/* index slot for height h: 1 present, 0 absent, -1 read error */
static inline int us_slot_get(long h, undo_slot_t* out){
    if (h < 0) return 0;
    int fd = open(UNDO_IDX_FILE, O_RDONLY); if (fd < 0) return 0;
    unsigned char e[16]; ssize_t r = pread(fd, e, 16, (off_t)(h + 1) * 16); close(fd);
    if (r != 16) return r < 0 ? -1 : 0;
    unsigned tag; memcpy(&tag, e + 12, 4);
    if (tag != UNDO_TAG) return 0;
    if (out){ memcpy(&out->file, e, 4); memcpy(&out->off, e + 4, 8); }
    return 1;
}
static inline int us_exists(long h){ return us_slot_get(h, 0) == 1; }

/* Read block h's run into a malloc'd buffer: the records WITHOUT the END
 * marker. Returns the byte length of the whole records. A run that has no
 * END yet (open: being written, or the writer died) is served as far as its
 * last whole record; *torn is set only when a PARTIAL record or garbage was
 * found (the old file's "short tail"). -1: no entry, or unreadable. */
static inline long us_read_run(long h, unsigned char** out, int* torn){
    if (torn) *torn = 0;
    *out = 0;
    undo_slot_t s; if (us_slot_get(h, &s) != 1) return -1;
    char name[32]; us_rev_name(name, s.file);
    int fd = open(name, O_RDONLY); if (fd < 0) return -1;
    size_t cap = 1u << 20, len = 0; unsigned char* buf = malloc(cap); if (!buf){ close(fd); return -1; }
    unsigned long long pos = s.off;
    for (;;){
        size_t off = 0; int found = 0, bad = 0, more = 0;
        for (;;){
            if (len - off < UNDO_REC_HDR){ more = 1; break; }
            if (us_is_end(buf + off)){ found = 1; break; }
            unsigned short slen; memcpy(&slen, buf + off + 49, 2);
            if (slen > UNDO_REC_MAXSCRIPT){ bad = 1; break; }
            if (len - off < (size_t)UNDO_REC_HDR + slen){ more = 1; break; }
            off += (size_t)UNDO_REC_HDR + slen;
        }
        if (found){ close(fd); *out = buf; return (long)off; }
        if (bad){ close(fd); if (torn) *torn = 1; *out = buf; return (long)off; }   /* garbage: malformed */
        (void)more;
        if (len == cap){ cap *= 2; unsigned char* nb = realloc(buf, cap); if (!nb){ free(buf); close(fd); return -1; } buf = nb; }
        ssize_t r = pread(fd, buf + len, cap - len, (off_t)pos);
        if (r < 0){ free(buf); close(fd); return -1; }
        if (r == 0){
            /* EOF before END: an OPEN run (the block is being applied, or the
             * process died mid-block). Whole records are served as they are,
             * exactly as the old per-height file read to its end; a partial
             * record at the end is what "torn" means. */
            if (len - off > 0 && torn) *torn = 1;
            close(fd); *out = buf; return (long)off;
        }
        len += (size_t)r; pos += (unsigned long long)r;
    }
}

/* ---- writer side (undo_log.c only) --------------------------------------- */
static inline int us_idx_open_rw(void){
    int fd = open(UNDO_IDX_FILE, O_RDWR | O_CREAT, 0644); if (fd < 0) return -1;
    unsigned char hd[16]; ssize_t r = pread(fd, hd, 16, 0);
    if (r != 16){ memset(hd, 0, 16); unsigned m = UNDO_MAGIC; memcpy(hd, &m, 4); if (pwrite(fd, hd, 16, 0) != 16){ close(fd); return -1; } }
    return fd;
}
static inline unsigned us_cur_file(int ifd){ unsigned char hd[16]; if (pread(ifd, hd, 16, 0) != 16) return 0; unsigned f; memcpy(&f, hd + 4, 4); return f; }
static inline int us_set_cur_file(int ifd, unsigned f){ return pwrite(ifd, &f, 4, 4) == 4 ? 0 : -1; }
static inline int us_slot_put(int ifd, long h, unsigned file, unsigned long long off){
    unsigned char e[16]; unsigned tag = UNDO_TAG; memcpy(e, &file, 4); memcpy(e + 4, &off, 8); memcpy(e + 12, &tag, 4);
    return pwrite(ifd, e, 16, (off_t)(h + 1) * 16) == 16 ? 0 : -1;
}
static inline int us_slot_clear(long h){
    int ifd = open(UNDO_IDX_FILE, O_RDWR); if (ifd < 0) return 0;
    unsigned char e[16]; int had = (pread(ifd, e, 16, (off_t)(h + 1) * 16) == 16); unsigned tag = 0; if (had) memcpy(&tag, e + 12, 4);
    int r = 0;
    if (tag == UNDO_TAG){ memset(e, 0, 16); r = pwrite(ifd, e, 16, (off_t)(h + 1) * 16) == 16 ? 1 : -1; }
    close(ifd); return r;
}
/* Append a whole run for height h (records as given, then END) as a new run
 * at the end of the current rev file. For tests and the legacy migration;
 * the live writer in undo_log.c appends record by record. */
static inline int us_append_run(long h, const unsigned char* recs, size_t len, int with_end){
    int ifd = us_idx_open_rw(); if (ifd < 0) return -1;
    unsigned file = us_cur_file(ifd); char name[32]; us_rev_name(name, file);
    struct stat sb; unsigned long long off = (stat(name, &sb) == 0) ? (unsigned long long)sb.st_size : 0;
    if (off >= UNDO_REV_MAX){ file++; if (us_set_cur_file(ifd, file) != 0){ close(ifd); return -1; } us_rev_name(name, file); off = 0; }
    if (us_slot_put(ifd, h, file, off) != 0){ close(ifd); return -1; }
    close(ifd);
    int fd = open(name, O_WRONLY | O_CREAT | O_APPEND, 0644); if (fd < 0) return -1;
    if (len && write(fd, recs, len) != (ssize_t)len){ close(fd); return -1; }
    if (with_end){ unsigned char e[UNDO_REC_HDR]; us_make_end(e, h); if (write(fd, e, UNDO_REC_HDR) != UNDO_REC_HDR){ close(fd); return -1; } }
    close(fd); return 0;
}
/* The block store pruned below `keep_from`: every height below loses its
 * index entry, and rev files that hold ONLY such heights are deleted (whole
 * files, like Core's rev*.dat with their blk*.dat). Returns files removed. */
static inline long us_prune_below(long keep_from){
    int ifd = open(UNDO_IDX_FILE, O_RDWR); if (ifd < 0) return 0;
    struct stat sb; if (fstat(ifd, &sb) != 0){ close(ifd); return 0; }
    long nslots = (long)(sb.st_size / 16) - 1; if (nslots < 0) nslots = 0;
    unsigned cur = us_cur_file(ifd);
    /* first file that still holds a kept height = min file over h >= keep_from */
    unsigned min_keep_file = cur;
    for (long h = keep_from; h < nslots; h++){
        unsigned char e[16]; if (pread(ifd, e, 16, (off_t)(h + 1) * 16) != 16) break;
        unsigned tag, f; memcpy(&tag, e + 12, 4); memcpy(&f, e, 4);
        if (tag == UNDO_TAG){ if (f < min_keep_file) min_keep_file = f; break; }   /* runs are appended in height order */
    }
    long removed = 0;
    for (unsigned f = 0; f < min_keep_file; f++){ char name[32]; us_rev_name(name, f); if (unlink(name) == 0) removed++; }
    unsigned char zero[16]; memset(zero, 0, 16);
    for (long h = 0; h < keep_from && h < nslots; h++){
        unsigned char e[16]; if (pread(ifd, e, 16, (off_t)(h + 1) * 16) != 16) break;
        unsigned tag, f; memcpy(&tag, e + 12, 4); memcpy(&f, e, 4);
        /* every pruned height loses its entry (Core marks the block as having no
         * undo); the bytes linger only while a higher height shares the file */
        (void)f;
        if (tag == UNDO_TAG){ if (pwrite(ifd, zero, 16, (off_t)(h + 1) * 16) != 16) break; }
    }
    close(ifd);
    return removed;
}
/* wipe everything (the UTXO rebuild regenerates it): returns files removed */
static inline long us_wipe(void){
    long n = 0; if (unlink(UNDO_IDX_FILE) == 0) n++;
    DIR* d = opendir("."); if (!d) return n; struct dirent* e;
    while ((e = readdir(d))){ if (strncmp(e->d_name, "rev", 3) == 0 && strstr(e->d_name, ".dat") && unlink(e->d_name) == 0) n++; }
    closedir(d); return n;
}
#endif
