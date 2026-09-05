/* daemon/mempool_persist.c -- Core's mempool.dat, read and written.
 *
 * FORMAT (Core node/mempool_persist.cpp), little-endian throughout:
 *
 *   uint64  version            1 = plain, 2 = obfuscated
 *   [v2]    compact_size 8, then 8 key bytes   -- the key is written with
 *                              VECTOR serialization, so it carries a
 *                              compact-size length prefix and the body
 *                              therefore starts at offset 17, not 16. Core
 *                              says so in a comment ("Use vector
 *                              serialization for convenient compact size
 *                              prefix"); assuming a bare 8-byte key decodes
 *                              the transaction COUNT correctly and then
 *                              fails on the first transaction.
 *   uint64  n_transactions
 *   n x {  raw tx (TX_WITH_WITNESS)  |  int64 entry_time  |  int64 fee_delta  }
 *   compact_size n_deltas, then n x { txid[32] | int64 delta }
 *   compact_size n_unbroadcast, then n x txid[32]
 *
 * WE WRITE VERSION 1. That is not a divergence invented here: it is Core's
 * own `-persistmempoolv1` option, and Core reads it unconditionally. The
 * obfuscation in v2 exists to stop antivirus software mangling the file, not
 * for any protocol reason, and its key is random -- so a v2 writer could
 * never produce a byte-comparable artifact anyway. We READ both, because
 * a file handed to us was most likely written by a default Core.
 *
 * The XOR key index is the WHOLE-FILE offset (Core's AutoFile passes
 * *m_position straight to the obfuscation), so the first body byte at offset
 * 17 uses key index 17 % 8 == 1.
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

typedef unsigned char u8;
typedef unsigned long long u64;

#define MPD_V1 1ULL
#define MPD_V2 2ULL

/* ---- little-endian scalars ---- */
static void put_u64(u8* p, u64 v){ for (int i=0;i<8;i++) p[i] = (u8)(v >> (8*i)); }
static u64  get_u64(const u8* p){ u64 v=0; for (int i=0;i<8;i++) v |= (u64)p[i] << (8*i); return v; }

/* Core's CompactSize. */
static int put_cs(u8* p, u64 v){
    if (v < 253){ p[0]=(u8)v; return 1; }
    if (v <= 0xffff){ p[0]=253; p[1]=(u8)v; p[2]=(u8)(v>>8); return 3; }
    if (v <= 0xffffffffULL){ p[0]=254; for(int i=0;i<4;i++) p[1+i]=(u8)(v>>(8*i)); return 5; }
    p[0]=255; for(int i=0;i<8;i++) p[1+i]=(u8)(v>>(8*i)); return 9;
}
static int get_cs(const u8* p, u64 avail, u64* out){
    if (avail < 1) return 0;
    if (p[0] < 253){ *out = p[0]; return 1; }
    if (p[0] == 253){ if (avail < 3) return 0; *out = (u64)p[1] | ((u64)p[2]<<8); return 3; }
    if (p[0] == 254){ if (avail < 5) return 0; *out = 0; for(int i=0;i<4;i++) *out |= (u64)p[1+i]<<(8*i); return 5; }
    if (avail < 9) return 0;
    *out = 0; for(int i=0;i<8;i++) *out |= (u64)p[1+i]<<(8*i);
    return 9;
}

/* ---- writer -------------------------------------------------------------
 * The caller supplies the entries; this file owns only the format. Returns
 * the number of transactions written, or -1. Writes to <path>.new and
 * renames, the same tmp+rename discipline every other durable file here
 * uses -- a torn mempool.dat should never be loadable. */
long mempool_dump_write(const char* path,
                        const u8* const* txs, const unsigned long* lens,
                        const long long* times, const long long* deltas, long n,
                        const u8* extra_delta_txids, const long long* extra_deltas,
                        long n_extra){
    if (!path || (n > 0 && (!txs || !lens))) return -1;
    char tmp[1024];
    if (snprintf(tmp, sizeof tmp, "%s.new", path) >= (int)sizeof tmp) return -1;
    FILE* f = fopen(tmp, "wb");
    if (!f) return -1;

    u8 hdr[16];
    put_u64(hdr, MPD_V1);
    put_u64(hdr+8, (u64)(n > 0 ? n : 0));
    if (fwrite(hdr, 1, 16, f) != 16) goto fail;

    for (long i = 0; i < n; i++){
        if (fwrite(txs[i], 1, lens[i], f) != lens[i]) goto fail;
        u8 tf[16];
        put_u64(tf,   (u64)(times  ? times[i]  : 0));
        put_u64(tf+8, (u64)(deltas ? deltas[i] : 0));
        if (fwrite(tf, 1, 16, f) != 16) goto fail;
    }
    /* mapDeltas: only entries for transactions NOT in the pool. Core erases
     * each dumped tx's delta from the map first, so this is the remainder. */
    { u8 cs[9]; int cl = put_cs(cs, (u64)(n_extra > 0 ? n_extra : 0));
      if (fwrite(cs, 1, (size_t)cl, f) != (size_t)cl) goto fail; }
    for (long i = 0; i < n_extra; i++){
        if (fwrite(extra_delta_txids + (size_t)i*32, 1, 32, f) != 32) goto fail;
        u8 d[8]; put_u64(d, (u64)extra_deltas[i]);
        if (fwrite(d, 1, 8, f) != 8) goto fail;
    }
    /* unbroadcast set: this node does not track which transactions are still
     * unbroadcast (sendrawtransaction relays to every live leg immediately),
     * so the set is empty rather than invented. Core reads an empty set
     * without complaint; it simply re-announces nothing extra. */
    { u8 cs[9]; int cl = put_cs(cs, 0);
      if (fwrite(cs, 1, (size_t)cl, f) != (size_t)cl) goto fail; }

    /* MEM-19 (audit 2026-09-03): fflush only pushes stdio's buffer into the
     * kernel -- it does not put the bytes on the disk. The rename was then
     * durable while the CONTENT was not, so a power loss shortly after
     * savemempool or a shutdown left mempool.dat renamed but empty or torn,
     * and the next boot reported a parse error on a file it had just written.
     * Core's DumpMempool calls FileCommit before RenameOver;
     * fee_estimator.c's writer in this same tree already does the fsync. The
     * DIRECTORY fsync matters too: without it the rename itself can be lost,
     * leaving the old file (or none) after a crash. */
    if (fflush(f) != 0) goto fail;
    if (fsync(fileno(f)) != 0) goto fail;
    fclose(f);
    if (rename(tmp, path) != 0){ remove(tmp); return -1; }
    { /* fsync the containing directory so the rename survives a power loss */
      char dir[1024]; snprintf(dir, sizeof dir, "%s", path);
      char* slash = strrchr(dir, '/');
      if (slash){ *slash = 0; } else { dir[0] = '.'; dir[1] = 0; }
      int dfd = open(dir, O_RDONLY | O_DIRECTORY);
      if (dfd >= 0){ fsync(dfd); close(dfd); } }
    return n;
fail:
    fclose(f); remove(tmp);
    return -1;
}

/* ---- reader -------------------------------------------------------------
 * Calls `sink` once per transaction, in file order. Returns the count, or -1
 * on a malformed file. Deliberately does NOT validate or admit anything --
 * the caller decides what to do with each transaction, because admission
 * belongs to the process that owns the mempool. */
long mempool_dump_read(const char* path,
                       int (*sink)(void* ctx, const u8* tx, unsigned long len,
                                   long long time, long long delta),
                       void* ctx, char* err, unsigned long errcap){
#define MPD_ERR(...) do{ if (err && errcap) snprintf(err, errcap, __VA_ARGS__); }while(0)
    FILE* f = fopen(path, "rb");
    if (!f){ MPD_ERR("cannot open %s", path); return -1; }
    if (fseek(f, 0, SEEK_END) != 0){ fclose(f); MPD_ERR("seek failed"); return -1; }
    long fsz = ftell(f);
    if (fsz < 16){ fclose(f); MPD_ERR("file too short to be a mempool dump"); return -1; }
    rewind(f);
    u8* buf = (u8*)malloc((size_t)fsz);
    if (!buf){ fclose(f); MPD_ERR("out of memory"); return -1; }
    if (fread(buf, 1, (size_t)fsz, f) != (size_t)fsz){ free(buf); fclose(f); MPD_ERR("short read"); return -1; }
    fclose(f);

    u64 version = get_u64(buf);
    u64 pos = 8;
    if (version == MPD_V2){
        /* vector-serialized key: compact-size length, then that many bytes */
        u64 klen = 0;
        int kl = get_cs(buf + 8, (u64)fsz - 8, &klen);
        if (!kl || klen != 8 || 8 + (u64)kl + klen > (u64)fsz){
            free(buf); MPD_ERR("malformed obfuscation key"); return -1; }
        u8 key[8]; memcpy(key, buf + 8 + kl, 8);
        pos = 8 + (u64)kl + klen;                 /* 17 for a one-byte prefix */
        /* key index is the WHOLE-FILE offset (Core passes the stream
         * position), so the first body byte uses index pos % 8. */
        int allzero = 1; for (int i=0;i<8;i++) if (key[i]) allzero = 0;
        if (!allzero) for (u64 i = pos; i < (u64)fsz; i++) buf[i] ^= key[i % 8];
    } else if (version != MPD_V1){
        free(buf); MPD_ERR("unsupported mempool.dat version %llu", (unsigned long long)version);
        return -1;
    }

    if (pos + 8 > (u64)fsz){ free(buf); MPD_ERR("truncated transaction count"); return -1; }
    u64 count = get_u64(buf + pos); pos += 8;

    extern int tx_parse(void* info, const unsigned char* tx, unsigned long txlen);
    long done = 0;
    for (u64 i = 0; i < count; i++){
        unsigned char info[64];
        if (pos >= (u64)fsz){ free(buf); MPD_ERR("truncated at transaction %llu", (unsigned long long)i); return -1; }
        if (tx_parse(info, buf + pos, (unsigned long)((u64)fsz - pos)) != 1){
            free(buf); MPD_ERR("transaction %llu does not parse", (unsigned long long)i); return -1; }
        u64 tl; memcpy(&tl, info, 8);
        if (tl == 0 || pos + tl + 16 > (u64)fsz){
            free(buf); MPD_ERR("transaction %llu overruns the file", (unsigned long long)i); return -1; }
        long long t = (long long)get_u64(buf + pos + tl);
        long long d = (long long)get_u64(buf + pos + tl + 8);
        if (sink && sink(ctx, buf + pos, (unsigned long)tl, t, d) < 0){
            free(buf); MPD_ERR("aborted at transaction %llu", (unsigned long long)i); return -1; }
        pos += tl + 16;
        done++;
    }
    /* mapDeltas and the unbroadcast set follow; both are read for their
     * length only. Deltas for transactions NOT in the dump would need a
     * prioritisetransaction path at load time, which this node does not wire
     * up -- stated rather than silently dropped. */
    { u64 nd = 0; int k = get_cs(buf + pos, (u64)fsz - pos, &nd);
      if (!k){ free(buf); MPD_ERR("truncated delta map"); return -1; }
      pos += (u64)k;
      if (pos + nd * 40 > (u64)fsz){ free(buf); MPD_ERR("delta map overruns the file"); return -1; }
      pos += nd * 40; }
    free(buf);
    return done;
#undef MPD_ERR
}
