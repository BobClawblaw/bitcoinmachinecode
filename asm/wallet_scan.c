/* wallet_scan.c -- the wallet rescan: walk the block archive and record every
 * output that pays this wallet and every input that spends one.
 *
 * WHY THIS EXISTS
 * ---------------
 * Until now the wallet learned of its money from two places, and neither was
 * a history:
 *   - daemon/build_addr_index.c inverts the UTXO SET, so it answers "what
 *     does this address own right now" but knows nothing about outputs that
 *     have since been spent, and nothing about when anything arrived;
 *   - wallet_txlog.c journals the sends this node itself made.
 * So "how much has this address received" had no data behind it at all, and
 * getreceivedbyaddress / listreceivedby* / listsinceblock / the `receive`
 * category of listtransactions all had to refuse rather than answer 0 --
 * an answer of 0 is indistinguishable to the caller from an address that
 * genuinely received nothing.
 *
 * This scan produces the missing thing: an ordered record of every wallet
 * event, with the height it happened at, from which confirmations, received
 * totals and since-block listings all follow.
 *
 * WHAT IS MATCHED
 * ---------------
 * The wallet is a single BIP32 seed deriving m/84'/0'/0'/<i>/<0|1>. The
 * caller hands in the hash160 of each derived key over a bounded index
 * window; an output is ours when its scriptPubKey is P2WPKH or P2PKH over
 * one of those hashes. Both forms are checked because they are the same key:
 * getnewaddress hands out the P2WPKH rendering, but a payer given the P2PKH
 * address of the same key is still paying this wallet.
 *
 * An input is ours when its outpoint is one this scan already recorded as a
 * receive. That is why the scan must run forward in height order and keep
 * its own set of owned outpoints as it goes -- a spend can only be
 * recognised after the output it spends has been seen.
 *
 * ON-DISK FORMAT -- <path>, appended in height order:
 *
 *     "BMCWSCN3"                        8-byte magic ("BMCWSCN2" = no
 *                                       is_coinbase byte; still readable)
 *     u32 tip_scanned                   highest height covered
 *     u32 n_records
 *     then n_records x 86 bytes:
 *       u32 height | u8[32] txid (WIRE order) | u32 vout | u64 value
 *       u8 kind (0 receive, 1 spend) | u32 keyidx | u8 branch
 *       u8[32] prev_txid -- on a SPEND, the outpoint that was spent; zero on
 *                           a receive. See wallet_scan.h for why one txid is
 *                           not enough to answer "is this output unspent".
 *       u8 is_coinbase   -- on a RECEIVE, 1 when the paying tx was its
 *                           block's first: the coin is unspendable until 100
 *                           confirmations, and a balance that ignores that
 *                           overstates what can actually be spent.
 *
 * The header is written LAST, after every record is durable, so a crash
 * mid-scan leaves a file whose header still describes the previous complete
 * scan -- never a partial one that looks whole. A reader that finds a short
 * or magic-less file treats it as absent, which is the honest reading: no
 * scan has completed.
 */

#include "wallet_scan.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Format 3 adds is_coinbase. An older BMCWSCN2 file is still READ (a forced
 * rescan of every existing wallet would be a worse trade than a balance that
 * cannot apply coinbase maturity until the next rescan) -- wscan_flags_known()
 * reports which one the reader got. */
/* Format 4 adds hdkey (which HD key owns the output). Formats 3 and 2 are
 * still READ -- forcing every existing wallet to rescan would be a worse
 * trade than a record set whose outputs are all attributed to the seed,
 * which is exactly what they are on a wallet that has never called
 * addhdkey. */
#define WSCAN_MAGIC  "BMCWSCN4"
#define WSCAN_MAGIC3 "BMCWSCN3"
#define WSCAN_MAGIC2 "BMCWSCN2"
#define WSCAN_HDR   16
#define WSCAN_REC   88
#define WSCAN_REC_V3 87
#define WSCAN_REC_V2 86

/* Set by wscan_read: whether the file it just read carries is_coinbase. */
static int g_wscan_flags_known = 0;
int wscan_flags_known(void){ return g_wscan_flags_known; }

/* ---- owned-outpoint set -------------------------------------------------
 * Open addressing over (txid,vout). Sized by the caller's cap so a wallet
 * with a lot of history does not silently start dropping spends: if it
 * fills, the scan FAILS rather than continuing to produce a record set that
 * is missing spends it could not remember. */
typedef struct {
    unsigned char txid[32];
    unsigned int  vout;
    unsigned long long value;
    unsigned int  keyidx;
    unsigned char branch;
    unsigned char hdkey;      /* carried so the SPEND record can name it too */
    unsigned char used;
} wscan_own;

typedef struct { wscan_own* e; unsigned long mask; unsigned long n; } wscan_set;

static unsigned long wscan_hash(const unsigned char txid[32], unsigned int vout){
    /* FNV-1a over the outpoint */
    unsigned long h = 1469598103934665603UL;
    for (int i = 0; i < 32; i++){ h ^= txid[i]; h *= 1099511628211UL; }
    for (int i = 0; i < 4; i++){ h ^= (unsigned char)(vout >> (8*i)); h *= 1099511628211UL; }
    return h;
}
static int wscan_set_init(wscan_set* s, unsigned long slots){
    unsigned long n = 1; while (n < slots) n <<= 1;
    s->e = calloc(n, sizeof *s->e);
    if (!s->e) return 0;
    s->mask = n - 1; s->n = 0;
    return 1;
}
static void wscan_set_free(wscan_set* s){ free(s->e); s->e = NULL; }
static wscan_own* wscan_set_find(wscan_set* s, const unsigned char txid[32], unsigned int vout){
    unsigned long i = wscan_hash(txid, vout) & s->mask;
    for (unsigned long probe = 0; probe <= s->mask; probe++){
        wscan_own* o = &s->e[(i + probe) & s->mask];
        if (!o->used) return NULL;
        if (o->vout == vout && !memcmp(o->txid, txid, 32)) return o;
    }
    return NULL;
}
static int wscan_set_add(wscan_set* s, const unsigned char txid[32], unsigned int vout,
                         unsigned long long value, unsigned int keyidx, unsigned char branch,
                         unsigned char hdkey){
    if (s->n * 4 >= (s->mask + 1) * 3) return 0;     /* keep load under 0.75 */
    unsigned long i = wscan_hash(txid, vout) & s->mask;
    for (unsigned long probe = 0; probe <= s->mask; probe++){
        wscan_own* o = &s->e[(i + probe) & s->mask];
        if (o->used){
            if (o->vout == vout && !memcmp(o->txid, txid, 32)) return 1;  /* already */
            continue;
        }
        memcpy(o->txid, txid, 32);
        o->vout = vout; o->value = value; o->keyidx = keyidx; o->branch = branch;
        o->hdkey = hdkey; o->used = 1; s->n++;
        return 1;
    }
    return 0;
}

/* ---- key set ------------------------------------------------------------ */
static int wscan_key_find(const wscan_key* keys, int nkeys, const unsigned char h[20],
                          unsigned int* keyidx, unsigned char* branch,
                          unsigned char* hdkey){
    /* keys are sorted by hash160 so this is a binary search; the window is
     * a couple of thousand entries and this runs per output of every tx in
     * the chain, so a linear scan would dominate the whole rescan. */
    int lo = 0, hi = nkeys - 1;
    while (lo <= hi){
        int mid = lo + (hi - lo) / 2;
        int c = memcmp(keys[mid].h160, h, 20);
        if (c == 0){ *keyidx = keys[mid].keyidx; *branch = keys[mid].branch;
                     *hdkey = keys[mid].hdkey; return 1; }
        if (c < 0) lo = mid + 1; else hi = mid - 1;
    }
    return 0;
}

int wscan_key_cmp(const void* a, const void* b){
    return memcmp(((const wscan_key*)a)->h160, ((const wscan_key*)b)->h160, 20);
}

/* ---- tx walking ---------------------------------------------------------
 * Deliberately a local, bounds-checked walk rather than a call into the
 * consensus tx parser: this runs over untrusted archive bytes for every
 * transaction in the chain, and every step below refuses rather than reads
 * past `end`. */
static unsigned long wscan_varint(const unsigned char* p, const unsigned char* end,
                                  unsigned long* consumed){
    *consumed = 0;
    if (p >= end) return 0;
    unsigned char b = p[0];
    if (b < 0xfd){ *consumed = 1; return b; }
    if (b == 0xfd){ if (p + 3 > end) return 0; *consumed = 3; return (unsigned long)p[1] | ((unsigned long)p[2] << 8); }
    if (b == 0xfe){ if (p + 5 > end) return 0; *consumed = 5;
        return (unsigned long)p[1] | ((unsigned long)p[2]<<8) | ((unsigned long)p[3]<<16) | ((unsigned long)p[4]<<24); }
    if (p + 9 > end) return 0;
    *consumed = 9;
    unsigned long v = 0;
    for (int i = 0; i < 8; i++) v |= (unsigned long)p[1+i] << (8*i);
    return v;
}

/* scriptPubKey -> our hash160, if it is a form this wallet can own.
 * P2SH added 2026-08-27 for watch-only sh(wpkh(...)) descriptors: the key
 * array entry for those is the P2SH SCRIPT hash (rpc_desc_expand), so the
 * exact-match lookup below stays a plain 20-byte compare. HD-seed wallets
 * never put a script hash in their key window, so the extra arm cannot
 * change what they match (a 160-bit collision between a key hash and a
 * script hash is not a real event). */
int wscan_spk_h160(const unsigned char* spk, unsigned long len, const unsigned char** h){
    if (len == 22 && spk[0] == 0x00 && spk[1] == 0x14){ *h = spk + 2; return 1; }   /* P2WPKH */
    if (len == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14 &&
        spk[23] == 0x88 && spk[24] == 0xac){ *h = spk + 3; return 1; }              /* P2PKH  */
    if (len == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87){
        *h = spk + 2; return 1; }                                                   /* P2SH   */
    /* P2WSH / P2TR: a 32-byte program; the key window holds its first 20
     * bytes (rpc_desc_expand), so imported wsh()/tr() descriptors match by
     * the same 20-byte compare. A 160-bit prefix collision with a real key
     * hash is not a real event, and HD-seed wallets never carry one. */
    if (len == 34 && (spk[0] == 0x00 || spk[0] == 0x51) && spk[1] == 0x20){
        *h = spk + 2; return 1; }
    return 0;
}

long wscan_run(long from, long to,
               const wscan_key* keys, int nkeys,
               long (*read_block)(long h, unsigned char* buf, long cap),
               unsigned char* blockbuf, long bufcap,
               const char* out_path,
               unsigned long own_slots,
               void (*progress)(long h, long to, void* ctx), void* ctx,
               char* err, unsigned long errcap){
    if (err && errcap) err[0] = 0;
    if (from < 0) from = 0;
    if (to < from){ if (err && errcap) snprintf(err, errcap, "empty height range"); return -1; }

    wscan_set own;
    if (!wscan_set_init(&own, own_slots ? own_slots : (1u << 16))){
        if (err && errcap) snprintf(err, errcap, "out of memory sizing the owned-outpoint set");
        return -1;
    }

    char tmp[1024];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", out_path) >= (int)sizeof tmp){
        wscan_set_free(&own);
        if (err && errcap) snprintf(err, errcap, "output path too long");
        return -1;
    }
    FILE* f = fopen(tmp, "wb");
    if (!f){
        wscan_set_free(&own);
        if (err && errcap) snprintf(err, errcap, "cannot open %s for writing", tmp);
        return -1;
    }
    /* placeholder header; the real one is written last (see the file note) */
    { unsigned char hdr[WSCAN_HDR]; memset(hdr, 0, sizeof hdr);
      if (fwrite(hdr, 1, sizeof hdr, f) != sizeof hdr){
          fclose(f); unlink(tmp); wscan_set_free(&own);
          if (err && errcap) snprintf(err, errcap, "short write on the header");
          return -1;
      } }

    long nrec = 0;
    unsigned char txidbuf[32];

    for (long h = from; h <= to; h++){
        if (progress && (h % 5000 == 0)) progress(h, to, ctx);
        long blen = read_block(h, blockbuf, bufcap);
        if (blen < 81){
            /* A height we cannot read is not "no wallet activity there" -- it
             * is unknown. Reporting a scan that silently skipped it would
             * understate every total derived from this file. */
            fclose(f); unlink(tmp); wscan_set_free(&own);
            if (err && errcap)
                snprintf(err, errcap, "block %ld could not be read (pruned or missing); "
                                      "the scan would be incomplete and was abandoned", h);
            return -1;
        }
        const unsigned char* p = blockbuf + 80;
        const unsigned char* end = blockbuf + blen;
        unsigned long cc;
        unsigned long ntx = wscan_varint(p, end, &cc);
        if (cc == 0 || ntx == 0){ fclose(f); unlink(tmp); wscan_set_free(&own);
            if (err && errcap) snprintf(err, errcap, "block %ld has an unreadable tx count", h);
            return -1; }
        p += cc;

        for (unsigned long t = 0; t < ntx; t++){
            const unsigned char* txstart = p;
            if (p + 4 > end) goto malformed;
            p += 4;
            int segwit = 0;
            if (p + 2 <= end && p[0] == 0x00 && p[1] == 0x01){ segwit = 1; p += 2; }
            const unsigned char* in_start = p;
            unsigned long n_in = wscan_varint(p, end, &cc);
            if (cc == 0 || n_in == 0) goto malformed;
            p += cc;
            /* --- inputs: a spend of an outpoint we own --- */
            const unsigned char* inputs_at = p;
            for (unsigned long i = 0; i < n_in; i++){
                if (p + 36 > end) goto malformed;
                p += 36;
                unsigned long sl = wscan_varint(p, end, &cc);
                if (cc == 0) goto malformed;
                p += cc + sl + 4;
                if (p > end) goto malformed;
            }
            unsigned long n_out = wscan_varint(p, end, &cc);
            if (cc == 0) goto malformed;
            p += cc;
            const unsigned char* out_body = p;
            for (unsigned long i = 0; i < n_out; i++){
                if (p + 8 > end) goto malformed;
                p += 8;
                unsigned long sl = wscan_varint(p, end, &cc);
                if (cc == 0) goto malformed;
                p += cc + sl;
                if (p > end) goto malformed;
            }
            const unsigned char* outs_end = p;
            /* witness section */
            if (segwit){
                for (unsigned long i = 0; i < n_in; i++){
                    unsigned long items = wscan_varint(p, end, &cc);
                    if (cc == 0) goto malformed;
                    p += cc;
                    for (unsigned long k = 0; k < items; k++){
                        unsigned long il = wscan_varint(p, end, &cc);
                        if (cc == 0) goto malformed;
                        p += cc + il;
                        if (p > end) goto malformed;
                    }
                }
            }
            if (p + 4 > end) goto malformed;
            p += 4;

            /* txid: sha256d over the STRIPPED serialization (BIP141). For a
             * non-witness tx that is the bytes as they stand. */
            if (segwit){
                /* version | inputs..outputs | locktime, marker/flag and the
                 * witness section dropped */
                unsigned long a = 4;
                unsigned long b = (unsigned long)(outs_end - in_start);
                unsigned long need = a + b + 4;
                unsigned char* s = malloc(need);
                if (!s){ fclose(f); unlink(tmp); wscan_set_free(&own);
                    if (err && errcap) snprintf(err, errcap, "out of memory stripping a witness tx");
                    return -1; }
                memcpy(s, txstart, 4);
                memcpy(s + 4, in_start, b);
                memcpy(s + 4 + b, p - 4, 4);
                wscan_sha256d(txidbuf, s, need);
                free(s);
            } else {
                wscan_sha256d(txidbuf, txstart, (unsigned long)(p - txstart));
            }

            /* --- record spends of outpoints we already own --- */
            { const unsigned char* q = inputs_at;
              for (unsigned long i = 0; i < n_in; i++){
                  unsigned int vo = (unsigned int)q[32] | ((unsigned int)q[33]<<8) |
                                    ((unsigned int)q[34]<<16) | ((unsigned int)q[35]<<24);
                  wscan_own* o = wscan_set_find(&own, q, vo);
                  if (o){
                      unsigned char rec[WSCAN_REC]; unsigned long w = 0;
                      unsigned int hh = (unsigned int)h;
                      for (int k=0;k<4;k++) rec[w++] = (unsigned char)(hh >> (8*k));
                      memcpy(rec + w, txidbuf, 32); w += 32;
                      for (int k=0;k<4;k++) rec[w++] = (unsigned char)(vo >> (8*k));
                      for (int k=0;k<8;k++) rec[w++] = (unsigned char)(o->value >> (8*k));
                      rec[w++] = 1;                                  /* kind: spend */
                      for (int k=0;k<4;k++) rec[w++] = (unsigned char)(o->keyidx >> (8*k));
                      rec[w++] = o->branch;
                      memcpy(rec + w, q, 32); w += 32;                /* the SPENT outpoint */
                      rec[w++] = 0;                                  /* is_coinbase: n/a on a spend */
                      rec[w++] = o->hdkey;                           /* inherited from the output spent */
                      if (fwrite(rec, 1, WSCAN_REC, f) != WSCAN_REC) goto shortwrite;
                      nrec++;
                  }
                  q += 36;
                  unsigned long sl = wscan_varint(q, end, &cc);
                  q += cc + sl + 4;
              } }

            /* --- record outputs paying us --- */
            { const unsigned char* q = out_body;
              for (unsigned long i = 0; i < n_out; i++){
                  unsigned long long val = 0;
                  for (int k=0;k<8;k++) val |= (unsigned long long)q[k] << (8*k);
                  q += 8;
                  unsigned long sl = wscan_varint(q, end, &cc);
                  q += cc;
                  const unsigned char* hh160;
                  unsigned int kidx; unsigned char br, hdk;
                  if (wscan_spk_h160(q, sl, &hh160) &&
                      wscan_key_find(keys, nkeys, hh160, &kidx, &br, &hdk)){
                      unsigned char rec[WSCAN_REC]; unsigned long w = 0;
                      unsigned int hgt = (unsigned int)h;
                      for (int k=0;k<4;k++) rec[w++] = (unsigned char)(hgt >> (8*k));
                      memcpy(rec + w, txidbuf, 32); w += 32;
                      for (int k=0;k<4;k++) rec[w++] = (unsigned char)((unsigned int)i >> (8*k));
                      for (int k=0;k<8;k++) rec[w++] = (unsigned char)(val >> (8*k));
                      rec[w++] = 0;                                  /* kind: receive */
                      for (int k=0;k<4;k++) rec[w++] = (unsigned char)(kidx >> (8*k));
                      rec[w++] = br;
                      memset(rec + w, 0, 32); w += 32;                /* no prev on a receive */
                      rec[w++] = (t == 0) ? 1 : 0;                    /* block's first tx = coinbase */
                      rec[w++] = hdk;                                 /* which HD key owns it */
                      if (fwrite(rec, 1, WSCAN_REC, f) != WSCAN_REC) goto shortwrite;
                      nrec++;
                      if (!wscan_set_add(&own, txidbuf, (unsigned int)i, val, kidx, br, hdk)){
                          fclose(f); unlink(tmp); wscan_set_free(&own);
                          if (err && errcap)
                              snprintf(err, errcap,
                                       "the owned-outpoint set filled at height %ld; the scan "
                                       "would start missing spends, so it was abandoned. "
                                       "Re-run with a larger set size", h);
                          return -1;
                      }
                  }
                  q += sl;
              } }
            continue;
        malformed:
            fclose(f); unlink(tmp); wscan_set_free(&own);
            if (err && errcap) snprintf(err, errcap, "block %ld tx %lu is malformed", h, t);
            return -1;
        }
    }

    /* header last: fflush + fsync, seek back, write, fsync again, rename */
    { unsigned char hdr[WSCAN_HDR];
      memcpy(hdr, WSCAN_MAGIC, 8);
      unsigned int tip = (unsigned int)to, n32 = (unsigned int)nrec;
      for (int k=0;k<4;k++) hdr[8+k]  = (unsigned char)(tip >> (8*k));
      for (int k=0;k<4;k++) hdr[12+k] = (unsigned char)(n32 >> (8*k));
      if (fflush(f) != 0 || fsync(fileno(f)) != 0) goto shortwrite;
      if (fseek(f, 0, SEEK_SET) != 0) goto shortwrite;
      if (fwrite(hdr, 1, sizeof hdr, f) != sizeof hdr) goto shortwrite;
      if (fflush(f) != 0 || fsync(fileno(f)) != 0) goto shortwrite;
    }
    if (fclose(f) != 0){ unlink(tmp); wscan_set_free(&own);
        if (err && errcap) snprintf(err, errcap, "close failed on %s", tmp);
        return -1; }
    wscan_set_free(&own);
    if (rename(tmp, out_path) != 0){ unlink(tmp);
        if (err && errcap) snprintf(err, errcap, "rename %s -> %s failed", tmp, out_path);
        return -1; }
    return nrec;

shortwrite:
    fclose(f); unlink(tmp); wscan_set_free(&own);
    if (err && errcap) snprintf(err, errcap, "short write while scanning");
    return -1;
}

/* ---- reader ------------------------------------------------------------- */
long wscan_read(const char* path, wscan_rec* out, long cap, long* tip_out){
    if (tip_out) *tip_out = -1;
    FILE* f = fopen(path, "rb");
    if (!f) return 0;                       /* absent == no scan has completed */
    unsigned char hdr[WSCAN_HDR];
    int ver = 0;
    if (fread(hdr, 1, sizeof hdr, f) != sizeof hdr){
        fclose(f); return 0;                /* torn: treat as absent */
    }
    if      (!memcmp(hdr, WSCAN_MAGIC,  8)) ver = 4;
    else if (!memcmp(hdr, WSCAN_MAGIC3, 8)) ver = 3;  /* no hdkey */
    else if (!memcmp(hdr, WSCAN_MAGIC2, 8)) ver = 2;  /* older: no is_coinbase */
    else { fclose(f); return 0; }           /* foreign: treat as absent */
    g_wscan_flags_known = (ver >= 3);
    const unsigned long recsz = ver >= 4 ? WSCAN_REC
                              : ver == 3 ? WSCAN_REC_V3 : WSCAN_REC_V2;
    unsigned int tip = 0, n = 0;
    for (int k=0;k<4;k++) tip |= (unsigned int)hdr[8+k]  << (8*k);
    for (int k=0;k<4;k++) n   |= (unsigned int)hdr[12+k] << (8*k);
    if (tip_out) *tip_out = (long)tip;
    long got = 0;
    unsigned char rec[WSCAN_REC];
    while (got < cap && got < (long)n && fread(rec, 1, recsz, f) == recsz){
        unsigned long w = 0;
        wscan_rec* r = &out[got];
        r->height = 0; for (int k=0;k<4;k++) r->height |= (unsigned int)rec[w++] << (8*k);
        memcpy(r->txid, rec + w, 32); w += 32;
        r->vout = 0;   for (int k=0;k<4;k++) r->vout   |= (unsigned int)rec[w++] << (8*k);
        r->value = 0;  for (int k=0;k<8;k++) r->value  |= (unsigned long long)rec[w++] << (8*k);
        r->kind = rec[w++];
        r->keyidx = 0; for (int k=0;k<4;k++) r->keyidx |= (unsigned int)rec[w++] << (8*k);
        r->branch = rec[w++];
        memcpy(r->prev_txid, rec + w, 32); w += 32;
        r->is_coinbase = ver >= 3 ? rec[w++] : 0; /* v2 cannot say; see wscan_flags_known */
        /* pre-v4 files predate added HD keys, so every output in them belongs
         * to the seed -- 0 is the truth for them, not a guess */
        r->hdkey = ver >= 4 ? rec[w++] : 0;
        got++;
    }
    fclose(f);
    return got;
}

/* ---- wscan_write --------------------------------------------------------
 * Rewrite the whole record file from an in-memory array, with the SAME
 * durability discipline wscan_run uses: records into a temp file, fsync,
 * header written LAST, fsync, rename. A crash therefore leaves either the
 * previous complete file or the new complete one -- never a half-written
 * record set that a reader would take as whole.
 *
 * This exists because importprunedfunds/removeprunedfunds edit the wallet's
 * record set without rescanning the chain, and the alternative -- a second
 * copy of the record layout in the RPC layer -- is how a format grows two
 * writers that disagree. The packing below is the only other place that
 * knows WSCAN_REC, and it sits beside the one in wscan_run for that reason.
 *
 * Returns 0 on success, -1 on failure with `err` filled; on failure nothing
 * at `path` is disturbed. */
int wscan_write(const char* path, const wscan_rec* recs, long n, long tip,
                char* err, unsigned long errcap){
    if (!path || (n > 0 && !recs)){
        if (err && errcap) snprintf(err, errcap, "bad arguments");
        return -1; }
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE* f = fopen(tmp, "wb");
    if (!f){ if (err && errcap) snprintf(err, errcap, "cannot create %s", tmp); return -1; }
    unsigned char hdr[WSCAN_HDR];
    memset(hdr, 0, sizeof hdr);
    if (fwrite(hdr, 1, sizeof hdr, f) != sizeof hdr) goto fail;   /* placeholder */
    for (long i = 0; i < n; i++){
        const wscan_rec* r = &recs[i];
        unsigned char rec[WSCAN_REC]; unsigned long w = 0;
        for (int k=0;k<4;k++) rec[w++] = (unsigned char)(r->height >> (8*k));
        memcpy(rec + w, r->txid, 32); w += 32;
        for (int k=0;k<4;k++) rec[w++] = (unsigned char)(r->vout >> (8*k));
        for (int k=0;k<8;k++) rec[w++] = (unsigned char)(r->value >> (8*k));
        rec[w++] = r->kind;
        for (int k=0;k<4;k++) rec[w++] = (unsigned char)(r->keyidx >> (8*k));
        rec[w++] = r->branch;
        memcpy(rec + w, r->prev_txid, 32); w += 32;
        rec[w++] = r->is_coinbase;
        rec[w++] = r->hdkey;
        if (w != WSCAN_REC) goto fail;      /* layout drift, caught here */
        if (fwrite(rec, 1, WSCAN_REC, f) != WSCAN_REC) goto fail;
    }
    { memcpy(hdr, WSCAN_MAGIC, 8);
      unsigned int t32 = (unsigned int)(tip < 0 ? 0 : tip), n32 = (unsigned int)n;
      for (int k=0;k<4;k++) hdr[8+k]  = (unsigned char)(t32 >> (8*k));
      for (int k=0;k<4;k++) hdr[12+k] = (unsigned char)(n32 >> (8*k));
      if (fflush(f) != 0 || fsync(fileno(f)) != 0) goto fail;
      if (fseek(f, 0, SEEK_SET) != 0) goto fail;
      if (fwrite(hdr, 1, sizeof hdr, f) != sizeof hdr) goto fail;
      if (fflush(f) != 0 || fsync(fileno(f)) != 0) goto fail; }
    if (fclose(f) != 0){ unlink(tmp);
        if (err && errcap) snprintf(err, errcap, "close failed on %s", tmp);
        return -1; }
    if (rename(tmp, path) != 0){ unlink(tmp);
        if (err && errcap) snprintf(err, errcap, "rename %s -> %s failed", tmp, path);
        return -1; }
    return 0;
fail:
    fclose(f); unlink(tmp);
    if (err && errcap) snprintf(err, errcap, "short write to %s", tmp);
    return -1;
}
