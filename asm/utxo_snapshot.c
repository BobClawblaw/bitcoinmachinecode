/* utxo_snapshot.c -- Core's assumeutxo snapshot serialization (the encoder).
 *
 * dumptxoutset writes a file Bitcoin Core's loadtxoutset can read, so every
 * byte here follows Core's node/utxo_snapshot.h + compressor.cpp exactly:
 *
 *   header: "utxo\xff" | u16 version(2) | net magic f9beb4d9 |
 *           base blockhash (32, wire) | u64 coins count
 *   coins:  txid (32, wire) | compactsize(#coins for this txid) | per coin:
 *             compactsize(vout)
 *             VARINT((height << 1) | coinbase)     Core's serialize.h VARINT
 *             VARINT(CompressAmount(value))        compressor.cpp
 *             compressed scriptPubKey              compressor.cpp
 *
 * Script compression: P2PKH -> kind 0 + hash20; P2SH -> 1 + hash20;
 * compressed P2PK -> kind 2|3 (the key's own first byte) + x-coord;
 * uncompressed P2PK -> kind 4|5 (4 + y-parity) + x-coord; anything else ->
 * VARINT(len + 6) + raw bytes.
 *
 * Every branch below is pinned by tests/test_utxo_snapshot.c against 14 coin
 * records lifted VERBATIM from a real snapshot the oracle Core wrote
 * (dumptxoutset at height 964065, 2026-08-25) -- all six special script
 * kinds, raw P2WPKH/P2TR, coinbase coins, amounts from 330 sat to 50 BTC.
 * The uncompressed-P2PK branch (kinds 4/5) is validated against those real
 * records too; note Core only compresses an uncompressed key whose payload
 * it considers valid, and this encoder mirrors that gate on the prefix and
 * length alone, as compressor.cpp's IsToPubKey does. */

#include "utxo_snapshot.h"
#include <string.h>

/* UTX-7 (audit 2026-09-03): Core compresses a 65-byte uncompressed P2PK only
 * when the key is FULLY VALID -- IsToPubKey (compressor.cpp) ends the 67-byte
 * arm with `return pubkey.IsFullyValid();`, and an invalid key falls through
 * to the raw VARINT(len+6) encoding.
 *
 * Note the asymmetry, which is Core's and is reproduced exactly below: the
 * 33-byte COMPRESSED arm is NOT gated. Compression there only relabels the
 * prefix byte, so DecompressScript reproduces the original bytes whatever the
 * key was. The uncompressed arm throws y away and keeps a parity bit, so
 * decompression has to RECOVER y by solving the curve equation -- which is
 * impossible if the point was never on the curve. That is the whole reason
 * the gate exists on one arm and not the other.
 *
 * pubkey_parse (bitcoin_pubkey.asm) is this tree's equivalent probe: for a
 * 65-byte 0x04 key it checks y^2 == x^3 + 7 (mod p), which is what
 * secp256k1_ec_pubkey_parse checks behind IsFullyValid. */
extern int pubkey_parse(const unsigned char* pub, unsigned long publen,
                        unsigned long long qx[4], unsigned long long qy[4]);

static long us_compact(unsigned char* o, unsigned long long v){
    if (v < 0xfd){ o[0] = (unsigned char)v; return 1; }
    if (v <= 0xffff){ o[0]=0xfd; o[1]=(unsigned char)v; o[2]=(unsigned char)(v>>8); return 3; }
    if (v <= 0xffffffffULL){ o[0]=0xfe; for (int i=0;i<4;i++) o[1+i]=(unsigned char)(v>>(8*i)); return 5; }
    o[0]=0xff; for (int i=0;i<8;i++) o[1+i]=(unsigned char)(v>>(8*i)); return 9;
}

/* serialize.h WriteVarInt: base-128 big-endian groups, +1 borrow on every
 * continuation byte. */
static long us_varint(unsigned char* o, unsigned long long n){
    unsigned char tmp[10]; int len = 0;
    for (;;){
        tmp[len] = (unsigned char)((n & 0x7f) | (len ? 0x80 : 0x00));
        if (n <= 0x7f) break;
        n = (n >> 7) - 1;
        len++;
    }
    long w = 0;
    for (int i = len; i >= 0; i--) o[w++] = tmp[i];
    return w;
}

/* compressor.cpp CompressAmount */
unsigned long long usnap_compress_amount(unsigned long long n){
    if (n == 0) return 0;
    int e = 0;
    while ((n % 10) == 0 && e < 9){ n /= 10; e++; }
    if (e < 9){
        int d = (int)(n % 10);
        n /= 10;
        return 1 + (n*9 + (unsigned long long)d - 1)*10 + (unsigned long long)e;
    }
    return 1 + (n - 1)*10 + 9;
}

/* The real UTXO set carries scripts far beyond the standard templates --
 * bare multisig and outright junk up to the consensus 10k -- and the first
 * full-set dump failed exactly there, so the bound is the consensus bound,
 * not a "reasonable" one. */
#define USNAP_MAX_SCRIPT 10000

/* UTX-7: Core's IsFullyValid for the 65-byte uncompressed form. `pub` points
 * at the 0x04 prefix (65 bytes). */
static int usnap_pubkey_fully_valid(const unsigned char* pub){
    unsigned long long qx[4], qy[4];
    return pubkey_parse(pub, 65, qx, qy) == 1;
}

long usnap_coin(unsigned int vout, unsigned long height, int coinbase,
                unsigned long long value,
                const unsigned char* spk, unsigned long spklen,
                unsigned char* out, unsigned long cap){
    unsigned char buf[USNAP_MAX_SCRIPT + 64];
    long o = 0;
    o += us_compact(buf + o, vout);
    o += us_varint(buf + o, (height << 1) | (unsigned long)(coinbase ? 1 : 0));
    o += us_varint(buf + o, usnap_compress_amount(value));
    /* script compression */
    if (spklen == 25 && spk[0]==0x76 && spk[1]==0xa9 && spk[2]==0x14 &&
        spk[23]==0x88 && spk[24]==0xac){
        o += us_varint(buf + o, 0);
        memcpy(buf + o, spk + 3, 20); o += 20;
    } else if (spklen == 23 && spk[0]==0xa9 && spk[1]==0x14 && spk[22]==0x87){
        o += us_varint(buf + o, 1);
        memcpy(buf + o, spk + 2, 20); o += 20;
    } else if (spklen == 35 && spk[0]==33 && (spk[1]==0x02 || spk[1]==0x03) &&
               spk[34]==0xac){
        o += us_varint(buf + o, spk[1]);          /* kind = the key's prefix */
        memcpy(buf + o, spk + 2, 32); o += 32;
    } else if (spklen == 67 && spk[0]==65 && spk[1]==0x04 && spk[66]==0xac &&
               usnap_pubkey_fully_valid(spk + 1)){
        /* UTX-7: the on-curve gate. Without it a bare P2PK output carrying a
         * non-curve 0x04 key -- these exist in mainnet's UTXO set -- was
         * written as kind 4/5 + x, which Core's DecompressScript cannot undo
         * (there is no y to recover), so loadtxoutset would fail to
         * deserialize or hash differently. Such keys now fall through to the
         * raw arm below, exactly as they do in Core. */
        o += us_varint(buf + o, 4 | (spk[65] & 1));
        memcpy(buf + o, spk + 2, 32); o += 32;    /* x-coord only */
    } else {
        if (spklen > USNAP_MAX_SCRIPT) return -1;
        o += us_varint(buf + o, spklen + 6);
        memcpy(buf + o, spk, spklen); o += (long)spklen;
    }
    if ((unsigned long)o > cap) return -1;
    memcpy(out, buf, (size_t)o);
    return o;
}

long usnap_header(const unsigned char base_hash_wire[32],
                  unsigned long long coins, unsigned char out[51]){
    long o = 0;
    memcpy(out, "utxo\xff", 5); o = 5;
    out[o++] = 0x02; out[o++] = 0x00;                  /* version 2 */
    out[o++] = 0xf9; out[o++] = 0xbe; out[o++] = 0xb4; out[o++] = 0xd9;
    memcpy(out + o, base_hash_wire, 32); o += 32;
    for (int i = 0; i < 8; i++) out[o++] = (unsigned char)(coins >> (8*i));
    return o;                                           /* 51 */
}
