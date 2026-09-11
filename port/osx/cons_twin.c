/* ============================================================================
 * cons_twin.c -- block consensus verifier for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_cons.asm (branch bmc_osx).
 *
 *   int cons_verify(const u8 *block, u64 len, u8 *txids_out, u64 cap);
 *
 * Returns 1 iff: pow_check passes; the compact-size tx count parses;
 * every tx parses (tx_parse) and its txid computes (tx_txid, cap 1 MiB);
 * tx[0] is the coinbase (n_in == 1); the txid list fills txids_out
 * exactly; the merkle root matches header[36..68]; the merkle call
 * reports no duplicate-txid mutation.
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16_t;
#include <stdio.h>
typedef unsigned char u8;

extern long tx_parse(u64 info[8], const void *tx, u64 txlen);
extern long tx_txid(u8 out[32], const void *tx, u64 txlen, void *buf, u64 buflen);
extern long merkle_root(u8 root[32], const u8 *txids, unsigned long n);
extern void sha256d(u8 out[32], const void *msg, unsigned long long len);
extern long pow_check(const u8 header[80]);

/* ----------------------------------------------------------------------------
 * UPSTREAM-BUG NOTE (2026-09-10, found mining the first osx regtest block):
 * asm/tx_txid (x86 bitcoin_tx.asm) rebuilds the unwitnessed serialization
 * CORRECTLY (byte-identical to Core's stripped form for a real segwit tx) but
 * then hashes the WRONG LENGTH -- its txid differs from Core's for every
 * segwit tx.  Latent on x86: the IBD path verifies through daemon/tx_verify.c's
 * C walker, not asm cons_verify; only submitblock reaches it.  This twin
 * computes the txid itself (strip marker/flag + witness in C, then sha256d) so
 * the osx node ACCEPTS segwit blocks exactly as Core does.  The x86 fix
 * belongs on main (bitcoin_tx.asm tx_txid's length computation).
 * -------------------------------------------------------------------------- */
static int txid_of_span(const u8* tx, u64 txlen, u8 out[32], u8* scratch, u64 cap){
    if (txlen < 10) return 0;               /* version + n_in + locktime minimum */
    const u8* end = tx + txlen;
    const u8* p = tx + 4;
    u64 hdr = 4;                            /* stripped body start (no marker/flag) */
    if (p + 2 <= end && p[0] == 0x00 && p[1] != 0x00){ p += 2; hdr = 6; }  /* BIP144 */
    u64 body;
    u64 nin = 0, nout = 0;
    { const u8* q = p;
      u64 csval[2]; int which = 0;
      while (q < end && which < 2){
          u64 v = *q++;
          if (v == 0xfd){ if (end - q < 2) return 0; v = (u64)q[0] | ((u64)q[1]<<8); q += 2; }
          else if (v == 0xfe){ if (end - q < 4) return 0; v = (u64)q[0] | ((u64)q[1]<<8) | ((u64)q[2]<<16) | ((u64)q[3]<<24); q += 4; }
          else if (v == 0xff){ if (end - q < 8) return 0; v = 0; for (int i = 0; i < 8; i++) v |= (u64)q[i] << (8*i); q += 8; }
          csval[which++] = v;
          if (which == 1){
              nin = v;
              for (u64 i = 0; i < nin; i++){
                  if (end - q < 36) return 0; q += 36;
                  u64 sl = *q++;
                  if (sl == 0xfd){ if (end - q < 2) return 0; sl = (u64)q[0] | ((u64)q[1]<<8); q += 2; }
                  else if (sl == 0xfe){ if (end - q < 4) return 0; sl = (u64)q[0] | ((u64)q[1]<<8) | ((u64)q[2]<<16) | ((u64)q[3]<<24); q += 4; }
                  else if (sl == 0xff){ if (end - q < 8) return 0; sl = 0; for (int k = 0; k < 8; k++) sl |= (u64)q[k] << (8*k); q += 8; }
                  if ((u64)(end - q) < sl) return 0; q += sl;
                  if (end - q < 4) return 0; q += 4;
              }
          } else {
              nout = v;
              for (u64 i = 0; i < nout; i++){
                  if (end - q < 8) return 0; q += 8;
                  u64 sl = *q++;
                  if (sl == 0xfd){ if (end - q < 2) return 0; sl = (u64)q[0] | ((u64)q[1]<<8); q += 2; }
                  else if (sl == 0xfe){ if (end - q < 4) return 0; sl = (u64)q[0] | ((u64)q[1]<<8) | ((u64)q[2]<<16) | ((u64)q[3]<<24); q += 4; }
                  else if (sl == 0xff){ if (end - q < 8) return 0; sl = 0; for (int k = 0; k < 8; k++) sl |= (u64)q[k] << (8*k); q += 8; }
                  if ((u64)(end - q) < sl) return 0; q += sl;
              }
          }
      }
      body = (u64)(q - tx);                /* END OF OUTPUTS = the witness start
                                            * for segwit, txlen-4 for legacy.
                                            * MUST be taken BEFORE the witness
                                            * skip: after it q points past the
                                            * witness and the "stripped" form
                                            * would include the witness stacks
                                            * (found by the testnet4 IBD: every
                                            * segwit block failed cons_verify;
                                            * the /tmp/ibd_bad_*.bin dumps +
                                            * a python hand-hash pinned it). */
      if (hdr == 6){                       /* segwit: skip the witness stacks */
          for (u64 i = 0; i < nin; i++){
              if (q >= end) return 0;
              u64 ni = *q++;
              if (ni == 0xfd){ if (end - q < 2) return 0; ni = (u64)q[0] | ((u64)q[1]<<8); q += 2; }
              else if (ni == 0xfe){ if (end - q < 4) return 0; ni = (u64)q[0] | ((u64)q[1]<<8) | ((u64)q[2]<<16) | ((u64)q[3]<<24); q += 4; }
              for (u64 j = 0; j < ni; j++){
                  if (q >= end) return 0;
                  u64 il = *q++;
                  if (il == 0xfd){ if (end - q < 2) return 0; il = (u64)q[0] | ((u64)q[1]<<8); q += 2; }
                  else if (il == 0xfe){ if (end - q < 4) return 0; il = (u64)q[0] | ((u64)q[1]<<8) | ((u64)q[2]<<16) | ((u64)q[3]<<24); q += 4; }
                  else if (il == 0xff){ if (end - q < 8) return 0; il = 0; for (int k = 0; k < 8; k++) il |= (u64)q[k] << (8*k); q += 8; }
                  if ((u64)(end - q) < il) return 0; q += il;
              }
          }
          if (q + 4 != end) return 0;      /* locktime must follow exactly */
      } else {
          if (end - q != 4) return 0;      /* legacy: only the locktime remains */
      }
    }
    /* stripped = version(4) || [n_in varint .. outs_end) || locktime(4)
     * body = offset of the witness section (= end of outputs; == txlen-4 for
     * legacy).  hdr is where the body starts: 6 with marker+flag, 4 without
     * (the first cut hardcoded 6 and ate two bytes of every legacy txid --
     * test_cons's valid-block fixtures caught it). */
    u64 blen = 4 + (body - hdr) + 4;
    if (blen > cap) return 0;
    memcpy(scratch, tx, 4);
    memcpy(scratch + 4, tx + hdr, body - hdr);
    memcpy(scratch + 4 + (body - hdr), end - 4, 4);
    sha256d(out, scratch, blen);
    return 1;
}

int cons_verify(const u8 *block, u64 len, u8 *txids_out, u64 cap)
{
    if (len < 82) return 0;
    if (pow_check(block) != 1) return 0;

    /* varint tx count at block[80] */
    const u8 *cnt = block + 80;
    u64 expect, idx;
    if (*cnt < 0xfd) {
        expect = *cnt;
        idx = 81;
    } else if (*cnt == 0xfd) {
        if ((u64)(cnt + 3 - block) > len) return 0;
        u16_t v16;
        memcpy(&v16, cnt + 1, 2);
        expect = v16;
        idx = 83;
    } else if (*cnt == 0xfe) {
        if ((u64)(cnt + 5 - block) > len) return 0;
        u32 v;
        memcpy(&v, cnt + 1, 4);
        expect = v;
        idx = 85;
    } else {
        if ((u64)(cnt + 9 - block) > len) return 0;
        memcpy(&expect, cnt + 1, 8);
        idx = 89;
    }
    if (expect == 0) return 0;              /* >= 1 tx (coinbase) */

    u64 off = idx;
    u32 count = 0;
    u8 scratch[1 << 20];

    while (len > off) {
        u64 remain = len - off;
        u64 info[8];
        memset(info, 0, sizeof info);
        if (tx_parse(info, block + off, remain) == 0) return 0;
        u64 txlen = info[0];
        if (txlen == 0) return 0;
        if (off + txlen > len) return 0;

        u32 nin;
        memcpy(&nin, (u8 *)info + 12, 4);   /* parsed info.n_in @+12 */
        if (count == 0 && nin != 1) return 0;   /* coinbase: one input */

        if ((u64)count >= cap) return 0;
        u8 txid[32];
        if (txid_of_span(block + off, txlen, txid, scratch, sizeof scratch) == 0)
            return 0;
        memcpy(txids_out + (u64)count * 32, txid, 32);
        count++;
        off += txlen;
    }
    if (off != len) return 0;
    if (count == 0) return 0;
    if ((u64)count != expect) return 0;

    u8 root[32];
    long mutated = merkle_root(root, txids_out, count);
    if (memcmp(root, block + 36, 32) != 0) return 0;
    if (mutated != 0) return 0;             /* Core bad-txns-duplicate */

    return 1;
}
