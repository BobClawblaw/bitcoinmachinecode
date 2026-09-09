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
typedef unsigned char u8;

extern long tx_parse(u64 info[8], const void *tx, u64 txlen);
extern long tx_txid(u8 out[32], const void *tx, u64 txlen, void *buf, u64 buflen);
extern long merkle_root(u8 root[32], const u8 *txids, unsigned long n);
extern long pow_check(const u8 header[80]);

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
        if (tx_txid(txid, block + off, txlen, scratch, sizeof scratch) == 0)
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
