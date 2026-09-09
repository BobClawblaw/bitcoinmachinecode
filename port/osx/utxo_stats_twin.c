/* ============================================================================
 * utxo_stats_twin.c -- UTXO-set statistics layer for the macOS/AArch64 port.
 * Functional twin of asm/bitcoin_utxo_stats.asm (branch bmc_osx).
 *
 * struct layout (offsets MUST match the x86 -- tests poke them directly):
 *   0 TXOUTS, 8 AMOUNT, 16 BOGOSIZE, 24 UNSP_N, 32 UNSP_AMT, 40 RAW_N,
 *   48 ZEROH, 56 WANT_MUHASH, 64 EXCL_GENESIS, 72 GENESIS_N,
 *   96 ACC (num3072, 384 B), 480 MUHASH (32 B), 512 GENESIS_KEY? (rodata)
 * -------------------------------------------------------------------------- */
#include <stdint.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef unsigned char u8;

#define ST_TXOUTS        0
#define ST_AMOUNT        8
#define ST_BOGOSIZE      16
#define ST_UNSP_N        24
#define ST_UNSP_AMT      32
#define ST_RAW_N         40
#define ST_ZEROH         48
#define ST_WANT_MUHASH   56
#define ST_EXCL_GENESIS  64
#define ST_GENESIS_N     72
#define ST_ACC           96
#define ST_MUHASH        480
#define MAX_SCRIPT_SIZE  10000
#define OP_RETURN        0x6a

extern void muhash_insert(u64 acc[48], const void *data, unsigned long len);

int utxo_script_unspendable(const u8 *script, unsigned long slen)
{
    if (slen > MAX_SCRIPT_SIZE) return 1;
    if (slen == 0) return 0;
    if (script[0] == OP_RETURN) return 1;
    return 0;
}

/* mainnet genesis coinbase outpoint, WIRE byte order (reversed display
 * form), read out of the oracle and reversed -- never recalled. */
static const u8 genesis_coinbase_key[36] = {
    0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
    0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a,
    0x00,0x00,0x00,0x00
};

void utxo_stats_init(u8 st[512], u64 want_muhash, u64 excl_genesis)
{
    memset(st, 0, 512);
    *(u64 *)(st + ST_WANT_MUHASH) = want_muhash;
    *(u64 *)(st + ST_EXCL_GENESIS) = excl_genesis;
}

void utxo_stats_add(u8 st[512], const u8 key36[36], u64 value,
                    u64 code, const u8 *script, unsigned long slen)
{
    (*(u64 *)(st + ST_RAW_N))++;
    if (code < 2) (*(u64 *)(st + ST_ZEROH))++;

    if (*(u64 *)(st + ST_EXCL_GENESIS) &&
        memcmp(key36, genesis_coinbase_key, 36) == 0) {
        (*(u64 *)(st + ST_GENESIS_N))++;
        return;
    }
    if (utxo_script_unspendable(script, slen)) {
        (*(u64 *)(st + ST_UNSP_N))++;
        (*(u64 *)(st + ST_UNSP_AMT)) += value;
        return;
    }
    (*(u64 *)(st + ST_TXOUTS))++;
    (*(u64 *)(st + ST_AMOUNT)) += value;
    (*(u64 *)(st + ST_BOGOSIZE)) += slen + 50;
    if (*(u64 *)(st + ST_WANT_MUHASH) == 0) return;

    /* serialize: key36(32+4) || code32 || value64 || varint(slen) || script */
    u8 buf[32 + 4 + 4 + 8 + 3 + MAX_SCRIPT_SIZE];
    u8 *p = buf;
    memcpy(p, key36, 32); p += 32;          /* txid (wire order) */
    memcpy(p, key36 + 32, 4); p += 4;       /* vout LE u32 */
    u32 code32 = (u32)code;
    memcpy(p, &code32, 4); p += 4;          /* (height<<1)|coinbase */
    memcpy(p, &value, 8); p += 8;           /* amount LE u64 */
    if (slen < 0xfd) {
        *p++ = (unsigned char)slen;
    } else {
        unsigned short v16 = (unsigned short)slen;
        *p++ = 0xfd;
        memcpy(p, &v16, 2);
        p += 2;
    }
    memcpy(p, script, slen); p += slen;
    muhash_insert((u64 *)(st + ST_ACC), buf, (unsigned long)(p - buf));
}

void utxo_stats_finalize(u8 st[512])
{
    if (*(u64 *)(st + ST_WANT_MUHASH) == 0) return;
    extern void muhash_finalize(u8 out[32], const u64 acc[48]);
    muhash_finalize(st + ST_MUHASH, (u64 *)(st + ST_ACC));
}
