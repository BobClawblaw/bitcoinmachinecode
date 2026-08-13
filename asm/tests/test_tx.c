/* test_tx.c -- 100% AI-generated harness validating the assembly bitcoin_tx.asm
 * transaction parser + the node hashing primitives (sha256d / merkle_root from
 * bitcoin_hash.asm) against the serialized genesis coinbase transaction.
 *
 * Expected values are derived from the Python oracle (validation/genesis_oracle.py
 * and tx_offsets probe), never hand-typed from memory.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8;
typedef unsigned long u64;
typedef unsigned int  u32;

/* bitcoin_tx.asm */
extern int tx_parse(u64 info[8], const void *tx, unsigned long txlen);
/* bitcoin_hash.asm */
extern void sha256d(u8 out[32], const void *msg, long len);
extern void merkle_root(u8 out[32], u8 hashes[], unsigned long n);

typedef struct {
    u64 tx_len;
    u32 version, n_in, n_out, locktime;
    u64 in0_script, in0_script_len;
    u64 out0_value, out0_script, out0_script_len;
} txinfo;

static int failures = 0;
static void cki(const char *lbl, long got, long exp){
    if (got==exp) printf("PASS %s\n", lbl);
    else { printf("FAIL %s got=%ld exp=%ld\n", lbl, got, exp); failures++; }
}
static void ckb(const char *lbl, const u8* got, const u8* exp){
    if (!memcmp(got,exp,32)) printf("PASS %s\n", lbl);
    else { printf("FAIL %s\n  got ", lbl); for(int i=0;i<32;i++)printf("%02x",got[i]);
           printf("\n  exp "); for(int i=0;i<32;i++)printf("%02x",exp[i]); printf("\n"); failures++; }
}

int main(void){
    /* serialized genesis coinbase transaction (from oracle) */
    const u8 tx[204] = {
        0x01,0x00,0x00,0x00, 0x01,
        /* input[0]: prevout(32B null) index(ffffffff) scriptlen(4d=77) script seq */
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0xff,0xff,0xff,0xff, 0x4d,
        /* scriptSig (77 bytes) */
        0x04,0xff,0xff,0x00,0x1d,0x01,0x04,0x45,0x54,0x68,0x65,0x20,0x54,0x69,0x6d,0x65,
        0x73,0x20,0x30,0x33,0x2f,0x4a,0x61,0x6e,0x2f,0x32,0x30,0x30,0x39,0x20,0x43,0x68,
        0x61,0x6e,0x63,0x65,0x6c,0x6c,0x6f,0x72,0x20,0x6f,0x6e,0x20,0x62,0x72,0x69,0x6e,
        0x6b,0x20,0x6f,0x66,0x20,0x73,0x65,0x63,0x6f,0x6e,0x64,0x20,0x62,0x61,0x69,0x6c,
        0x6f,0x75,0x74,0x20,0x66,0x6f,0x72,0x20,0x62,0x61,0x6e,0x6b,0x73,
        0xff,0xff,0xff,0xff,
        /* n_out = 1 */
        0x01,
        /* output[0]: value(8) scriptlen(43=67) script */
        0x00,0xf2,0x05,0x2a,0x01,0x00,0x00,0x00, 0x43,
        0x41,0x04,0x67,0x8a,0xfd,0xb0,0xfe,0x55,0x48,0x27,0x19,0x67,0xf1,0xa6,0x71,0x30,
        0xb7,0x10,0x5c,0xd6,0xa8,0x28,0xe0,0x39,0x09,0xa6,0x79,0x62,0xe0,0xea,0x1f,0x61,
        0xde,0xb6,0x49,0xf6,0xbc,0x3f,0x4c,0xef,0x38,0xc4,0xf3,0x55,0x04,0xe5,0x1e,0xc1,
        0x12,0xde,0x5c,0x38,0x4d,0xf7,0xba,0x0b,0x8d,0x57,0x8a,0x4c,0x70,0x2b,0x6b,0xf1,
        0x1d,0x5f,0xac,
        /* locktime = 0 */
        0x00,0x00,0x00,0x00
    };

    /* reference txid = sha256d(tx), internal/LE byte order (== genesis merkle root) */
    const u8 exp_txid[32] = {
        0x3b,0xa3,0xed,0xfd,0x7a,0x7b,0x12,0xb2,0x7a,0xc7,0x2c,0x3e,0x67,0x76,0x8f,0x61,
        0x7f,0xc8,0x1b,0xc3,0x88,0x8a,0x51,0x32,0x3a,0x9f,0xb8,0xaa,0x4b,0x1e,0x5e,0x4a};

    txinfo ti;
    memset(&ti, 0xAA, sizeof(ti));
    int ok = tx_parse((u64*)&ti, tx, sizeof(tx));
    cki("tx_parse returns 1", ok, 1);
    cki("tx_len", (long)ti.tx_len, 204);
    cki("version", ti.version, 1);
    cki("n_in", ti.n_in, 1);
    cki("n_out", ti.n_out, 1);
    cki("locktime", ti.locktime, 0);
    cki("in0_script offset", (long)ti.in0_script, 42);
    cki("in0_script_len", (long)ti.in0_script_len, 77);
    cki("out0_value offset", (long)ti.out0_value, 124);
    cki("out0_script offset", (long)ti.out0_script, 133);
    cki("out0_script_len", (long)ti.out0_script_len, 67);
    cki("out0_value bytes", (ti.out0_value<sizeof(tx))?*(const u64*)(tx+ti.out0_value):0, 5000000000ULL);

    /* txid = sha256d(tx) must equal genesis merkle root (internal order) */
    u8 d[32];
    sha256d(d, tx, sizeof(tx));
    ckb("txid == sha256d(tx)==merkle-root", d, exp_txid);

    /* merkle_root over a single txid is that txid (no dup-hash for 1 leaf) */
    u8 buf[32], root[32];
    memcpy(buf, d, 32);
    merkle_root(root, buf, 1);
    ckb("merkle(1tx)==txid", root, exp_txid);

    /* tx_parse must reject truncations */
    u8 trunc[32];
    memcpy(trunc, tx, 32);
    cki("tx_parse rejects truncated (32B)", tx_parse((u64*)&ti, trunc, sizeof(trunc)), 0);

    /* a 2-byte varint (0xfd) input-count path: build n_in=0xfd-style can't be a
     * valid tx (0xfd inputs impossible), so instead exercise via scriptlen using
     * a synthetic single-input tx where scriptlen uses 0xfd prefix. We only need
     * to prove the decoder handles 0xfd; craft minimal: version, n_in=1,
     * prevout32, index, scriptlen varint 0xfd 08 00 (len 0x0008=8), 8B script,
     * seq, n_out=0, locktime. Build in a buffer. */
    u8 mini[100];
    size_t m = 0;
    u32 one=1;                  memcpy(mini+m,&one,4); m+=4;
    mini[m++]=1;                /* n_in=1 */
    memset(mini+m,0x11,32);     m+=32;  /* prevout */
    u32 fidx=0xffffffff;        memcpy(mini+m,&fidx,4); m+=4;
    mini[m++]=0xfd; mini[m++]=0x08; mini[m++]=0x00;  /* scriptlen 0xfd 08 00 */
    memset(mini+m,0x22,8);      m+=8;   /* script */
    u32 seq=0xffffffff;         memcpy(mini+m,&seq,4); m+=4;
    mini[m++]=0;                /* n_out=0 */
    u32 lt=0;                   memcpy(mini+m,&lt,4); m+=4;
    ok = tx_parse((u64*)&ti, mini, m);
    cki("tx_parse 0xfd-varint scriptlen", ok, 1);
    cki("  scriptlen(0xfd path)", (long)ti.in0_script_len, 8);
    cki("  n_out==0", ti.n_out, 0);

    printf("\n%s (%d failures)\n", failures?"TESTS FAILED":"ALL TESTS PASSED", failures);
    return failures?1:0;
}
