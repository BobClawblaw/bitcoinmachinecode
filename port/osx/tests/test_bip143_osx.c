/* test_bip143_osx.c -- native gate for the BIP143 (segwit v0) sighash path on
 * the macOS port.  bitcoin_bip143 needs NO PORT: production links the
 * arch-neutral asm/bitcoin_segwit.c directly (the x86 asm module exists only
 * for the x86 differential harness).  This gate proves the Darwin-compiled C:
 *
 *   1. BIP-0143's published P2WPKH worked example: sighash == the digest
 *      printed in the BIP (c37af311...cb670).
 *   2. The real mainnet P2WPKH spend (validation/fixtures/
 *      p2wpkh_481824_562.json -- block 481824 tx 562, the first real P2WPKH
 *      spend; amount 194300 is the spent prevout value per
 *      validation/bip143_ref.py, which verifies this exact signature):
 *      segwit_v0_sighash -> native ECDSA verify of the witness signature
 *      against the witness pubkey MUST return 1.  A wrong sighash cannot
 *      verify; this ties the port to the chain.
 *   3. swtx_parse contract on the fixture: sign-extended version, nin/nout,
 *      and the exact in_off/out_off offset tables (in_off[i] = prevout
 *      offset; the nin/nout entries are the end sentinels).
 *
 * der_parse_sig/be_to_limbs live in the not-yet-ported bitcoin_script, so
 * the driver does the minimal DER parse and BE->limbs itself; the verify
 * itself goes through the ported ecdsa/pubkey twins.
 *
 * Cross-arch: validation/bip143_corpus_dump.c runs this same C on .242
 * (gcc/x86) and the x86 ASM twin over a generated corpus; the dumps are
 * byte-diffed (see worklog).  Expected fixture sighash:
 *   32f2913ca9ca1dfe273dacf102150551c5d74e4f0c34b431e9180da27793a9a6
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef unsigned char u8;
typedef long long i64;
typedef unsigned long long u64;

extern long swtx_parse_export(void* t, unsigned* off);
extern long segwit_v0_sighash(u8 out32[32], const u8* tx, i64 txlen, i64 n_in,
                              unsigned ht, u64 amount, const u8* scriptCode,
                              u64 sc_len, u8* pre, long cap);
extern int  pubkey_parse(const u8* pub, unsigned long plen, u64 qx[4], u64 qy[4]);
extern int  ecdsa_verify(const u64 z[4], const u64 r[4], const u64 s[4],
                         const u64 qx[4], const u64 qy[4]);

static int fails = 0;
static void ck(const char* name, int ok){
    printf("%s %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) fails++;
}
static void hx(const u8* d, int n){ for (int i=0;i<n;i++) printf("%02x", d[i]); }

static unsigned hexval(unsigned char c){
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}
static int unhex(const char* h, u8* out){
    int n = 0;
    while (h[0] && h[1]){ out[n++] = (u8)((hexval(h[0]) << 4) | hexval(h[1])); h += 2; }
    return n;
}

/* swtx_t layout pinned by the module header (offsets tx@0 txlen@8 end@16
 * version@24 locktime@32 nin@40 nout@48 inputs@56 in_off@64 out_off@72) */
typedef struct {
    const u8* tx; i64 txlen; const u8* end;
    i64 version; unsigned locktime;
    i64 nin, nout;
    const u8* inputs; const unsigned* in_off; const unsigned* out_off;
} swtx_t;

static void be_to_limbs(u64 z[4], const u8* b){
    for (int j = 0; j < 4; j++){
        u64 v = 0;
        for (int k = 0; k < 8; k++) v = (v << 8) | b[(3-j)*8 + k];
        z[j] = v;
    }
}
/* minimal DER sig parse: 0x30 len, two INTEGERs, optional 1-byte hashtype */
static int drv_der_parse(const u8* sig, unsigned long slen,
                         u64 r[4], u64 s[4], unsigned* ht){
    if (slen < 9 || sig[0] != 0x30 || sig[2] != 0x02) return 0;
    unsigned rl = sig[3], p = 4;
    if (rl == 0 || p + rl > slen) return 0;
    const u8* rb = sig + p; p += rl;
    if (p + 2 > slen || sig[p] != 0x02) return 0;
    unsigned sl = sig[p+1]; p += 2;
    if (sl == 0 || p + sl > slen) return 0;
    const u8* sb = sig + p; p += sl;
    *ht = 1;
    if (p < slen){ if (slen - p != 1) return 0; *ht = sig[p]; }
    while (rl > 1 && rb[0] == 0){ rb++; rl--; }   /* strip DER leading zeros */
    while (sl > 1 && sb[0] == 0){ sb++; sl--; }
    if (rl > 32 || sl > 32) return 0;
    u8 rbe[32] = {0}, sbe[32] = {0};
    memcpy(rbe + (32 - rl), rb, rl);
    memcpy(sbe + (32 - sl), sb, sl);
    be_to_limbs(r, rbe);
    be_to_limbs(s, sbe);
    return 1;
}

static u8 pre[1 << 16];

int main(void){
    /* ---------------- 1. BIP143 worked example ---------------- */
    static const char* EX_TX =
        "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541d"
        "b4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b"
        "1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb20600000000"
        "1976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d0000"
        "00001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
    /* BARE implied P2PKH scriptCode (25 B) -- segwit_v0_sighash prepends the
   compactsize itself (see bitcoin_segwit.c line ~527); the 26-byte
   1976a914...88ac form is the PYTHON oracle's convention, not this ABI */
    static const char* EX_SC = "76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac";
    u8 extx[512], exsc[64], exdig[32], out[32];
    int n = unhex(EX_TX, extx);
    int m = unhex(EX_SC, exsc);
    unhex("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670", exdig);

    long plen = segwit_v0_sighash(out, extx, n, 1, 1, 600000000, exsc, m,
                                  pre, sizeof pre);
    ck("BIP143 example: preimage built", plen > 0);
    int ok = plen > 0 && memcmp(out, exdig, 32) == 0;
    if (!ok){ printf("  got "); hx(out, 32); printf("\n  exp "); hx(exdig, 32); printf("\n"); }
    ck("BIP143 example: sighash == published digest", ok);

    /* ---------------- 2. real mainnet fixture (block 481824 tx 562) -------- */
    static const char* FIX_TX =
        "01000000000101ad2bb91208eef398def3ed3e784d9ee9b7befeb56a3053c356"
        "1849b88bc4cedf0000000000ffffffff037a3e0100000000001600148d7a0a34"
        "61e3891723e5fdf8129caa0075060cff7a3e0100000000001600148d7a0a3461"
        "e3891723e5fdf8129caa0075060cff0000000000000000256a2342697462616e"
        "6b20496e632e204a6170616e20737570706f7274732053656757697421024830"
        "45022100a6e33a7aff720ba9f33a0a8346a16fdd022196862796d511d31978c4"
        "0c9ad48b02206fb8f67bd699a8c952b3386a81d122c366d2d36cd08e2de21207"
        "e6aa6f96ce9501210283409659355b6d1cc3c32decd5d561abaac86c37a353b5"
        "2895a5e6c196d6f44800000000";
    static const char* FIX_SC =
        "76a9148d7a0a3461e3891723e5fdf8129caa0075060cff88ac";
    static const char* FIX_DIG =
        "32f2913ca9ca1dfe273dacf102150551c5d74e4f0c34b431e9180da27793a9a6";
    u8 ftx[512], fsc[64], fdig[32];
    int fl = unhex(FIX_TX, ftx);
    int fs = unhex(FIX_SC, fsc);
    unhex(FIX_DIG, fdig);

    plen = segwit_v0_sighash(out, ftx, fl, 0, 1, 194300, fsc, fs,
                             pre, sizeof pre);
    ck("fixture: preimage length == 182", plen == 182);
    ok = plen == 182 && memcmp(out, fdig, 32) == 0;
    if (!ok){ printf("  got "); hx(out, 32); printf("\n  exp "); hx(fdig, 32); printf("\n"); }
    ck("fixture: sighash == bip143_ref.py value", ok);

    /* native ECDSA verify of the actual witness signature (witness starts at
     * out_off[3] == 157: 02 items, 72-byte sig, 33-byte pubkey) */
    u64 r[4], s[4], qx[4], qy[4], z[4];
    unsigned ht = 0;
    const u8* wit = ftx + 157;
    const u8* sig = wit + 2;                 /* nitems=02 */
    u8 pub[33];
    memcpy(pub, ftx + 157 + 2 + 72 + 1, 33);
    ck("fixture: DER sig parses", drv_der_parse(sig, 72, r, s, &ht) == 1);
    ck("fixture: hashtype SIGHASH_ALL", ht == 1);
    ck("fixture: pubkey parses", pubkey_parse(pub, 33, qx, qy) == 1);
    be_to_limbs(z, out);
    int vr = ecdsa_verify(z, r, s, qx, qy);
    if (!vr){ printf("  sighash "); hx(out, 32); printf("\n"); }
    ck("fixture: witness signature verifies under the sighash", vr == 1);

    /* ---------------- 3. swtx_parse contract on the fixture ---------------- */
    static unsigned off[1200000/4];
    swtx_t t; memset(&t, 0, sizeof t);
    t.tx = ftx; t.txlen = fl;
    long pr = swtx_parse_export(&t, off);
    ck("swtx_parse(fixture) ok", pr == 1);
    if (pr == 1){
        ck("  version sign-extended int64 == 1", t.version == 1);
        ck("  locktime == 0", t.locktime == 0);
        ck("  nin==1 nout==3", t.nin == 1 && t.nout == 3);
        ck("  txlen == 269", (u64)t.txlen == 269);
        ck("  end == tx + txlen", t.end == t.tx + t.txlen);
        ck("  in_off = {7, 48}", off[0] == 7 && off[1] == 48);
        ck("  out_off = {49, 80, 111, 157}",
           off[2] == 49 && off[3] == 80 && off[4] == 111 && off[5] == 157);
    }

    printf(fails ? "FAILURES %d\n" : "ALL TESTS PASSED (0 failures)\n", fails);
    return fails ? 1 : 0;
}
