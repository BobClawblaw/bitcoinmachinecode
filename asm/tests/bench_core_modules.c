/* bench_core_modules.c -- one harness, a section per Bitcoin Core benchmark
 * that the suite in scripts/bench_vs_core.sh did not pair before 2026-09-27.
 * Every section mirrors the SHAPE of the Core benchmark it names (the same
 * work per iteration, the same sizes), so the two numbers compare directly;
 * where the work is not the same, the line says so and BENCHMARKS.md repeats
 * it. Measurement: thread CPU time, min of ROUNDS rounds (interference can
 * only add time), one pinned core when run through the script.
 *
 * Output: one `RESULT <ours> <core-benchmark> <ns per op> <unit> [note]` line
 * per pair, greppable by the runner, plus a human line before it.
 *
 *   VerifyScriptP2WPKH          p2wpkh_verify on a real mainnet spend (481824:562)
 *   VerifyScriptP2TR_KeyPath    taproot_keypath_verify on a key-path spend signed
 *                               in setup with private key 1 (as Core's bench does)
 *   VerifyScriptP2TR_ScriptPath taproot_verify_input on a tapscript leaf spend
 *                               (2-leaf tree, checksig leaf; Core's is 1 leaf)
 *   BlockEncodingNoExtra        cmpct_recv over a 3,000-short-id compact block
 *                               against a 50,000-tx pool that holds none of them
 *   GCSFilterConstruct          bf_basic_build on block 482,566 (ns/element from
 *                               the filter's own N; Core: 100,000 synthetic elements)
 *   GCSBlockFilterGetHash       bf_header over that filter (ns/byte)
 *   ReadRawBlockBench/WriteBlockBench  store_read_at / store_append of block 413,567
 *   MuHash / MuHashMul / MuHashPrecompute / MuHashFinalize
 *   CHACHA20_*, POLY1305_*, FSCHACHA20POLY1305_* (64 B, 256 B, 1 MB)
 *   EllSwiftCreate, BIP324_ECDH
 *   Bech32Encode, Bech32Decode, Base58CheckEncode
 *
 * argv[1] = block413567.raw (Core's bench fixture); argv[2] = rounds (default 15). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "crypto_chacha20.h"
#include "crypto_poly1305.h"
#include "crypto_bip324.h"
#include "crypto_ellswift.h"
#include "block_filter.h"
#include "../daemon/muhash_p2.inc.h"

typedef unsigned char u8; typedef uint64_t u64;

/* ---- entry points ------------------------------------------------------ */
extern int  p2wpkh_verify(const uint8_t* tx, int64_t txlen, int64_t n_in,
                          const uint8_t* prev_spk, int64_t prev_spklen, uint64_t amount,
                          const uint8_t* vchSig, uint64_t siglen,
                          const uint8_t* vchPub, uint64_t publen);
typedef struct {
    const uint8_t* tx;   int64_t txlen;
    int64_t  n_in;
    uint8_t  hash_type;
    const uint8_t* prevouts;
    const uint8_t* amounts;
    const uint8_t* spks;
    int64_t  num_inputs;
    int      ext_flag;
    const uint8_t* tapleaf;
    uint32_t codesep_pos;
    const uint8_t* annex;
    uint64_t annexlen;
} tapctx_t;
extern long taproot_sighash(uint8_t* out32, const tapctx_t* c, uint8_t* pre, long cap);
extern int  taproot_keypath_verify(const uint8_t* spk, const uint8_t* sig, int siglen,
                                   const uint8_t* tx, int64_t txlen, int64_t n_in,
                                   const uint8_t* prevouts, const uint8_t* amounts,
                                   const uint8_t* spks, int64_t num_inputs);
extern int  taproot_verify_input(const uint8_t* spk,
                                 const uint8_t* const* wit, const uint32_t* witlen, uint32_t nwit,
                                 const uint8_t* tx, int64_t txlen, int64_t n_in,
                                 const uint8_t* prevouts, const uint8_t* amounts,
                                 const uint8_t* spks, int64_t num_inputs,
                                 const char** reason);
extern int  bip340_pubkey(u8 xonly[32], const u8 priv_be[32]);
extern int  bip340_sign(u8 sig[64], const u8* msg, unsigned long msglen, const u8 priv_be[32], const u8 aux[32]);
extern long cmpctblock_build(unsigned char* out, const unsigned char* blockbuf, unsigned long blen, unsigned long long nonce);
extern long cmpct_recv_cmpctblock(int fd, void* mp, const unsigned char* pl, unsigned long plen,
                                  unsigned char* out, unsigned long cap, const unsigned char blockhash[32]);
extern unsigned long mpool_struct_size(unsigned long slots);
extern void mpool_init(void* mp, unsigned long slots, void* blob, unsigned long blob_cap);
extern long mpool_put(void* mp, const unsigned char txid[32], const unsigned char* tx, unsigned long txlen);
extern void sha256d(u8 out[32], const void* msg, int64_t len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  store_init(void* st);
extern int  store_append(void* st, const void* hash, const void* raw, unsigned long long len);
extern void store_rd_init(void* st);
extern long store_read_at(void* st, unsigned long height, void* buf, unsigned long cap);
extern void muhash_init(void* acc);
extern void muhash_insert(void* acc, const void* data, unsigned long len);
extern void muhash_finalize(unsigned char out[32], const void* acc);
extern void num3072_mul(void* a, const void* b);
extern void num3072_set_one(void* a);
extern void      bech32_init(void);
extern long long bech32_encode(char* out, const char* hrp, long long hrplen, const unsigned char* data5, long long datalen, long long spec);
extern long long bech32_decode(unsigned char* out5, char* out_hrp, long long hrp_cap, const char* s);
extern long long bech32_verify_checksum(const char* hrp, long long hrplen, const unsigned char* data5, long long datalen, long long spec);
extern long long bech32_convert_bits(unsigned char* out, const unsigned char* in, long long inlen, long long frombits, long long tobits, long long pad);
extern void base58check_encode(char* out, const unsigned char* payload, long long paylen);

#include "taproot_scriptpath_vec.h"

/* ---- measurement -------------------------------------------------------- */
static int ROUNDS = 15;
static double cpu_s(void){ struct timespec t; clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t); return t.tv_sec + t.tv_nsec*1e-9; }
/* min-of-ROUNDS of (one round = iters calls); returns ns per call */
#define MEASURE(iters, body) ({ double best = 1e30; for (int r_ = 0; r_ < ROUNDS; r_++){ double t0_ = cpu_s(); for (long i_ = 0; i_ < (iters); i_++){ body; } double t_ = cpu_s() - t0_; if (t_ < best) best = t_; } best / (double)(iters) * 1e9; })
static void result(const char* ours, const char* core, double ns, const char* unit, const char* note){
    printf("  %-30s %12.2f %s%s%s\n", ours, ns, unit, note ? "   " : "", note ? note : "");
    char key[96]; size_t k = 0;                                   /* the RESULT line's name carries no spaces */
    for (const char* p = ours; *p && k + 1 < sizeof key; p++) key[k++] = (*p == ' ') ? '_' : *p;
    key[k] = 0;
    printf("RESULT %s %s %.4f %s\n", key, core, ns, unit);
}
static int hexval(char c){ return c>='0'&&c<='9' ? c-'0' : c>='a'&&c<='f' ? c-'a'+10 : c>='A'&&c<='F' ? c-'A'+10 : -1; }
static long unhex(u8* out, const char* h){ long n = 0; while (h[0] && h[1]){ int a = hexval(h[0]), b = hexval(h[1]); if (a<0||b<0) return -1; out[n++] = (u8)(a*16+b); h += 2; } return n; }
static u64 rs = 0x9E3779B97F4A7C15ULL; static u64 rnd(void){ rs^=rs<<13; rs^=rs>>7; rs^=rs<<17; return rs; }
static void put32(u8* p, uint32_t v){ p[0]=v; p[1]=v>>8; p[2]=v>>16; p[3]=v>>24; }
static void put64(u8* p, u64 v){ for (int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }
static long read_file(const char* path, u8** out){ FILE* f = fopen(path,"rb"); if(!f) return -1; fseek(f,0,SEEK_END); long n = ftell(f); fseek(f,0,SEEK_SET); *out = malloc((size_t)n); if (fread(*out,1,(size_t)n,f) != (size_t)n){ fclose(f); return -1; } fclose(f); return n; }

/* ---- 1. VerifyScript ---------------------------------------------------- */
/* the real 481824:562 P2WPKH spend tests/test_p2wpkh_real.c pins */
static const char* WPKH_TX = "01000000000101ad2bb91208eef398def3ed3e784d9ee9b7befeb56a3053c3561849b88bc4cedf0000000000ffffffff037a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa0075060cff7a3e0100000000001600148d7a0a3461e3891723e5fdf8129caa0075060cff0000000000000000256a2342697462616e6b20496e632e204a6170616e20737570706f727473205365675769742102483045022100a6e33a7aff720ba9f33a0a8346a16fdd022196862796d511d31978c40c9ad48b02206fb8f67bd699a8c952b3386a81d122c366d2d36cd08e2de21207e6aa6f96ce9501210283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f44800000000";
static const char* WPKH_SPK = "00148d7a0a3461e3891723e5fdf8129caa0075060cff";
static const char* WPKH_SIG = "3045022100a6e33a7aff720ba9f33a0a8346a16fdd022196862796d511d31978c40c9ad48b02206fb8f67bd699a8c952b3386a81d122c366d2d36cd08e2de21207e6aa6f96ce9501";
static const char* WPKH_PUB = "0283409659355b6d1cc3c32decd5d561abaac86c37a353b52895a5e6c196d6f448";
static const uint64_t WPKH_AMOUNT = 194300;

static void bench_verify_script(void){
    printf("== VerifyScript (Core src/bench/verify_script.cpp): one input verified per op ==\n");
    static u8 tx[512], spk[64], sig[80], pub[40];
    long txl = unhex(tx, WPKH_TX), spkl = unhex(spk, WPKH_SPK), sigl = unhex(sig, WPKH_SIG), publ = unhex(pub, WPKH_PUB);
    if (txl < 0 || p2wpkh_verify(tx, txl, 0, spk, spkl, WPKH_AMOUNT, sig, (u64)sigl, pub, (u64)publ) != 1){ printf("FAIL: the P2WPKH fixture does not verify\n"); exit(1); }
    double ns = MEASURE(2000, p2wpkh_verify(tx, txl, 0, spk, spkl, WPKH_AMOUNT, sig, (u64)sigl, pub, (u64)publ));
    result("p2wpkh_verify", "VerifyScriptP2WPKH", ns, "ns/op", "(BIP143 sighash + ECDSA, a real mainnet input; Core precomputes its sighash midstates)");

    /* key path: private key 1, an x-only output key WITHOUT a tweak -- the
     * verifier checks the BIP340 signature against the 32 bytes in the
     * scriptPubKey either way, so the work per op is Core's */
    u8 priv[32] = {0}; priv[31] = 1; u8 xonly[32];
    if (!bip340_pubkey(xonly, priv)){ printf("FAIL: bip340_pubkey\n"); exit(1); }
    static u8 ktx[256]; u8* q = ktx;
    put32(q, 2); q += 4; *q++ = 1; memset(q, 0x11, 32); q += 32; put32(q, 0); q += 4; *q++ = 0; put32(q, 0xffffffffu); q += 4;
    *q++ = 1; put64(q, 1); q += 8; *q++ = 34; *q++ = 0x51; *q++ = 0x20; memcpy(q, xonly, 32); q += 32; put32(q, 0); q += 4;
    long ktxl = q - ktx;
    u8 prevouts[36]; memset(prevouts, 0x11, 32); put32(prevouts + 32, 0);
    u8 amounts[8]; put64(amounts, 100000);
    u8 spks[35]; spks[0] = 34; spks[1] = 0x51; spks[2] = 0x20; memcpy(spks + 3, xonly, 32);
    tapctx_t c = { ktx, ktxl, 0, 0, prevouts, amounts, spks, 1, 0, NULL, 0xffffffffu, NULL, 0 };
    u8 h[32], pre[512], ksig[64], aux[32] = {0};
    if (taproot_sighash(h, &c, pre, sizeof pre) <= 0 || !bip340_sign(ksig, h, 32, priv, aux)){ printf("FAIL: key-path setup\n"); exit(1); }
    if (taproot_keypath_verify(spks + 1, ksig, 64, ktx, ktxl, 0, prevouts, amounts, spks, 1) != 1){ printf("FAIL: the key-path spend signed in setup does not verify\n"); exit(1); }
    ns = MEASURE(2000, taproot_keypath_verify(spks + 1, ksig, 64, ktx, ktxl, 0, prevouts, amounts, spks, 1));
    result("taproot_keypath_verify", "VerifyScriptP2TR_KeyPath", ns, "ns/op", "(BIP341 sighash + BIP340 verify; Core precomputes its sighash midstates)");

    const sp_vec_t* v = &sp_vectors[0]; const char* reason = 0;
    if (taproot_verify_input(v->spk, v->wit, v->witlen, v->nwit, v->tx, v->txlen, 0, v->prevouts, v->amounts, v->spks, v->numin, &reason) != 1){ printf("FAIL: the script-path vector does not verify (%s)\n", reason ? reason : "?"); exit(1); }
    ns = MEASURE(2000, taproot_verify_input(v->spk, v->wit, v->witlen, v->nwit, v->tx, v->txlen, 0, v->prevouts, v->amounts, v->spks, v->numin, &reason));
    result("taproot_verify_input(script)", "VerifyScriptP2TR_ScriptPath", ns, "ns/op", "(control block of a 2-leaf tree + a checksig leaf; Core: a 1-leaf tree)");
}

/* ---- 2. BlockEncoding --------------------------------------------------- */
/* one tx of Core's bench shape: 1 input with a 200-byte scriptSig push, 1
 * output OP_1 OP_EQUAL with value = i (the prevout txid carries i too) */
static long mk_tx(u8* out, u64 i){
    u8* q = out; put32(q, 2); q += 4; *q++ = 1; memset(q, 0, 32); put64(q, i); q += 32; put32(q, 0); q += 4;
    *q++ = 0xca; *q++ = 0x4c; *q++ = 200; memset(q, 42, 200); q += 200;      /* 202-byte scriptSig: PUSHDATA1 200 */
    put32(q, 0xffffffffu); q += 4; *q++ = 1; put64(q, i); q += 8; *q++ = 2; *q++ = 0x51; *q++ = 0x87; put32(q, 0); q += 4;
    return q - out;
}
static void bench_block_encoding(void){
    printf("== BlockEncodingNoExtra (Core src/bench/blockencodings.cpp): a 3,000-short-id compact block against a 50,000-tx pool that holds none ==\n");
    enum { NPOOL = 50000, NBLK = 3000 };
    unsigned long blob_cap = 16u << 20; u8* blob = malloc(blob_cap);
    void* mp = calloc(1, mpool_struct_size(65536)); mpool_init(mp, 65536, blob, blob_cap);
    static u8 txb[300]; u8 id[32];
    for (u64 i = 0; i < NPOOL; i++){ long l = mk_tx(txb, 1000000 + i); sha256d(id, txb, l); if (mpool_put(mp, id, txb, (unsigned long)l) < 0){ printf("FAIL: mpool_put at %llu\n", (unsigned long long)i); exit(1); } }
    unsigned long bcap = 90 + NBLK * 300; u8* blk = malloc(bcap); memset(blk, 0x33, 80); blk[80] = 0xfd; blk[81] = NBLK & 0xff; blk[82] = NBLK >> 8;
    unsigned long bo = 83; for (u64 i = 0; i < NBLK; i++) bo += (unsigned long)mk_tx(blk + bo, i);
    u8 bh[32]; block_hash(bh, blk);
    u8* cb = malloc(bo + 64); long cl = cmpctblock_build(cb, blk, bo, 0x1234ULL);
    if (cl <= 0){ printf("FAIL: cmpctblock_build\n"); exit(1); }
    int fd = open("/dev/null", O_WRONLY); u8* out = malloc(bo + 64);
    long n = cmpct_recv_cmpctblock(fd, mp, cb, (unsigned long)cl, out, bo + 64, bh);
    if (n != 0){ printf("FAIL: expected no reconstruction (nothing in the pool), got %ld\n", n); exit(1); }
    double ns = MEASURE(20, cmpct_recv_cmpctblock(fd, mp, cb, (unsigned long)cl, out, bo + 64, bh));
    result("cmpct_recv_cmpctblock(50k pool, 3k ids)", "BlockEncodingNoExtra", ns, "ns/op", "(short ids of every pool tx computed and matched; the getblocktxn goes to /dev/null)");
    close(fd); free(blob); free(mp); free(blk); free(cb); free(out);
}

/* ---- 3. GCS filter ------------------------------------------------------ */
static long read_cs(const u8* p, u64* v){ if (p[0] < 0xfd){ *v = p[0]; return 1; } if (p[0] == 0xfd){ *v = p[1] | (p[2] << 8); return 3; } if (p[0] == 0xfe){ *v = p[1] | (p[2]<<8) | ((u64)p[3]<<16) | ((u64)p[4]<<24); return 5; } *v = 0; for (int i=0;i<8;i++) *v |= (u64)p[1+i] << (8*i); return 9; }
static void bench_gcs(void){
    printf("== GCS filter (Core src/bench/gcs_filter.cpp): construct, and hash the encoded filter ==\n");
    u8* blk; long bl = read_file("tests/fixtures/blk_482566.bin", &blk);
    FILE* pf = fopen("tests/fixtures/blk_482566.prevouts", "r");
    if (bl < 0 || !pf){ printf("SKIP: tests/fixtures/blk_482566.{bin,prevouts} absent\n"); return; }
    static bf_script prev[8000]; static u8 prevbuf[8000 * 40]; unsigned long np = 0, po = 0; char line[1024];
    while (fgets(line, sizeof line, pf) && np < 8000){ char a[80], hx[600]; unsigned vout; unsigned long long val; if (sscanf(line, "%79s %u %llu %599s", a, &vout, &val, hx) != 4) continue; long l = unhex(prevbuf + po, hx); if (l < 0 || po + (unsigned long)l > sizeof prevbuf) break; prev[np].script = prevbuf + po; prev[np].len = (unsigned long)l; np++; po += (unsigned long)l; }
    fclose(pf);
    u8 hash[32]; block_hash(hash, blk);
    static u8 filt[1 << 20]; long fl = bf_basic_build(blk, (unsigned long)bl, hash, prev, np, filt, sizeof filt);
    if (fl <= 0){ printf("FAIL: bf_basic_build\n"); exit(1); }
    u64 nel; read_cs(filt, &nel);
    double ns = MEASURE(5, bf_basic_build(blk, (unsigned long)bl, hash, prev, np, filt, sizeof filt));
    printf("  block 482,566: %lu prevout scripts, filter %ld bytes, N = %llu elements: %.1f us per filter, %.1f ns per element (a real block: parse, extract, dedup, build)\n",
           np, fl, (unsigned long long)nel, ns / 1e3, ns / (double)nel);
    free(blk);
    /* Core's shape exactly: 100,000 unique 32-byte elements. Ours takes a block,
     * so the block is one transaction with 100,000 outputs whose 32-byte
     * scripts are the elements (OP_1 then 31 bytes carrying i; no OP_RETURN,
     * which BIP158 excludes). No spent prevouts. */
    enum { NE = 100000 };
    unsigned long sbl = 80 + 1 + 4 + 1 + 36 + 1 + 4 + 5 + (unsigned long)NE * 41 + 4 + 16; u8* sb = calloc(1, sbl); u8* q = sb;
    memset(q, 0x44, 80); q += 80; *q++ = 1;                       /* header, ntx = 1 */
    put32(q, 1); q += 4; *q++ = 1; memset(q, 0, 32); q += 32; put32(q, 0xffffffffu); q += 4; *q++ = 0; put32(q, 0xffffffffu); q += 4;
    *q++ = 0xfe; put32(q, NE); q += 4;                             /* nout = 100,000 */
    for (uint32_t i = 0; i < NE; i++){ put64(q, 1); q += 8; *q++ = 32; q[0] = 0x51; memset(q + 1, 0, 31); put32(q + 1, i); q += 32; }
    put32(q, 0); q += 4; unsigned long sblen = (unsigned long)(q - sb);
    block_hash(hash, sb);
    long sfl = bf_basic_build(sb, sblen, hash, NULL, 0, filt, sizeof filt);
    if (sfl <= 0){ printf("FAIL: bf_basic_build over the 100,000-output block (%ld)\n", sfl); exit(1); }
    read_cs(filt, &nel);
    if (nel != NE){ printf("FAIL: the synthetic filter holds %llu elements, not %d\n", (unsigned long long)nel, NE); exit(1); }
    ns = MEASURE(3, bf_basic_build(sb, sblen, hash, NULL, 0, filt, sizeof filt));
    printf("  synthetic block: 100,000 outputs of 32-byte scripts -> filter %ld bytes, N = %llu\n", sfl, (unsigned long long)nel);
    result("bf_basic_build (100k elements)", "GCSFilterConstruct", ns, "ns/op", "(one filter over 100,000 unique 32-byte elements, as Core's; ours also parses the 4 MB block that carries them)");
    u8 prevh[32] = {0}, out[32];
    ns = MEASURE(50, bf_header(filt, (unsigned long)sfl, prevh, out));
    result("bf_header (100k-element filter)", "GCSBlockFilterGetHash", ns, "ns/op", "(sha256d of the encoded 100,000-element filter plus the header link)");
    free(sb);
}

/* ---- 4. block read / write -------------------------------------------- */
static void bench_store(const char* raw_path){
    printf("== block read/write (Core src/bench/readwriteblock.cpp): block 413,567 through the block store ==\n");
    u8* raw; long rl = read_file(raw_path, &raw);
    if (rl <= 0){ printf("SKIP: %s unreadable\n", raw_path); return; }
    char dir[] = "/tmp/bench_core_store_XXXXXX"; if (!mkdtemp(dir)){ printf("FAIL: mkdtemp\n"); exit(1); }
    char cwd[512]; if (!getcwd(cwd, sizeof cwd)) exit(1);
    if (chdir(dir)) exit(1);
    static u8 st[4096]; if (store_init(st) != 1){ printf("FAIL: store_init\n"); exit(1); } store_rd_init(st);
    u8 h[32]; block_hash(h, raw);
    if (store_append(st, h, raw, (u64)rl) < 0){ printf("FAIL: store_append\n"); exit(1); }
    u8* buf = malloc((size_t)rl + 64);
    long got = store_read_at(st, 0, buf, (unsigned long)rl + 64);
    if (got != rl || memcmp(buf, raw, (size_t)rl)){ printf("FAIL: store_read_at returned %ld\n", got); exit(1); }
    double ns = MEASURE(200, store_read_at(st, 0, buf, (unsigned long)rl + 64));
    result("store_read_at (block 413567)", "ReadRawBlockBench", ns, "ns/op", "(raw bytes back from the archive; Core's ReadBlockBench also deserialises and checks, 25x more)");
    int rounds_save = ROUNDS; ROUNDS = 3;
    ns = MEASURE(50, store_append(st, h, raw, (u64)rl));
    ROUNDS = rounds_save;
    result("store_append (block 413567)", "WriteBlockBench", ns, "ns/op", "(the same block appended again each op, as Core's WriteBlock does)");
    free(buf); free(raw);
    if (chdir(cwd)) exit(1);
    char cmd[600]; snprintf(cmd, sizeof cmd, "rm -rf '%s'", dir); if (system(cmd)) {}
}

/* ---- 5. MuHash ---------------------------------------------------------- */
static void num3072_inv(u8 out[384], const u8 in[384]){
    num3072_set_one(out);
    for (int byte = 383; byte >= 0; byte--) for (int bit = 7; bit >= 0; bit--){ num3072_mul(out, out); if ((MUHASH_P_MINUS_2[byte] >> bit) & 1) num3072_mul(out, in); }
}
static void bench_muhash(void){
    printf("== MuHash3072 (Core src/bench/crypto_hash.cpp): insert, multiply, precompute, finalize ==\n");
    static u64 acc[48], elem[48], inv[48], tmp[48]; u8 key[32] = {0}; uint32_t i = 0;
    muhash_init(acc);
    double ins = MEASURE(2000, key[0] = (u8)(++i); muhash_insert(acc, key, 32));
    result("muhash_insert", "MuHash", ins, "ns/op", "(SHA256 + ChaCha20 expansion + one 3072-bit modmul)");
    muhash_init(elem); memset(key, 0x5a, 32); muhash_insert(elem, key, 32);   /* one element, as a num3072 */
    double mul = MEASURE(5000, num3072_mul(acc, elem));
    result("num3072_mul", "MuHashMul", mul, "ns/op", NULL);
    result("muhash_insert - num3072_mul", "MuHashPrecompute", ins - mul, "ns/op", "(derived: the element hash alone)");
    memcpy(tmp, acc, 384);
    double fin = MEASURE(1, num3072_inv((u8*)inv, (u8*)elem); memcpy(tmp, acc, 384); num3072_mul(tmp, inv); u8 o[32]; muhash_finalize(o, tmp));
    result("num3072_inv + mul + muhash_finalize", "MuHashFinalize", fin, "ns/op", "(Fermat inverse of the denominator, then the digest; Core's Finalize does the same inverse)");
}

/* ---- 6. ChaCha20 / Poly1305 / the BIP324 AEAD --------------------------- */
static void bench_aead(void){
    printf("== ChaCha20, Poly1305, FSChaCha20Poly1305 (Core src/bench/chacha20.cpp, poly1305.cpp): 64 B, 256 B, 1 MB ==\n");
    static u8 in[1 << 20], out[(1 << 20) + 64]; memset(in, 0x5a, sizeof in);
    u8 key[32]; memset(key, 11, 32); u8 nonce[12]; memset(nonce, 7, 12);
    const unsigned long sizes[3] = { 64, 256, 1 << 20 }; const char* cn[3] = { "CHACHA20_64BYTES", "CHACHA20_256BYTES", "CHACHA20_1MB" };
    const char* pn[3] = { "POLY1305_64BYTES", "POLY1305_256BYTES", "POLY1305_1MB" }; const char* fn[3] = { "FSCHACHA20POLY1305_64BYTES", "FSCHACHA20POLY1305_256BYTES", "FSCHACHA20POLY1305_1MB" };
    for (int s = 0; s < 3; s++){
        unsigned long n = sizes[s]; long iters = n >= (1 << 20) ? 20 : 20000;
        chacha20_ctx c; chacha20_init(&c, key); chacha20_seek(&c, nonce, 0);
        double ns = MEASURE(iters, chacha20_crypt(&c, in, out, n));
        char nm[48]; snprintf(nm, sizeof nm, "chacha20_crypt %lu B", n);
        result(nm, cn[s], ns / (double)n, "ns/byte", NULL);
    }
    for (int s = 0; s < 3; s++){
        unsigned long n = sizes[s]; long iters = n >= (1 << 20) ? 20 : 20000; u8 tag[16];
        double ns = MEASURE(iters, poly1305_ctx p; poly1305_init(&p, key); poly1305_update(&p, in, n); poly1305_finish(&p, tag));
        char nm[48]; snprintf(nm, sizeof nm, "poly1305 %lu B", n);
        result(nm, pn[s], ns / (double)n, "ns/byte", NULL);
    }
    /* the AEAD as the transport uses it: two ElligatorSwift keys, one cipher */
    u8 sk_a[32], sk_b[32], es_a[64], es_b[64], magic[4] = { 0xf9, 0xbe, 0xb4, 0xd9 }, rb[32];
    for (int i = 0; i < 32; i++){ sk_a[i] = (u8)(rnd() & 0xff); sk_b[i] = (u8)(rnd() & 0xff); rb[i] = (u8)(rnd() & 0xff); }
    sk_a[0] &= 0x7f; sk_b[0] &= 0x7f; sk_a[31] |= 1; sk_b[31] |= 1;
    if (!ellswift_create(es_a, sk_a, rb, 32) || !ellswift_create(es_b, sk_b, rb, 32)){ printf("FAIL: ellswift_create for the AEAD keys\n"); exit(1); }
    static bip324_cipher_t ci;
    if (!bip324_init(&ci, sk_a, es_a, es_b, magic, 1, 0)){ printf("FAIL: bip324_init\n"); exit(1); }
    for (int s = 0; s < 3; s++){
        unsigned long n = sizes[s]; long iters = n >= (1 << 20) ? 20 : 20000;
        double ns = MEASURE(iters, bip324_encrypt(&ci, out, in, n, NULL, 0, 0));
        char nm[48]; snprintf(nm, sizeof nm, "bip324_encrypt %lu B", n);
        result(nm, fn[s], ns / (double)n, "ns/byte", s == 0 ? "(the whole v2 packet: length cipher + ChaCha20-Poly1305 with rekeying)" : NULL);
    }
}

/* ---- 7. ElligatorSwift / BIP324 ECDH ------------------------------------ */
static void bench_ellswift(void){
    printf("== ElligatorSwift (Core src/bench/ellswift.cpp, bip324_ecdh.cpp) ==\n");
    u8 sk[32], es[64], rb[32], their[64], ours[64], out[32];
    for (int i = 0; i < 32; i++){ sk[i] = (u8)(rnd() & 0xff); rb[i] = (u8)(rnd() & 0xff); }
    for (int i = 0; i < 64; i++){ their[i] = (u8)(rnd() & 0xff); ours[i] = (u8)(rnd() & 0xff); }
    sk[0] &= 0x7f; sk[31] |= 1;
    if (!ellswift_create(es, sk, rb, 32)){ printf("FAIL: ellswift_create\n"); exit(1); }
    /* as Core's bench: the first 32 bytes of each encoding become the next key */
    double ns = MEASURE(500, if (!ellswift_create(es, sk, rb, 32)) exit(1); memcpy(sk, es, 32); sk[0] &= 0x7f; sk[31] |= 1);
    result("ellswift_create", "EllSwiftCreate", ns, "ns/op", NULL);
    ns = MEASURE(500, ellswift_ecdh(out, their, ours, sk, 1));
    result("ellswift_ecdh", "BIP324_ECDH", ns, "ns/op", "(random encodings on both sides, as Core's bench)");
}

/* ---- 8. Bech32 / Base58 ------------------------------------------------- */
static void bench_codecs(void){
    printf("== Bech32 and Base58 (Core src/bench/bech32.cpp, base58.cpp) ==\n");
    bech32_init();
    static const u8 v[32] = { 0xc9,0x7f,0x5a,0x67,0xec,0x38,0x1b,0x76,0x0a,0xea,0xf6,0x75,0x73,0xbc,0x16,0x48,0x45,0xff,0x39,0xa3,0xbb,0x26,0xa1,0xce,0xe4,0x01,0xac,0x67,0x24,0x3b,0x48,0xdb };
    u8 d5[80]; d5[0] = 0; long long n5 = bech32_convert_bits(d5 + 1, v, 32, 8, 5, 1); if (n5 < 0) exit(1); n5 += 1;
    char s[128];
    double ns = MEASURE(20000, bech32_encode(s, "bc", 2, d5, n5, 0));
    result("bech32_encode (per input byte)", "Bech32Encode", ns / 32.0, "ns/byte", "(32 data bytes, as Core's)");
    /* Core's bench decodes a fixed string that is NOT a valid address (it never
     * checks the result); a valid one of the same shape, from our encoder,
     * makes both sides do the whole decode + checksum. 58 chars vs Core's 52;
     * the row is per character. */
    static char addr[128]; bech32_encode(addr, "bc", 2, d5, n5, 0); u8 o5[128]; char hrp[16];
    long long nd = bech32_decode(o5, hrp, sizeof hrp, addr);
    if (nd < 0 || !bech32_verify_checksum(hrp, (long long)strlen(hrp), o5, nd, 0)){ printf("FAIL: bech32 decode/verify of the fixture address\n"); exit(1); }
    ns = MEASURE(20000, nd = bech32_decode(o5, hrp, sizeof hrp, addr); bech32_verify_checksum(hrp, (long long)strlen(hrp), o5, nd, 0));
    result("bech32_decode + verify (per char)", "Bech32Decode", ns / (double)strlen(addr), "ns/byte", "(decode and checksum verification, as Core's Decode)");
    static const u8 b58in[32] = { 17,79,8,99,150,189,208,162,22,23,203,163,36,58,147,227,139,2,215,100,91,38,11,141,253,40,117,21,16,90,200,24 };
    char b58[80];
    ns = MEASURE(20000, base58check_encode(b58, b58in, 32));
    result("base58check_encode (per byte)", "Base58CheckEncode", ns / 32.0, "ns/byte", "(32 bytes, as Core's; plain Base58Encode and Decode have no counterpart here)");
}

int main(int argc, char** argv){
    const char* raw = argc > 1 ? argv[1] : "/storage/bitcoin-core-source/src/bench/data/block413567.raw";
    if (argc > 2) ROUNDS = atoi(argv[2]);
    printf("bench_core_modules: CPU time (CLOCK_THREAD_CPUTIME_ID), min-of-%d rounds\n\n", ROUNDS);
    bench_verify_script();
    bench_block_encoding();
    bench_gcs();
    bench_store(raw);
    bench_muhash();
    bench_aead();
    bench_ellswift();
    bench_codecs();
    return 0;
}
