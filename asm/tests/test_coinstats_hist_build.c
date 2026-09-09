/* tests/test_coinstats_hist_build.c -- the coinstats history builder over a
 * synthetic four-block chain, checked two ways: every height's block_info
 * and counters against hand-computed values (Core's rules: the genesis
 * coinbase never enters the set, an OP_RETURN output is unspendables.scripts,
 * unclaimed rewards per block), and the MuHash at the tip against a direct
 * fold of the surviving coins -- which exercises the builder's removal
 * algebra (the denominator) and its bookkeeping end to end. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "../daemon/coinstats_hist_fmt.h"
#include "test_tmpdir.h"
typedef uint8_t u8; typedef uint16_t u16; typedef uint32_t u32; typedef uint64_t u64;
extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void store_rd_init(void* st);
extern int  tx_txid(void* out, const void* tx, unsigned long txlen, void* buf, unsigned long buflen);
extern void utxo_stats_init(void* st, unsigned long want_muhash, unsigned long excl_genesis);
extern void utxo_stats_add(void* st, const u8* key36, u64 value, u64 code, const u8* script, unsigned long slen);
extern void muhash_finalize(unsigned char out[32], const void* acc);
extern int  csi_hist_query(long h, int want_digest, csi_hist_out_t* o);
extern long csi_hist_first(void), csi_hist_last(void);
static int failures = 0;
static void ck(const char* l, int cond){ if (cond) printf("  ok  %s\n", l); else { printf("  FAIL %s\n", l); failures++; } }
static u8 store_buf[4096];
typedef struct { u64 value; const u8* script; int slen; } outspec;
/* version | nin (coinbase or one prevout) | nout outputs | locktime; no witness */
static long mk_tx(u8* p, int tag, const u8* prev_txid, u32 prev_vout, const outspec* outs, int nout){
    u8* s = p; *p++ = 1; *p++ = 0; *p++ = 0; *p++ = (u8)tag; *p++ = 1;
    if (prev_txid){ memcpy(p, prev_txid, 32); p += 32; memcpy(p, &prev_vout, 4); p += 4; }
    else { memset(p, 0, 32); p += 32; memset(p, 0xff, 4); p += 4; }
    *p++ = 0; memset(p, 0xff, 4); p += 4;
    *p++ = (u8)nout;
    for (int i = 0; i < nout; i++){ memcpy(p, &outs[i].value, 8); p += 8; *p++ = (u8)outs[i].slen; memcpy(p, outs[i].script, (size_t)outs[i].slen); p += outs[i].slen; }
    memset(p, 0, 4); p += 4; return p - s;
}
static void p2wpkh(u8* spk, u8 fill){ spk[0] = 0x00; spk[1] = 0x14; memset(spk + 2, fill, 20); }
extern int  csi_hist_check(int full, char* why, unsigned long why_cap);
extern long csi_hist_base_to(void);
extern void csi_hist_repair_configure(const char*, const char*, const char*, int, int);
extern int  csi_hist_repair_tick(long applied, int in_ibd, long long now);
extern int  csi_hist_repair_state(void);
extern const char* csi_hist_status(void);
static int log_has(const char* file, const char* needle){
    FILE* f = fopen(file, "r"); if (!f) return 0; char line[512]; int hit = 0;
    while (fgets(line, sizeof line, f)) if (strstr(line, needle)){ hit = 1; break; }
    fclose(f); return hit;
}
static int copy_file(const char* from, const char* to){
    FILE* a = fopen(from, "rb"); if (!a) return 0; FILE* b = fopen(to, "wb"); if (!b){ fclose(a); return 0; }
    static u8 buf[1 << 16]; size_t n; while ((n = fread(buf, 1, sizeof buf, a)) > 0) fwrite(buf, 1, n, b);
    fclose(a); fclose(b); return 1;
}
static void write_script(const char* name, const char* body){ FILE* f = fopen(name, "w"); fputs(body, f); fclose(f); chmod(name, 0755); }
/* a pass-2 REMOVE event in the builder's packed layout (55 bytes + the script) */
static void write_bogus_remove(const char* path, const u8* txid, u64 value, const u8* spk, int slen){
    FILE* f = fopen(path, "wb"); u32 v32; u16 v16; u8 c;
    v32 = 1; fwrite(&v32, 4, 1, f);            /* spend_h */
    fwrite(txid, 32, 1, f);                    /* txid */
    v32 = 0; fwrite(&v32, 4, 1, f);            /* vout */
    fwrite(&value, 8, 1, f);                   /* value */
    v32 = 2; fwrite(&v32, 4, 1, f);            /* height */
    c = 1; fwrite(&c, 1, 1, f);                /* cb */
    v16 = (u16)slen; fwrite(&v16, 2, 1, f);    /* slen */
    fwrite(spk, (size_t)slen, 1, f); fclose(f);
}
/* spin the supervisor until it leaves RUNNING (the stub builders take about a second) */
static int tick_until_settled(long long* now){
    for (int i = 0; i < 300; i++){ int st = csi_hist_repair_tick(3, 0, *now); if (st != 2) return st; usleep(50000); *now += 1; }
    return 2;
}
int main(void){
    char tool[4096]; if (!getcwd(tool, sizeof tool - 48)) return 1;
    if (getenv("BMC_CSH_BUILDER")) snprintf(tool, sizeof tool, "%s", getenv("BMC_CSH_BUILDER")); else strcat(tool, "/daemon/bmc_build_coinstats_hist");
    tt_isolate();
    memset(store_buf, 0, sizeof store_buf); ck("store_init", store_init(store_buf) == 1);
    static u8 blk[4][8192]; long blen[4]; u8 hash[4][32]; static u8 scratch[16384]; u8 txid[6][32];
    u8 G[22], A[22], B[22]; p2wpkh(G, 0x01); p2wpkh(A, 0x11); p2wpkh(B, 0x22); u8 nulldata[3] = {0x6a, 0x01, 0xaa};
    for (int h = 0; h < 4; h++){ memset(blk[h], 0xA0 + h, 80); memset(hash[h], 0xB0 + h, 32); }
    #define BTC(x) ((u64)((x) * 100000000.0 + 0.5))
    /* block 0: a coinbase of 50 to G -- the genesis rule: never in the set */
    { outspec o[1] = {{BTC(50), G, 22}}; blk[0][80] = 1; long l = mk_tx(blk[0] + 81, 0, 0, 0, o, 1); blen[0] = 81 + l; tx_txid(txid[0], blk[0] + 81, l, scratch, sizeof scratch); }
    /* block 1: coinbase 50 to A */
    { outspec o[1] = {{BTC(50), A, 22}}; blk[1][80] = 1; long l = mk_tx(blk[1] + 81, 1, 0, 0, o, 1); blen[1] = 81 + l; tx_txid(txid[1], blk[1] + 81, l, scratch, sizeof scratch); }
    /* block 2: coinbase 50 to B; tx spends block 1's coinbase (50) -> 30 to A, 19.999 to B, 0.001 OP_RETURN */
    { outspec cb[1] = {{BTC(50), B, 22}}; outspec o[3] = {{BTC(30), A, 22}, {BTC(19.999), B, 22}, {BTC(0.001), nulldata, 3}};
      blk[2][80] = 2; long la = mk_tx(blk[2] + 81, 2, 0, 0, cb, 1); long lb = mk_tx(blk[2] + 81 + la, 3, txid[1], 0, o, 3); blen[2] = 81 + la + lb;
      tx_txid(txid[2], blk[2] + 81, la, scratch, sizeof scratch); tx_txid(txid[3], blk[2] + 81 + la, lb, scratch, sizeof scratch); }
    /* block 3: coinbase 50.3 to B (0.2 of subsidy + fee unclaimed); tx spends tx3:0 (30) -> 29.5 to B (fee 0.5) */
    { outspec cb[1] = {{BTC(50.3), B, 22}}; outspec o[1] = {{BTC(29.5), B, 22}};
      blk[3][80] = 2; long la = mk_tx(blk[3] + 81, 4, 0, 0, cb, 1); long lb = mk_tx(blk[3] + 81 + la, 5, txid[3], 0, o, 1); blen[3] = 81 + la + lb;
      tx_txid(txid[4], blk[3] + 81, la, scratch, sizeof scratch); tx_txid(txid[5], blk[3] + 81 + la, lb, scratch, sizeof scratch); }
    for (int h = 0; h < 4; h++) ck("store_append", store_append(store_buf, hash[h], blk[h], blen[h]) == h);
    store_rd_init(store_buf);
    { char cmd[4300]; snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest %s . 3 2 2>/dev/null", tool); ck("builder ran to height 3 with two workers", system(cmd) == 0); }
    ck("rows cover 0..3", csi_hist_first() == 0 && csi_hist_last() == 3);
    csi_hist_out_t o;
    ck("h0: the genesis coinbase never enters the set: txouts 0, amount 0; genesis 50, unclaimed 0", csi_hist_query(0, 0, &o) == 1 && o.txouts == 0 && o.amount == 0 && o.d_genesis == BTC(50) && o.d_unclaimed == 0 && o.subsidy == BTC(50));
    ck("h1: 1 coin, 50 BTC; coinbase 50, unclaimed 0", csi_hist_query(1, 0, &o) == 1 && o.txouts == 1 && o.amount == BTC(50) && o.d_coinbase == BTC(50) && o.d_prevout == 0 && o.d_unclaimed == 0);
    ck("h2: 3 coins, 99.999 BTC; prevout_spent 50, coinbase 50, new_outputs 49.999, scripts 0.001, unclaimed 0",
       csi_hist_query(2, 0, &o) == 1 && o.txouts == 3 && o.amount == BTC(99.999) && o.d_prevout == BTC(50) && o.d_coinbase == BTC(50) && o.d_new_ex_cb == BTC(49.999) && o.d_scripts == BTC(0.001) && o.d_unclaimed == 0);
    ck("h3: 4 coins, 149.799 BTC; prevout_spent 30, coinbase 50.3, new_outputs 29.5, unclaimed 0.2",
       csi_hist_query(3, 1, &o) == 1 && o.txouts == 4 && o.amount == BTC(149.799) && o.d_prevout == BTC(30) && o.d_coinbase == BTC(50.3) && o.d_new_ex_cb == BTC(29.5) && o.d_unclaimed == BTC(0.2) && o.digest_valid);
    /* the MuHash at the tip against a direct fold of the four surviving coins */
    { static u8 st[512] __attribute__((aligned(16))); utxo_stats_init(st, 1, 0); u8 key[36]; u32 v;
      memcpy(key, txid[2], 32); v = 0; memcpy(key + 32, &v, 4); utxo_stats_add(st, key, BTC(50), (2ULL << 1) | 1, B, 22);       /* block 2 coinbase */
      memcpy(key, txid[3], 32); v = 1; memcpy(key + 32, &v, 4); utxo_stats_add(st, key, BTC(19.999), (2ULL << 1) | 0, B, 22);   /* tx3:1 */
      memcpy(key, txid[4], 32); v = 0; memcpy(key + 32, &v, 4); utxo_stats_add(st, key, BTC(50.3), (3ULL << 1) | 1, B, 22);     /* block 3 coinbase */
      memcpy(key, txid[5], 32); v = 0; memcpy(key + 32, &v, 4); utxo_stats_add(st, key, BTC(29.5), (3ULL << 1) | 0, B, 22);     /* tx5:0 */
      u8 want[32]; muhash_finalize(want, st + 96);
      ck("the digest at height 3 equals a direct fold of the surviving coins (numerator x denominator^-1 == the set)", !memcmp(want, o.digest, 32));
      csi_hist_out_t o2; csi_hist_query(2, 1, &o2);
      ck("the digest at height 2 differs from height 3's", memcmp(o2.digest, o.digest, 32) != 0); }

    /* ---- 2026-09-08: the base file, the builder's cleanup and resume, the health check, the repair ---- */
    printf("---- the base file ----\n");
    u8 golden[32]; memcpy(golden, o.digest, 32); char why[200]; char cmd[4600];
    ck("the builder wrote a complete base to height 3 and removed its scratch", csi_hist_base_to() == 3 && access(CSH_BASE_FILE, R_OK) == 0 && access(CSH_TMPDIR, F_OK) != 0);
    ck("the full check passes: every row hashes and the header's sum matches", csi_hist_check(1, why, sizeof why) == 1 && strstr(why, "complete to 3"));
    ck("a golden copy of the base", copy_file(CSH_BASE_FILE, "base.golden"));

    printf("---- a dead run's leftovers are discarded, not appended to ----\n");
    { /* the old layout's range file beside the archive and an unmarked scratch file: the
       * range files are opened in APPEND mode, so a builder that kept them would fold this
       * bogus removal of block 2's coinbase into height 1 and the digest would change */
      unlink(CSH_BASE_FILE);
      write_bogus_remove("csh_r_w00_000.tmp", txid[2], BTC(50), B, 22);
      mkdir(CSH_TMPDIR, 0755); write_bogus_remove(CSH_TMPDIR "/csh_r_w00_000.tmp", txid[2], BTC(50), B, 22);
      snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest %s . 3 2 2>leftovers.log", tool);
      ck("the builder ran over the leftovers", system(cmd) == 0);
      ck("it said what it discarded", log_has("leftovers.log", "discarded"));
      csi_hist_out_t o3; int q = csi_hist_query(3, 1, &o3);
      ck("the digest at height 3 equals the first build's (the leftovers did not leak into the rows)", q == 1 && !memcmp(golden, o3.digest, 32));
      ck("the old-layout file beside the archive is gone", access("csh_r_w00_000.tmp", F_OK) != 0);
      ck("the check passes", csi_hist_check(1, why, sizeof why) == 1); }

    printf("---- resume at the pass after the last marker ----\n");
    { unlink(CSH_BASE_FILE);
      snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest BMC_CSH_STOP_AFTER=1 %s . 3 2 2>resume1.log", tool);
      ck("stopped after pass 1: marker written, no base yet", system(cmd) == 0 && access(CSH_TMPDIR "/pass1.done", F_OK) == 0 && access(CSH_BASE_FILE, F_OK) != 0);
      ck("pass 1's outputs are all there for pass 2 (2 workers x 256 buckets, both sides)", access(CSH_TMPDIR "/csh_o_w00_000.tmp", F_OK) == 0 && access(CSH_TMPDIR "/csh_s_w01_255.tmp", F_OK) == 0);
      snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest BMC_CSH_STOP_AFTER=2 %s . 3 2 2>resume2.log", tool);
      ck("the second run resumed at pass 2 and stopped after it", system(cmd) == 0 && log_has("resume2.log", "resuming at pass 2") && access(CSH_TMPDIR "/pass2.done", F_OK) == 0);
      ck("pass 2 kept its inputs until it completed, then removed them; pass 3's inputs are there", access(CSH_TMPDIR "/csh_o_w00_000.tmp", F_OK) != 0 && access(CSH_TMPDIR "/csh_r_w00_000.tmp", F_OK) == 0);
      snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest %s . 3 2 2>resume3.log", tool);
      ck("the third run resumed at pass 3 and completed", system(cmd) == 0 && log_has("resume3.log", "resuming at pass 3") && csi_hist_base_to() == 3);
      csi_hist_out_t o4; int q = csi_hist_query(3, 1, &o4);
      ck("the resumed build's digest equals the first build's, the scratch is gone, the check passes", q == 1 && !memcmp(golden, o4.digest, 32) && access(CSH_TMPDIR, F_OK) != 0 && csi_hist_check(1, why, sizeof why) == 1);
      /* a marker without its inputs (a pass 2 killed midway used to eat pass 1's
       * buckets as it read them; 2026-09-09) starts over instead of joining
       * half-empty buckets */
      unlink(CSH_BASE_FILE);
      snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest BMC_CSH_STOP_AFTER=1 %s . 3 2 2>/dev/null", tool); (void)!system(cmd);
      unlink(CSH_TMPDIR "/csh_o_w00_007.tmp"); unlink(CSH_TMPDIR "/csh_s_w00_007.tmp");
      snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest %s . 3 2 2>missing.log", tool);
      ck("pass 1's marker with a bucket missing: the run starts over, and the base is right", system(cmd) == 0 && log_has("missing.log", "starting over") && !log_has("missing.log", "resuming at pass 2") && csi_hist_base_to() == 3);
      { csi_hist_out_t o6; ck("... same digest as the clean build", csi_hist_query(3, 1, &o6) == 1 && !memcmp(golden, o6.digest, 32)); }
      /* markers for another target height are not resumed */
      unlink(CSH_BASE_FILE);
      snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest BMC_CSH_STOP_AFTER=1 %s . 3 2 2>/dev/null", tool); (void)!system(cmd);
      snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest %s . 2 2 2>target.log", tool);
      ck("a different target height starts over instead of resuming (base to 2)", system(cmd) == 0 && !log_has("target.log", "resuming") && csi_hist_base_to() == 2);
      snprintf(cmd, sizeof cmd, "BMC_CHAIN=regtest %s . 3 2 2>/dev/null", tool); ck("rebuilt to 3", system(cmd) == 0 && csi_hist_base_to() == 3); }

    printf("---- a broken base is named and quarantined; a torn row answers 'no record' ----\n");
    { int fd = open(CSH_BASE_FILE, O_RDWR); u8 b = 0;
      ck("flip a byte inside row 2", fd >= 0 && pread(fd, &b, 1, CSH_HDR + 2 * CSH_REC + 40) == 1 && (b ^= 1, pwrite(fd, &b, 1, CSH_HDR + 2 * CSH_REC + 40) == 1)); close(fd);
      csi_hist_out_t o5;
      ck("the torn row is 'no record'; its neighbours still answer", csi_hist_query(2, 0, &o5) == 0 && csi_hist_query(1, 0, &o5) == 1);
      ck("the full check names row 2 and quarantines the base", csi_hist_check(1, why, sizeof why) == -1 && strstr(why, "row 2") && access(CSH_BASE_FILE, F_OK) != 0);
      ck("without a base the reader falls back to the tail (none here): first = -1", csi_hist_first() == -1);
      /* intact rows under a header whose sum is wrong */
      copy_file("base.golden", CSH_BASE_FILE);
      fd = open(CSH_BASE_FILE, O_RDWR); u8 zero[32] = {0}; (void)!pwrite(fd, zero, 32, 32); close(fd);
      ck("a header sum that does not match the rows is quarantined too", csi_hist_check(1, why, sizeof why) == -1 && strstr(why, "hash to the header") && access(CSH_BASE_FILE, F_OK) != 0);
      /* an incomplete base (the builder died in pass 4 before the flag) is absent, not broken */
      copy_file("base.golden", CSH_BASE_FILE);
      fd = open(CSH_BASE_FILE, O_RDWR); u32 z = 0; (void)!pwrite(fd, &z, 4, 12); close(fd);
      ck("a base without the complete flag is rejected", csi_hist_check(0, why, sizeof why) == -1 && strstr(why, "rejected") && csi_hist_first() == -1);
      unlink(CSH_BASE_FILE); }

    printf("---- the repair: a supervised builder ----\n");
    { write_script("stub_ok.sh", "#!/bin/sh\nsleep 1\ncp base.golden " CSH_BASE_FILE "\n");
      write_script("stub_fail.sh", "#!/bin/sh\nsleep 1\nexit 1\n");
      long long now = 1000000;
      csi_hist_repair_configure("./stub_ok.sh", ".", "regtest", 2, 0);
      ck("disabled: the base stays absent and the state says so", csi_hist_repair_tick(3, 0, now) == 5 && access(CSH_BASE_FILE, F_OK) != 0 && strstr(csi_hist_status(), "coinstatshistrepair=0"));
      csi_hist_repair_configure("./stub_fail.sh", ".", "regtest", 2, 1);
      ck("during initial block download nothing is spawned", csi_hist_repair_tick(3, 1, now) == 6);
      ck("the missing base spawns the builder", csi_hist_repair_tick(3, 0, now) == 2 && strstr(csi_hist_status(), "being rebuilt"));
      int st = tick_until_settled(&now);
      ck("a builder that ends without a base: backoff, attempt 1", st == 4 && strstr(csi_hist_status(), "failed 1 time"));
      ck("no respawn inside the backoff", csi_hist_repair_tick(3, 0, now + 60) == 4);
      now += 6 * 3600 + 1;
      ck("after the backoff it tries again", csi_hist_repair_tick(3, 0, now) == 2);
      st = tick_until_settled(&now); now += 6 * 3600 + 1;
      ck("second failure backs off again", st == 4 && csi_hist_repair_tick(3, 0, now) == 2);
      st = tick_until_settled(&now); now += 6 * 3600 + 1;
      ck("the third failure gives up for this boot", st == 7 && csi_hist_repair_tick(3, 0, now) == 7 && strstr(csi_hist_status(), "restart to retry"));
      /* the good builder: reconfigured (a new boot), the base comes back and is verified */
      csi_hist_repair_configure("./stub_ok.sh", ".", "regtest", 2, 1);
      ck("a new boot spawns the builder again", csi_hist_repair_tick(3, 0, now) == 2);
      st = tick_until_settled(&now);
      ck("the rebuilt base is verified and adopted: rows 0..3, status says complete", st == 1 && csi_hist_base_to() == 3 && csi_hist_check(1, why, sizeof why) == 1 && strstr(csi_hist_status(), "complete to 3"));
      ck("a healthy base: the tick stays OK and never spawns", csi_hist_repair_tick(3, 0, now + 60) == 1);
      ck("the status file for the RPC parent carries the same line", log_has("coinstats_hist.status", "complete to 3"));
      /* a builder running outside this process: its lock is respected */
      unlink(CSH_BASE_FILE); mkdir(CSH_TMPDIR, 0755);
      int lk = open(CSH_TMPDIR "/lock", O_RDWR | O_CREAT, 0644); ck("hold the builder's lock", lk >= 0 && flock(lk, LOCK_EX | LOCK_NB) == 0);
      csi_hist_repair_configure("./stub_ok.sh", ".", "regtest", 2, 1);
      ck("a held lock means wait, not spawn", csi_hist_repair_tick(3, 0, now) == 3 && strstr(csi_hist_status(), "outside this process"));
      flock(lk, LOCK_UN); close(lk);
      ck("released: the builder is spawned", csi_hist_repair_tick(3, 0, now) == 2);
      st = tick_until_settled(&now);
      ck("and its base is adopted", st == 1 && csi_hist_base_to() == 3); }
    printf("%s (%d failure(s))\n", failures ? "TESTS FAILED" : "ALL TESTS PASSED", failures);
    return failures ? 1 : 0;
}
