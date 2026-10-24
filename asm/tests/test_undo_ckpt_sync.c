/* test_undo_ckpt_sync.c -- ST2-4 (audit 2026-10-23): the checkpoint makes
 * the undo store durable BEFORE the WAL.
 *
 * THE BUG. persist_applied_height fsyncs the WAL (utxo.dat) and then the
 * applied-height file. The undo runs (rev*.dat) and their undo.idx slots
 * were never synced at all, so after a power loss the WAL could hold a
 * block's spends while its undo was gone: the ghost guard
 * (utxo_live_recover_partial_block) finds a block applied past the
 * checkpoint only through undo_exists(h) and would not see it, and a reorg
 * could not disconnect a checkpointed block.
 *
 * THE OBSERVATION. A seccomp filter traps fsync and fdatasync; the SIGSYS
 * handler records which file each call names (/proc/self/fd) and answers 0
 * (no durability is needed here). One spend block is applied under a
 * per-block checkpoint; the recorded order must put rev00000.dat and
 * undo.idx before utxo.dat. The control: the WAL fsync is seen at all. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <signal.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include "test_tmpdir.h"

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

extern long store_init(void* st);
extern long store_append(void* st, const u8 hash[32], const void* raw, long len);
extern void block_hash(u8 out[32], const u8 hdr[80]);
extern int  pow_check(const u8 hdr[80]);
extern int  tx_txid(u8 out[32], const u8* tx, unsigned long txlen, u8* buf, unsigned long buflen);
extern void sha256d(u8 out[32], const void* msg, long len);
extern int  utxo_live_init(const char* dir);
extern long utxo_live_catchup(void* store_buf);
extern long utxo_live_applied_height(void);
extern void utxo_live_test_set_ckpt_batch(long n);
extern int  undo_exists(long height);

long mempool_resolve_confirmed_utxo(void* u, const u8 txid[32], unsigned long index,
                                    u64* value, const u8** script, unsigned long* slen){
    (void)u;(void)txid;(void)index;(void)value;(void)script;(void)slen;
    fprintf(stderr, "test_undo_ckpt_sync: unexpected mempool_resolve_confirmed_utxo\n");
    abort();
}

static int failures = 0;
static void ck(const char* l, long got, long exp){
    if (got==exp) printf("PASS %s (got %ld)\n", l, got);
    else { printf("FAIL %s got=%ld exp=%ld\n", l, got, exp); failures++; }
}

/* ---- the sync trap: the order in which files were synced ---- */
#define NLOG 64
static char g_log[NLOG][64]; static volatile int g_nlog, g_armed;
static void on_sigsys(int sig, siginfo_t* si, void* ctx){
    (void)sig; (void)si;
    ucontext_t* uc = (ucontext_t*)ctx;
    if (g_armed && g_nlog < NLOG){
        char lp[64], tgt[256];
        snprintf(lp, sizeof lp, "/proc/self/fd/%d", (int)uc->uc_mcontext.gregs[REG_RDI]);
        ssize_t n = readlink(lp, tgt, sizeof tgt - 1);
        if (n < 0) n = 0;
        tgt[n] = 0;
        const char* base = strrchr(tgt, '/'); base = base ? base + 1 : tgt;
        size_t bl = strlen(base); if (bl >= sizeof g_log[0]) bl = sizeof g_log[0] - 1;
        memcpy(g_log[g_nlog], base, bl); g_log[g_nlog][bl] = 0; g_nlog++;
    }
    uc->uc_mcontext.gregs[REG_RAX] = 0;
}
static int install_trap(void){
    struct sigaction sa; memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = on_sigsys; sa.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSYS, &sa, 0)) return -1;
    struct sock_filter f[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fsync, 1, 0),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fdatasync, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog p = { (unsigned short)(sizeof f / sizeof f[0]), f };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &p);
}
static int first_at(const char* name){ for (int i = 0; i < g_nlog; i++) if (!strcmp(g_log[i], name)) return i; return -1; }

static void put32(u8* p, u32 v){ p[0]=(u8)v; p[1]=(u8)(v>>8); p[2]=(u8)(v>>16); p[3]=(u8)(v>>24); }
static void put64(u8* p, u64 v){ for(int i=0;i<8;i++) p[i]=(u8)(v>>(8*i)); }

static u8 g_txid_scratch[1<<12];

/* Coinbase-only block, scriptPubKey OP_1, min difficulty (same shape as
 * test_utxo_catchup_crash_resume.c). Returns len; fills hash + cb txid. */
static long mk_and_mine(u8* raw, u8 hash[32], u8 cb_txid_out[32],
                        const u8 prev[32], u32 tag, u32 tstamp){
    u8 tx[80], txid[32];   /* 65-byte coinbase: 64 overflowed by one (see test_blk_dryrun.c) */
    u8* q = tx;
    put32(q,1); q+=4;
    *q++ = 1;
    memset(q,0,32); q+=32;
    put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 50000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long txlen = q - tx;
    if (!tx_txid(txid, tx, (unsigned long)txlen, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (coinbase)\n"); failures++;
    }
    if (cb_txid_out) memcpy(cb_txid_out, txid, 32);

    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, txid, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = 1;
    memcpy(o, tx, (size_t)txlen); o += txlen;
    long len = o - raw;

    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}

/* Coinbase + tx1 spending `spend_txid`:0 (empty scriptSig vs OP_1 -- valid),
 * creating one new OP_1 output. Fills tx1's txid so the NEXT block can chain
 * its spend onto this one. */
static long mk_and_mine_spend(u8* raw, u8 hash[32], u8 tx1_txid_out[32],
                              const u8 prev[32], const u8 spend_txid[32],
                              u32 tag, u32 tstamp){
    u8 cb[80], cb_txid[32];   /* 65-byte coinbase: 64 overflowed by one */
    u8* q = cb;
    put32(q,1); q+=4;
    *q++ = 1;
    memset(q,0,32); q+=32;
    put32(q,0xffffffffu); q+=4;
    *q++ = 4; put32(q, tag); q+=4;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 50000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long cblen = q - cb;
    if (!tx_txid(cb_txid, cb, (unsigned long)cblen, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (spend-block coinbase)\n"); failures++;
    }

    u8 tx1[128], tx1_txid[32];
    q = tx1;
    put32(q,1); q+=4;
    *q++ = 1;
    memcpy(q, spend_txid, 32); q+=32; put32(q,0); q+=4;
    *q++ = 0;
    put32(q,0xffffffffu); q+=4;
    *q++ = 1;
    put64(q, 40000000ULL); q+=8;
    *q++ = 1; *q++ = 0x51;
    put32(q,0); q+=4;
    long tx1len = q - tx1;
    if (!tx_txid(tx1_txid, tx1, (unsigned long)tx1len, g_txid_scratch, sizeof g_txid_scratch)) {
        printf("FAIL tx_txid (tx1)\n"); failures++;
    }
    if (tx1_txid_out) memcpy(tx1_txid_out, tx1_txid, 32);

    u8 pair[64], root[32];
    memcpy(pair, cb_txid, 32); memcpy(pair+32, tx1_txid, 32);
    sha256d(root, pair, 64);

    u8* o = raw;
    put32(o,1); o+=4;
    memcpy(o, prev, 32); o+=32;
    memcpy(o, root, 32); o+=32;
    put32(o, tstamp); o+=4;
    put32(o, 0x207fffffu); o+=4;
    put32(o, 0); o+=4;
    *o++ = 2;
    memcpy(o, cb, (size_t)cblen); o += cblen;
    memcpy(o, tx1, (size_t)tx1len); o += tx1len;
    long len = o - raw;

    u32 nonce = 0;
    while (!pow_check(raw)) { nonce++; put32(raw+76, nonce); }
    block_hash(hash, raw);
    return len;
}



static u8 store_buf[4096];
static u8 raw[512];

int main(void){
    tt_isolate();
    memset(store_buf, 0, sizeof store_buf);
    if (store_init(store_buf) != 1){ printf("FAIL store_init\n"); return 1; }
    if (utxo_live_init(".") != 1){ printf("FAIL utxo_live_init\n"); return 1; }
    utxo_live_test_set_ckpt_batch(0);                 /* a checkpoint after every block */

    /* 101 coinbase-only blocks: height 0's coinbase is mature at 101 */
    u8 prev[32]; memset(prev, 0, 32); u8 cb0[32];
    long n1 = 101;
    for (long h = 0; h < n1; h++){
        u8 hash[32], cbt[32];
        long len = mk_and_mine(raw, hash, cbt, prev, (u32)h, 1600000000u + (u32)h);
        if (h == 0) memcpy(cb0, cbt, 32);
        if (store_append(store_buf, hash, raw, len) != h){ printf("FAIL append %ld\n", h); return 1; }
        memcpy(prev, hash, 32);
    }
    ck("base catch-up applies 101", utxo_live_catchup(store_buf), n1);

    /* the spend block, under the trap: it writes an undo run and checkpoints */
    { u8 hash[32], t1[32];
      long len = mk_and_mine_spend(raw, hash, t1, prev, cb0, (u32)n1, 1600001000u);
      if (store_append(store_buf, hash, raw, len) != n1){ printf("FAIL append spend\n"); return 1; } }
    if (install_trap()){ printf("FAIL seccomp: %s\n", strerror(errno)); return 1; }
    g_nlog = 0; g_armed = 1;
    long r = utxo_live_catchup(store_buf);
    g_armed = 0;
    ck("the spend block applies", r, 1);
    ck("its undo run exists", undo_exists(n1), 1);
    ck("applied height checkpointed", utxo_live_applied_height(), n1);
    printf("synced, in order:"); for (int i = 0; i < g_nlog; i++) printf(" %s", g_log[i]); printf("\n");
    int wal = first_at("utxo.dat"), rev = first_at("rev00000.dat"), idx = first_at("undo.idx");
    ck("control: the checkpoint fsyncs the WAL", wal >= 0, 1);
    ck("the checkpoint syncs the rev file", rev >= 0, 1);
    ck("...before the WAL", rev >= 0 && rev < wal, 1);
    ck("the checkpoint syncs undo.idx", idx >= 0, 1);
    ck("...before the WAL", idx >= 0 && idx < wal, 1);

    if (failures){ printf("\nFAILED (%d failures)\n", failures); return 1; }
    printf("\nALL PASS (0 failures)\n");
    return 0;
}
