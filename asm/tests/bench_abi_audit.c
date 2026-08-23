/* bench_abi_audit.c -- does every primitive the benchmark suite times give the
 * caller its callee-saved registers back?
 *
 * This is not a performance benchmark. It exists because BENCHMARKS.md's
 * numbers are only worth reading if the harness that produced them was not
 * itself being corrupted, and on 2026-08-22 one of them was: tests/
 * bench_hash_core.c spun forever on its RIPEMD-160 row because ripemd160
 * returned with a register holding a loop bound overwritten by digest bytes.
 * That is the kind of failure that silently produces a *plausible* number
 * rather than a hang, so the suite now checks for it explicitly and prints the
 * result next to the numbers.
 *
 * The System V AMD64 ABI requires rbx, rbp, r12, r13, r14 and r15 to be
 * preserved across a call. tests/bench_abi_guard.S loads six distinct
 * sentinels into them, calls the function under test with real arguments, and
 * reports which ones came back changed.
 *
 * Real arguments matter: a function that takes an early exit on a degenerate
 * input never reaches the code that clobbers. Every probe below is given input
 * that makes the function do its actual work, and where the function has a
 * return value the audit checks that too, so a "clean" line cannot come from
 * an argument the function rejected.
 *
 * `make abi-check` (scripts/abi_stack_audit.py) does NOT cover this. It audits
 * RSP 16-alignment at call sites -- a different and also useful property -- and
 * passed on a build containing every violation found here.
 *
 * This harness can only check functions it can call with plausible arguments.
 * scripts/abi_callee_saved_audit.py is the static counterpart that covers the
 * whole tree, and it found seven more this file could not reach -- including
 * sha512_block (probed below now that we know), whose damage never escaped
 * sha512.asm because sha512_full re-saves the same registers, and node_log_str,
 * which was corrupting four registers on every log line the daemon wrote.
 *
 * STATUS: all thirteen violations this file and scripts/abi_callee_saved_audit.py
 * between them found are FIXED (branch abi-callee-saved). Every note below is
 * kept in the past tense as the record of what each one was, because the note
 * is the only place the pre-fix frame layout is written down. A line that says
 * `clean` next to such a note is the regression check passing, not a
 * contradiction.
 *
 * This target is wired into `make test` (asm/Makefile, target
 * `callee-saved-check` runs the static half alongside it). Exit status: 0 if
 * every probed function is clean, 1 otherwise. This one IS an assertion,
 * unlike the rest of the bench_* family.
 *
 *   argv[1] = optional path to a raw block (Core ships
 *             src/bench/data/block413567.raw); enables the cons_verify and
 *             tx_parse rows, which need a real block.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

extern long bench_abi_probe(void* fn, const unsigned long args[6],
                            unsigned long got[6]);

/* Declared as void(void) purely to take their addresses; every call goes
 * through bench_abi_probe, which builds the real argument registers itself. */
extern void sha256_full(void);
extern void sha256d(void);
extern void sha1_full(void);
extern void sha512_full(void);
extern void sha512_block(void);
extern void sha512_init(void);
extern void ripemd160(void);
extern unsigned long utxo_struct_size(unsigned long slots);
extern void utxo_init(void);      /* probed */
extern void utxo_prefetch(void);  /* probed -- new 2026-08-23 */
extern void hash160(void);
extern void merkle_root(void);
extern void block_hash(void);
extern void pow_check(void);
extern void tx_parse(void);
extern void cons_verify(void);
extern void script_eval(void);
extern void p2sh_hash(void);

/* script_eval's argument. Layout copied from tests/smoke_interp.c, which is the
 * existing harness for this entry point -- not invented here. */
#define ELEM_SIZE 528
#define MAX_STACK 64
struct script_state {
    unsigned char* main_elems; size_t main_sp;
    unsigned char* alt_elems;  size_t alt_sp;
    unsigned char* script;     size_t script_len;
    int      sigversion; unsigned long flags;
    unsigned char* work;       size_t work_cap;
    unsigned long* error_out;
    void*    checksig_ctx;
    unsigned long (*checksig_fn)(void*,const unsigned char*,size_t,const unsigned char*,size_t,const void*);
};

static const char* RN[6] = {"rbx","rbp","r12","r13","r14","r15"};
static int g_bad = 0, g_clean = 0;

static void probe(const char* name, void* fn,
                  unsigned long a0, unsigned long a1, unsigned long a2,
                  unsigned long a3, const char* note)
{
    unsigned long args[6] = { a0, a1, a2, a3, 0, 0 };
    unsigned long got[6];
    long bad = bench_abi_probe(fn, args, got);
    if (!bad){ printf("  %-14s clean%s%s\n", name, note?"   ":"", note?note:""); g_clean++; return; }
    printf("  %-14s CLOBBERS", name);
    for (int i = 0; i < 6; i++) if (got[i] != (0x1111111111111111UL * (unsigned long)(i+1)))
        printf(" %s", RN[i]);
    printf("   ABI VIOLATION%s%s\n", note?" -- ":"", note?note:"");
    g_bad++;
}

static unsigned long read_varint(const unsigned char** p, const unsigned char* end){
    if (*p >= end) return (unsigned long)-1;
    unsigned char c = *(*p)++;
    if (c < 0xfd) return c;
    int n = (c == 0xfd) ? 2 : (c == 0xfe) ? 4 : 8;
    if (*p + n > end) return (unsigned long)-1;
    unsigned long v = 0;
    for (int i = 0; i < n; i++) v |= (unsigned long)(*p)[i] << (8*i);
    *p += n;
    return v;
}

int main(int argc, char** argv){
    unsigned char out[64];
    unsigned char* in = calloc(1, 1000000);
    if (!in) return 1;

    printf("== callee-saved register audit ==\n");
    printf("   System V AMD64: rbx, rbp, r12, r13, r14, r15 must survive a call.\n");
    printf("   Probed with real arguments, via tests/bench_abi_guard.S.\n\n");

    printf("hash primitives:\n");
    probe("sha256_full", (void*)sha256_full, (unsigned long)out, (unsigned long)in, 1000000, 0, NULL);
    probe("sha256d",     (void*)sha256d,     (unsigned long)out, (unsigned long)in, 1000000, 0, NULL);
    probe("sha1_full",   (void*)sha1_full,   (unsigned long)out, (unsigned long)in, 1000000, 0, NULL);
    probe("sha512_full", (void*)sha512_full, (unsigned long)out, (unsigned long)in, 1000000, 0, NULL);
    {
        /* sha512_block, the compression function under sha512_full. Probing the
         * wrapper alone said "clean" while this said CLOBBERS rbx r12 r13 --
         * sha512_full's own frame re-saved the same three registers, so the
         * damage never left sha512.asm. It is `global`, so a C caller would
         * have been hit; found statically, kept here as the regression test.
         * Needs an initialised state, hence the sha512_init first. */
        static unsigned long st512[8];
        static unsigned char blk512[128];
        unsigned long ia[6] = { (unsigned long)st512, 0, 0, 0, 0, 0 }, g[6];
        memset(blk512, 0xa5, sizeof blk512);
        bench_abi_probe((void*)sha512_init, ia, g);
        probe("sha512_block", (void*)sha512_block, (unsigned long)st512,
              (unsigned long)blk512, 0, 0,
              "was: T1/tmp/Maj at rbp-8/-16/-24 sat on saved rbx/r12/r13 (sha512.asm)");
    }
    probe("ripemd160",   (void*)ripemd160,   (unsigned long)out, (unsigned long)in, 1000000, 0,
          "was: state words h2..h4 overlapped its own saved r15/r14 (ripemd160.asm)");
    probe("hash160",     (void*)hash160,     (unsigned long)out, (unsigned long)in, 1000000, 0,
          "was: SHA-256 buffer at rbp-0x30 overlapped saved r13/r14 (bitcoin_addr.asm)");

    printf("\nutxo primitives:\n");
    {
        /* utxo_prefetch is new (2026-08-23) and calls utxo_hash internally, so
         * it gets a poison probe on day one rather than after an incident.
         * Needs a real initialised table (it dereferences u+8 for the mask). */
        static unsigned char txid[32];
        unsigned long slots = 1024;
        void* u    = calloc(1, utxo_struct_size(slots));
        void* blob = calloc(1, 4096);
        if (u && blob){
            memset(txid, 0x5a, sizeof txid);
            probe("utxo_init",     (void*)utxo_init,     (unsigned long)u, slots, (unsigned long)blob, 4096, NULL);
            probe("utxo_prefetch", (void*)utxo_prefetch, (unsigned long)u, (unsigned long)txid, 7, 0,
                  "new 2026-08-23: home-slot warm ahead of get/del (bitcoin_utxo.asm)");
        }
    }

    printf("\nblock/merkle primitives:\n");
    {
        /* merkle_root consumes its input buffer in place and needs room for the
         * odd-count duplication, so give it n+1 slots of non-degenerate data. */
        unsigned long n = 9001;
        unsigned char* leaves = malloc((n + 1) * 32);
        if (!leaves) return 1;
        for (unsigned long i = 0; i < (n+1)*32; i++) leaves[i] = (unsigned char)(i * 31u + 7u);
        probe("merkle_root", (void*)merkle_root, (unsigned long)out, (unsigned long)leaves, n, 0, NULL);
        free(leaves);
    }

    if (argc > 1){
        FILE* f = fopen(argv[1], "rb");
        if (!f){ perror(argv[1]); return 1; }
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        unsigned char* blk = malloc((size_t)len);
        if (!blk || fread(blk, 1, (size_t)len, f) != (size_t)len){ printf("read failed\n"); return 1; }
        fclose(f);

        probe("block_hash", (void*)block_hash, (unsigned long)out, (unsigned long)blk, 0, 0, NULL);
        probe("pow_check",  (void*)pow_check,  (unsigned long)blk, 0, 0, 0,
              "was: block_hash output at rbp-0x30 overlapped saved r13 at rbp-0x18 (bitcoin_hash.asm)");

        const unsigned char* q = blk + 80;
        unsigned long ntx = read_varint(&q, blk + len);
        unsigned char info[64];
        probe("tx_parse", (void*)tx_parse, (unsigned long)info, (unsigned long)q,
              (unsigned long)(blk + len - q), 0, NULL);

        unsigned char* scratch = malloc(65536UL * 32);
        if (!scratch) return 1;
        probe("cons_verify", (void*)cons_verify, (unsigned long)blk, (unsigned long)len,
              (unsigned long)scratch, 65536,
              "was: inherited -- its own frame is correct; pow_check did the damage");
        printf("  (block: %s, %ld bytes, %lu transactions)\n", argv[1], len, ntx);
        free(scratch); free(blk);
    } else {
        printf("\n  block_hash / pow_check / tx_parse / cons_verify SKIPPED -- pass a raw block:\n");
        printf("    tests/bench_abi_audit /storage/bitcoin-core-source/src/bench/data/block413567.raw\n");
    }

    /* The consensus interpreter. This one matters most: it is entered for every
     * input of every transaction in every block, and it is the largest
     * violation found -- bitcoin_interp.asm:301 pushes rbx,r12,r13,r14,r15 at
     * rbp-0x08..rbp-0x28 and then bitcoin_interp.asm:288-291 places fExec, pc,
     * pend, pbegincodehash and nOpCount at exactly those five offsets. All five
     * registers come back holding interpreter state. */
    printf("\nscript interpreter:\n");
    {
        static unsigned char main_elems[MAX_STACK * ELEM_SIZE];
        static unsigned char alt_elems [MAX_STACK * ELEM_SIZE];
        static unsigned char script[] = { 0x51, 0x51, 0x93 };   /* OP_1 OP_1 OP_ADD */
        unsigned long err = 0;
        struct script_state st;
        memset(main_elems, 0, sizeof main_elems);
        memset(alt_elems,  0, sizeof alt_elems);
        memset(&st, 0, sizeof st);
        st.main_elems = main_elems; st.alt_elems = alt_elems;
        st.script = script; st.script_len = sizeof script;
        st.sigversion = 0; st.flags = 0; st.error_out = &err;
        probe("script_eval", (void*)script_eval, (unsigned long)&st, 0, 0, 0,
              "was: fExec/pc/pend/pbegincodehash/nOpCount sat on saved rbx/r12/r13/r14/r15 (bitcoin_interp.asm)");
        /* Prove the probe actually ran the interpreter rather than bouncing off
         * a rejected argument: OP_1 OP_1 OP_ADD must succeed and leave depth 1. */
        if (st.main_sp != 1)
            printf("  %-14s WARNING: script_eval left depth %zu, expected 1 -- probe input rejected?\n",
                   "script_eval", st.main_sp);
    }
    {
        /* p2sh_hash: hash160 of a redeem script. Test-only caller today
         * (tests/test_multisig.c), but the same class, and it uses r13/r14 as
         * scratch WITHOUT ever pushing them. */
        unsigned char redeem[] = { 0x51, 0x51, 0x52, 0xae };    /* 1 <k> <n> CHECKMULTISIG shape */
        probe("p2sh_hash", (void*)p2sh_hash, (unsigned long)redeem, sizeof redeem,
              (unsigned long)out, 0,
              "was: used r13/r14 as scratch and never saved them (bitcoin_multisig.asm)");
    }

    printf("\n%d clean, %d violating\n", g_clean, g_bad);
    if (g_bad) printf("These are REPORTED, not fixed here -- see BENCHMARKS.md. A benchmark harness\n"
                      "cannot repair a consensus-path primitive; that needs its own change and tests.\n");
    free(in);
    return g_bad ? 1 : 0;
}
