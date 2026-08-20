/* tests/test_stack_push_len.c -- regression test for a real production
 * crash (2026-08-20): stack_push's byte-copy loop walked off the end of
 * its destination buffer and SIGSEGV'd inside a worker thread doing legacy
 * script verification, ~3.5 hours into an otherwise-healthy overnight
 * archive replay, with NO error logged anywhere (the daemon's SIGCHLD is
 * ignored by convention, so the crash was invisible until this session
 * added core dumps and a PID-liveness watchdog specifically to catch it).
 *
 * Root cause, found via `gdb -batch -ex "bt full" -ex "thread apply all bt"`
 * against the resulting core file: five opcodes (OP_TOALTSTACK,
 * OP_FROMALTSTACK, OP_2ROT, OP_ROLL, OP_TUCK) each copy a stack element
 * into a thread-local scratch buffer (interp_tmp / elem_tmp0..3) via
 * elem_move (which correctly stores the length as a uint32), then
 * immediately re-read that same length field with `mov rcx, [reg]` -- a
 * 64-BIT load -- before handing it to stack_push as the byte count. That
 * pulls in 4 bytes of the scratch buffer's own DATA (left over from
 * whatever it held on the recipient's LAST use -- these buffers are
 * reused across ops, never cleared) as garbage high bits of the count.
 * stack_push then copies that many bytes, walking off the end of every
 * buffer involved within a handful of iterations. Exactly the same bug
 * class as the OP_SIZE fix earlier this session (a uint32 length field
 * read via a 64-bit instruction) -- found by grepping bitcoin_interp.asm
 * for the same `mov rcx, [reg]` pattern once the first instance's shape
 * was known, not just from this one crash.
 *
 * Each opcode's scratch slot is reused across calls (never cleared), so
 * each test here deliberately "poisons" the target opcode's slot with a
 * LONG all-nonzero-byte element first (a legitimate use -- the poisoning
 * call itself must succeed cleanly), then immediately follows with a
 * SHORT element through the SAME opcode -- the short call's copy of the
 * length field picks up the long call's leftover data bytes as garbage.
 * Under the bug this makes stack_push try to copy an ~2^32-2^64-byte
 * "string" into a 528-byte buffer -- a near-immediate SIGSEGV, not a
 * clean error return -- so every case here runs in a forked child and is
 * asserted via the child's exit status (crashed vs completed cleanly),
 * not just its return value. Verified via `git stash` that all five
 * reliably SIGSEGV the child against the pre-fix interpreter and complete
 * cleanly against the fix.
 *
 * SECOND bug found while writing this test: even with the length-field
 * fix in place, OP_ROLL still crashed every time -- a wholly separate,
 * unconditional bug (not data-dependent) in the same handler: `mov rdi,
 * [r12+8]` loads the current stack-pointer VALUE instead of its ADDRESS
 * (`lea rdi, [r12+8]`, the convention used at every other call site in
 * this file) before calling stack_elem_ptr/stack_erase_index/stack_push
 * -- the latter two dereference that "pointer" as real memory, so a
 * garbage small integer there SIGSEGVs immediately. OP_PICK shares this
 * same handler and inherited the identical bug via stack_dup_index. Fixed
 * alongside the length-field bug once the test caught it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/wait.h>
#include <unistd.h>

#define ELEM_SIZE 528
#define ELEM_DATA_OFF 4
#define MAX_STACK 1000

struct script_state {
    uint8_t* main_elems; size_t main_sp;
    uint8_t* alt_elems;  size_t alt_sp;
    uint8_t* script;     size_t script_len;
    int      sigversion; uint64_t flags;
    uint8_t* work;       size_t work_cap;
    uint64_t* error_out;
    void*    checksig_ctx;
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t,
                            const uint8_t*, size_t, const void*);
};
extern int script_eval(struct script_state* st);

static uint8_t g_main[MAX_STACK*ELEM_SIZE];
static uint8_t g_alt[MAX_STACK*ELEM_SIZE];

/* Runs `script` (already-assembled bytes) via script_eval in a FORKED
 * child -- the exact bug under test crashes the process, so isolating each
 * attempt in its own child lets the parent report a clean FAIL (via the
 * child's wait status) instead of taking the whole test binary down. */
static int run_forked(const uint8_t* script, size_t slen){
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid == 0){
        memset(g_main, 0, sizeof g_main);
        memset(g_alt, 0, sizeof g_alt);
        struct script_state s; memset(&s, 0, sizeof s);
        uint64_t err = 0;
        s.main_elems = g_main; s.main_sp = 0;
        s.alt_elems = g_alt; s.alt_sp = 0;
        s.script = (uint8_t*)script; s.script_len = slen;
        s.flags = 0; s.error_out = &err;
        int r = script_eval(&s);
        _exit(r ? 0 : 2);   /* 0 = clean accept, 2 = clean (non-crash) reject */
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) return -WTERMSIG(status);   /* negative = crashed */
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -999;
}

static uint8_t* put_push(uint8_t* p, const uint8_t* data, uint8_t n){
    *p++ = n; memcpy(p, data, n); return p + n;
}
static uint8_t* put_op(uint8_t* p, uint8_t op){ *p++ = op; return p; }

static int failures = 0;
static void ck(const char* label, int got, int expect_crash){
    int crashed = (got < 0);
    int ok = crashed == expect_crash;
    printf("%s %s: %s (raw=%d)\n", ok ? "PASS" : "FAIL", label,
           crashed ? "crashed" : "completed cleanly", got);
    if (!ok) failures++;
}

static const uint8_t LONG8[8]  = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x01,0x11};
#define OP_TOALTSTACK   0x6b
#define OP_FROMALTSTACK 0x6c
#define OP_DROP         0x75
#define OP_2ROT         0x71
#define OP_ROLL         0x7a
#define OP_TUCK         0x7d
#define OP_0            0x00

int main(void){
    uint8_t buf[256]; uint8_t* p;

    /* OP_TOALTSTACK: poison interp_tmp with a long push+TOALTSTACK+
     * FROMALTSTACK+DROP round trip, then a short TOALTSTACK triggers it. */
    p = buf;
    p = put_push(p, LONG8, 8);
    p = put_op(p, OP_TOALTSTACK);
    p = put_op(p, OP_FROMALTSTACK);
    p = put_op(p, OP_DROP);
    p = put_push(p, (const uint8_t[]){0x99}, 1);
    p = put_op(p, OP_TOALTSTACK);
    ck("OP_TOALTSTACK", run_forked(buf, p - buf), 0);

    /* OP_FROMALTSTACK: short element parked on the altstack first (while
     * interp_tmp is still fresh/zero, so that push is safe), THEN
     * interp_tmp is poisoned via a long push+TOALTSTACK+FROMALTSTACK+DROP
     * round trip, THEN the short element is pulled back -- that final
     * FROMALTSTACK is the one under test. */
    p = buf;
    p = put_push(p, (const uint8_t[]){0x99}, 1);
    p = put_op(p, OP_TOALTSTACK);           /* short value parked on altstack */
    p = put_push(p, LONG8, 8);
    p = put_op(p, OP_TOALTSTACK);
    p = put_op(p, OP_FROMALTSTACK);          /* poisons interp_tmp with LONG8 */
    p = put_op(p, OP_DROP);
    p = put_op(p, OP_FROMALTSTACK);          /* trigger: pulls the short value back */
    ck("OP_FROMALTSTACK", run_forked(buf, p - buf), 0);

    /* OP_ROLL: "roll index 0" (rolls the bottom-most remaining element to
     * the top -- a legitimate, if trivial, roll) exercises elem_tmp0's
     * copy-through-scratch path. First on a long element (poisons
     * elem_tmp0 safely), then with a short element newly underneath it
     * (trigger). */
    p = buf;
    p = put_push(p, LONG8, 8);                     /* stack: [LONG8] */
    p = put_op(p, OP_0);                            /* stack: [LONG8, 0] */
    p = put_op(p, OP_ROLL);      /* poisons elem_tmp0; stack: [LONG8] */
    p = put_push(p, (const uint8_t[]){0x77}, 1);    /* stack: [LONG8, 0x77] */
    p = put_op(p, OP_0);                             /* stack: [LONG8, 0x77, 0] */
    p = put_op(p, OP_ROLL);      /* trigger: rolls the short 0x77 element */
    ck("OP_ROLL", run_forked(buf, p - buf), 0);

    /* OP_PICK: shares OP_ROLL's handler up to the ROLL/PICK branch, so it
     * hit the SAME &sp-pointer bug (`mov` instead of `lea`) found above --
     * unconditional, not data-dependent like the length bug, so a single
     * call is enough to prove it. */
    p = buf;
    p = put_push(p, LONG8, 8);   /* stack: [LONG8] */
    p = put_op(p, OP_0);          /* stack: [LONG8, 0] */
    p = put_op(p, 0x79 /* OP_PICK */);
    ck("OP_PICK", run_forked(buf, p - buf), 0);

    /* OP_2ROT: needs 6 items; rotate long items first (poisons elem_tmp0/1
     * with LONG8-shaped data), then a second round with short items
     * (trigger). */
    p = buf;
    for (int i=0;i<6;i++) p = put_push(p, LONG8, 8);
    p = put_op(p, OP_2ROT);      /* poisons elem_tmp0/elem_tmp1; still 6 elems */
    for (int i=0;i<6;i++) p = put_op(p, OP_DROP);   /* clear all 6 */
    for (int i=0;i<6;i++) p = put_push(p, (const uint8_t[]){(uint8_t)(0x60+i)}, 1);
    p = put_op(p, OP_2ROT);
    ck("OP_2ROT", run_forked(buf, p - buf), 0);

    /* OP_TUCK: x1 x2 -> x2 x1 x2, uses elem_tmp2/elem_tmp3. Long pair
     * first (poison), short pair second (trigger). */
    p = buf;
    p = put_push(p, LONG8, 8);
    p = put_push(p, LONG8, 8);
    p = put_op(p, OP_TUCK);
    for (int i=0;i<3;i++) p = put_op(p, OP_DROP);
    p = put_push(p, (const uint8_t[]){0x55}, 1);
    p = put_push(p, (const uint8_t[]){0x66}, 1);
    p = put_op(p, OP_TUCK);
    ck("OP_TUCK", run_forked(buf, p - buf), 0);

    printf("\n%s (%d failures)\n", failures==0 ? "ALL TESTS PASSED" : "TESTS FAILED", failures);
    return failures ? 1 : 0;
}
