/* tests/test_csv_disable_flag.c -- 2026-09-02: the CHECKSEQUENCEVERIFY
 * disable-flag test in bitcoin_interp.asm was `test rax, 0x80000000`. An
 * imm32 sign-extends, so it tested 0xFFFFFFFF80000000: a 5-byte operand with
 * any of bits 32-39 set and bit 31 clear was taken as "disabled" -> NOP ->
 * the script passed. Core tests bit 31 only (nSequence & (1<<31) as int64),
 * then masks the operand to its low 32 bits and ENFORCES it. Found by nasm's
 * -w+number-overflow when the assembler warnings became errors. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#define ELEM_SIZE 528
#define MAX_STACK 1000
#define SCRIPT_VERIFY_CHECKSEQUENCEVERIFY (1u<<10)
struct sc_slice { const uint8_t* p; size_t n; };
struct script_state {                 /* matches bitcoin_interp.asm */
    uint8_t* main_elems; size_t main_sp; uint8_t* alt_elems; size_t alt_sp;
    uint8_t* script; size_t script_len; int sigversion; uint64_t flags;
    uint8_t* work; size_t work_cap; uint64_t* error_out; void* checksig_ctx;
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t, const uint8_t*, size_t, const struct sc_slice*);
    uint32_t tx_locktime;   /* +104 */
    uint32_t in_sequence;   /* +108 */
    uint32_t tx_version;    /* +112 */
    uint32_t pad_;
};
extern int script_eval(struct script_state* st);
static uint8_t main_elems[MAX_STACK*ELEM_SIZE], alt_elems[MAX_STACK*ELEM_SIZE];
static int fails = 0;
static void ck(const char* l, int c){ printf("  %s %s\n", c ? "ok  " : "FAIL", l); if (!c) fails++; }
static int hex2b(const char* h, uint8_t* out){ int n=0; for(const char*p=h;p[0]&&p[1];p+=2){ unsigned v; sscanf(p,"%2x",&v); out[n++]=(uint8_t)v; } return n; }
/* run <script_hex> with tx version v and this input's nSequence s; 1 = script ran to the end with a true top */
static int run(const char* script_hex, uint32_t v, uint32_t s, uint64_t* err){
    static uint8_t script[64]; size_t n = (size_t)hex2b(script_hex, script);
    memset(main_elems, 0, sizeof main_elems); memset(alt_elems, 0, sizeof alt_elems);
    struct script_state st; memset(&st, 0, sizeof st);
    st.main_elems = main_elems; st.alt_elems = alt_elems; st.script = script; st.script_len = n;
    st.flags = SCRIPT_VERIFY_CHECKSEQUENCEVERIFY; st.error_out = err; *err = 0;
    st.tx_version = v; st.in_sequence = s;
    return script_eval(&st);
}
int main(void){
    uint64_t err;
    printf("== operand bit 31 set: disabled -> NOP -> passes (Core) ==\n");
    ck("0x80000000 CSV, v2, seq 0", run("050000008000b2", 2, 0, &err) == 1);
    printf("== operand 10 (blocks), v2 ==\n");
    ck("seq 0  -> unsatisfied", run("5ab2", 2, 0, &err) == 0);
    ck("seq 10 -> satisfied",   run("5ab2", 2, 10, &err) == 1);
    printf("== THE BUG: operand 2^32+10 -- bit 32 set, bit 31 CLEAR ==\n");
    /* Core: not disabled (only bit 31 counts), masked to 10, input seq 0 < 10 -> UNSATISFIED_LOCKTIME.
     * Before the fix ours saw the sign-extended mask, called it disabled, and passed. */
    ck("2^32+10 CSV, v2, seq 0 -> must FAIL like Core", run("050a00000001b2", 2, 0, &err) == 0);
    ck("2^32+10 CSV, v2, seq 10 -> satisfied (masked operand 10 <= 10)", run("050a00000001b2", 2, 10, &err) == 1);
    ck("2^32+10 CSV, v1 -> version < 2 fails", run("050a00000001b2", 1, 10, &err) == 0);
    printf("%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL PASS", fails);
    return fails ? 1 : 0;
}
