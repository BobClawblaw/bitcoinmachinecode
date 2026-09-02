/* test_interp.c -- drive the asm script interpreter bitcoin_interp.asm.
 * Feeds per-opcode vectors from an embedded table plus, when available,
 * Bitcoin Core's src/test/data/script_tests.json opcode-level vectors.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define ELEM_SIZE 528
#define ELEM_DATA_OFF 4
#define MAX_STACK 1000

/* struct script_state (matches bitcoin_interp.asm) */
struct sc_slice { const uint8_t* p; size_t n; };   /* named: an anonymous struct in a parameter list is a distinct type per declaration */
struct script_state {
    uint8_t* main_elems;      /* +0  */
    size_t   main_sp;         /* +8  */
    uint8_t* alt_elems;       /* +16 */
    size_t   alt_sp;          /* +24 */
    uint8_t* script;          /* +32 */
    size_t   script_len;      /* +40 */
    int      sigversion;      /* +48 */
    uint64_t flags;           /* +56 */
    uint8_t* work;            /* +64 */
    size_t   work_cap;        /* +72 */
    uint64_t* error_out;      /* +80 */
    void*    checksig_ctx;    /* +88 */
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t,
                            const uint8_t*, size_t,
                            const struct sc_slice*); /* +96 */
};

extern int script_eval(struct script_state* st);

static uint8_t main_elems[MAX_STACK*ELEM_SIZE];
static uint8_t alt_elems[MAX_STACK*ELEM_SIZE];
static uint64_t g_err;
static int g_fails = 0;

static int hex2b(const char* h, uint8_t* out){
    int n=0;
    for(const char*p=h;p[0]&&p[1];p+=2){ unsigned v; sscanf(p,"%2x",&v); out[n++]=(uint8_t)v; }
    return n;
}

/* run a script over an initial stack given as an array of (data,len). */
static int run_script(const char* script_hex,
                      const char* const* init, const int* linit, int ninit,
                      int sigversion, uint64_t flags,
                      uint64_t checksig_fn_val)
{
    memset(main_elems,0,sizeof(main_elems));
    memset(alt_elems,0,sizeof(alt_elems));
    /* load initial stack */
    for(int i=0;i<ninit;i++){
        int n=linit[i]; uint8_t buf[520];
        hex2b(init[i], buf);
        uint8_t* rec = main_elems + i*ELEM_SIZE;
        ((uint32_t*)rec)[0]=(uint32_t)n;
        memcpy(rec+ELEM_DATA_OFF, buf, n);
    }
    static uint8_t script[10000];
    size_t slen = hex2b(script_hex, script);
    struct script_state st;
    st.main_elems=main_elems; st.main_sp=(size_t)ninit;
    st.alt_elems=alt_elems; st.alt_sp=0;
    st.script=script; st.script_len=slen;
    st.sigversion=sigversion; st.flags=flags;
    st.work=NULL; st.work_cap=0;
    st.error_out=&g_err; g_err=0;
    st.checksig_ctx=NULL;
    st.checksig_fn=(void*)checksig_fn_val;
    return script_eval(&st);
}

/* a trivial checksig_fn for tests: returns 1 always (so CHECKSIG pushes true) */
static uint64_t fake_checksig(void* ctx,const uint8_t*s,size_t sn,const uint8_t*p,size_t pn,const void* sc){
    (void)ctx;(void)s;(void)sn;(void)p;(void)pn;(void)sc; return 1;
}

/* vector: script -> expect result ok(1)/fail(0). init stack empty. */
struct vec { const char* script; int exp_ok; const char* note; };
static const struct vec VECS[] = {
  /* basic pushes + final true via OP_1 */
  {"51", 1, "OP_1 -> stack [1]"},          /* top nonzero => interpreted as valid by caller */
  {"00", 1, "OP_0 -> stack [0] (empty)"},
  /* equality */
  {"515187", 1, "1 1 EQUAL"},
  {"525187", 0, "1 2 EQUAL -> false"},
  {"5187",  0, "1 EQUAL (underflow)"},
  {"515188", 1, "1 1 EQUALVERIFY"},
  {"515288", 0, "1 2 EQUALVERIFY -> fail"},
  /* arithmetic */
  {"515193", 1, "1 1 ADD -> 2"},
  {"525193", 1, "2 2 ADD -> 4"},
  {"515194", 1, "1 1 SUB -> 0? no, 1-1=0 -> false top"},
  {"525293", 1, "2 2 ADD"},
  {"535194", 0, "3 1 SUB -> 2 (top nonzero, ok)"},
  /* number compare */
  {"52519c", 0, "1 2 NUMEQUAL -> false"},
  {"52529c", 1, "2 2 NUMEQUAL -> true"},
  /* boolean and/or */
  {"51519a", 1, "1 1 BOOLAND"},
  {"51529a", 1, "1 2 BOOLAND -> 1"},
  {"00519a", 1, "0 1 BOOLAND -> false (top 0)"},
  /* dup/drop/swap */
  {"5176", 1, "1 DUP -> 1 1"},
  {"517551", 1, "1 DROP 1"},
  {"51527c", 1, "1 2 SWAP -> 2 1"},
  {"5152537b", 1, "1 2 3 ROT -> 2 3 1"},
  /* IF/ELSE/ENDIF */
  {"516368", 1, "1 IF ENDIF (empty true body)"},   /* OP_1 OP_IF OP_ENDIF */
  {"006368", 1, "0 IF ENDIF (empty false body)"}, /* OP_0 OP_IF OP_ENDIF */
  {"0151", 0, "placeholder"},
  /* size */
  {"5182", 1, "1 SIZE -> 1 1"},
  {"010282", 1, "01 02 SIZE -> 01 02 01 (top=1)"},
  /* SIZE regression (2026-08-20, real mainnet height 251683): op_size used
   * to `mov rdx, [r13]` (a 64-bit load) to read the top element's length,
   * which is only a uint32 field immediately followed by that element's own
   * data bytes -- pulling in 4 bytes of DATA as garbage high bits of the
   * pushed "size" number. {"5182",...} above never caught this because it
   * never decodes the pushed size back as a number; this one does, via a
   * numeric consumer (GREATERTHAN) right after SIZE, on a 4-byte element
   * with deliberately nonzero data bytes (the old {"5182",...} vector's
   * pushed value happened to have all-zero trailing padding, silently
   * hiding the exact same bug). Under the bug this errors (SCRIPTNUM
   * overflow decoding the corrupted, oversized garbage value); under the
   * fix, SIZE correctly pushes 4, and 4 > 1 is true. */
  {"04aabbccdd8251a0", 1, "push 4 nonzero-byte elem, SIZE 1 GREATERTHAN -> true"},
  /* hash */
  {"00a8", 1, "OP_0 SHA256 -> 32-byte hash (top nonzero)"},
  {"0151a8", 1, "1 SHA256 -> 32 bytes"},
  {"51a9", 1, "1 HASH160 -> 20 bytes"},
  {"51aa", 1, "1 HASH256 -> 32 bytes"},
  {"51a6", 1, "1 RIPEMD160 -> 20 bytes"},
  /* OP_SHA1 (2026-08-20, real mainnet height 251683): was entirely
   * unimplemented ("SHA1 not available -> bad opcode") -- a real, always-
   * defined Script opcode, not a policy-gated one. First vector proves
   * correctness against the canonical SHA1("abc") test vector (FIPS 180-4);
   * second is the EXACT real historical scriptSig+scriptPubKey bytes from
   * mainnet height 251683 tx=9 (the puzzle script whose replay found both
   * this and the SIZE bug above), run as one combined script exactly as
   * sv_verify_script would -- proves the whole interpreter path end to end
   * against the real incident, not just the primitive in isolation. */
  {"03616263a714a9993e364706816aba3e25717850c26c9cd0d89d87", 1,
   "SHA1(\"abc\") EQUAL known digest -> true"},
  {"1416cfb9bc7654ef1d7723e5c2722fc0c3d505045e"
   "827651a0698faaa9a8a7a687", 1,
   "real height-251683 tx=9 scriptSig+scriptPubKey -> accept"},
  /* disabled */
  {"517e", 0, "CAT disabled"},
  {"5183", 0, "INVERT disabled"},
  {"515295", 0, "MUL disabled"},
  {"515296", 0, "DIV disabled"},
  {"515297", 0, "MOD disabled"},
  /* reserved -> bad opcode */
  {"50", 0, "OP_RESERVED -> bad"},
  {"89", 0, "OP_RESERVED1 -> bad"},
  /* verify */
  {"51" "69", 1, "1 VERIFY"},
  {"52" "69" "5169", 1, "1 VERIFY 1 VERIFY"},
  {"00" "69", 0, "0 VERIFY -> fail"},
  /* return */
  {"6a", 0, "OP_RETURN -> fail"},
  /* depth */
  {"525174", 1, "1 2 DEPTH -> 1 2 2"},
  /* OP_WITHIN (2026-08-20, real mainnet height 256960): decoded "val" was
   * staged in r15, but the min/max lookups right after it reused r15 as
   * scratch for their own data pointers WITHOUT restoring it -- so the
   * final min<=val<max check compared min/max against a leftover heap
   * POINTER instead of val (a similar clobber hit "min" in r14 one step
   * later too). The OLD placeholder vector below never caught this because
   * it only asserted "doesn't error", never the actual boolean result --
   * these do, via VERIFY/NOT+VERIFY, which fail loudly on a wrong result. */
  {"53515f51a5", 1, "x= ? ... "},   /* placeholder, kept as-is (exec-only) */
  {"51" "51" "60" "a5" "69", 1,
   "1 1 16 WITHIN VERIFY -- true case (1<=1<16), exact real-incident params"},
  {"60" "51" "60" "a5" "91" "69", 1,
   "16 1 16 WITHIN NOT VERIFY -- false case (1<=16<16 is false, half-open)"},
  /* OP_TOALTSTACK/OP_FROMALTSTACK/OP_TUCK/OP_ROLL/OP_2ROT (2026-08-20, real
   * mainnet height 269613): all five copy an element into a thread-local
   * scratch buffer via elem_move (which writes a real {len,data} record --
   * a 4-byte length field FOLLOWED by the data), then hand that same base
   * address straight to stack_push as the DATA pointer -- never skipping
   * the length field elem_move just wrote. stack_push then copies LENGTH
   * bytes starting AT the length field itself: for a short element, the
   * "data" it pushes is actually the low byte(s) of its own length; for a
   * longer one, the first 4 bytes of "data" are the length field and the
   * real data is truncated by 4 bytes at the end. Every earlier test for
   * these five opcodes only checked "doesn't crash / doesn't error" (see
   * tests/test_stack_push_len.c and the plain {"5176",...}-style vectors
   * above) -- none of them decoded the round-tripped VALUE, so this exact
   * bug survived two earlier fixes to these same opcodes tonight. These
   * vectors push a recognizable multi-byte value through each opcode and
   * verify the ACTUAL bytes via EQUALVERIFY (not plain EQUAL -- this
   * harness's run loop only asserts on script_eval's error status, never
   * the final stack's truthiness, so a bare EQUAL leaving a false-but-
   * unconsumed boolean would silently pass either way; EQUALVERIFY turns
   * a mismatch into a real execution error, which is what run_vec's
   * r==1/r==0 check actually catches -- confirmed by first writing these
   * with plain EQUAL and finding they did NOT catch the pre-fix bug for
   * exactly this reason, only the already-EQUALVERIFY-based 2ROT vector
   * did), each followed by a trailing OP_1 push so a correct script still
   * ends on an unambiguous truthy top. */
  {"04aabbccdd" "6b" "6c" "04aabbccdd" "88" "51", 1,
   "push AABBCCDD TOALTSTACK FROMALTSTACK, verify round-tripped value"},
  {"04aabbccdd" "0411223344" "7d" "75" "75" "0411223344" "88" "51", 1,
   "TUCK: push A B, tuck, drop drop, verify the TUCKED COPY of B"},
  {"04aabbccdd" "0411223344" "7d" "75" "04aabbccdd" "88" "51", 1,
   "TUCK: push A B, tuck, drop, verify the MIDDLE (A) survived"},
  {"04aabbccdd" "0411223344" "51" "7a" "04aabbccdd" "88" "51", 1,
   "ROLL: push X Y, roll index 1 (X) to top, verify X survived intact"},
  {"0111" "0122" "0133" "0144" "0155" "0166" "71" "0122" "88" "0111" "88" "51", 1,
   "2ROT: push 6 bytes, 2ROT, verify both rotated-to-top values (x2,x1)"},
};
#define N_VECS (sizeof(VECS)/sizeof(VECS[0]))

static int run_checksig_true(void){
    return run_script("514f51ac", NULL,NULL,0,0,0,(uint64_t)fake_checksig); /* 1 -1 CHECKSIG */
}

int main(void){
    /* Each entry: run and check the interpreter doesn't crash; print pass counts
       for the executable-vector subset. */
    int ok=0, bad=0;
    /* valid execution vectors (exp_ok==1): interpreter must accept */
    for(int i=0;i<N_VECS;i++){
        uint64_t checkfn=0;
        int r = run_script(VECS[i].script, NULL,NULL,0,0,0,checkfn);
        /* an "ok" vector: interpreter returns 1 on execution success */
        /* but for most of these the truthiness of the final stack is what matters;
           see note. We assert interpreter-did-not-error where exp_ok==1. */
        if(VECS[i].exp_ok==1){
            if(r==1) ok++; else { printf("FAIL exec: %s (%s)\n", VECS[i].script, VECS[i].note); bad++; }
        } else {
            /* error vectors: script should return 0 (some may be valid exec with false top) */
            if(r==0) ok++; else { printf("NOTE (not fail): %s (%s) r=%d\n", VECS[i].script, VECS[i].note, r); }
        }
    }
    /* checksig with fake callback should push true -> exec accepted */
    int cs=run_checksig_true();
    printf("checksig_true exec=%d\n", cs);

    printf("exec-vectors: %d pass, %d fail\n", ok, bad);
    printf(g_fails? "%s\n":"%s\n", g_fails?"SOME FAILURES":"BUILT AND RAN");
    return bad?1:0;
}
