/* bitcoin_scriptverify.c -- VerifyScript driven by the ASM interpreter.
 *
 * Stage A of PLAN_SCRIPT_VERIFY.md: the single entry point block connection
 * will call. It is a THIN WRAPPER by design -- all script semantics live in
 * bitcoin_interp.asm's script_eval, which is the authoritative consensus
 * implementation. This file only does what VerifyScript does around
 * EvalScript: run scriptSig, run scriptPubKey over the resulting stack, check
 * the resolved stack, handle BIP16 P2SH, and enforce CLEANSTACK.
 *
 * WHY IT EXISTS ALONGSIDE bitcoin_verify.c. That file implements the same
 * VerifyScript logic against its OWN private C EvalScript. Two interpreters
 * cannot both be consensus. The asm one was chosen, so this file replaces
 * bitcoin_verify.c's role over time; until then bitcoin_verify.c is kept as a
 * differential reference and both are run over the same vectors
 * (tests/test_scriptverify_parity.c). Identical signature, identical return
 * codes, so the comparison is exact rather than approximate.
 *
 * SCOPE, STATED PLAINLY. Legacy signatures only, and only SIGHASH_ALL,
 * because sighash_all is the only legacy sighash this codebase has (see
 * PLAN_SCRIPT_VERIFY.md's Stage B correction). Any other hashtype returns
 * SCRIPT_ERR_SIG_HASHTYPE rather than being silently mis-hashed. Witness
 * dispatch is not here yet and callers must not assume it: sv_verify_script
 * takes no amount and no witness stack, exactly like the function it mirrors.
 */
#include <stdint.h>
#include <string.h>
#include "script_error_codes.h"

/* ---- interpreter ABI (bitcoin_interp.asm) ---- */
#define ELEM_SIZE     528
#define ELEM_DATA_OFF 4
#define MAX_STACK     1000
#define SIGV_BASE     0

struct script_state {
    uint8_t*  main_elems; size_t main_sp;
    uint8_t*  alt_elems;  size_t alt_sp;
    uint8_t*  script;     size_t script_len;
    int       sigversion; uint64_t flags;
    uint8_t*  work;       size_t work_cap;
    uint64_t* error_out;
    void*     checksig_ctx;
    uint64_t (*checksig_fn)(void*, const uint8_t*, size_t,
                            const uint8_t*, size_t, const void*);
};
extern int script_eval(struct script_state* st);

/* ---- audited crypto layer, the same primitives bitcoin_verify.c uses ---- */
extern int  sighash_all(uint8_t out[32], const uint8_t* tx, unsigned long txlen,
                        unsigned long input_index, const uint8_t* script,
                        unsigned long script_len, uint8_t* preimg, unsigned long cap);
extern int  der_parse_sig(const uint8_t* sig, unsigned long siglen,
                          uint64_t r[4], uint64_t s[4], uint32_t* hashtype);
extern int  pubkey_parse(const uint8_t* pub, unsigned long publen,
                         uint64_t qx[4], uint64_t qy[4]);
extern int  ecdsa_verify(const uint64_t z[4], const uint64_t r[4], const uint64_t s[4],
                         const uint64_t Qx[4], const uint64_t Qy[4]);
extern void be_to_limbs(uint64_t out[4], const uint8_t* be, unsigned long n);

/* ---- script verification flags we act on directly ---- */
#define SV_P2SH        (1ULL<<0)
#define SV_SIGPUSHONLY (1ULL<<5)
#define SV_CLEANSTACK  (1ULL<<8)

/* ------------------------------------------------------------------ stack */
typedef struct { uint8_t* e; size_t sp; } sv_stack;

static uint8_t* sv_rec(sv_stack* s, size_t i){ return s->e + i*ELEM_SIZE; }
static uint32_t sv_len(sv_stack* s, size_t i){ return *(uint32_t*)sv_rec(s,i); }
static const uint8_t* sv_dat(sv_stack* s, size_t i){ return sv_rec(s,i)+ELEM_DATA_OFF; }

/* CastToBool: false only for empty, or a value that is entirely zero bytes
 * with an optional negative-zero sign bit on the last one. */
static int sv_true(sv_stack* s, size_t i){
    uint32_t n = sv_len(s,i);
    const uint8_t* d = sv_dat(s,i);
    for (uint32_t k=0;k<n;k++){
        if (d[k] != 0){
            if (k == n-1 && d[k] == 0x80) return 0;   /* negative zero */
            return 1;
        }
    }
    return 0;
}

/* --------------------------------------------------- legacy checksig hook */
struct sv_ctx {
    const uint8_t* tx; unsigned long txlen; unsigned long nIn;
    uint8_t* work; unsigned long workcap;
    int bad_hashtype;          /* sticky: an unsupported SIGHASH was seen */
};

static uint64_t sv_checksig(void* cptr, const uint8_t* sig, size_t siglen,
                            const uint8_t* pub, size_t publen, const void* slice){
    struct sv_ctx* c = (struct sv_ctx*)cptr;
    const struct { const uint8_t* p; size_t n; }* sc = slice;
    if (!siglen) return 0;                       /* empty sig: fail, not error */

    /* Only SIGHASH_ALL can be hashed correctly today. Flag anything else so
     * the caller reports SIG_HASHTYPE instead of silently checking the wrong
     * message -- a wrong-but-plausible hash would reject a VALID spend, and
     * during a chain replay that looks like chain corruption, not a gap. */
    uint8_t ht = sig[siglen-1];
    if ((ht & 0x1f) != 1 || (ht & 0x80)){ c->bad_hashtype = 1; return 0; }

    uint64_t r[4], s[4]; uint32_t dht;
    if (!der_parse_sig(sig, (unsigned long)siglen, r, s, &dht)) return 0;
    if (dht != 1){ c->bad_hashtype = 1; return 0; }

    uint8_t z[32];
    if (!sighash_all(z, c->tx, c->txlen, c->nIn, sc->p, (unsigned long)sc->n,
                     c->work, c->workcap)) return 0;
    uint64_t zl[4]; be_to_limbs(zl, z, 32);
    uint64_t qx[4], qy[4];
    if (!pubkey_parse(pub, (unsigned long)publen, qx, qy)) return 0;
    return (uint64_t)ecdsa_verify(zl, r, s, qx, qy);
}

/* ------------------------------------------------------------ script shape */
static int sv_is_p2sh(const uint8_t* spk, size_t spl){
    return spl==23 && spk[0]==0xa9 && spk[1]==0x14 && spk[22]==0x87;
}

/* OP_1NEGATE(0x4f) and OP_1..OP_16(0x51..0x60) count as pushes, per Core. */
static int sv_push_only(const uint8_t* s, size_t n){
    size_t i=0;
    while (i<n){
        uint8_t op = s[i];
        if (op==0x4f || (op>=0x51 && op<=0x60)){ i++; continue; }
        if (op <= 0x4e){
            if (op < 0x4b) i += 1u+op;
            else if (op==0x4b+1){ if (i+2>n) return 0; i += 2u + s[i+1]; }
            else if (op==0x4b+2){ if (i+3>n) return 0; i += 3u + (size_t)(s[i+1] | (s[i+2]<<8)); }
            else { if (i+5>n) return 0;
                   i += 5u + (size_t)(s[i+1] | (s[i+2]<<8) | (s[i+3]<<16) | ((uint32_t)s[i+4]<<24)); }
            continue;
        }
        return 0;
    }
    return i==n;
}

/* ------------------------------------------------------------------ driver */
static int sv_run(const uint8_t* script, size_t slen, sv_stack* st,
                  uint64_t flags, struct sv_ctx* ctx, int* err){
    static uint8_t alt[MAX_STACK*ELEM_SIZE];
    static uint8_t scratch[1<<16];
    static uint8_t scopy[20000];
    uint64_t e = SCRIPT_ERR_OK;
    if (slen > sizeof scopy){ *err = SCRIPT_ERR_SCRIPT_SIZE; return 0; }
    memcpy(scopy, script, slen);

    struct script_state s;
    memset(&s, 0, sizeof s);
    s.main_elems = st->e;  s.main_sp = st->sp;
    s.alt_elems  = alt;    s.alt_sp  = 0;
    s.script     = scopy;  s.script_len = slen;
    s.sigversion = SIGV_BASE;
    s.flags      = flags;
    s.work       = scratch; s.work_cap = sizeof scratch;
    s.error_out  = &e;
    s.checksig_ctx = ctx;
    s.checksig_fn  = sv_checksig;

    int ok = script_eval(&s);
    st->sp = s.main_sp;
    if (!ok){ *err = (int)e; return 0; }
    return 1;
}

int sv_verify_script(const unsigned char* scriptSig, unsigned long ssl,
                     const unsigned char* scriptPubKey, unsigned long spl,
                     uint64_t flags, unsigned long nIn,
                     const unsigned char* tx, unsigned long txlen,
                     unsigned char* work, unsigned long workcap){
    static uint8_t main_e[MAX_STACK*ELEM_SIZE];
    static uint8_t copy_e[MAX_STACK*ELEM_SIZE];
    sv_stack st = { main_e, 0 };
    sv_stack cp = { copy_e, 0 };
    struct sv_ctx ctx = { tx, txlen, nIn, work, workcap, 0 };
    int err = SCRIPT_ERR_OK;

    memset(main_e, 0, sizeof main_e);

    if ((flags & SV_SIGPUSHONLY) && !sv_push_only(scriptSig, ssl))
        return SCRIPT_ERR_SIG_PUSHONLY;

    if (!sv_run(scriptSig, ssl, &st, flags, &ctx, &err))
        return ctx.bad_hashtype ? SCRIPT_ERR_SIG_HASHTYPE : err;

    if (flags & SV_P2SH){
        memcpy(copy_e, main_e, sizeof copy_e);
        cp.sp = st.sp;
    }

    if (!sv_run(scriptPubKey, spl, &st, flags, &ctx, &err))
        return ctx.bad_hashtype ? SCRIPT_ERR_SIG_HASHTYPE : err;

    if (st.sp == 0) return SCRIPT_ERR_EVAL_FALSE;
    if (!sv_true(&st, st.sp-1)) return SCRIPT_ERR_EVAL_FALSE;

    /* ---- BIP16: the top scriptSig push is itself the script to run ---- */
    if ((flags & SV_P2SH) && sv_is_p2sh(scriptPubKey, spl)){
        if (!sv_push_only(scriptSig, ssl)) return SCRIPT_ERR_SIG_PUSHONLY;
        if (cp.sp == 0) return SCRIPT_ERR_INVALID_STACK_OPERATION;

        static uint8_t redeem[20000];
        uint32_t rl = sv_len(&cp, cp.sp-1);
        if (rl > sizeof redeem) return SCRIPT_ERR_PUSH_SIZE;
        memcpy(redeem, sv_dat(&cp, cp.sp-1), rl);

        cp.sp--;                          /* pop the serialised script */
        memcpy(main_e, copy_e, sizeof main_e);
        st.sp = cp.sp;

        if (!sv_run(redeem, rl, &st, flags, &ctx, &err))
            return ctx.bad_hashtype ? SCRIPT_ERR_SIG_HASHTYPE : err;
        if (st.sp == 0) return SCRIPT_ERR_EVAL_FALSE;
        if (!sv_true(&st, st.sp-1)) return SCRIPT_ERR_EVAL_FALSE;
    }

    /* CLEANSTACK is only meaningful with P2SH on, matching Core's assertion
     * that the two flags are not independent. */
    if ((flags & SV_CLEANSTACK) && st.sp != 1) return SCRIPT_ERR_CLEANSTACK;

    return SCRIPT_ERR_OK;
}
