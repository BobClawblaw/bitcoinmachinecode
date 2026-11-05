/* C port of Bitcoin Core v31.1's script-number semantics, line for line:
 *   CScriptNum(vch, fRequireMinimal, nMaxNumSize)   script/script.h:245
 *   CScriptNum::set_vch                              script/script.h:375
 *   CScriptNum::serialize                            script/script.h:341
 *   CastToBool                                       script/interpreter.cpp:36
 *   EvalScript numeric opcodes, OP_WITHIN            script/interpreter.cpp:919-1009
 *   OP_CHECKLOCKTIMEVERIFY / OP_CHECKSEQUENCEVERIFY  script/interpreter.cpp:522-600
 *   CheckLockTime / CheckSequence                    script/interpreter.cpp:1745, :1782
 * Error codes are Core's ScriptError enum values (script/script_error.h). */
#ifndef CORE_SCRIPTNUM_H
#define CORE_SCRIPTNUM_H
#include <stdint.h>
#include <string.h>

#define C_ERR_OK 0
#define C_ERR_SCRIPTNUM 4
#define C_ERR_NUMEQUALVERIFY 15
#define C_ERR_INVALID_STACK_OPERATION 18
#define C_ERR_NEGATIVE_LOCKTIME 21
#define C_ERR_UNSATISFIED_LOCKTIME 22

#define C_FLAG_MINIMALDATA (1ULL << 6)
#define C_FLAG_CLTV        (1ULL << 9)
#define C_FLAG_CSV         (1ULL << 10)

/* returns 1 and *out, or 0 for "throws scriptnum_error" */
static int core_snum_decode(const uint8_t* v, size_t n, int fRequireMinimal,
                            size_t nMaxNumSize, int64_t* out){
    if (n > nMaxNumSize) return 0;                       /* "script number overflow" */
    if (fRequireMinimal && n > 0){
        if ((v[n - 1] & 0x7f) == 0){
            if (n <= 1 || (v[n - 2] & 0x80) == 0) return 0;   /* "non-minimally encoded" */
        }
    }
    if (n == 0){ *out = 0; return 1; }
    int64_t result = 0;
    for (size_t i = 0; i != n; ++i)
        result |= (int64_t)((uint64_t)v[i] << (8 * i));
    if (v[n - 1] & 0x80){
        *out = -((int64_t)(result & ~(0x80ULL << (8 * (n - 1)))));
        return 1;
    }
    *out = result;
    return 1;
}

static size_t core_snum_serialize(int64_t value, uint8_t out[10]){
    if (value == 0) return 0;
    size_t n = 0;
    const int neg = value < 0;
    uint64_t absvalue = neg ? ~(uint64_t)value + 1 : (uint64_t)value;
    while (absvalue){ out[n++] = (uint8_t)(absvalue & 0xff); absvalue >>= 8; }
    if (out[n - 1] & 0x80) out[n++] = neg ? 0x80 : 0;
    else if (neg) out[n - 1] |= 0x80;
    return n;
}

static int core_cast_to_bool(const uint8_t* v, size_t n){
    for (size_t i = 0; i < n; i++){
        if (v[i] != 0){
            if (i == n - 1 && v[i] == 0x80) return 0;
            return 1;
        }
    }
    return 0;
}

/* A tiny stack: elements of up to 16 bytes (numeric operands only). */
typedef struct { uint8_t d[16]; size_t n; } c_elem;
typedef struct { c_elem e[8]; size_t sp; } c_stack;

static void c_push_num(c_stack* s, int64_t v){
    uint8_t b[10]; size_t n = core_snum_serialize(v, b);
    memcpy(s->e[s->sp].d, b, n); s->e[s->sp].n = n; s->sp++;
}

/* Executes ONE opcode over stack s. Returns C_ERR_OK or the error. */
static int core_exec1(c_stack* s, uint8_t op, uint64_t flags,
                      uint32_t tx_locktime, uint32_t in_seq, uint32_t tx_version){
    const int fmin = (flags & C_FLAG_MINIMALDATA) != 0;
    switch (op){
    case 0x8b: case 0x8c: case 0x8f: case 0x90: case 0x91: case 0x92: {
        if (s->sp < 1) return C_ERR_INVALID_STACK_OPERATION;
        int64_t bn; c_elem* t = &s->e[s->sp - 1];
        if (!core_snum_decode(t->d, t->n, fmin, 4, &bn)) return C_ERR_SCRIPTNUM;
        switch (op){
        case 0x8b: bn += 1; break;
        case 0x8c: bn -= 1; break;
        case 0x8f: bn = -bn; break;
        case 0x90: if (bn < 0) bn = -bn; break;
        case 0x91: bn = (bn == 0); break;
        case 0x92: bn = (bn != 0); break;
        }
        s->sp--; c_push_num(s, bn); return C_ERR_OK; }
    case 0x93: case 0x94: case 0x9a: case 0x9b: case 0x9c: case 0x9d: case 0x9e:
    case 0x9f: case 0xa0: case 0xa1: case 0xa2: case 0xa3: case 0xa4: {
        if (s->sp < 2) return C_ERR_INVALID_STACK_OPERATION;
        int64_t bn1, bn2, bn = 0;
        c_elem* a = &s->e[s->sp - 2]; c_elem* b = &s->e[s->sp - 1];
        if (!core_snum_decode(a->d, a->n, fmin, 4, &bn1)) return C_ERR_SCRIPTNUM;
        if (!core_snum_decode(b->d, b->n, fmin, 4, &bn2)) return C_ERR_SCRIPTNUM;
        switch (op){
        case 0x93: bn = bn1 + bn2; break;
        case 0x94: bn = bn1 - bn2; break;
        case 0x9a: bn = (bn1 != 0 && bn2 != 0); break;
        case 0x9b: bn = (bn1 != 0 || bn2 != 0); break;
        case 0x9c: case 0x9d: bn = (bn1 == bn2); break;
        case 0x9e: bn = (bn1 != bn2); break;
        case 0x9f: bn = (bn1 < bn2); break;
        case 0xa0: bn = (bn1 > bn2); break;
        case 0xa1: bn = (bn1 <= bn2); break;
        case 0xa2: bn = (bn1 >= bn2); break;
        case 0xa3: bn = (bn1 < bn2 ? bn1 : bn2); break;
        case 0xa4: bn = (bn1 > bn2 ? bn1 : bn2); break;
        }
        s->sp -= 2; c_push_num(s, bn);
        if (op == 0x9d){
            c_elem* t = &s->e[s->sp - 1];
            if (core_cast_to_bool(t->d, t->n)) s->sp--;
            else return C_ERR_NUMEQUALVERIFY;
        }
        return C_ERR_OK; }
    case 0xa5: {
        if (s->sp < 3) return C_ERR_INVALID_STACK_OPERATION;
        int64_t bn1, bn2, bn3;
        c_elem* x = &s->e[s->sp - 3]; c_elem* mn = &s->e[s->sp - 2]; c_elem* mx = &s->e[s->sp - 1];
        if (!core_snum_decode(x->d, x->n, fmin, 4, &bn1)) return C_ERR_SCRIPTNUM;
        if (!core_snum_decode(mn->d, mn->n, fmin, 4, &bn2)) return C_ERR_SCRIPTNUM;
        if (!core_snum_decode(mx->d, mx->n, fmin, 4, &bn3)) return C_ERR_SCRIPTNUM;
        int f = (bn2 <= bn1 && bn1 < bn3);
        s->sp -= 3; c_push_num(s, f ? 1 : 0); return C_ERR_OK; }
    case 0xb1: {                                               /* CLTV */
        if (!(flags & C_FLAG_CLTV)) return C_ERR_OK;
        if (s->sp < 1) return C_ERR_INVALID_STACK_OPERATION;
        int64_t nLockTime; c_elem* t = &s->e[s->sp - 1];
        if (!core_snum_decode(t->d, t->n, fmin, 5, &nLockTime)) return C_ERR_SCRIPTNUM;
        if (nLockTime < 0) return C_ERR_NEGATIVE_LOCKTIME;
        /* CheckLockTime */
        const int64_t TH = 500000000;
        if (!(((int64_t)tx_locktime < TH && nLockTime < TH) ||
              ((int64_t)tx_locktime >= TH && nLockTime >= TH))) return C_ERR_UNSATISFIED_LOCKTIME;
        if (nLockTime > (int64_t)tx_locktime) return C_ERR_UNSATISFIED_LOCKTIME;
        if (in_seq == 0xffffffffu) return C_ERR_UNSATISFIED_LOCKTIME;
        return C_ERR_OK; }
    case 0xb2: {                                               /* CSV */
        if (!(flags & C_FLAG_CSV)) return C_ERR_OK;
        if (s->sp < 1) return C_ERR_INVALID_STACK_OPERATION;
        int64_t nSequence; c_elem* t = &s->e[s->sp - 1];
        if (!core_snum_decode(t->d, t->n, fmin, 5, &nSequence)) return C_ERR_SCRIPTNUM;
        if (nSequence < 0) return C_ERR_NEGATIVE_LOCKTIME;
        if ((nSequence & (int64_t)(1U << 31)) != 0) return C_ERR_OK;
        /* CheckSequence */
        const int64_t txToSequence = (int64_t)in_seq;
        if (tx_version < 2) return C_ERR_UNSATISFIED_LOCKTIME;   /* uint32_t version */
        if (txToSequence & (int64_t)(1U << 31)) return C_ERR_UNSATISFIED_LOCKTIME;
        const uint32_t mask = (1U << 22) | 0x0000ffffU;
        const int64_t txm = txToSequence & mask;
        const int64_t nm = nSequence & (int64_t)mask;
        const int64_t TF = 1 << 22;
        if (!((txm < TF && nm < TF) || (txm >= TF && nm >= TF))) return C_ERR_UNSATISFIED_LOCKTIME;
        if (nm > txm) return C_ERR_UNSATISFIED_LOCKTIME;
        return C_ERR_OK; }
    }
    return -1;
}
#endif
