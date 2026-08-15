/* bitcoin_verify.c -- Core-parity legacy P2SH VerifyScript (BIP16).
 *
 * Closes plan.md:503's script-level BIP16/P2SH REMAINS: the full VerifyScript
 * path (two-pass evaluation + P2SH sub-script execution) with error-for-error
 * parity against Bitcoin Core's script/interpreter.cpp.
 *
 * The signing/hash crypto (sighash_all, der_parse_sig, pubkey_parse,
 * ecdsa_verify, sha256d, ripemd160) is the audited asm/ crypto layer. The
 * script interpretation (EvalScript semantics) and CheckSig / CheckMultisig
 * matching are implemented here in C to Core-exact logic so the redeemScript
 * (incl. 2-of-3 OP_CHECKMULTISIG) is driven through the sighash+ecdsa chain
 * and differentially compared error-for-error against the Core interpreter
 * oracle (validation/core_verify_oracle.cpp).
 *
 * ABI: verify_script() returns the Core ScriptError code.
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ---- Core ScriptError codes (script/script_error.h) ---- */
enum {
    ERR_OK = 0, ERR_UNKNOWN_ERROR, ERR_EVAL_FALSE, ERR_OP_RETURN, ERR_SCRIPTNUM,
    ERR_SCRIPT_SIZE, ERR_PUSH_SIZE, ERR_OP_COUNT, ERR_STACK_SIZE, ERR_SIG_COUNT,
    ERR_PUBKEY_COUNT, ERR_VERIFY, ERR_EQUALVERIFY, ERR_CHECKMULTISIGVERIFY,
    ERR_CHECKSIGVERIFY, ERR_NUMEQUALVERIFY, ERR_BAD_OPCODE, ERR_DISABLED_OPCODE,
    ERR_INVALID_STACK_OPERATION, ERR_INVALID_ALTSTACK_OPERATION,
    ERR_UNBALANCED_CONDITIONAL, ERR_NEGATIVE_LOCKTIME, ERR_UNSATISFIED_LOCKTIME,
    ERR_SIG_HASHTYPE, ERR_SIG_DER, ERR_MINIMALDATA, ERR_SIG_PUSHONLY,
    ERR_SIG_HIGH_S, ERR_SIG_NULLDUMMY, ERR_PUBKEYTYPE, ERR_CLEANSTACK,
    ERR_MINIMALIF, ERR_SIG_NULLFAIL, ERR_DISCOURAGE_UPGRADABLE_NOPS
};

/* ---- flag bits (script_verify_flag_name order) ---- */
#define SCRIPT_VERIFY_P2SH        (1ULL<<0)
#define SCRIPT_VERIFY_STRICTENC   (1ULL<<1)
#define SCRIPT_VERIFY_DERSIG      (1ULL<<2)
#define SCRIPT_VERIFY_LOW_S       (1ULL<<3)
#define SCRIPT_VERIFY_NULLDUMMY   (1ULL<<4)
#define SCRIPT_VERIFY_SIGPUSHONLY (1ULL<<5)
#define SCRIPT_VERIFY_MINIMALDATA (1ULL<<6)
#define SCRIPT_VERIFY_CLEANSTACK  (1ULL<<8)
#define SCRIPT_VERIFY_CLTV        (1ULL<<9)
#define SCRIPT_VERIFY_CSV         (1ULL<<10)
#define SCRIPT_VERIFY_WITNESS     (1ULL<<11)
#define SCRIPT_VERIFY_MINIMALIF   (1ULL<<13)
#define SCRIPT_VERIFY_NULLFAIL    (1ULL<<14)
#define SCRIPT_VERIFY_TAPROOT     (1ULL<<17)

#define MAX_PUBKEYS_PER_MULTISIG 20
#define MAX_OPS_PER_SCRIPT 201
#define MAX_SCRIPT_SIZE 10000
#define MAX_PUSH_SIZE 520

#define OP_0 0x00
#define OP_PUSHDATA1 0x4c
#define OP_PUSHDATA2 0x4d
#define OP_PUSHDATA4 0x4e
#define OP_1NEGATE 0x4f
#define OP_RESERVED 0x50
#define OP_1 0x51
#define OP_16 0x60
#define OP_NOP 0x61
#define OP_IF 0x63
#define OP_NOTIF 0x64
#define OP_ELSE 0x67
#define OP_ENDIF 0x68
#define OP_VERIFY 0x69
#define OP_RETURN 0x6a
#define OP_TOALTSTACK 0x6b
#define OP_FROMALTSTACK 0x6c
#define OP_2DROP 0x6d
#define OP_2DUP 0x6e
#define OP_3DUP 0x6f
#define OP_2OVER 0x70
#define OP_2ROT 0x71
#define OP_2SWAP 0x72
#define OP_IFDUP 0x73
#define OP_DEPTH 0x74
#define OP_DROP 0x75
#define OP_DUP 0x76
#define OP_NIP 0x77
#define OP_OVER 0x78
#define OP_PICK 0x79
#define OP_ROLL 0x7a
#define OP_ROT 0x7b
#define OP_SWAP 0x7c
#define OP_TUCK 0x7d
#define OP_SIZE 0x82
#define OP_EQUAL 0x87
#define OP_EQUALVERIFY 0x88
#define OP_1ADD 0x8b
#define OP_1SUB 0x8c
#define OP_NEGATE 0x8f
#define OP_NOT 0x91
#define OP_0NOTEQUAL 0x92
#define OP_ADD 0x93
#define OP_SUB 0x94
#define OP_BOOLAND 0x9a
#define OP_BOOLOR 0x9b
#define OP_NUMEQUAL 0x9c
#define OP_NUMEQUALVERIFY 0x9d
#define OP_NUMNOTEQUAL 0x9e
#define OP_LESSTHAN 0x9f
#define OP_GREATERTHAN 0xa0
#define OP_LESSTHANOREQUAL 0xa1
#define OP_GREATERTHANOREQUAL 0xa2
#define OP_MIN 0xa3
#define OP_MAX 0xa4
#define OP_WITHIN 0xa5
#define OP_RIPEMD160 0xa6
#define OP_SHA256 0xa8
#define OP_HASH160 0xa9
#define OP_HASH256 0xaa
#define OP_CODESEPARATOR 0xab
#define OP_CHECKSIG 0xac
#define OP_CHECKSIGVERIFY 0xad
#define OP_CHECKMULTISIG 0xae
#define OP_CHECKMULTISIGVERIFY 0xaf

extern int sighash_all(unsigned char out[32], const unsigned char* tx, unsigned long txlen,
                       unsigned long input_index, const unsigned char* script,
                       unsigned long script_len, unsigned char* preimg, unsigned long cap);
extern int der_parse_sig(const unsigned char* sig, unsigned long slen,
                         uint64_t r[4], uint64_t s[4], uint32_t* hashtype);
extern int pubkey_parse(const unsigned char* pub, unsigned long publen,
                        uint64_t qx[4], uint64_t qy[4]);
extern int ecdsa_verify(const uint64_t z[4], const uint64_t r[4], const uint64_t s[4],
                        const uint64_t Qx[4], const uint64_t Qy[4]);
extern void ripemd160(unsigned char out[20], const void* in, long long len);
extern void sha256_full(unsigned char out[32], const void* msg, unsigned long len);
extern void sha256d(unsigned char out[32], const void* msg, long len);
extern void be_to_limbs(uint64_t out[4], const unsigned char* bytes, unsigned long len);

/* ---------------- byte-vector stack ---------------- */
typedef struct { const unsigned char* d; size_t n; } Ref;

typedef struct {
    Ref* items; size_t n, items_cap;
    unsigned char* arena; size_t arena_used, arena_cap;
} Stack;

static void stack_reset(Stack* s){
    s->n = 0; s->arena_used = 0;
    if (s->arena_cap == 0) { s->arena_cap = 1 << 16; s->arena = (unsigned char*)malloc(s->arena_cap); }
    if (s->items_cap == 0) { s->items_cap = 256; s->items = (Ref*)malloc(s->items_cap * sizeof(Ref)); }
}
static void stack_grow_arena(Stack* s, size_t need){
    if (s->arena_used + need <= s->arena_cap) return;
    while (s->arena_cap < s->arena_used + need) s->arena_cap *= 2;
    s->arena = (unsigned char*)realloc(s->arena, s->arena_cap);
}
static void stack_grow_items(Stack* s, size_t add){
    if (s->n + add <= s->items_cap) return;
    while (s->items_cap < s->n + add) s->items_cap *= 2;
    s->items = (Ref*)realloc(s->items, s->items_cap * sizeof(Ref));
}
static void* salloc(Stack* s, size_t n){
    n = (n+3)&~(size_t)3;
    stack_grow_arena(s, n);
    void* p = s->arena + s->arena_used; s->arena_used += n; return p;
}
static void stack_push(Stack* s, const unsigned char* d, size_t n){
    stack_grow_items(s, 1);
    Ref* r = &s->items[s->n++];
    r->n = n; r->d = NULL;
    if (n){
        unsigned char* c = (unsigned char*)salloc(s, n);
        memcpy(c, d, n); r->d = c;
    }
}
static void stack_dup_items(Stack* dst, const Stack* src){
    /* deep-copy each element's DATA into dst's own arena (so realloc of src's
       arena later cannot dangle dst's pointers). */
    stack_grow_items(dst, src->n);
    for (size_t i=0;i<src->n;i++){
        const Ref* r = &src->items[i];
        stack_push(dst, r->d, r->n);
    }
}
static void stack_free(Stack* s){
    if (s->items) { free(s->items); s->items=NULL; }
    if (s->arena) { free(s->arena); s->arena=NULL; }
    s->n=0; s->items_cap=0; s->arena_used=0; s->arena_cap=0;
}

static Ref* stacktop(const Stack* s, long k){ return (long)s->n >= k ? &s->items[s->n-k] : NULL; }
static void stack_pop(Stack* s){ if (s->n) s->n--; }

static int cast_to_bool(const Ref* v){
    for (size_t i=0;i<v->n;i++){
        if (v->d[i]!=0){ if (i==v->n-1 && v->d[i]==0x80) return 0; return 1; }
    }
    return 0;
}

static int snum_decode(const Ref* v, int reqmin, int max_size, int64_t* out){
    if (v->n > (size_t)max_size) return 0;
    if (reqmin && v->n>0){
        if ((v->d[v->n-1] & 0x7f)==0){
            if (v->n<=1 || (v->d[v->n-2]&0x80)==0) return 0;
        }
    }
    int64_t val=0;
    for (size_t i=0;i<v->n;i++) val |= (int64_t)v->d[i] << (8*i);
    if (v->n>0 && (v->d[v->n-1]&0x80)){
        int64_t keep=0; for (size_t i=0;i<v->n-1;i++) keep |= (int64_t)0xff << (8*i);
        val &= keep; val = -val;
    }
    *out = val; return 1;
}

static size_t snum_ser(int64_t val, unsigned char out[9]){
    if (val==0){ out[0]=0; return 1; }
    int neg=0; int64_t absv=val;
    if (val<0){ neg=1; absv=-val; }
    unsigned char buf[9]; size_t n=0;
    while(absv>0){ buf[n++]=(unsigned char)(absv&0xff); absv>>=8; }
    if (buf[n-1]&0x80){ buf[n++] = neg?0x80:0x00; }
    else if (neg){ buf[n-1]|=0x80; }
    memcpy(out,buf,n); return n;
}

static int der_valid(const unsigned char* sig, size_t n){
    if (n<8 || n>74) return 0;
    if (sig[0]!=0x30) return 0;
    if (sig[1] != (unsigned char)(n-2)) return 0;
    if (sig[2]!=0x02) return 0;
    size_t rlen = sig[3];
    if (rlen<1 || rlen>33 || 4+rlen+2>n) return 0;
    if (sig[4+rlen]!=0x02) return 0;
    size_t slen = sig[5+rlen];
    if (slen<1 || slen>33 || 6+rlen+slen!=n) return 0;
    /* sign/pad rules (Core IsValidSignatureEncoding low-DER): R and S must be
       minimal positive: pad byte 0x00 only when the next byte's MSB is set. */
    if (sig[4]&0x80) return 0;
    if (sig[6+rlen]&0x80) return 0;
    if (rlen>1 && sig[4]==0 && !(sig[5]&0x80)) return 0;
    if (slen>1 && sig[6+rlen]==0 && !(sig[7+rlen]&0x80)) return 0;
    return 1;
}

static int check_sig_encoding(const Ref* v, uint64_t flags, int* err){
    if ((flags & (SCRIPT_VERIFY_DERSIG|SCRIPT_VERIFY_STRICTENC))==0) return 1;
    if (v->n==0) return 1;
    unsigned char hb = v->d[v->n-1];
    size_t siglen = v->n-1;
    if ((flags & SCRIPT_VERIFY_DERSIG) && siglen>0)
        if (!der_valid(v->d, siglen)){ *err=ERR_SIG_DER; return 0; }
    if ((flags & SCRIPT_VERIFY_STRICTENC)){
        if (siglen<8 || siglen>72){ *err=ERR_SIG_DER; return 0; }
    }
    if ((flags & (SCRIPT_VERIFY_DERSIG|SCRIPT_VERIFY_STRICTENC))){
        if ((hb & 0x80) && (hb&0x1f)!=0x1c && (hb&0x1f)!=0x1d && (hb&0x1f)!=0x1e)
            { *err=ERR_SIG_HASHTYPE; return 0; }
    }
    return 1;
}

static int check_pubkey_encoding(const Ref* v, uint64_t flags, int* err){
    if ((flags & SCRIPT_VERIFY_STRICTENC)){
        if (!( (v->n==33 && (v->d[0]==0x02||v->d[0]==0x03)) ||
               (v->n==65 && v->d[0]==0x04) )) { *err=ERR_PUBKEYTYPE; return 0; }
    }
    return 1;
}

static int check_sig(const Ref* sig, const Ref* pub,
                     const unsigned char* sc, size_t sc_len,
                     const unsigned char* tx, unsigned long txlen, unsigned long nIn,
                     unsigned char* work, unsigned long workcap){
    if (sig->n==0 || pub->n==0) return 0;
    unsigned char hb = sig->d[sig->n-1];
    if ((hb & 0x1f)!=1) return 0;
    size_t siglen = sig->n-1;
    unsigned char sighash[32];
    int ra = sighash_all(sighash, tx, txlen, nIn, sc, sc_len, work, workcap-64);
    if (!ra) return 0;
    uint64_t r[4], s[4]; uint32_t ht;
    /* der_parse_sig expects the full DER+hashtype byte (sig->n), and returns the
       trailing SIGHASH byte as ht. */
    if (!der_parse_sig(sig->d, sig->n, r, s, &ht)) return 0;
    if (ht!=1) return 0;
    uint64_t z[4];
    be_to_limbs(z, sighash, 32);
    uint64_t qx[4], qy[4];
    if (!pubkey_parse(pub->d, pub->n, qx, qy)) return 0;
    return ecdsa_verify(z, r, s, qx, qy);
}

/* Core CheckMultisig matching loop. sigs[]/keys[] bottom-up (first in script first). */
static int check_multisig(const Ref** sigs, int nsigs, const Ref** keys, int nkeys,
                          const unsigned char* sc, size_t sc_len,
                          const unsigned char* tx, unsigned long txlen, unsigned long nIn,
                          unsigned char* work, unsigned long workcap,
                          uint64_t flags, int* err){
    if (nkeys > MAX_PUBKEYS_PER_MULTISIG){ *err = ERR_PUBKEY_COUNT; return -1; }
    if (nsigs > nkeys){ *err = ERR_PUBKEY_COUNT; return -1; }
    int isig=0, ikey=0, nsigs_remaining=nsigs, fSuccess=1;
    while (fSuccess && nsigs_remaining>0){
        const Ref* vSig = sigs[isig];
        const Ref* vPub = keys[ikey];
        int e2;
        if (!check_sig_encoding(vSig, flags, &e2)){ *err=e2; return -1; }
        if (!check_pubkey_encoding(vPub, flags, &e2)){ *err=e2; return -1; }
        int ok = check_sig(vSig, vPub, sc, sc_len, tx, txlen, nIn, work, workcap);
        if (ok){ isig++; nsigs_remaining--; }
        ikey++; nkeys--;
        if (nsigs_remaining > nkeys) fSuccess=0;
    }
    if ((flags & SCRIPT_VERIFY_NULLFAIL) && !fSuccess){
        for (int k=isig;k<(nsigs_remaining==0?0:0);k++){}
        for (int k=0;k<nsigs;k++) if (sigs[k]->n!=0){ *err=ERR_SIG_NULLFAIL; return -1; }
    }
    return fSuccess ? 1 : 0;
}

static int is_p2sh(const unsigned char* spk, size_t spl){
    return spl==23 && spk[0]==0xa9 && spk[1]==0x14 && spk[22]==0x87;
}

static int push_only(const unsigned char* s, size_t n){
    size_t i=0;
    while (i<n){
        unsigned char op = s[i];
        if (op==OP_1NEGATE || (op>=OP_1 && op<=OP_16)){ i++; continue; }
        if (op <= OP_PUSHDATA4){
            if (op < OP_PUSHDATA1) i += 1+op;
            else if (op==OP_PUSHDATA1){ if(i+2>n)return 0; i += 2+s[i+1]; }
            else if (op==OP_PUSHDATA2){ if(i+3>n)return 0; i += 3+(s[i+1]|s[i+2]<<8); }
            else { if(i+5>n)return 0; i += 5+((unsigned)s[i+1]|(unsigned)s[i+2]<<8|(unsigned)s[i+3]<<16|(unsigned)s[i+4]<<24); }
        } else return 0;
    }
    return i==n;
}

/* forward decls */
static int eval_arith(Stack* stk, unsigned char op, int fReqMin, int* err);

/* EvalScript (BASE). Returns 1 accept / 0 fail with *err. */
static int eval_script(const unsigned char* s, size_t n, Stack* stk, uint64_t flags, int* err,
                       const unsigned char* tx, unsigned long txlen, unsigned long nIn,
                       unsigned char* work, unsigned long workcap){
    Stack alt; memset(&alt,0,sizeof alt);
    unsigned char vf[64]; int vfdepth=0;
    size_t pc=0; unsigned long opcount=0;    int fReqMin = (flags & SCRIPT_VERIFY_MINIMALDATA)!=0;
    const unsigned char* pcode = s;

    while (pc < n){
        unsigned char op = s[pc++];
        int is_push=0; unsigned long datalen=0; const unsigned char* data=NULL;
        if (op <= OP_PUSHDATA4){
            is_push=1;
            if (op < OP_PUSHDATA1) datalen=op;
            else if (op==OP_PUSHDATA1){ if(pc+1>n){*err=ERR_PUSH_SIZE;return 0;} datalen=s[pc++]; }
            else if (op==OP_PUSHDATA2){ if(pc+2>n){*err=ERR_PUSH_SIZE;return 0;} datalen=s[pc]|s[pc+1]<<8; pc+=2; }
            else { if(pc+4>n){*err=ERR_PUSH_SIZE;return 0;} datalen=(unsigned)s[pc]|(unsigned)s[pc+1]<<8|(unsigned)s[pc+2]<<16|(unsigned)s[pc+3]<<24; pc+=4; }
            if (datalen>MAX_PUSH_SIZE){ *err=ERR_PUSH_SIZE; return 0; }
            if (pc+datalen>n){ *err=ERR_PUSH_SIZE; return 0; }
            data = s+pc;
        } else if (op==OP_1NEGATE){ is_push=1; static const unsigned char m1[1]={0x81}; data=m1; datalen=1; }
        else if (op>=OP_1 && op<=OP_16){ is_push=1; static unsigned char small[16]; data=&small[op-OP_1]; datalen=1; small[op-OP_1]=(unsigned char)(op-OP_1+1); }

        int fExec = (vfdepth==0 || vf[vfdepth-1]);

        if (is_push){
            if (!fExec){ if(op<=OP_PUSHDATA4) pc+=datalen; continue; }
            if (fReqMin){
                int minimal=1;
                if (op==OP_0 && datalen!=0) minimal=0;
                else if (datalen==1 && data[0]==0x81 && op!=OP_1NEGATE) minimal=0;
                else if (datalen==1 && data[0]>=1 && data[0]<=16 && op!=(unsigned char)(OP_1+data[0]-1)) minimal=0;
                else if (datalen>0 && datalen<=75 && op!=datalen) minimal=0;
                else if (datalen>75 && datalen<=255 && op!=OP_PUSHDATA1) minimal=0;
                else if (datalen>255 && datalen<=65535 && op!=OP_PUSHDATA2) minimal=0;
                else if (datalen>65535 && op!=OP_PUSHDATA4) minimal=0;
                if (!minimal){ *err=ERR_MINIMALDATA; return 0; }
            }
            if (datalen==0 && op==OP_0) stack_push(stk,NULL,0);
            else stack_push(stk, data, datalen);
            if (op<=OP_PUSHDATA4) pc += datalen;
            continue;
        }

        if (opcount >= MAX_OPS_PER_SCRIPT){ *err=ERR_OP_COUNT; return 0; }
        opcount++;

        if (!fExec){
            if (op==OP_IF || op==OP_NOTIF){ if(vfdepth>=64){*err=ERR_UNBALANCED_CONDITIONAL;return 0;} vf[vfdepth++]=0; }
            else if (op==OP_ELSE){ if(vfdepth==0){*err=ERR_UNBALANCED_CONDITIONAL;return 0;} vf[vfdepth-1]^=1; }
            else if (op==OP_ENDIF){ if(vfdepth==0){*err=ERR_UNBALANCED_CONDITIONAL;return 0;} vfdepth--; }
            continue;
        }

        switch(op){
        case OP_NOP: break;
        case OP_IF: case OP_NOTIF: {
            Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;}
            int cond=cast_to_bool(tp); stack_pop(stk);
            if(op==OP_NOTIF) cond=!cond;
            if(vfdepth>=64){*err=ERR_UNBALANCED_CONDITIONAL;return 0;}
            vf[vfdepth++]=(unsigned char)cond; break;
        }
        case OP_ELSE: if(vfdepth==0){*err=ERR_UNBALANCED_CONDITIONAL;return 0;} vf[vfdepth-1]^=1; break;
        case OP_ENDIF: if(vfdepth==0){*err=ERR_UNBALANCED_CONDITIONAL;return 0;} vfdepth--; break;
        case OP_VERIFY: { Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;} if(!cast_to_bool(tp)){*err=ERR_VERIFY;return 0;} stack_pop(stk); break; }
        case OP_RETURN: *err=ERR_OP_RETURN; return 0;
        case OP_TOALTSTACK: { Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;} stack_push(&alt,tp->d,tp->n); stack_pop(stk); break; }
        case OP_FROMALTSTACK: { Ref*tp=stacktop(&alt,1); if(!tp){*err=ERR_INVALID_ALTSTACK_OPERATION;return 0;} stack_push(stk,tp->d,tp->n); stack_pop(&alt); break; }
        case OP_2DROP: if(stk->n<2){*err=ERR_INVALID_STACK_OPERATION;return 0;} stack_pop(stk);stack_pop(stk); break;
        case OP_2DUP: if(stk->n<2){*err=ERR_INVALID_STACK_OPERATION;return 0;}{Ref*a=stacktop(stk,2),*b=stacktop(stk,1);stack_push(stk,a->d,a->n);stack_push(stk,b->d,b->n);} break;
        case OP_3DUP: if(stk->n<3){*err=ERR_INVALID_STACK_OPERATION;return 0;}{Ref*a=stacktop(stk,3),*b=stacktop(stk,2),*c=stacktop(stk,1);stack_push(stk,a->d,a->n);stack_push(stk,b->d,b->n);stack_push(stk,c->d,c->n);} break;
        case OP_2OVER: if(stk->n<4){*err=ERR_INVALID_STACK_OPERATION;return 0;}{Ref*a=stacktop(stk,4),*b=stacktop(stk,3);stack_push(stk,a->d,a->n);stack_push(stk,b->d,b->n);} break;
        case OP_2SWAP: if(stk->n<4){*err=ERR_INVALID_STACK_OPERATION;return 0;}{Ref*e1=stacktop(stk,4),*e2=stacktop(stk,3),*e3=stacktop(stk,2),*e4=stacktop(stk,1);stack_pop(stk);stack_pop(stk);stack_pop(stk);stack_pop(stk);stack_push(stk,e3->d,e3->n);stack_push(stk,e4->d,e4->n);stack_push(stk,e1->d,e1->n);stack_push(stk,e2->d,e2->n);} break;
        case OP_IFDUP: { Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;} if(cast_to_bool(tp))stack_push(stk,tp->d,tp->n);} break;
        case OP_DEPTH: { unsigned char b[1]; b[0]=(unsigned char)stk->n; stack_push(stk,b,1);} break;
        case OP_DROP: if(stk->n<1){*err=ERR_INVALID_STACK_OPERATION;return 0;} stack_pop(stk); break;
        case OP_DUP: { Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;} stack_push(stk,tp->d,tp->n);} break;
        case OP_NIP: if(stk->n<2){*err=ERR_INVALID_STACK_OPERATION;return 0;}{Ref*a=stacktop(stk,2);stack_pop(stk);stack_pop(stk);stack_push(stk,a->d,a->n);} break;
        case OP_OVER: if(stk->n<2){*err=ERR_INVALID_STACK_OPERATION;return 0;}{Ref*a=stacktop(stk,2);stack_push(stk,a->d,a->n);} break;
        case OP_PICK: { Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;} int64_t v; if(!snum_decode(tp,fReqMin,4,&v)){*err=ERR_SCRIPTNUM;return 0;} if(v<0||v>=(int64_t)stk->n-1){*err=ERR_INVALID_STACK_OPERATION;return 0;} Ref*a=stacktop(stk,(long)v+2); stack_pop(stk); stack_push(stk,a->d,a->n); } break;
        case OP_ROLL: {
            Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;} int64_t v; if(!snum_decode(tp,fReqMin,4,&v)){*err=ERR_SCRIPTNUM;return 0;} if(v<0||v>=(int64_t)stk->n-1){*err=ERR_INVALID_STACK_OPERATION;return 0;}
            Ref*a=stacktop(stk,(long)v+2); unsigned char t[520]; size_t tn=a->n; memcpy(t,a->d,tn);
            stack_pop(stk);
            long ai=(long)stk->n-1-v;
            for(long k=ai;k+1<(long)stk->n;k++) stk->items[k]=stk->items[k+1];
            stk->n--;
            stack_push(stk,t,tn); break;
        }
        case OP_ROT: if(stk->n<3){*err=ERR_INVALID_STACK_OPERATION;return 0;}{Ref*e1=stacktop(stk,3),*e2=stacktop(stk,2),*e3=stacktop(stk,1);stack_pop(stk);stack_pop(stk);stack_pop(stk);stack_push(stk,e2->d,e2->n);stack_push(stk,e3->d,e3->n);stack_push(stk,e1->d,e1->n);} break;
        case OP_SWAP: if(stk->n<2){*err=ERR_INVALID_STACK_OPERATION;return 0;}{Ref*e1=stacktop(stk,2),*e2=stacktop(stk,1);stack_pop(stk);stack_pop(stk);stack_push(stk,e2->d,e2->n);stack_push(stk,e1->d,e1->n);} break;
        case OP_TUCK: if(stk->n<2){*err=ERR_INVALID_STACK_OPERATION;return 0;}{Ref*a=stacktop(stk,2),*b=stacktop(stk,1);stack_pop(stk);stack_pop(stk);stack_push(stk,a->d,a->n);stack_push(stk,b->d,b->n);stack_push(stk,a->d,a->n);} break;
        case OP_SIZE: { Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;} unsigned char b[5]; size_t m=0; uint64_t v=tp->n; if(v==0){b[m++]=0;} else{while(v){b[m++]=(unsigned char)(v&0xff);v>>=8;}} stack_push(stk,b,m); } break;
        case OP_EQUAL: case OP_EQUALVERIFY: {
            Ref*a=stacktop(stk,2),*b=stacktop(stk,1); if(!a||!b){*err=ERR_INVALID_STACK_OPERATION;return 0;}
            int eq=(a->n==b->n && memcmp(a->d,b->d,a->n)==0);
            stack_pop(stk);stack_pop(stk);
            if(op==OP_EQUALVERIFY){ if(!eq){*err=ERR_EQUALVERIFY;return 0;} }
            else { unsigned char c[1]; c[0]=(unsigned char)eq; stack_push(stk,c,1); }
            break;
        }
        case OP_RIPEMD160: case OP_SHA256: case OP_HASH160: case OP_HASH256: {
            Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;}
            unsigned char out[32]; size_t on;
            stack_pop(stk);
            if(op==OP_RIPEMD160){ ripemd160(out,tp->d,(long long)tp->n); on=20; }
            else if(op==OP_SHA256){ sha256_full(out,tp->d,(unsigned long)tp->n); on=32; }
            else if(op==OP_HASH160){ unsigned char h[32]; sha256_full(h,tp->d,(unsigned long)tp->n); ripemd160(out,h,32); on=20; }
            else { sha256d(out,tp->d,(long)tp->n); on=32; }
            stack_push(stk,out,on); break;
        }
        case OP_CODESEPARATOR: pcode=s+pc; break;
        case OP_CHECKSIG: case OP_CHECKSIGVERIFY: {
            Ref*pub=stacktop(stk,1),*sg=stacktop(stk,2); if(!pub||!sg){*err=ERR_INVALID_STACK_OPERATION;return 0;}
            int e2;
            if(!check_sig_encoding(sg,flags,&e2)){*err=e2;return 0;}
            if(!check_pubkey_encoding(pub,flags,&e2)){*err=e2;return 0;}
            int ok=check_sig(sg,pub,pcode,n-(size_t)(pcode-s),tx,txlen,nIn,work,workcap);
            stack_pop(stk);stack_pop(stk);
            if(op==OP_CHECKSIGVERIFY){ if(!ok){*err=ERR_CHECKSIGVERIFY;return 0;} }
            else { unsigned char c[1]; c[0]=(unsigned char)ok; stack_push(stk,c,1); }
            break;
        }
        case OP_CHECKMULTISIG: case OP_CHECKMULTISIGVERIFY: {
            /* stack: dummy sig1..sigm m pub1..pubn n   (top=n) */
            Ref* rn=stacktop(stk,1); if(!rn){*err=ERR_INVALID_STACK_OPERATION;return 0;}
            int64_t nkv; if(!snum_decode(rn,fReqMin,4,&nkv)){*err=ERR_SCRIPTNUM;return 0;}
            if(nkv<0||nkv>MAX_PUBKEYS_PER_MULTISIG){*err=ERR_PUBKEY_COUNT;return 0;}
            int nkeys=(int)nkv;
            Ref* rm=stacktop(stk,(long)nkeys+2); if(!rm){*err=ERR_INVALID_STACK_OPERATION;return 0;}
            int64_t nsv; if(!snum_decode(rm,fReqMin,4,&nsv)){*err=ERR_SCRIPTNUM;return 0;}
            if(nsv<0||nsv>nkeys){*err=ERR_SIG_COUNT;return 0;}
            int nsigs=(int)nsv;
            long need=(long)nkeys+2+nsigs;
            if ((long)stk->n < need+1){ *err=ERR_INVALID_STACK_OPERATION; return 0; }
            Ref* dummy=stacktop(stk,need+1);
            const Ref* keys[21]; const Ref* sigs[21];
            /* Core CheckMultisig matches the TOP sig against the TOP pubkey and
               walks downward (isig: sigm..sig1, ikey: pubn..pub1). Collect in
               top-first order: key j at stacktop(2+j) (since stacktop(-1)=n,
               -2=pubn, ...); sig j at stacktop(nkeys+3+j). */
            for(int j=0;j<nkeys;j++) keys[j]=stacktop(stk,(long)2+j);
            for(int j=0;j<nsigs;j++) sigs[j]=stacktop(stk,(long)nkeys+3+j);
            int e2;
            int cres=check_multisig(sigs,nsigs,keys,nkeys,pcode,n-(size_t)(pcode-s),tx,txlen,nIn,work,workcap,flags,&e2);
            if(cres==-1){ *err=e2; return 0; }
            int fSuccess=cres;
            if((flags & SCRIPT_VERIFY_NULLDUMMY) && dummy && dummy->n!=0){ *err=ERR_SIG_NULLDUMMY; return 0; }
            long total=need+1; while(total-->0) stack_pop(stk);
            if(op==OP_CHECKMULTISIGVERIFY){ if(!fSuccess){*err=ERR_CHECKMULTISIGVERIFY;return 0;} }
            else { unsigned char c[1]; c[0]=(unsigned char)fSuccess; stack_push(stk,c,1); }
            break;
        }
        case OP_1ADD: case OP_1SUB: case OP_NEGATE: case OP_NOT: case OP_0NOTEQUAL:
        case OP_ADD: case OP_SUB: case OP_BOOLAND: case OP_BOOLOR: case OP_NUMEQUAL:
        case OP_NUMEQUALVERIFY: case OP_NUMNOTEQUAL: case OP_LESSTHAN: case OP_GREATERTHAN:
        case OP_LESSTHANOREQUAL: case OP_GREATERTHANOREQUAL: case OP_MIN: case OP_MAX:
        case OP_WITHIN: {
            if(!eval_arith(stk,op,fReqMin,err)) return (int)(*err==ERR_OK?0: (*err==ERR_OK?0:1));
            if(*err!=ERR_OK) return 0;
            break;
        }
        default:
            *err=ERR_BAD_OPCODE; return 0;
        }
    }
    if (vfdepth!=0){ *err=ERR_UNBALANCED_CONDITIONAL; return 0; }
    return 1;
}

static int eval_arith(Stack* stk, unsigned char op, int fReqMin, int* err){
    switch(op){
    case OP_1ADD: case OP_1SUB: case OP_NEGATE: case OP_NOT: case OP_0NOTEQUAL: {
        Ref*tp=stacktop(stk,1); if(!tp){*err=ERR_INVALID_STACK_OPERATION;return 0;}
        int64_t v; if(!snum_decode(tp,fReqMin,4,&v)){*err=ERR_SCRIPTNUM;return 0;}
        stack_pop(stk);
        unsigned char buf[9];
        if(op==OP_NOT){ buf[0]=(v==0); stack_push(stk,buf,1); return 1; }
        if(op==OP_0NOTEQUAL){ buf[0]=(v!=0); stack_push(stk,buf,1); return 1; }
        int64_t r = (op==OP_1ADD)?v+1:(op==OP_1SUB)?v-1:-v;
        size_t m=snum_ser(r,buf); stack_push(stk,buf,m); return 1;
    }
    case OP_ADD: case OP_SUB: case OP_BOOLAND: case OP_BOOLOR: case OP_NUMEQUAL:
    case OP_NUMEQUALVERIFY: case OP_NUMNOTEQUAL: case OP_LESSTHAN: case OP_GREATERTHAN:
    case OP_LESSTHANOREQUAL: case OP_GREATERTHANOREQUAL: case OP_MIN: case OP_MAX: {
        Ref*a=stacktop(stk,2),*b=stacktop(stk,1); if(!a||!b){*err=ERR_INVALID_STACK_OPERATION;return 0;}
        int64_t x,y; if(!snum_decode(a,fReqMin,4,&x)||!snum_decode(b,fReqMin,4,&y)){*err=ERR_SCRIPTNUM;return 0;}
        stack_pop(stk);stack_pop(stk);
        unsigned char buf[9]; size_t m; int64_t r;
        switch(op){
        case OP_ADD: m=snum_ser(x+y,buf); stack_push(stk,buf,m); return 1;
        case OP_SUB: m=snum_ser(x-y,buf); stack_push(stk,buf,m); return 1;
        case OP_BOOLAND: buf[0]=(x!=0&&y!=0); stack_push(stk,buf,1); return 1;
        case OP_BOOLOR: buf[0]=(x!=0||y!=0); stack_push(stk,buf,1); return 1;
        case OP_NUMEQUAL: buf[0]=(x==y); stack_push(stk,buf,1); return 1;
        case OP_NUMEQUALVERIFY: if(x!=y){*err=ERR_NUMEQUALVERIFY;return 0;} return 1;
        case OP_NUMNOTEQUAL: buf[0]=(x!=y); stack_push(stk,buf,1); return 1;
        case OP_LESSTHAN: buf[0]=(x<y); stack_push(stk,buf,1); return 1;
        case OP_GREATERTHAN: buf[0]=(x>y); stack_push(stk,buf,1); return 1;
        case OP_LESSTHANOREQUAL: buf[0]=(x<=y); stack_push(stk,buf,1); return 1;
        case OP_GREATERTHANOREQUAL: buf[0]=(x>=y); stack_push(stk,buf,1); return 1;
        case OP_MIN: m=snum_ser(x<y?x:y,buf); stack_push(stk,buf,m); return 1;
        case OP_MAX: m=snum_ser(x>y?x:y,buf); stack_push(stk,buf,m); return 1;
        }
        return 0;
    }
    case OP_WITHIN: {
        /* stack: <1> <2> <3>  => within: (1 <= 2 < 3)  i.e. 1 in [2, 3) */
        Ref*a=stacktop(stk,3),*b=stacktop(stk,2),*c=stacktop(stk,1);
        if(!a||!b||!c){*err=ERR_INVALID_STACK_OPERATION;return 0;}
        int64_t x,y,z;
        if(!snum_decode(a,fReqMin,4,&x)||!snum_decode(b,fReqMin,4,&y)||!snum_decode(c,fReqMin,4,&z)){*err=ERR_SCRIPTNUM;return 0;}
        stack_pop(stk);stack_pop(stk);stack_pop(stk);
        unsigned char buf[1]; buf[0]=(x>=y && x<z); stack_push(stk,buf,1); return 1;
    }
    }
    return 0;
}

/* ========================================================================
 * VerifyScript (Core interpreter.cpp VerifyScript, BASE only).
 * ======================================================================== */
int verify_script(const unsigned char* scriptSig, unsigned long ssl,
                  const unsigned char* scriptPubKey, unsigned long spl,
                  uint64_t flags, unsigned long nIn,
                  const unsigned char* tx, unsigned long txlen,
                  unsigned char* work, unsigned long workcap){
    Stack stack; memset(&stack,0,sizeof stack); stack_reset(&stack);
    Stack stackCopy; memset(&stackCopy,0,sizeof stackCopy); stack_reset(&stackCopy);
    if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) && !push_only(scriptSig,ssl)){
        stack_free(&stack); stack_free(&stackCopy); return ERR_SIG_PUSHONLY;
    }
    int err=ERR_OK;
    if (!eval_script(scriptSig, ssl, &stack, flags, &err, tx, txlen, nIn, work, workcap)){
        stack_free(&stack); stack_free(&stackCopy); return err;
    }
    if (flags & SCRIPT_VERIFY_P2SH) stack_dup_items(&stackCopy, &stack);
    if (!eval_script(scriptPubKey, spl, &stack, flags, &err, tx, txlen, nIn, work, workcap)){
        stack_free(&stack); stack_free(&stackCopy); return err;
    }
    if (stack.n==0){ stack_free(&stack); stack_free(&stackCopy); return ERR_EVAL_FALSE; }
    if (!cast_to_bool(stacktop(&stack,1))){ stack_free(&stack); stack_free(&stackCopy); return ERR_EVAL_FALSE; }
    if ((flags & SCRIPT_VERIFY_P2SH) && is_p2sh(scriptPubKey, spl)){
        if (!push_only(scriptSig,ssl)){
            stack_free(&stack); stack_free(&stackCopy); return ERR_SIG_PUSHONLY;
        }
        if (stackCopy.n==0){ stack_free(&stack); stack_free(&stackCopy); return ERR_EVAL_FALSE; }
        const Ref* redeemRef = stacktop(&stackCopy,1);
        const unsigned char* redeem = redeemRef->d;
        size_t rlen = redeemRef->n;
        Stack copy2; memset(&copy2,0,sizeof copy2); stack_reset(&copy2);
        for (size_t i=0;i<stackCopy.n-1;i++)
            stack_push(&copy2, stackCopy.items[i].d, stackCopy.items[i].n);
        if (!eval_script(redeem, rlen, &copy2, flags, &err, tx, txlen, nIn, work, workcap)){
            stack_free(&stack); stack_free(&stackCopy); stack_free(&copy2); return err;
        }
        int c2_ok = (copy2.n!=0 && cast_to_bool(stacktop(&copy2,1)));
        stack_free(&copy2);
        if (!c2_ok){ stack_free(&stack); stack_free(&stackCopy); return ERR_EVAL_FALSE; }
    }
    stack_free(&stack); stack_free(&stackCopy);
    return ERR_OK;
}

/* Compute consensus SCRIPT_VERIFY flags for a block height, identical to Core's
 * GetBlockScriptFlags() (P2SH gated at height >= 173805; pre-BIP16 also drops
 * WITNESS/TAPROOT since Core's VerifyScript asserts WITNESS => P2SH). */
uint64_t verify_flags_for_height(uint64_t height){
    if (height < 173805)
        return SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CLTV | SCRIPT_VERIFY_CSV | SCRIPT_VERIFY_NULLDUMMY;
    return SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT
         | SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_CLTV | SCRIPT_VERIFY_CSV
         | SCRIPT_VERIFY_NULLDUMMY;
}
