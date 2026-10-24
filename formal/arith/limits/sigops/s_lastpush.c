/* L-S2: the P2SH subscript a scriptSig yields for sigop counting.
 *
 * bmc: the REAL txv_sgc_last_push (asm/daemon/tx_verify.c), which
 * txv_sigop_cost_tx uses for both the P2SH sigop count and the P2SH-wrapped
 * witness program lookup.
 * Core v31.1: CScript::GetSigOpCount(const CScript& scriptSig)
 * (script/script.cpp) for a P2SH scriptPubKey:
 *     while (pc < scriptSig.end()) {
 *         if (!scriptSig.GetOp(pc, opcode, vData)) return 0;
 *         if (opcode > OP_16) return 0;
 *     }
 *     return CScript(vData.begin(), vData.end()).GetSigOpCount(true);
 * with GetScriptOp (script/script.cpp) clearing vData on every op and
 * filling it only for a push. "return 0" and "count an empty subscript" are
 * the same number, so the claim is: bmc's effective subscript (its data, or
 * empty when it returns 0) equals Core's (vData, or empty on a 0 return),
 * byte for byte -- the count of equal bytes is equal.
 * The same loop with IsPushOnly is CountWitnessSigOps's wrapped-witness
 * source (an empty vData can never be a witness program, so a 0 return and
 * an empty subscript also agree there).
 * Bound: every scriptSig of length <= NB bytes (all opcodes, all push
 * forms with their length fields). */
#include <stdint.h>
#include <string.h>
#include "../../lib/nondet.h"
typedef unsigned char u8; typedef unsigned long u64;
#include "../gen/s_last_push.inc"
#ifndef NB
#define NB 9
#endif
/* Core: returns 1 and the last op's vData, or 0 */
static int core_last_push(const u8* s, unsigned long n, const u8** d, unsigned long* dl){
    unsigned long pc = 0; const u8* vd = 0; unsigned long vl = 0;
    while (pc < n){
        vd = 0; vl = 0;                                   /* pvchRet->clear() */
        unsigned op = s[pc++];
        if (op <= 0x4e){
            unsigned long sz;
            if (op < 0x4c) sz = op;
            else if (op == 0x4c){ if (n - pc < 1) return 0; sz = s[pc++]; }
            else if (op == 0x4d){ if (n - pc < 2) return 0; sz = s[pc] | ((unsigned long)s[pc+1] << 8); pc += 2; }
            else { if (n - pc < 4) return 0; sz = s[pc] | ((unsigned long)s[pc+1] << 8) | ((unsigned long)s[pc+2] << 16) | ((unsigned long)s[pc+3] << 24); pc += 4; }
            if (n - pc < sz) return 0;
            vd = s + pc; vl = sz; pc += sz;
        }
        if (op > 0x60) return 0;                          /* opcode > OP_16 */
    }
    *d = vd; *dl = vl; return 1;
}
int main(void){
    unsigned long n = nondet_u64(); ASSUME(n <= NB);
    u8 s[NB + 8];      /* slack: keeps `p + 4 > end` inside one object */
    for (int i = 0; i < NB + 8; i++) s[i] = nondet_u8();
    const u8* bd = 0; unsigned long bl = 0;
    int bok = txv_sgc_last_push(s, n, &bd, &bl);
    const u8* cd = 0; unsigned long cl = 0;
    int cok = core_last_push(s, n, &cd, &cl);
    unsigned long beff = bok ? bl : 0, ceff = cok ? cl : 0;
#ifdef REACH
    CHECK(!(bok && bl > 0), "REACH a non-empty subscript");
    CHECK(!(cok == 0 && n > 0), "REACH a Core 0 return");
#else
    CHECK(beff == ceff, "same subscript length");
    if (beff == ceff && beff){
        CHECK(bd == cd, "same subscript bytes (same position in the scriptSig)");
    }
#endif
    return 0;
}
