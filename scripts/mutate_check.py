#!/usr/bin/env python3
"""mutate_check.py -- do the new tests actually catch a broken implementation?

A test suite that passes is evidence of nothing until you have watched it fail.
This applies a list of ONE-INSTRUCTION (or one-constant) mutations to the real
assembly, rebuilds, runs the test that is supposed to notice, and reports
whether it did. Every mutation below changes an INSTRUCTION or a NUMERIC
CONSTANT that the CPU executes -- never a comment, never whitespace. (An
earlier attempt in this project was vacuous because it edited a comment that
happened to contain the string "adc"; the `assert_executable` check here exists
so that cannot happen again: a mutation whose `old` text appears only inside a
comment is refused.)

Run from the repo root:
    python3 scripts/mutate_check.py            # all mutations
    python3 scripts/mutate_check.py schnorr    # only ones whose name matches

Every mutation is reverted afterwards, including on failure or Ctrl-C.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ASM = os.path.join(ROOT, "asm")


class Mut:
    def __init__(self, name, path, old, new, tests, why, expect_survive=None,
                 extra_edits=()):
        self.name = name
        self.path = os.path.join(ASM, path)
        self.old = old
        self.new = new
        # Further (old, new) pairs applied after the first, for mutations that
        # cannot be expressed as one contiguous edit (e.g. moving a buffer back
        # out of the stack frame touches its definition AND every reference).
        self.extra_edits = extra_edits
        self.tests = tests          # list of (make_target, argv)
        self.why = why
        # Some mutations CANNOT be caught by any black-box test, and saying so
        # in the repo is worth more than deleting them. Set to the reason.
        self.expect_survive = expect_survive


def strip_comments(src):
    """NASM ';' comments and C '/* */' + '//' comments, blanked not removed."""
    out = []
    for line in src.splitlines(True):
        i = line.find(";")
        out.append(line[:i] + "\n" if i >= 0 else line)
    return "".join(out)


MUTATIONS = [
    # ---------------- BIP340 verify ----------------
    Mut("schnorr-drop-even-y", "secp256k1_schnorr.asm",
        "    test byte [rbp+YR], 1\n    jnz .invalid\n",
        "    test byte [rbp+YR], 1\n",
        [("tests/test_schnorr_diff", []),
         ("tests/test_schnorr", ["tests/bip340_test_vectors.csv"])],
        "removing the even-Y test must make every 'oddy' case false-ACCEPT"),

    Mut("schnorr-drop-infinity", "secp256k1_schnorr.asm",
        "    or  rax, [rbp+RPT+88]\n    jz  .invalid\n",
        "    or  rax, [rbp+RPT+88]\n",
        [("tests/test_schnorr_diff", [])],
        "the R==infinity test is defence in depth, not the thing that rejects today",
        expect_survive=(
            "point_add writes the CANONICAL infinity (1, 1, 0), so an infinite R "
            "reaches schnorr_x_eq_r as X == 1, Z == 0; the compare then asks "
            "r*0 == 1, which is false, and the signature is rejected anyway. "
            "No input can therefore distinguish the two versions. The check "
            "stays because the compare alone would ACCEPT a (0, *, 0) infinity "
            "against r == 0 -- tests/test_schnorr_diff.c asserts exactly that "
            "with schnorr_x_eq_r(0,0,0) == 1, so the hazard is pinned even "
            "though the mutation is unobservable.")),

    Mut("schnorr-no-negate", "secp256k1_schnorr.asm",
        "    jz   .done_neg\n    mov rax, [P_LIMBS]\n",
        "    jmp  .done_neg\n    mov rax, [P_LIMBS]\n",
        [("tests/test_schnorr_diff", []),
         ("tests/test_schnorr", ["tests/bip340_test_vectors.csv"])],
        "computing s*G + e*P instead of s*G - e*P must reject every valid signature"),

    Mut("schnorr-x-compare-drop-top-limb", "secp256k1_schnorr.asm",
        "    mov  rax, [rbp-0x60+24]\n    cmp  rax, [r13+24]\n    jne  .no\n",
        "    mov  rax, [rbp-0x60+24]\n",
        [("tests/test_schnorr_diff", [])],
        "checking only 3 of the 4 limbs of x(R) weakens the compare; no corpus of "
        "real signatures can see this, which is why schnorr_x_eq_r is exported"),

    Mut("schnorr-fixed-comb-wrong-scalar", "secp256k1_schnorr.asm",
        "    lea rdi, [rbp+SG]\n    lea rsi, [rbp+S_SLIMS]\n    call point_scalar_mul_fixed\n",
        "    lea rdi, [rbp+SG]\n    lea rsi, [rbp+E_SLIMS]\n    call point_scalar_mul_fixed\n",
        [("tests/test_schnorr_diff", []),
         ("tests/test_schnorr", ["tests/bip340_test_vectors.csv"])],
        "e*G instead of s*G must reject every valid signature"),

    Mut("schnorr-preimg-back-to-a-global", "secp256k1_schnorr.asm",
        "%define PREIMG     -0x4b2          ; 320 bytes: tagh||tagh||r||pk||msg\n",
        "%define PREIMG     -0x4b2          ; 320 bytes: tagh||tagh||r||pk||msg\n",
        [("tests/test_schnorr_thread_stress", ["tests/bip340_test_vectors.csv"]),
         ("tests/test_schnorr", ["tests/bip340_test_vectors.csv"])],
        "putting the BIP340 challenge preimage back in a process-global buffer must "
        "make concurrent verification false-REJECT valid signatures",
        extra_edits=(
            ("section .text\n\n; --------", "section .data\nalign 16\nschnorr_preimg: times 320 db 0\n\nsection .text\n\n; --------"),
            ("[rbp+PREIMG+128]", "[rel schnorr_preimg+128]"),
            ("[rbp+PREIMG+96]",  "[rel schnorr_preimg+96]"),
            ("[rbp+PREIMG+64]",  "[rel schnorr_preimg+64]"),
            ("[rbp+PREIMG+32]",  "[rel schnorr_preimg+32]"),
            ("[rbp+PREIMG]",     "[rel schnorr_preimg]"),
        )),

    # ---------------- fe_inv addition chain ----------------
    Mut("fe_inv-chain-short-rung", "secp256k1_fe.asm",
        "    FEINV_SQN 23\n    FEINV_MUL rbp-0xb0\n",
        "    FEINV_SQN 22\n    FEINV_MUL rbp-0xb0\n",
        [("tests/test_fe_repr", []), ("tests/test_mul_carry_regression", [])],
        "one squaring short in the tail changes the exponent, so a^chain != a^-1"),

    Mut("fe_inv-chain-wrong-operand", "secp256k1_fe.asm",
        "    FEINV_SQN 44\n    FEINV_MUL rbp-0xd0                  ; T = x220\n",
        "    FEINV_SQN 44\n    FEINV_MUL rbp-0xb0                  ; T = x220\n",
        [("tests/test_fe_repr", []), ("tests/test_mul_carry_regression", [])],
        "multiplying by x22 where the chain needs x44"),

    # ---------------- batched merkle ----------------
    Mut("sha256d64-wrong-length-pad", "bitcoin_hash.asm",
        "    times 55 db 0\n    db 0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00\n",
        "    times 55 db 0\n    db 0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00\n",
        [("tests/test_merkle_batch", []), ("tests/test_cons", [])],
        "the first hash's padded length must be 512 bits, not 256"),

    Mut("sha256d64-no-state-reset", "bitcoin_hash.asm",
        "    D64_SETIV rbp-0x50\n    D64_SETIV rbp-0x70\n    lea  rdi, [rbp-0x50]\n    lea  rsi, [rbp-0xb0]\n",
        "    lea  rdi, [rbp-0x50]\n    lea  rsi, [rbp-0xb0]\n",
        [("tests/test_merkle_batch", []), ("tests/test_cons", [])],
        "the second SHA-256 must start from the IV, not from the first one's state"),

    Mut("merkle-odd-level-off-by-one", "bitcoin_hash.asm",
        "    cmp r11, r14\n    jae %%dup                  ; no sibling -> duplicate the left node\n",
        "    cmp r11, r14\n    ja  %%dup                  ; no sibling -> duplicate the left node\n",
        [("tests/test_merkle_batch", []), ("tests/test_cons", [])],
        "the last node of an odd level must be duplicated, not paired with the next level's memory"),

    Mut("merkle-wrong-write-stride", "bitcoin_hash.asm",
        "    shl rax, 5             ; 32 output bytes per staged pair\n",
        "    shl rax, 6             ; 32 output bytes per staged pair\n",
        [("tests/test_merkle_batch", []), ("tests/test_cons", [])],
        "each staged pair produces 32 output bytes, not 64"),
]


def assert_executable(src, old, name):
    """The mutated text must appear OUTSIDE comments -- otherwise the mutation
    is cosmetic and the whole exercise proves nothing."""
    bare = strip_comments(src)
    key = strip_comments(old).strip()
    if not key:
        sys.exit("mutation %s: `old` is entirely comment text" % name)
    first = key.splitlines()[0].strip()
    if first not in bare:
        sys.exit("mutation %s: `%s` never appears outside a comment -- "
                 "this mutation would be vacuous" % (name, first))


def run(cmd, cwd=ASM):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def main():
    want = sys.argv[1] if len(sys.argv) > 1 else ""
    muts = [m for m in MUTATIONS if want in m.name]
    if not muts:
        sys.exit("no mutation matches %r" % want)

    print("%d mutations\n" % len(muts))
    survived = []
    for m in muts:
        src = open(m.path).read()
        if m.old not in src:
            sys.exit("mutation %s: anchor text not found in %s -- the source moved,\n"
                     "fix the anchor rather than deleting the mutation" % (m.name, m.path))
        assert_executable(src, m.old, m.name)
        try:
            mutated = src.replace(m.old, m.new, 1)
            for eo, en in m.extra_edits:
                if eo not in mutated:
                    sys.exit("mutation %s: extra-edit anchor %r not found" % (m.name, eo[:60]))
                mutated = mutated.replace(eo, en)
            open(m.path, "w").write(mutated)
            caught = False
            detail = []
            for target, argv in m.tests:
                b = run(["make", target])
                if b.returncode != 0:
                    caught = True
                    detail.append("%s: BUILD FAILED (mutation is not assemblable)" % target)
                    continue
                t = run([os.path.join(ASM, target)] + argv)
                ok = (t.returncode == 0)
                detail.append("%s: %s" % (target, "still passes" if ok else "FAILS (caught)"))
                if not ok:
                    caught = True
            if m.expect_survive:
                status = "as-expected" if not caught else "UNEXPECTED-CATCH"
            else:
                status = "CAUGHT " if caught else "SURVIVED"
            print("[%s] %-34s %s" % (status, m.name, m.why))
            for d in detail:
                print("            %s" % d)
            if m.expect_survive:
                print("            expected to survive: %s" % m.expect_survive)
            elif not caught:
                survived.append(m.name)
        finally:
            open(m.path, "w").write(src)
            run(["make", m.tests[0][0]])   # leave the tree rebuilt from clean source

    print()
    if survived:
        print("%d mutation(s) SURVIVED: %s" % (len(survived), ", ".join(survived)))
        print("A surviving mutation means the tests do not actually check that behaviour.")
        return 1
    print("all %d mutations caught" % len(muts))
    return 0


if __name__ == "__main__":
    sys.exit(main())
