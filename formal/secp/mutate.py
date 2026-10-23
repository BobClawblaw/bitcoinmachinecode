"""mutate.py -- show every proof can FAIL.  For each mutant: copy asm/ to a
scratch tree, change ONE line of product code there, rebuild that tree's
objects + the lifter image (build.sh with ASM=/B=), and run the proofs that
cover the line.  A mutant passes this check only if the build succeeds and at
least one selected proof is NOT proved.  The real tree is never touched.
   mutate.py [MUTANT-ID ...]"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
ASM = os.path.join(ROOT, 'asm')
PY = sys.executable
LIM = [os.path.join(HERE, 'lim')]

# id, file, line, old text (must be on that line), new text, proofs to run, what it models
MUTANTS = [
    ('M-FE-MUL', 'secp256k1_fe.asm', 296, 'adc  r12, 0', 'add  r12, 0', 'FE-MUL-P', 'a0*b row loses its carry'),
    ('M-FE-C', 'secp256k1_fe.asm', 64, '0x00000001000003D1', '0x00000001000003D0', 'FE-RED', 'fold constant 977 -> 976'),
    ('M-FE-RED', 'secp256k1_fe.asm', 410, 'adc  r9,  rbx', 'add  r9,  rbx', 'FE-RED', 'second fold drops a carry'),
    ('M-FE-ADD', 'secp256k1_fe.asm', 148, 'cmovc r8,  rax', 'cmovnc r8,  rax', 'FE-ADD', 'inverted final select'),
    ('M-FE-SUB', 'secp256k1_fe.asm', 185, 'sbb r11, [rdx + 24]', 'sub r11, [rdx + 24]', 'FE-SUB', 'borrow chain broken'),
    ('M-FE-INL', 'secp256k1_fe_inline.inc', 113, 'adc  rdi, rdi', 'add  rdi, rdi', 'FE-ADDM,FE-DBL',
     'FE_ADD_TAIL ignores the second carry'),
    ('M-FE-HALF', 'secp256k1_point_ct.asm', 1310, 'rcr  r11, 1', 'shr  r11, 1', 'FE-HALF', 'halving drops bit 256'),
    ('M-FE-INV', 'secp256k1_fe.asm', 717, 'FEINV_SQN 23', 'FEINV_SQN 22', 'FE-INV', 'addition chain one squaring short'),
    ('M-SQRT-C', 'crypto_fe_sqrt.c', 72, 'fe_sqr_n(t1, t1, 6)', 'fe_sqr_n(t1, t1, 5)', 'FE-SQRT', 'C sqrt chain wrong'),
    ('M-SC-ADD', 'secp256k1_scalar.asm', 180, 'cmovnc r8, rcx', 'cmovc r8, rcx', 'SC-ADD', 'inverted conditional subtract'),
    ('M-SC-SUB', 'secp256k1_scalar.asm', 219, 'sbb rax, rax', 'xor rax, rax', 'SC-SUB', 'borrow never adds n back'),
    ('M-SC-MUL', 'secp256k1_scalar.asm', 320, 'adc    r8,  rdx', 'add    r8,  rdx', 'SC-MUL', 'MULACC loses the high-half carry'),
    ('M-SC-FOLD', 'secp256k1_scalar.asm', 392, 'adc    r8,  [rbp-80+8]', 'add    r8,  [rbp-80+8]', 'SC-MUL',
     'FOLD add drops a carry'),
    ('M-SC-DELTA', 'secp256k1_scalar.asm', 52, '0x402DA1732FC9BEBF', '0x402DA1732FC9BEBE', 'SC-MUL,SC-ADD',
     'DELTA = 2^256 - n off by one'),
    ('M-SC-NFOLD', 'secp256k1_scalar.asm', [422, 423, 424, 425, 426], 'FOLD', '', 'SC-MUL',
     'eight FOLDs -> three (the bound chain needs four)'),
    ('M-SC-INV', 'secp256k1_scalar.asm', 97, 'db 0x3f,', 'db 0x3d,', 'SC-INV', 'Fermat exponent n-2 -> n-4'),
    ('M-SPLIT', 'secp256k1_scalar.asm', 721, 'shr  rax, 63', 'shr  rax, 62', 'SC-SPLIT', 'rounding bit 383 -> 382'),
    ('M-RANGE', 'bitcoin_keys.asm', 64, 'jae .bad', 'jae .ok', 'SC-RANGE', 'the pre-fix k == n bug restored'),
    ('M-INRANGE', 'secp256k1_ecdsa.asm', 113, 'jmp .no', 'jmp .yes', 'SC-INRANGE', 'x == n accepted'),
    ('M-B340-RED', 'bip340_sign.c', 72, 'sel4(r, borrow - 1, s, a);', 'sel4(r, borrow, s, a);', 'B340-RED',
     'reduce_n selects the wrong side'),
    ('M-B340-CRY2', 'bip340_sign.c', 60, 'c = (uint64_t)(t >> 64) & 1;', 'c = (uint64_t)(a[i] < b[i] + c);',
     'B340', 'the CRY-2 lost-borrow bug restored (b[i] + c wraps)'),
    ('M-CT-TAIL', 'secp256k1_fe_inline.inc', 115, 'cmovnz r8,  rax', 'jz %%mut\n    mov r8, rax\n%%mut:',
     'CT-pointh_add,CT-gen_ct', 'FE_ADD_TAIL select becomes a branch'),
    ('M-CT-SCADD', 'secp256k1_scalar.asm', 180, 'cmovnc r8, rcx', 'jc .mut\n    mov r8, rcx\n.mut:', 'CT-sc_add',
     'sc_add select becomes a branch'),
    ('M-CT-TABLE', 'secp256k1_point_ct.asm', 751, 'mov  ebx, eax', 'mov  ebx, eax\n    mov  rax, [G_COMB_TABLE + rax*8]',
     'CT-gen_ct', 'a secret-indexed table load'),
]


def run_one(mid, f, line, old, new, sel, what, log):
    tmp = tempfile.mkdtemp(prefix='secp-mut-', dir=os.environ.get('MUT_TMP', os.path.join(HERE, 'build')))
    try:
        sasm = os.path.join(tmp, 'asm')
        shutil.copytree(ASM, sasm, symlinks=True, copy_function=shutil.copy2,
                        ignore=shutil.ignore_patterns('tests', '*.a', 'bitcoind', '.git'))
        p = os.path.join(sasm, f)
        lines = open(p).read().split('\n')
        for ln in (line if isinstance(line, list) else [line]):
            if old not in lines[ln - 1]:
                return 'BAD-MUTANT', 'line %d of %s does not contain %r' % (ln, f, old)
            lines[ln - 1] = lines[ln - 1].replace(old, new, 1)
        open(p, 'w').write('\n'.join(lines))
        os.utime(p, None)
        env = dict(os.environ, ASM=sasm, B=os.path.join(tmp, 'build'))
        b = subprocess.run(['bash', os.path.join(HERE, 'build.sh')], env=env, capture_output=True, text=True)
        log.write('== %s build rc=%d\n%s%s\n' % (mid, b.returncode, b.stdout[-2000:], b.stderr[-2000:]))
        if b.returncode != 0:
            return 'BUILD-FAILED', b.stderr.strip().splitlines()[-1:] if b.stderr else ''
        r = subprocess.run(LIM + ['900', PY, os.path.join(HERE, 'run_all.py'), '--only', sel], env=env,
                           capture_output=True, text=True, cwd=HERE)
        log.write(r.stdout + r.stderr + '\n')
        caught = [l.strip() for l in r.stdout.splitlines() if l.startswith('  NOT PROVED')]
        if r.returncode != 0 and caught:
            return 'CAUGHT', caught[0][:240]
        return 'NOT-CAUGHT', r.stdout.strip().splitlines()[-1:] if r.stdout else r.stderr[-300:]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    want = set(sys.argv[1:])
    fails = 0
    os.makedirs(os.path.join(HERE, 'build'), exist_ok=True)
    with open(os.path.join(HERE, 'build', 'mutants.log'), 'w') as log:
        for m in MUTANTS:
            if want and m[0] not in want:
                continue
            t0 = time.time()
            res, info = run_one(*m, log=log)
            ok = res == 'CAUGHT'
            fails += 0 if ok else 1
            print('%-5s %-12s %-28s %-10s %5.0fs  %s :: %s' % ('PASS' if ok else 'FAIL', m[0], '%s:%s' % (m[1], m[2] if isinstance(m[2], int) else '%d-%d' % (m[2][0], m[2][-1])),
                                                             res, time.time() - t0, m[6], info), flush=True)
    print('MUTANTS: %d failures' % fails)
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
