#!/usr/bin/env python3
"""p2sh_diff.py -- differential parity of the ASM P2SH VerifyScript vs Bitcoin Core.

Drives the SAME (scriptSig, scriptPubKey, tx, inputIndex, flags) triples (from
gen_p2sh_vectors.gen_cases) through two engines and requires identical verdict +
ScriptError code:

  * Core : validation/core_verify_oracle (compiled against Bitcoin Core's
           script/interpreter.cpp VerifyScript)
  * ASM  : asm/tests/verify_p2sh_shim      (bitcoin_verify.c VerifyScript)

The corpus covers GENUINE P2SH spends -- a real 2-of-3 OP_CHECKMULTISIG redeem
signed with two real legacy SIGHASH_ALL signatures (redeem as signing script)
and a 1-of-1 P2PKH-shaped redeem -- plus negatives (bad redeem / non-pushonly,
wrong sig, insufficient sigs, null dummy, empty scriptSig, and the pre-BIP16
P2SH-flag-off regime) which must be rejected identically to Core.

Exit 0 if zero divergences.
"""
import os, sys, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
ORACLE = os.environ.get('P2SH_ORACLE', '/tmp/core_verify_oracle')
SHIM = os.path.join(ROOT, 'asm', 'tests', 'verify_p2sh_shim')

sys.path.insert(0, HERE)
from gen_p2sh_vectors import gen_cases

class Engines:
    def __init__(self):
        self.co = subprocess.Popen([ORACLE], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.sh = subprocess.Popen([SHIM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    def ask(self, p, flags, idx, tx, ss, spk):
        sss = ss.hex() if ss else '-'
        spks = spk.hex() if spk else '-'
        p.stdin.write('VERIFY %x %d %s %s %s\n' % (flags, idx, tx.hex(), sss, spks))
        p.stdin.flush()
        return p.stdout.readline().strip()
    def core(self, flags, idx, tx, ss, spk):
        r = self.ask(self.co, flags, idx, tx, ss, spk).split()
        return (int(r[1]), int(r[2]))
    def asm(self, flags, idx, tx, ss, spk):
        r = self.ask(self.sh, flags, idx, tx, ss, spk).split()
        return (int(r[1]), int(r[2]))
    def close(self):
        for p in (self.co, self.sh):
            try: p.stdin.write('QUIT\n'); p.stdin.flush()
            except Exception: pass
            try: p.terminate()
            except Exception: pass

def main():
    eng = Engines()
    divs = []
    total = [0, 0]
    try:
        for (name, flags, idx, tx, ss, spk) in gen_cases():
            cok, cerr = eng.core(flags, idx, tx, ss, spk)
            aok, aerr = eng.asm(flags, idx, tx, ss, spk)
            total[0] += 1
            same = (cok == aok and cerr == aerr)
            if same: total[1] += 1
            print('  %-20s flags=%08x core=(%d,%d) asm=(%d,%d) %s'
                  % (name, flags, cok, cerr, aok, aerr, 'OK' if same else 'DIVERGE'))
            if not same:
                divs.append({'case': name, 'flags': hex(flags), 'core': (cok, cerr), 'asm': (aok, aerr)})
    finally:
        eng.close()
    print('\n==== P2SH differential ==== agree=%d/%d divergences=%d'
          % (total[1], total[0], len(divs)))
    for dd in divs: print('  DIVERGENCE', dd)
    return 0 if not divs else 1

if __name__ == '__main__':
    sys.exit(main())
