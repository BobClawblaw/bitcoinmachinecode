#!/usr/bin/env python3
"""diff_tapscript_stack.py -- check gen_tapscript_stack_vectors.py's expected
verdicts against Bitcoin Core itself, not against a reading of Core.

Every vector is replayed through validation/core_verify_oracle's TAPVERIFY
command, which runs Core's real VerifyScript with a PrecomputedTransactionData
built from the spent output and the consensus flag set at a taproot-active
height (GetBlockScriptFlags: P2SH|WITNESS|TAPROOT + DERSIG/NULLDUMMY/CLTV/CSV).

Build the oracle first (from the repo root):
  SRC=/storage/bitcoin-core-source; B=$SRC/build
  g++ -std=c++20 -O1 -I$SRC/src -I$B/src -I$SRC/src/univalue/include \
      -o /tmp/core_verify_oracle validation/core_verify_oracle.cpp \
      -Wl,--start-group $B/lib/libbitcoin_common.a $B/lib/libbitcoin_consensus.a \
      $B/lib/libbitcoin_crypto.a $B/lib/libbitcoin_util.a \
      $B/lib/libbitcoin_clientversion.a $B/src/univalue/libunivalue.a \
      $B/src/secp256k1/lib/libsecp256k1.a -Wl,--end-group

Usage: python3 validation/diff_tapscript_stack.py [path-to-core_verify_oracle]
"""
import os, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gen_tapscript_stack_vectors import build_vectors

ORACLE = sys.argv[1] if len(sys.argv) > 1 else "/tmp/core_verify_oracle"

if not os.path.exists(ORACLE):
    sys.exit("core_verify_oracle not built at %s -- see this file's header" % ORACLE)

vs = build_vectors()
lines = []
for v in vs:
    lines.append("TAPVERIFY 0 %s 1 %d %s" % (v['tx'].hex(), v['value'], v['spk'].hex()))
lines.append("QUIT")

p = subprocess.run([ORACLE], input="\n".join(lines) + "\n",
                   capture_output=True, text=True)
out = [l for l in p.stdout.strip().splitlines() if l.startswith("OK ")]
if len(out) != len(vs):
    sys.exit("oracle returned %d lines for %d vectors:\n%s\n%s"
             % (len(out), len(vs), p.stdout[:400], p.stderr[:400]))

bad = 0
for v, line in zip(vs, out):
    parts = line.split(None, 3)
    got = int(parts[1]); err = parts[3] if len(parts) > 3 else parts[2]
    ok = (got == v['expect'])
    if not ok: bad += 1
    print("%-16s item=%-8d expect=%d core=%d  %-8s  %s"
          % (v['name'], v['item'], v['expect'], got, "OK" if ok else "MISMATCH", err))
print("\n%s (%d/%d agree with Core)" % ("DIVERGENCE" if bad else "ALL AGREE",
                                        len(vs) - bad, len(vs)))
sys.exit(1 if bad else 0)
