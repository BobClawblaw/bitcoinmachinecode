#!/usr/bin/env python3
"""spend_corpus_diff.py -- differential SCRIPT-EXECUTION corpus vs Bitcoin Core.

WHY THIS EXISTS (ASSESSMENT.md sect.5 item 2). The existing block-level
differentials (corpus_diff, fullchain_diff, consensus_diff) all drive
`cons_verify` -- merkle root, PoW, sizes, sigop counts, duplicate txids. That
is a STRUCTURAL check: it never executes a script. Every false-ACCEPT this
project has ever found lived in the script interpreter (the SETcc byte-width
bug diverged on 5,050 scripts in the accept direction), and no amount of
block-level replay or mutation could see it, because Core-running miners never
mined a block that exercises it.

So this harness closes the gap the assessment names: REAL mainnet spends,
executed through the REAL verify stack on both sides, with mutations designed
to make the two disagree.

  Surface G -- real-spend ACCEPT parity. For each sampled spend (a real
      confirmed input: its scriptSig/witness, the prevout's scriptPubKey and
      amount, the spending tx, the input index, and the height's consensus
      flags), Core and the ASM stack must BOTH accept. A rejection here is a
      false-NEGATIVE consensus bug on bytes the chain already contains.
  Surface H -- real-spend MUTATION parity, the false-ACCEPT hunt. Each spend
      is mutated in ways that SHOULD flip the verdict to reject, and both
      engines must agree on the new verdict AND its error class. A mutation
      Core rejects and the ASM accepts is a chain-split-direction defect --
      the class this project cares most about. Mutations are script-level,
      not byte-noise: signature bit flips, DER length/leading-zero edits,
      hashtype-byte edits, pubkey mangling, push-opcode substitutions,
      minimal-encoding violations, stack-depth perturbations, and
      opcode-boundary edits inside the scriptSig.

Corpus is epoch-stratified so every script era is exercised on its own terms:
pre-BIP16 bare, P2SH, segwit v0 (P2WPKH/P2WSH), and taproot (key-path and
script-path), each with the consensus flags real for its height.

ENGINE DIALECTS -- the hard-won part. Each verify entry point wants a
specific transaction serialization, and getting it wrong produces convincing
FALSE divergences (this harness produced eight of them before it was right):
  * legacy  -> WITNESS-STRIPPED tx. Core's legacy SignatureHash omits witness
               data, so a legacy input inside a SEGWIT transaction (they
               exist: one real tx here had 7 witness inputs out of 234) hashes
               the wrong bytes if you pass the raw form.
  * v0      -> RAW tx. BIP143 builds its own serialization internally.
  * v1/taproot -> WITNESS-STRIPPED tx, since BIP341's SigMsg commits to the
               transaction without witnesses.
And the ASM side must be driven through the PRODUCTION verifier
(bitcoin_scriptverify.c's sv_verify_script), not bitcoin_verify.c's
superseded standalone verify_script -- a differential that drives code the
node does not run measures a program nobody executes.

Both engines are driven over the SAME line protocol
(validation/core_verify_oracle.cpp and asm/tests/verify_p2sh_shim.c speak it
already; taproot/segwit inputs use TAPVERIFY, which carries the prevout
amounts BIP143/BIP341 sighashes require).

Usage:
  spend_corpus_diff.py [--per-epoch N] [--mut-per-spend M] [--seed S]
                       [--oracle PATH] [--shim PATH] [--workers W]

Exit 0 iff zero divergences. Writes spend_corpus_diff_report.{json,txt}.
"""
import sys, os, json, time, subprocess, random, base64, argparse
import http.client, select
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
ORACLE = os.path.join(ROOT, 'validation', 'core_verify_oracle')
SHIM   = os.path.join(ROOT, 'asm', 'tests', 'verify_p2sh_shim')
REPORT_JSON = os.path.join(HERE, 'spend_corpus_diff_report.json')
REPORT_TXT  = os.path.join(HERE, 'spend_corpus_diff_report.txt')

# --- Core RPC (same pattern as corpus_diff.py) --------------------------------
RPC_HOST = os.environ.get('BMC_ORACLE_RPC_HOST', '127.0.0.1')
RPC_PORT = int(os.environ.get('BMC_ORACLE_RPC_PORT', '8335'))
COOKIE_PATH = os.environ.get('BMC_ORACLE_COOKIE', '/storage/core-oracle/.cookie')

def _auth():
    try:
        cookie = open(COOKIE_PATH).read().strip()
    except Exception:
        conf = os.environ.get('BMC_ORACLE_CONF', '/storage/core-oracle/bitcoin.conf')
        u = p = None
        try:
            for line in open(conf):
                if line.startswith('rpcuser='):     u = line.split('=',1)[1].strip()
                elif line.startswith('rpcpassword='): p = line.split('=',1)[1].strip()
        except Exception:
            pass
        if not u:
            raise RuntimeError('no oracle RPC credentials (cookie or conf)')
        cookie = '%s:%s' % (u, p)
    return 'Basic ' + base64.b64encode(cookie.encode()).decode()

# Lazy, on purpose: synth_corpus_diff.py imports THIS module for Engine/ORACLE/
# SHIM and never makes an RPC call, so the auth used to be computed at import
# time and the synth harness demanded BMC_ORACLE_COOKIE pointing at any
# readable file just to start. Compute on first real rpc() use instead --
# spend still needs the credentials when it runs, nothing else pays for them.
_AUTH = None

def _rpc_auth():
    global _AUTH
    if _AUTH is None:
        _AUTH = _auth()
    return _AUTH

def rpc(method, params=None):
    body = json.dumps({'jsonrpc':'1.0','id':'x','method':method,'params':params or []})
    c = http.client.HTTPConnection(RPC_HOST, RPC_PORT, timeout=300)
    try:
        c.request('POST', '/', body, headers={'Authorization':_rpc_auth(), 'Content-Type':'application/json'})
        r = c.getresponse(); raw = r.read()
    finally:
        c.close()
    d = json.loads(raw)
    if d.get('error'):
        raise RuntimeError('%s: %s' % (method, d['error']))
    return d['result']

# --- consensus flags by height (Core's GetBlockScriptFlags) -------------------
# Only the bits that gate script BEHAVIOUR; matched to core_verify_oracle's
# uint32 bitmask (script/interpreter.h).
F_P2SH      = 1 << 0
F_DERSIG    = 1 << 2
F_NULLDUMMY = 1 << 4
F_CLTV      = 1 << 9
F_CSV       = 1 << 10
F_WITNESS   = 1 << 11
F_TAPROOT   = 1 << 17

BIP16_H, DERSIG_H, CSV_H, SEGWIT_H, TAPROOT_H = 173805, 363725, 419328, 481824, 709632

def flags_for_height(h):
    f = 0
    if h >= BIP16_H:   f |= F_P2SH
    if h >= DERSIG_H:  f |= F_DERSIG
    if h >= CSV_H:     f |= F_CSV | F_CLTV
    if h >= SEGWIT_H:  f |= F_WITNESS | F_NULLDUMMY
    if h >= TAPROOT_H: f |= F_TAPROOT
    return f

# --- engine drivers -----------------------------------------------------------
class Engine:
    """One long-lived shim/oracle process speaking the VERIFY/TAPVERIFY protocol.

    Reads are TIMED OUT rather than blocking: an engine that does not implement
    a verb simply says nothing, and a blocking readline() would wedge the whole
    corpus forever with no output (exactly what the first run of this harness
    did -- the ASM shim knows only VERIFY/QUIT, so every witness spend hung it).
    A timeout is reported as a capability gap, never silently as agreement."""
    READ_TIMEOUT = 20.0
    def __init__(self, path, name):
        self.path, self.name = path, name
        self.p = None
        self.verbs = set()
        self.spawn()
    def spawn(self):
        if self.p:
            try: self.p.kill()
            except Exception: pass
        self.p = subprocess.Popen([self.path], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, bufsize=1, text=True)
    def _readline_timeout(self):
        r, _, _ = select.select([self.p.stdout], [], [], self.READ_TIMEOUT)
        if not r:
            return None            # engine said nothing: unimplemented verb
        return self.p.stdout.readline()

    def ask(self, line):
        """-> (ok, err) on a verdict; (None, None) on engine failure;
        ('unsupported', None) when the engine does not answer this verb."""
        for attempt in (0, 1):
            try:
                self.p.stdin.write(line + '\n'); self.p.stdin.flush()
                out = self._readline_timeout()
                if out is None:
                    # mute engine: respawn (its stdin state is now unknown) and
                    # report the gap honestly rather than retrying forever.
                    self.spawn()
                    return 'unsupported', None
                if not out:
                    raise RuntimeError('eof')
                parts = out.split()
                # OK <0|1> <error_code> [error_string]
                if len(parts) >= 3 and parts[0] == 'OK':
                    return int(parts[1]), int(parts[2])
                return None, None
            except Exception:
                if attempt == 0:
                    self.spawn(); continue
                return None, None

    def supports(self, verb, probe_line):
        """One-time capability probe so the corpus can SKIP a surface an engine
        cannot drive, and say so in the report, instead of counting silence as
        agreement."""
        if verb in self.verbs:
            return True
        ok, _ = self.ask(probe_line)
        if ok == 'unsupported':
            return False
        self.verbs.add(verb)
        return True
    def quit(self):
        try:
            self.p.stdin.write('QUIT\n'); self.p.stdin.flush(); self.p.wait(timeout=5)
        except Exception:
            try: self.p.kill()
            except Exception: pass

def verify_line(spend, mutated_tx_hex=None, mutated_ss_hex=None, engine='core'):
    """Build the protocol line for a spend, per engine.

    Core drives everything witness-bearing through TAPVERIFY (its
    implementation is full VerifyScript with a PrecomputedTransactionData, so
    it covers v0 and v1 alike). The ASM side has a verb per surface, because
    its entry points differ: taproot_verify_input for v1, and
    sv_verify_witness_v0 for v0 -- the same split daemon/tx_verify.c makes."""
    tx = mutated_tx_hex if mutated_tx_hex is not None else spend['tx_hex']
    kind = spend.get('kind', 'legacy')
    if kind in ('v1', 'v0'):
        if engine == 'core' or kind == 'v1':
            parts = ['TAPVERIFY', str(spend['idx']), tx, str(len(spend['prevouts']))]
            for amt, spk in spend['prevouts']:
                parts += [str(amt), spk]
            return ' '.join(parts)
        ss = mutated_ss_hex if mutated_ss_hex is not None else (spend.get('ss_hex') or '-')
        return 'WITVERIFY %08x %d %s %d %s %s' % (
            spend['flags'], spend['idx'], tx, spend['amount'], spend['spk_hex'], ss or '-')
    ss = mutated_ss_hex if mutated_ss_hex is not None else spend['scriptsig_hex']
    return 'VERIFY %08x %d %s %s %s' % (spend['flags'], spend['idx'], tx, ss, spend['spk_hex'])

# --- spend harvesting ---------------------------------------------------------
res_skips = []

def harvest_block(h, want, rng):
    """Pull up to `want` real spends out of block h, with everything both
    engines need: the spending tx, the input index, every prevout (amount +
    scriptPubKey -- all of them, since BIP341 hashes all spent outputs), and
    the height's consensus flags."""
    bh = rpc('getblockhash', [h])
    blk = rpc('getblock', [bh, 2])
    flags = flags_for_height(h)
    spends = []
    txs = blk['tx'][1:]           # skip coinbase (no scripts to verify)
    rng.shuffle(txs)
    for tx in txs:
        if len(spends) >= want:
            break
        txhex = rpc('getrawtransaction', [tx['txid'], False, bh])
        prevouts, ok = [], True
        for vin in tx['vin']:
            try:
                pv = rpc('getrawtransaction', [vin['txid'], True, None])
            except Exception:
                # no txindex for that parent: try via its own block if known
                ok = False; break
            out = pv['vout'][vin['vout']]
            prevouts.append((int(round(out['value'] * 1e8)), out['scriptPubKey']['hex']))
        if not ok or not prevouts:
            continue
        idx = rng.randrange(len(tx['vin']))
        vin = tx['vin'][idx]
        # ROUTE BY PREVOUT SCRIPT TYPE, not by "does this input carry a
        # witness". taproot_verify_input handles witness v1 ONLY; a v0
        # program (P2WPKH/P2WSH, incl. P2SH-wrapped) sent there is correctly
        # refused, which the first run of this harness misread as a node
        # divergence. Everything that is not v1 goes to the VERIFY path.
        spk_hex = prevouts[idx][1]
        has_wit = bool(vin.get('txinwitness'))
        is_v1 = spk_hex.startswith('5120') and len(spk_hex) == 68
        # THREE-WAY ROUTING, learned the hard way (this harness produced
        # phantom divergences in BOTH directions before it existed):
        #   v1 taproot            -> TAPVERIFY (the only verb that carries
        #                            the witness + every prevout amount)
        #   ANY other witness     -> NOT CHECKABLE HERE. A P2SH-wrapped or
        #     spend (v0, P2SH-wrapped)  native v0 spend sent to plain VERIFY
        #                            loses its witness entirely: our stack
        #                            then accepts on the scriptSig alone
        #                            while Core enforces witness rules
        #                            (MINIMALIF/NULLFAIL) and rejects -- a
        #                            harness artifact that looks exactly
        #                            like a false-ACCEPT. Skipped and
        #                            REPORTED until the shim's TAPVERIFY is
        #                            generalised to v0 programs.
        #   pure non-witness      -> VERIFY
        # v0 (native P2WPKH/P2WSH, or P2SH-wrapped) is now checkable too:
        # the ASM shim grew a WITVERIFY verb (2026-08-25) driving the same
        # sv_verify_witness_v0 the node uses. Core's side uses TAPVERIFY,
        # which is full VerifyScript and therefore covers every witness
        # version -- so both engines see the identical spend.
        ss_hex = vin.get('scriptSig', {}).get('hex', '')
        # A witness program is OP_<0..16> followed by a 2..40 byte push --
        # NOT just the v0/v1 shapes. Anything else in that family (e.g. the
        # P2A anchor 51024e73: v1 with a 2-byte program) is valid-by-policy
        # for Core under current rules and is NOT verifiable through either
        # of our per-version entry points, so it is skipped and reported
        # rather than mis-routed to the legacy path (which is what made an
        # anchor spend look like a divergence).
        def _is_witness_program(h):
            if len(h) < 4 or len(h) % 2: return False
            b = bytes.fromhex(h)
            if not (b[0] == 0x00 or 0x51 <= b[0] <= 0x60): return False
            return len(b) >= 2 and b[1] == len(b) - 2 and 2 <= b[1] <= 40
        is_wprog = _is_witness_program(spk_hex)
        is_v0_native = (spk_hex.startswith('0014') and len(spk_hex) == 44) or \
                       (spk_hex.startswith('0020') and len(spk_hex) == 68)
        is_v0_wrapped = bool(has_wit and ss_hex and spk_hex.startswith('a914'))
        witness = is_v1
        if is_v1:
            kind = 'v1'
        elif is_v0_native or is_v0_wrapped:
            kind = 'v0'
        elif is_wprog or has_wit:
            kind = 'other-witness'      # future/unknown version, or P2A anchors
        else:
            kind = 'legacy'
        if kind == 'other-witness':
            res_skips.append(spk_hex[:8])
            continue
        spends.append({
            'height': h, 'txid': tx['txid'], 'idx': idx, 'flags': flags,
            'tx_hex': txhex, 'witness': witness, 'kind': kind, 'ss_hex': ss_hex,
            'scriptsig_hex': vin.get('scriptSig', {}).get('hex', ''),
            'spk_hex': prevouts[idx][1], 'amount': prevouts[idx][0],
            'prevouts': prevouts,
        })
    return spends

# --- the mutation battery (script-level, verdict-flipping by design) ----------
def _flip_hex_byte(hexs, byte_off, mask=0x01):
    b = bytearray.fromhex(hexs)
    if byte_off >= len(b):
        return None
    b[byte_off] ^= mask
    return b.hex()

def mutations_for(spend, n, rng):
    # For witness spends the ONLY mutation vector that both engines can see
    # identically is the transaction itself: Core's TAPVERIFY carries the tx
    # (and derives the scriptSig from it), while a scriptSig-only mutation
    # would reach the ASM side alone and manufacture a phantom divergence --
    # which it did, on every P2SH-wrapped v0 spend, until this guard existed.
    if spend.get('kind') in ('v0', 'v1'):
        return _tx_mutations(spend, n, rng)
    return _scriptsig_mutations(spend, n, rng)

def _tx_mutations(spend, n, rng):
    """Byte mutations inside the tx's witness region -- visible to BOTH
    engines because both are handed the whole transaction."""
    out = []
    tx = spend['tx_hex']
    nb = len(tx) // 2
    lo = int(nb * 0.6)                     # witness data lives in the tail
    for _ in range(n):
        off = rng.randrange(lo, max(lo + 1, nb - 4))
        m = _flip_hex_byte(tx, off, 1 << rng.randrange(8))
        if m:
            out.append(('wit-flip@%d' % off, {'mutated_tx_hex': m}))
    return out

def _scriptsig_mutations(spend, n, rng):
    """Yield (name, kwargs-for-verify_line) mutations that SHOULD flip the
    verdict to reject. Both engines see identical bytes; disagreement is the
    finding. Legacy inputs mutate the scriptSig (cheap, surgical); witness
    inputs must mutate the tx itself, since the witness lives there."""
    out = []
    if True:
        ss = spend['scriptsig_hex']
        if not ss:
            return out
        nb = len(ss) // 2
        b = bytearray.fromhex(ss)
        cands = []
        # 1) signature body bit flips (the DER blob after the first push byte)
        for _ in range(max(1, n // 2)):
            if nb > 2:
                cands.append(('sig-flip@%d' % (off := rng.randrange(1, nb)),
                              _flip_hex_byte(ss, off, 1 << rng.randrange(8))))
        # 2) hashtype byte (last byte of the first push, classically)
        if nb > 2:
            m = bytearray(b); m[min(nb - 1, b[0] if b[0] < nb else nb - 1)] ^= 0x01
            cands.append(('hashtype-flip', m.hex()))
        # 3) push-opcode substitution (breaks minimal encoding / length)
        if nb > 1:
            m = bytearray(b); m[0] = (m[0] + 1) & 0xff
            cands.append(('pushlen+1', m.hex()))
            m = bytearray(b); m[0] = 0x4c        # OP_PUSHDATA1 where direct push was minimal
            cands.append(('nonminimal-push', m.hex()))
        # 4) DER leading-zero / length surgery inside the signature
        if nb > 4:
            m = bytearray(b); m[2] = (m[2] + 1) & 0xff   # DER total-length byte
            cands.append(('der-len+1', m.hex()))
        # 5) truncate the scriptSig by one byte (stack-depth / parse edge)
        if nb > 1:
            cands.append(('trunc-1', b[:-1].hex()))
        # 6) append a junk push (leftover stack element)
        cands.append(('append-junk', (b + bytearray([0x51])).hex()))
        rng.shuffle(cands)
        for name, m in cands[:n]:
            if m:
                out.append((name, {'mutated_ss_hex': m}))
    return out

# --- one spend, both engines --------------------------------------------------
def run_spend(spend, core, asm, nmut, rng, res):
    c_ok, c_err = core.ask(verify_line(spend, engine='core'))
    a_ok, a_err = asm.ask(verify_line(spend, engine='asm'))
    res['spends'] += 1
    if c_ok == 'unsupported' or a_ok == 'unsupported':
        # One side cannot drive this surface (today: the ASM shim has no
        # TAPVERIFY verb, so witness spends are not yet differentially
        # checkable here). Counted and reported, never scored as parity.
        res['skipped_unsupported'] += 1
        res['skipped_detail'].setdefault(
            'witness' if spend['witness'] else 'legacy', 0)
        res['skipped_detail']['witness' if spend['witness'] else 'legacy'] += 1
        return
    if c_ok is None or a_ok is None:
        res['engine_fail'] += 1
        return
    # Surface G: both must accept a real confirmed spend.
    if c_ok != a_ok:
        res['accept_div'].append({'kind': 'accept-parity', 'height': spend['height'],
                                  'txid': spend['txid'], 'idx': spend['idx'],
                                  'core': c_ok, 'asm': a_ok,
                                  'core_err': c_err, 'asm_err': a_err})
    else:
        res['accept_ok'] += 1
        if c_ok != 1:
            # Both reject a real chain spend: not a divergence, but worth
            # recording -- it means the harness fed something incomplete.
            res['both_reject'] += 1
    # Surface H: mutations must agree, and must not go ASM-accept/Core-reject.
    for name, kw in mutations_for(spend, nmut, rng):
        line_c = verify_line(spend, engine='core', **kw)
        line_a = verify_line(spend, engine='asm', **kw)
        mc_ok, mc_err = core.ask(line_c)
        ma_ok, ma_err = asm.ask(line_a)
        line = line_a
        if mc_ok == 'unsupported' or ma_ok == 'unsupported':
            res['skipped_unsupported'] += 1
            continue
        if mc_ok is None or ma_ok is None:
            res['engine_fail'] += 1
            continue
        res['muts'] += 1
        if mc_ok == ma_ok:
            res['mut_agree'] += 1
            if mc_ok == 1:
                res['mut_both_accept'] += 1   # mutation did not flip the verdict
        else:
            rec = {'kind': 'mutation-parity', 'mutation': name,
                   'height': spend['height'], 'txid': spend['txid'],
                   'idx': spend['idx'], 'core': mc_ok, 'asm': ma_ok,
                   'core_err': mc_err, 'asm_err': ma_err, 'line': line[:400]}
            res['mut_div'].append(rec)
            if ma_ok == 1 and mc_ok == 0:
                res['false_accept'].append(rec)   # THE class that matters

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--per-epoch', type=int, default=6)
    ap.add_argument('--spends-per-block', type=int, default=3)
    ap.add_argument('--mut-per-spend', type=int, default=6)
    ap.add_argument('--seed', type=int, default=20260825)
    ap.add_argument('--oracle', default=ORACLE)
    ap.add_argument('--shim', default=SHIM)
    args = ap.parse_args()

    for p in (args.oracle, args.shim):
        if not os.path.exists(p):
            print('missing engine: %s' % p); return 2

    tip = rpc('getblockcount')
    rng = random.Random(args.seed)
    epochs = [
        ('pre-bip16',      1000, BIP16_H - 1),
        ('bip16-dersig',   BIP16_H, DERSIG_H - 1),
        ('dersig-csv',     DERSIG_H, CSV_H - 1),
        ('csv-segwit',     CSV_H, SEGWIT_H - 1),
        ('segwit-taproot', SEGWIT_H, TAPROOT_H - 1),
        ('taproot-tip',    TAPROOT_H, tip),
    ]
    heights = []
    for name, lo, hi in epochs:
        for _ in range(args.per_epoch):
            heights.append((name, rng.randrange(lo, max(lo + 1, hi))))

    core = Engine(args.oracle, 'core')
    asm  = Engine(args.shim, 'asm')
    res = {'spends': 0, 'accept_ok': 0, 'both_reject': 0, 'muts': 0,
           'mut_agree': 0, 'mut_both_accept': 0, 'engine_fail': 0,
           'skipped_unsupported': 0, 'skipped_detail': {},
           'accept_div': [], 'mut_div': [], 'false_accept': [], 'by_epoch': {}}
    t0 = time.time()
    for name, h in heights:
        try:
            spends = harvest_block(h, args.spends_per_block, rng)
        except Exception as e:
            print('  harvest h=%d failed: %s' % (h, e)); continue
        res.setdefault('skipped_v0_witness', 0)
        res['by_epoch'].setdefault(name, 0)
        res['by_epoch'][name] += len(spends)
        for sp in spends:
            run_spend(sp, core, asm, args.mut_per_spend, rng, res)
        print('  %-16s h=%-8d spends=%d  running: accept_ok=%d muts=%d div=%d false_accept=%d'
              % (name, h, len(spends), res['accept_ok'], res['muts'],
                 len(res['accept_div']) + len(res['mut_div']), len(res['false_accept'])))
    core.quit(); asm.quit()
    res['elapsed'] = round(time.time() - t0, 1)
    res['tip'] = tip
    res['seed'] = args.seed

    ndiv = len(res['accept_div']) + len(res['mut_div'])
    with open(REPORT_JSON, 'w') as f:
        json.dump(res, f, indent=1)
    with open(REPORT_TXT, 'w') as f:
        f.write('Differential SCRIPT-EXECUTION corpus vs Core\n')
        f.write('generated: %s  tip: %s  elapsed: %ss  seed: %s\n\n'
                % (time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), tip,
                   res['elapsed'], args.seed))
        f.write('spends: %d (accept-parity ok %d, both-reject %d)\n'
                % (res['spends'], res['accept_ok'], res['both_reject']))
        f.write('mutations: %d (agree %d, did-not-flip %d)\n'
                % (res['muts'], res['mut_agree'], res['mut_both_accept']))
        f.write('by epoch: %s\n' % json.dumps(res['by_epoch']))
        f.write('routing: v1/taproot -> TAPVERIFY both sides;\n'
                '         v0 (native + P2SH-wrapped) -> Core TAPVERIFY vs ASM WITVERIFY;\n'
                '         pure non-witness -> VERIFY both sides.\n')
        f.write('engine failures: %d\n' % res['engine_fail'])
        if res['skipped_unsupported']:
            f.write('SKIPPED (an engine cannot drive the verb): %d  %s\n'
                    % (res['skipped_unsupported'], json.dumps(res['skipped_detail'])))
            f.write('  -> the ASM verify shim implements VERIFY only; witness/taproot\n'
                    '     spends need a TAPVERIFY verb on that side before they can be\n'
                    '     differentially checked here. NOT counted as agreement.\n')
        f.write('\n')
        if ndiv == 0:
            f.write('ZERO DIVERGENCES across real mainnet spends and their mutations.\n')
        else:
            f.write('DIVERGENCES: %d (FALSE-ACCEPTS: %d)\n\n'
                    % (ndiv, len(res['false_accept'])))
            for d in (res['false_accept'] or res['accept_div'] + res['mut_div'])[:40]:
                f.write(json.dumps(d) + '\n')
    print('\n%s' % open(REPORT_TXT).read())
    return 0 if ndiv == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
