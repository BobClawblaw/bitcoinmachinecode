#!/usr/bin/env python3
"""bip30_diff.py -- chain-context BIP30 differential: ASM node vs Bitcoin Core.

BIP30 (duplicate-txid rule) is a UTXO/chain-context consensus rule. Core's
ConnectBlock (validation.cpp "Do not allow blocks that contain transactions
which 'overwrite' older transactions, unless those are already completely
spent") rejects a block with `bad-txns-BIP30` when any tx output (txid, vout)
would collide with an already-unspent coin, EXCEPT for the two historical
mainnet duplicate-coinbase blocks (heights 91842 / 91880) that Core
grandfathers via IsBIP30Repeat.

WHAT THIS HARNESS ACTUALLY DRIVES -- read this before trusting a green run.

Until 2026-08-23 this file drove asm/tests/bip30_shim for both parts, and
claimed to prove "the ASM node implements that exact rule to zero divergence".
It did not. bip30_shim.c IMPLEMENTS BIP30 itself -- is_bip30_repeat(), the
`enforce` flag and the utxo_get collision test are all inside the shim -- and
the shim is not linked into daemon/bitcoind. The daemon had no BIP30 check at
all (LOG.md incident #30). A green differential sat beside a missing rule for
as long as both existed, because the differential was validating the shim.

  PART 1 now drives asm/tests/bip30_daemon_shim, which contains NO BIP30 logic:
      `enforce` comes from the daemon's real gate
      (utxo_live_test_bip30_enforced) and `bip30` is set only by the real
      BIP30 arm of the real apply path (utxo_live_test_took_bip30_reject).

      WHAT PART 1 CAN AND CANNOT CATCH -- measured by sabotage, 2026-08-23,
      because an unverified claim about a test's power is how this file came
      to overclaim in the first place:

        sabotage the GATE (drop the 91842 grandfather) -> 2 divergences at
          exactly h91842, one of them "ASM rejected a real in-chain block".
          Caught.
        sabotage the CHECK (disable the duplicate scan, leave the gate) ->
          0 divergences. NOT caught.

      Part 1 replays only real mainnet blocks and no real block violates
      BIP30, so "false-bip30=0" passes whether or not the check exists. What
      Part 1 proves is that the ENFORCEMENT GATE is Core-exact across the
      affected region and that the daemon false-rejects none of 91,889 real
      blocks. Detection of an actual violation is proved by
      tests/test_bip30_daemon, which constructs a genuine txid collision.

      (The gate-sabotage run is also the one piece of evidence that the
      daemon's check fires on the REAL historical duplicate: with 91842 no
      longer grandfathered, the daemon rejected it.)

      It is slower than the old shim because it does full block connection --
      that is the price of testing what ships.

  PART 2 still drives the legacy bip30_shim and therefore still proves only
      that the SHIM matches Core on constructed duplicates. Repointing it needs
      synthetic regtest blocks to survive full block connection, which is more
      than a shim swap. Until then, treat PART 2 as a Core-semantics reference,
      not as evidence about bitcoind. tests/test_bip30_daemon covers the same
      constructed-duplicate case against the real apply path.

  PART 1 - Real-mainnet chain-context region sweep (the BIP30 affected region):
      replay real mainnet blocks 0..91900 through the DAEMON's apply path
      (chain context), and assert:
        * every real block is ACCEPTED (bip30=0)  -- matching Core, which has
          them all in-chain (zero false rejections);
        * the BIP30 enforcement switch is Core-exact: fEnforceBIP30==0 only at
          the two IsBIP30Repeat blocks (91842 / 91880) and ==1 everywhere else
          in the region (grandfather fires "there and only there").

  PART 2 - Constructive duplicate-coinbase / duplicate-txid semantics vs real
      Core (self-hosted regtest): build a private chain, create a live tx, then
      attempt a byte-identical duplicate in a later block:
        * while the earlier coin is STILL UNSPENT -> Core bad-txns-BIP30 and
          ASM bip30=1 agree (duplicate NOT accepted while live = "only there");
        * after that coin is fully SPENT -> Core no longer reports bad-txns-
          BIP30 and ASM bip30=0 agree (duplicate accepted there = the 91842 ->
          91880 historical relationship, where the prior coin's spending makes
          the re-spend of a prior non-ancestor coinbase valid).

Requires: the SCRATCH Core oracle at /storage/core-oracle (never the
production install at /storage/bitcoin), and both shim binaries --
`make tests/bip30_daemon_shim tests/bip30_shim`.

Usage:
  bip30_diff.py [--seed-end 91500] [--region-start 91500] [--region-end 91888]
                [--shim PATH]
Exit 0 if zero divergences. Writes validation/bip30_diff_report.json.
"""
import os, sys, subprocess, hashlib, struct, time, json, shutil, argparse, tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, '..'))
# PART 1 drives the DAEMON's own apply path (asm/tests/bip30_daemon_shim,
# which contains no BIP30 logic of its own). PART 2 still drives the old
# tests/bip30_shim -- see the module docstring for exactly what that means.
SHIM = os.path.join(ROOT, 'asm', 'tests', 'bip30_daemon_shim')
SHIM_LEGACY = os.path.join(ROOT, 'asm', 'tests', 'bip30_shim')
REPORT = os.path.join(HERE, 'bip30_diff_report.json')

# The compliance oracle is the SCRATCH Core at /storage/core-oracle, never the
# production install at /storage/bitcoin -- that one is off limits, including
# for reads, and PART 2 additionally *launches* a regtest node from the binary
# it names here.
CORE_BIN_DIR = "/storage/bitcoin-core-source/build/bin"
MAIN_CLI = [CORE_BIN_DIR + "/bitcoin-cli",
            "-conf=/storage/core-oracle/bitcoin.conf",
            "-datadir=/storage/core-oracle"]
RPC_BIN = CORE_BIN_DIR + "/bitcoind"

# The two historical mainnet duplicate-coinbase blocks (validation.cpp IsBIP30Repeat).
BIP30_GRANDFATHER = {91842, 91880}


def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()


# ---------------------------------------------------------------------------
# ASM chain-context shim driver
# ---------------------------------------------------------------------------
class Shim:
    """Drives either CONNECT shim. bip30_daemon_shim takes a scratch directory
    (it re-inits a real utxo_live view per RESET); bip30_shim takes none."""
    def __init__(self, path=SHIM, scratch=None):
        argv = [path]
        self._tmp = None
        if os.path.basename(path) == 'bip30_daemon_shim':
            if scratch is None:
                self._tmp = tempfile.mkdtemp(prefix='bip30_daemon_shim.')
                scratch = self._tmp
            argv.append(scratch)
        self.p = subprocess.Popen(argv, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, text=True, bufsize=1)
    def send(self, s):
        self.p.stdin.write(s + "\n"); self.p.stdin.flush()
        return self.p.stdout.readline().strip()
    def connect(self, hexblk, h):
        r = self.send("CONNECT %s %d" % (hexblk, h)).split()
        return {'enforce': int(r[1]), 'bip30': int(r[2]), 'ntx': int(r[3]), 'added': int(r[4])}
    def reset(self):
        self.send("RESET")
    def close(self):
        self.send("QUIT")
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True); self._tmp = None


# ---------------------------------------------------------------------------
# PART 1: real-mainnet chain-context region sweep
# ---------------------------------------------------------------------------
def mainnet_block_hex(h):
    cli = MAIN_CLI
    out = subprocess.run(cli + ["getblockhash", str(h)], capture_output=True, text=True)
    hsh = out.stdout.strip()
    out = subprocess.run(cli + ["getblock", hsh, "0"], capture_output=True, text=True)
    return out.stdout.strip()


def part1(args, core_tip):
    print("\n===== PART 1: real-mainnet chain-context BIP30 region sweep =====")
    divs = []
    seed_end = args.seed_end
    region_start = args.region_start
    region_end = args.region_end

    # fetch seed blocks 0..seed_end-1 and region blocks region_start..region_end
    def fetch(lo, hi):
        with ThreadPoolExecutor(24) as ex:
            return list(ex.map(mainnet_block_hex, range(lo, hi)))
    print("fetching seed 0..%d ..." % (seed_end - 1), flush=True)
    seed = fetch(0, seed_end)
    print("fetching region %d..%d ..." % (region_start, region_end), flush=True)
    region = fetch(region_start, region_end + 1)

    shim = Shim(args.shim)
    shim.reset()
    t0 = time.time()
    for h, hexb in enumerate(seed):
        r = shim.connect(hexb, h)
        if r['bip30'] != 0:
            divs.append({'where': 'seed@%d' % h, 'detail': 'false BIP30 on real in-chain block'})
            break
    seed_n = len(seed)
    t_seed = time.time() - t0

    t0 = time.time()
    region_n = 0
    for i, hexb in enumerate(region):
        h = region_start + i
        r = shim.connect(hexb, h)
        region_n += 1
        exp_enforce = 0 if h in BIP30_GRANDFATHER else 1
        if r['bip30'] != 0:
            divs.append({'where': 'region@%d' % h,
                         'detail': 'ASM rejected a real in-chain block (false BIP30)'})
        if r['enforce'] != exp_enforce:
            divs.append({'where': 'region@%d' % h,
                         'detail': 'enforce=%d expected %d (IsBIP30Repeat)' % (r['enforce'], exp_enforce)})
    t_region = time.time() - t0
    shim.close()

    print("SEED  0..%d: %d blocks, false-bip30=%d" % (seed_end - 1, seed_n,
          sum(1 for d in divs if 'seed' in d['where'])))
    print("REGION %d..%d: %d blocks, false-bip30+enforce-mismatch=%d"
          % (region_start, region_end, region_n, sum(1 for d in divs if 'region' in d['where'])))
    print("  seed %.1fs, region %.1fs" % (t_seed, t_region))
    for d in divs:
        print("  DIVERGENCE", d)
    return divs, {'seed_blocks': seed_n, 'region_blocks': region_n,
                  'region_start': region_start, 'region_end': region_end,
                  'grandfathered_zero_enforce': sorted(BIP30_GRANDFATHER)}


# ---------------------------------------------------------------------------
# PART 2: constructive semantics vs real Core (self-hosted regtest)
# ---------------------------------------------------------------------------
DATADIR = "/tmp/bip30regtest"
REG_CLI = [CORE_BIN_DIR + "/bitcoin-cli", "-datadir=%s" % DATADIR, "-regtest",
           "-rpcport=18455", "-rpcuser=regtest", "-rpcpassword=regtestpass"]


def reg_call(*a, stdin=None):
    a = [str(x) for x in a]
    if stdin is not None:
        r = subprocess.run(REG_CLI + ["-stdin"] + list(a), capture_output=True,
                           text=True, input=stdin + "\n")
    else:
        r = subprocess.run(REG_CLI + list(a), capture_output=True, text=True)
    out = r.stdout.strip()
    try: return json.loads(out)
    except Exception: return out


def varint(n):
    if n < 0xfd: return bytes([n])
    if n <= 0xffff: return b'\xfd' + struct.pack('<H', n)
    if n <= 0xffffffff: return b'\xfe' + struct.pack('<I', n)
    return b'\xff' + struct.pack('<Q', n)


def csnum_pushed(n):
    if n == 0: return b'\x00'
    s = bytearray(); ab = abs(n)
    while ab:
        s.append(ab & 0xff); ab >>= 8
    if s[-1] & 0x80: s.append(0)
    return bytes([len(s)]) + bytes(s)


def coinbase(height):
    cb = struct.pack('<I', 1); cb += varint(1)
    cb += b'\x00' * 32 + struct.pack('<I', 0xffffffff)
    sc = csnum_pushed(height) + b'\x00'
    cb += varint(len(sc)) + sc; cb += struct.pack('<I', 0xffffffff)
    cb += varint(1)
    cb += struct.pack('<Q', (50 * 100000000) >> (height // 150))
    cb += varint(1) + b'\x51'; cb += struct.pack('<I', 0)
    return cb


def merkle_root(txids):
    if len(txids) == 1: return txids[0]
    md = []
    for i in range(0, len(txids), 2):
        a = txids[i]; b = txids[i+1] if i+1 < len(txids) else txids[i]
        md.append(sha256d(a + b))
    return merkle_root(md)


def build_block(prev_be, nbits, txs, height, blk_time):
    cb = coinbase(height); cb_id = sha256d(cb)[::-1].hex()
    all_txs = [(cb.hex(), cb_id)] + txs
    body = varint(len(all_txs)) + b''.join(bytes.fromhex(t[0]) for t in all_txs)
    txids = [bytes.fromhex(t[1])[::-1] for t in all_txs]
    merk = merkle_root(txids)
    exp = (nbits >> 24) & 0xff; mant = nbits & 0x7fffff
    target = (mant >> (8*(3-exp))) if exp <= 3 else (mant << (8*(exp-3)))
    for nonce in range(0, 0x2000000):
        hdr = struct.pack('<I', 0x20000000) + bytes.fromhex(prev_be)[::-1] + merk \
              + struct.pack('<I', blk_time) + struct.pack('<I', nbits) + struct.pack('<I', nonce)
        if int.from_bytes(sha256d(hdr), 'little') <= target:
            return hdr + body
    raise RuntimeError("nonce")


def optrue_tx(prev_txid_le, prev_vout, out_val):
    txin = prev_txid_le + struct.pack('<I', prev_vout).hex() + "01" + "51" + "ffffffff"
    return (struct.pack('<I', 1).hex() + varint(1).hex() + txin
            + varint(1).hex() + struct.pack('<Q', out_val).hex()
            + varint(1).hex() + "51" + struct.pack('<I', 0).hex())


def part2(args, shim_path):
    print("\n===== PART 2: constructive duplicate-txid semantics vs real Core =====")
    divs = []
    # fresh self-hosted regtest node
    subprocess.run(REG_CLI + ["stop"], capture_output=True, text=True)
    time.sleep(2)
    shutil.rmtree(DATADIR, ignore_errors=True)
    os.makedirs(DATADIR)
    open(os.path.join(DATADIR, "bitcoin.conf"), "w").write(
        "regtest=1\nserver=1\nrpcuser=regtest\nrpcpassword=regtestpass\nrpcport=18455\n")
    subprocess.Popen([RPC_BIN, "--datadir=%s" % DATADIR, "-regtest", "-server=1",
                      "-rpcuser=regtest", "-rpcpassword=regtestpass", "-rpcport=18455",
                      "-listen=0", "-daemon=1", "-dbcache=100"],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(90):
        r = subprocess.run(REG_CLI + ["getblockcount"], capture_output=True, text=True)
        if r.stdout.strip().isdigit(): break
        time.sleep(1)
    reg_call("createwallet", "test")
    reg_call("generatetoaddress", 105, reg_call("getnewaddress"))
    base = reg_call("getblockcount")
    tip = reg_call("getbestblockhash")
    tipraw = bytes.fromhex(reg_call("getblock", tip, "0"))
    nbits = int.from_bytes(tipraw[72:76], 'little')
    tip_time = int.from_bytes(tipraw[68:72], 'little')

    # capture baseline chain for ASM replay
    chain = {}
    with ThreadPoolExecutor(16) as ex:
        blobs = list(ex.map(lambda h: reg_call("getblock", reg_call("getblockhash", h), "0"),
                            range(0, base + 1)))
    for h, hb in enumerate(blobs): chain[h] = hb

    tip_h = base
    for i in range(1, 108):          # lay 107 OP_TRUE coinbase-only blocks
        blk = build_block(tip, nbits, [], tip_h+1, tip_time + i)
        r = reg_call("submitblock", stdin=blk.hex())
        if r not in (None, ''):
            divs.append({'where': 'lay@%d' % (tip_h+1), 'detail': 'setup %s' % r}); break
        tip_h += 1; chain[tip_h] = blk.hex()
        tip = reg_call("getbestblockhash")
        tipraw = bytes.fromhex(reg_call("getblock", tip, "0")); tip_time = int.from_bytes(tipraw[68:72], 'little')

    cb_blk = reg_call("getblock", reg_call("getblockhash", base+1), "2")
    cb_txid = cb_blk["tx"][0]["txid"]
    cb_txid_le = ''.join(cb_txid[i:i+2] for i in range(len(cb_txid)-2, -1, -2))
    T_live = optrue_tx(cb_txid_le, 0, 4999900000)
    tid = reg_call("decoderawtransaction", T_live)["txid"]

    blk_live = build_block(tip, nbits, [(T_live, tid)], tip_h+1, tip_time + 1)
    r = reg_call("submitblock", stdin=blk_live.hex())
    if r not in (None, ''):
        raise RuntimeError("mine T_live -> %s" % r)
    tip_h += 1; chain[tip_h] = blk_live.hex()
    t_live_h = tip_h
    tip = reg_call("getbestblockhash")
    tipraw = bytes.fromhex(reg_call("getblock", tip, "0")); tip_time = int.from_bytes(tipraw[68:72], 'little')
    if not reg_call("gettxout", tid, 0):
        raise RuntimeError("(T_live,0) not live")

    # Case A: duplicate while live
    blk_dupA = build_block(tip, nbits, [(T_live, tid)], tip_h+1, tip_time + 1)
    rA = reg_call("submitblock", stdin=blk_dupA.hex())

    # spend (T_live,0)
    tid_le = ''.join(tid[i:i+2] for i in range(len(tid)-2, -1, -2))
    T_spend = optrue_tx(tid_le, 0, 4999800000)
    stid = reg_call("decoderawtransaction", T_spend)["txid"]
    blk_spend = build_block(tip, nbits, [(T_spend, stid)], tip_h+1, tip_time + 1)
    rs = reg_call("submitblock", stdin=blk_spend.hex())
    if rs not in (None, ''):
        raise RuntimeError("spend -> %s" % rs)
    tip_h += 1; chain[tip_h] = blk_spend.hex()
    spend_h = tip_h
    tip = reg_call("getbestblockhash")
    tipraw = bytes.fromhex(reg_call("getblock", tip, "0")); tip_time = int.from_bytes(tipraw[68:72], 'little')

    # Case B: same duplicate after spend
    blk_dupB = build_block(tip, nbits, [(T_live, tid)], tip_h+1, tip_time + 1)
    rB = reg_call("submitblock", stdin=blk_dupB.hex())

    # ASM replay: two fresh chain contexts
    chain_list = sorted((h, hb) for h, hb in chain.items() if h <= tip_h)

    def asm_replay_connect(up_to_height, blk_hex, blk_height):
        sh = Shim(shim_path); sh.reset()
        for h, hb in chain_list:
            if h > up_to_height: break
            sh.connect(hb, h)
        res = sh.connect(blk_hex, blk_height); sh.close()
        return res

    aA = asm_replay_connect(t_live_h, blk_dupA.hex(), t_live_h + 1)
    aB = asm_replay_connect(spend_h, blk_dupB.hex(), spend_h + 1)
    subprocess.run(REG_CLI + ["stop"], capture_output=True, text=True)

    coreA_bip30 = 'BIP30' in str(rA)
    coreB_bip30 = 'BIP30' in str(rB)
    agreeA = (aA['bip30'] == 1) and coreA_bip30
    agreeB = (aB['bip30'] == 0) and (not coreB_bip30)
    print("  A duplicate-live  : Core=%r (bad-txns-BIP30)  ASM bip30=%d -> agree=%s"
          % (coreA_bip30, aA['bip30'], agreeA))
    print("  B duplicate-spent : Core BIP30=%r (reject=%r)  ASM bip30=%d -> agree=%s"
          % (coreB_bip30, rB, aB['bip30'], agreeB))
    if not agreeA: divs.append({'where': 'constructive-A', 'detail': 'live-duplicate verdict mismatch'})
    if not agreeB: divs.append({'where': 'constructive-B', 'detail': 'spent-duplicate verdict mismatch'})
    return divs, {'case_A': {'core_verdict': rA, 'asm_bip30': aA['bip30']},
                  'case_B': {'core_verdict': rB, 'asm_bip30': aB['bip30']},
                  'agree_A': agreeA, 'agree_B': agreeB,
                  't_live_txid': tid, 't_live_height': t_live_h, 'spend_height': spend_h}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--seed-end', type=int, default=91500)
    ap.add_argument('--region-start', type=int, default=91500)
    ap.add_argument('--region-end', type=int, default=91888)
    ap.add_argument('--shim', default=SHIM)
    ap.add_argument('--part', choices=['1', '2', 'all'], default='all')
    args = ap.parse_args()

    divs = []
    report = {'generated': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}
    part1_res = part2_res = None

    tip = subprocess.run(MAIN_CLI + ["getblockcount"], capture_output=True, text=True).stdout.strip()
    report['mainnet_tip'] = tip
    print("mainnet Core tip:", tip)

    if args.part in ('1', 'all'):
        d, r1 = part1(args, tip)
        divs += d; part1_res = r1
    if args.part in ('2', 'all'):
        d, r2 = part2(args, SHIM_LEGACY)
        divs += d; part2_res = r2

    report['part1'] = part1_res
    report['part2'] = part2_res
    report['divergences'] = divs
    os.makedirs(os.path.dirname(REPORT), exist_ok=True)
    with open(REPORT, 'w') as f:
        json.dump(report, f, indent=1)
    print("\n===== bip30 differential report =====")
    print("  divergences: %d" % len(divs))
    for d in divs:
        print("   ", d)
    print("  report -> %s" % REPORT)
    return 0 if not divs else 1


if __name__ == '__main__':
    sys.exit(main())
