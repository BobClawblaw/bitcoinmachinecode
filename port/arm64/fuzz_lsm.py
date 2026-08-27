#!/usr/bin/env python3
"""Differential fuzzer for the PORTED bitcoin_utxo_lsm.S.

A pure-Python model of the LSM (memtable dict + this-generation tombstones +
sorted immutable runs + manifest) drives the C driver t_lsm interactively via a
MARK sentinel. Every op's output (put/del returns, C counter, G get, W full-set
walk) is compared against the model, and after every flush/compact the on-disk
run files + manifest are byte-compared against the model's own serialization
(header magic/gen/nrec/bloom_bits, 3-seed FNV bloom, sparse index every
SPARSE_STRIDE, PUSH/DEL records). reload/reload_ro must reconstruct the exact
pre-reload live set (WAL-tail + manifest + runs replay), including with the
checkpoint (utxo.idx) removed.
"""
import subprocess, sys, os, struct, random, shutil

BIN = '/home/svc/bitcoinmachinecode/port/arm64/t_lsm'
P = None
MAGIC_RUN3 = 0x33555255
MAGIC_MANIFEST2 = 0x324E4D55
SPARSE_STRIDE = 256
SEEDS = (0x811c9dc5, 0xa1b2c3d4, 0x5bd1e995)

def key36(txid, idx):
    return txid + idx.to_bytes(4, 'little')

P_BLOOM = struct.Struct('<QI')   # (bits, bbytes) not used; kept for clarity

def bloom_for(n, keys):
    bb = n * 10
    if bb < 64:
        bb = 64
    bits = 1
    while bits < bb:
        bits <<= 1
    cap = 2 ** 25                 # BLOOM_MAX_BYTES*8
    if bits > cap:
        bits = cap
    bmask = bits - 1
    bloom = bytearray(bits >> 3)
    for key in keys:
        for seed in SEEDS:
            h = seed & 0xFFFFFFFF
            for b in key:
                h ^= b
                h = (h * 16777619) & 0xFFFFFFFF
            bit = h & bmask
            bloom[bit >> 3] |= 1 << (bit & 7)
    return bits, bytes(bloom)

def build_run(gen, run_no, records, bloom_n=None):
    """records: sorted list of (key, 'P'/'D', rec); rec=(value,h,cb,sl,scr) or None.
    bloom_n: count used to size the bloom filter. The ASM sizes a FLUSH run's bloom
    from its own nrec, but a COMPACTED run's bloom from the input upper_bound
    (sum of the merged runs' nrecs), which can exceed the output nrec."""
    nrec = len(records)
    bn = bloom_n if bloom_n is not None else nrec
    bits, bloom = bloom_for(bn, [r[0] for r in records])
    bbytes = bits >> 3
    recblob = b''
    offs = []
    off = 44 + bbytes
    for idx, (key, t, rec) in enumerate(records):
        if idx % SPARSE_STRIDE == 0:
            offs.append((key, off))
        rb = key + bytes([1 if t == 'P' else 2])
        if t == 'P':
            value, h, cb, sl, scr = rec
            rb += struct.pack('<QHIB', value, sl, h, cb) + scr
        off += len(rb)
        recblob += rb
    sparse_off, sparse_n = off, len(offs)
    sparse = b''.join(k + struct.pack('<Q', o) for k, o in offs)
    hdr = struct.pack('<I', MAGIC_RUN3) + struct.pack('<Q', gen) + struct.pack('<Q', nrec)
    hdr += struct.pack('<Q', bits) + struct.pack('<Q', sparse_off) + struct.pack('<Q', sparse_n)
    return hdr + bloom + recblob + sparse

def build_manifest(manifest_n, total_live, entries):
    hdr = struct.pack('<I', MAGIC_MANIFEST2) + struct.pack('<Q', manifest_n) + struct.pack('<Q', total_live)
    return hdr + b''.join(struct.pack('<QQ', g, r) for g, r in entries)

class Model:
    def __init__(self):
        self.mem = {}
        self.tomb = set()
        self.runs = []              # list of {'gen','run_no','recs':{key:(t,rec)}}
        self.next_gen = 0
        self.next_run_no = 0
        self.op_count = 0
        self.tl = 0
        self.last_persist_tl = None
        self.manifest_n = 0

    def live_set(self):
        obs = {}
        for k, rec in self.mem.items():
            obs[k] = rec
        for k in self.tomb:                       # unflushed tombstones shadow
            if k not in obs:
                obs[k] = None
        for r in reversed(self.runs):
            for k, (t, rec) in r['recs'].items():
                if k in obs:
                    continue
                obs[k] = None if t == 'D' else rec
        return {k: rec for k, rec in obs.items() if rec is not None}

    def get(self, k):
        if k in self.mem:
            return ('P', self.mem[k])
        if k in self.tomb:
            return None
        for r in reversed(self.runs):
            if k in r['recs']:
                return r['recs'][k]
        return None

    def put(self, k, rec):
        was = k in self.mem
        if not was:
            self.mem[k] = rec        # put-if-absent: existing keys keep their record
            self.tl += 1
        self.op_count += 1
        return 0 if was else 1

    def delete(self, k):
        if k in self.mem:
            del self.mem[k]
        self.tomb.add(k)
        self.op_count += 1
        self.tl -= 1
        return 1

    def should_flush(self):
        return self.op_count >= OP_THR or len(self.mem) >= FILL_THR

    def flush(self):
        records = [(k, 'P', self.mem[k]) for k in sorted(self.mem)]
        records += [(k, 'D', None) for k in sorted(self.tomb - set(self.mem))]
        records.sort(key=lambda x: x[0])
        if records:
            run = dict(gen=self.next_gen, run_no=self.next_run_no,
                       recs={k: (t, rec) for k, t, rec in records}, bloom_n=len(records))
            self.runs.append(run)
            self.next_gen += 1
            self.next_run_no += 1
            self.manifest_n = len(self.runs)
            self.last_persist_tl = self.tl
        self.mem = {}
        self.tomb = set()
        self.op_count = 0
        return 1

    def compact(self):
        if len(self.runs) < 2:
            return 0
        batch = min(len(self.runs), 64)
        is_full = (batch == len(self.runs))
        upper_bound = sum(len(r['recs']) for r in self.runs[:batch])
        merged = {}
        for r in reversed(self.runs[:batch]):
            for k, tv in r['recs'].items():
                if k not in merged:
                    merged[k] = tv
        records = [(k, t, rec) for k, (t, rec) in merged.items() if t == 'P']
        records.sort(key=lambda x: x[0])
        run = dict(gen=self.next_gen, run_no=self.next_run_no,
                   recs={k: (t, rec) for k, t, rec in records}, bloom_n=upper_bound)
        self.runs = [run] + self.runs[batch:]
        self.next_gen += 1
        self.next_run_no += 1
        self.manifest_n = len(self.runs)
        if self.last_persist_tl is not None:
            if is_full:
                self.tl = len(records) + (self.tl - self.last_persist_tl)
                self.last_persist_tl = len(records)
            # partial: carry last_persist_tl unchanged
        return 1

def dumpstr(live):
    out = ["W %d" % len(live)]
    for k in sorted(live):
        v, h, cb, sl, scr = live[k]
        # exact driver format: "keyhex V C SL <scripthex>" (trailing space when SL==0)
        out.append("%s %d %d %d %s" % (k.hex(), v, (h << 1) | cb, sl, scr.hex()))
    return out

def verify_runs(model, wd, fails, tag):
    for r in model.runs:
        path = wd + '/utxo_run_%06u.dat' % r['run_no']
        records = [(k, t, rec) for k, (t, rec) in sorted(r['recs'].items())]
        exp = build_run(r['gen'], r['run_no'], records, r.get('bloom_n'))
        if not os.path.exists(path):
            fails.append((tag, 'missing run file run_no=%d' % r['run_no'], 'present')); continue
        got = open(path, 'rb').read()
        if got != exp:
            d = next((i for i in range(min(len(got), len(exp))) if got[i] != exp[i]), -1)
            open(wd + '/EXP_run_%06u.dat' % r['run_no'], 'wb').write(exp)
            open(wd + '/ACT_run_%06u.dat' % r['run_no'], 'wb').write(got)
            fails.append((tag, 'run bytes run_no=%d got=%d exp=%d firstdiff=%d' % (r['run_no'], len(got), len(exp), d), ''))
            global P
            if P is not None and P.poll() is None:
                try:
                    P.stdin.write(b'udump\n'); P.stdin.flush()
                    P.stdin.write(b'mark\n'); P.stdin.flush()
                    ud = []
                    while True:
                        ln = P.stdout.readline()
                        if not ln or ln.decode().rstrip('\n') == 'MARK':
                            break
                        ud.append(ln.decode().strip())
                    print('MEMTABLE DUMP (run_no=%d):' % r['run_no'])
                    for u in ud:
                        print('   ', u)
                except Exception as e:
                    print('(udump failed:', e, ')')
    mp = wd + '/utxo_manifest.dat'
    if os.path.exists(mp):
        entries = [(r['gen'], r['run_no']) for r in model.runs]
        pers = model.last_persist_tl if model.last_persist_tl is not None else model.tl
        exp = build_manifest(len(entries), pers, entries)
        got = open(mp, 'rb').read()
        if got != exp:
            fails.append((tag, 'manifest got=%d exp=%d' % (len(got), len(exp)), ''))
    import re
    pat = re.compile(r'^utxo_run_(\d{6})\.dat$')
    for f in os.listdir(wd):
        m = pat.match(f)
        if not m:
            continue
        if not any(r['run_no'] == int(m.group(1)) for r in model.runs):
            fails.append((tag, 'stray run file %s' % f, ''))


def run_case(seed, iters, rootdir):
    global OP_THR, FILL_THR
    rng = random.Random(seed)
    OP_THR, FILL_THR = 5, 6
    TOMB_CAP, MAN_CAP, SLOTS = 48, 32, 512
    wd = '%s/s%d_i%d' % (rootdir, seed, iters)
    shutil.rmtree(wd, ignore_errors=True)
    os.makedirs(wd)

    model = Model()
    fails = []
    def check(dev, exp, where):
        if dev != exp:
            fails.append((where, dev, exp))

    p = subprocess.Popen([BIN], stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=wd)
    op_log = open(wd + '/ops.txt', 'w')
    global P
    P = p
    def send(op):
        op_log.write(op + '\n'); op_log.flush()
        p.stdin.write((op + '\n').encode()); p.stdin.flush()
        p.stdin.write(b'mark\n'); p.stdin.flush()
        lines = []
        while True:
            line = p.stdout.readline()
            if not line:
                return lines + ['__EOF__']
            l = line.decode().rstrip('\n')
            if l == 'MARK':
                return lines
            lines.append(l)

    dev = send('init %d %d %d %d %d' % (OP_THR, FILL_THR, TOMB_CAP, MAN_CAP, SLOTS))
    check(dev, ['init 1', 'C 0'], 'init')

    live = {}
    def pick_key():
        return (bytes(rng.randrange(256) for _ in range(32)), rng.randrange(0, 4))
    def newrec():
        sl = rng.randrange(0, 40)
        return (rng.getrandbits(60), rng.randrange(0, 1 << 20), rng.randrange(0, 2),
                sl, bytes(rng.randrange(256) for _ in range(sl)))

    for i in range(iters):
        if i and i % 30 == 0:
            if rng.random() < 0.5 and os.path.exists(wd + '/utxo.idx'):
                os.remove(wd + '/utxo.idx')        # crash-safety: drop checkpoint
            dev = send('reload %d' % SLOTS)
            rc = model.op_count          # reload replays the WAL tail = current gen's op count
            check(dev, ['reload %d' % rc] + dumpstr(model.live_set()), 'reload@%d' % i)
            continue
        r = rng.random()
        if r < 0.5 and len(live) < 12:
            # put: fresh (not live) or overwrite an in-mem key
            if len(model.mem) and rng.random() < 0.3:
                k = rng.choice(list(model.mem.keys()))
            else:
                k = None
                for _ in range(300):
                    txid, idx = pick_key()
                    kk = key36(txid, idx)
                    if kk not in live:
                        break
                else:
                    kk = key36(*pick_key())
                k = kk
            rec = newrec()
            rc = model.put(k, rec)
            if rc == 1:
                live[k] = rec
            dev = send('put %s %d %d %d %d %s' % (k[:32].hex(), int.from_bytes(k[32:], 'little'),
                                                   rec[0], rec[1], rec[2],
                                                   rec[4].hex() if rec[4] else '-'))
            check(dev, ['put %d' % rc, 'C %d' % model.tl], 'put@%d' % i)
            if model.should_flush():
                model.flush()
                verify_runs(model, wd, fails, 'flush-auto@%d' % i)
        elif r < 0.8 and live:
            k = rng.choice(list(live.keys()))
            model.delete(k)
            del live[k]
            dev = send('del %s %d' % (k[:32].hex(), int.from_bytes(k[32:], 'little')))
            check(dev, ['del 1', 'C %d' % model.tl], 'del@%d' % i)
            if model.should_flush():
                model.flush()
                verify_runs(model, wd, fails, 'flush-auto@%d' % i)
        elif r < 0.9:
            txid, idx = pick_key(); k = key36(txid, idx)
            g = model.get(k)
            dev = send('get %s %d' % (txid.hex(), idx))
            if g is None:
                check(dev, ['G 0'], 'get@%d' % i)
            else:
                v, h, cb, sl, scr = g[1]
                check(dev, ['G 1 %d %d %d %d %s' % (v, h, cb, sl, scr.hex())], 'get@%d' % i)
        elif r < 0.95:
            model.flush()
            dev = send('flush')
            check(dev, ['flush 1'] + dumpstr(model.live_set()), 'flush@%d' % i)
            verify_runs(model, wd, fails, 'flush@%d' % i)
        else:
            dev = send('walk')
            check(dev, dumpstr(model.live_set()), 'walk@%d' % i)

        if len(model.runs) >= 2 and rng.random() < 0.3:
            before = model.live_set()
            dev = send('compact')
            model.compact()
            check(dev, ['compact 1'] + dumpstr(before), 'compact@%d' % i)
            verify_runs(model, wd, fails, 'compact@%d' % i)

    # final read-only reload_ro: reconstructs live set, no mutation afterwards
    before = model.live_set()
    if os.path.exists(wd + '/utxo.idx'):
        os.remove(wd + '/utxo.idx')
    dev = send('reload_ro %d' % SLOTS)
    check(dev, ['reload_ro %d' % model.op_count] + dumpstr(before), 'reload_ro-final')
    verify_runs(model, wd, fails, 'reload_ro-final')

    dev = send('close')
    check(dev, ['close'], 'close')
    p.stdin.close(); p.wait()
    verify_runs(model, wd, fails, 'final')
    return fails

def main():
    seed = int(sys.argv[1]); iters = int(sys.argv[2])
    rootdir = sys.argv[3] if len(sys.argv) > 3 else '/tmp/lsmfuzz'
    os.makedirs(rootdir, exist_ok=True)
    fails = run_case(seed, iters, rootdir)
    for f in fails[:12]:
        print('FAIL@%s:\n  dev=%r\n  exp=%r' % (f[0], f[1], f[2]))
    print('SEED=%d iters=%d FAILS=%d' % (seed, iters, len(fails)))

if __name__ == '__main__':
    main()
