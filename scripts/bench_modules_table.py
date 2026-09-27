#!/usr/bin/env python3
"""Join Core's bench_bitcoin CSV with bench_core_modules' RESULT lines into one
table, one row per pair, in the same unit.

    bench_modules_table.py <core.csv ...> <ours.txt> [--md]

Core's CSV (nanobench -output-csv) carries seconds per iteration in column 5
(`min`); several Core benchmarks measure one op over a buffer and are reported
here per byte or per element, so the two sides read in the same unit -- the
divisor for each Core benchmark is fixed below and comes from the Core source
(the buffer sizes in chacha20.cpp / poly1305.cpp / bech32.cpp / base58.cpp,
the 100,000 elements of gcs_filter.cpp). Our side prints its unit itself.
With several CSVs, the minimum over them is taken (min-of-reps)."""
import csv, sys

# Core benchmark -> (divisor, unit) so that Core's seconds/iteration become
# the unit our RESULT line uses for the same pair.
CORE_UNIT = {
    'CHACHA20_64BYTES': (64, 'ns/byte'), 'CHACHA20_256BYTES': (256, 'ns/byte'), 'CHACHA20_1MB': (1 << 20, 'ns/byte'),
    'POLY1305_64BYTES': (64, 'ns/byte'), 'POLY1305_256BYTES': (256, 'ns/byte'), 'POLY1305_1MB': (1 << 20, 'ns/byte'),
    'FSCHACHA20POLY1305_64BYTES': (64, 'ns/byte'), 'FSCHACHA20POLY1305_256BYTES': (256, 'ns/byte'), 'FSCHACHA20POLY1305_1MB': (1 << 20, 'ns/byte'),
    'Bech32Encode': (32, 'ns/byte'), 'Bech32Decode': (52, 'ns/byte'), 'Base58CheckEncode': (32, 'ns/byte'),
}
# pairs whose two sides do not do the same work; the table says so
CAVEAT = {
    'VerifyScriptP2WPKH': 'Core precomputes the sighash midstates once; ours hashes per op',
    'VerifyScriptP2TR_KeyPath': 'Core precomputes the sighash midstates once; ours hashes per op',
    'VerifyScriptP2TR_ScriptPath': 'ours spends a 2-leaf tree (one more merkle step); Core a 1-leaf tree',
    'GCSFilterConstruct': '100,000 unique 32-byte elements on both sides; ours also parses the 4 MB block carrying them',
    'GCSBlockFilterGetHash': 'the encoded 100,000-element filter hashed on both sides',
    'ReadRawBlockBench': 'raw bytes on both sides',
    'WriteBlockBench': 'the same block appended each op on both sides',
    'MuHashFinalize': 'Core inverts by safegcd; ours by Fermat exponentiation (6,142 modmuls)',
    'Bech32Decode': 'decode + checksum verification on both sides',
    'Base58CheckEncode': 'no plain Base58Encode / Base58Decode on our side',
    'BlockEncodingNoExtra': '50,000-tx pool, 3,000 short ids, none present, both sides',
}

def load_core(paths):
    best = {}
    for p in paths:
        with open(p, newline='') as f:
            for row in csv.reader(f, skipinitialspace=True):
                if not row or row[0].startswith('#') or row[0] == 'Benchmark': continue
                name = row[0].split(' using ')[0].strip().strip('"')
                try: v = float(row[4])
                except (ValueError, IndexError): continue
                if name not in best or v < best[name]: best[name] = v
    return best

def load_ours(path):
    ours = {}
    with open(path) as f:
        for line in f:
            if not line.startswith('RESULT '): continue
            _, name, core, ns, unit = line.split(None, 4)
            ours[core] = (name, float(ns), unit.strip())
    return ours

def main():
    args = [a for a in sys.argv[1:] if not a.startswith('--')]
    md = '--md' in sys.argv
    core = load_core(args[:-1]); ours = load_ours(args[-1])
    rows = []
    for cname, (oname, ons, unit) in ours.items():
        if cname in core:
            div, cunit = CORE_UNIT.get(cname, (1, 'ns/op'))
            cns = core[cname] * 1e9 / div
            ratio = (ons / cns) if (cns > 0 and unit == cunit) else None   # no ratio across different units
            rows.append((cname, oname, cns, ons, unit if unit == cunit else f'{unit}|{cunit}', ratio))
        else:
            rows.append((cname, oname, None, ons, unit, None))
    if md:
        print('| Core benchmark | this project | Core | ours | unit | ours/Core | note |')
        print('|---|---|---:|---:|---|---:|---|')
        for cname, oname, cns, ons, unit, ratio in rows:
            c = f'{cns:,.2f}' if cns is not None else '(not run)'
            r = '' if ratio is None else (f'**{ratio:.2f}x slower**' if ratio > 1.05 else f'**{1/ratio:.2f}x faster**' if ratio < 0.95 else 'parity')
            print(f'| `{cname}` | `{oname}` | {c} | {ons:,.2f} | {unit} | {r} | {CAVEAT.get(cname, "")} |')
    else:
        print(f'{"Core benchmark":<30} {"Core":>14} {"ours":>14}  {"unit":<12} ours/Core  this project')
        for cname, oname, cns, ons, unit, ratio in rows:
            c = f'{cns:14.2f}' if cns is not None else f'{"(not run)":>14}'
            r = f'{ratio:8.2f}x' if ratio is not None else '        -'
            print(f'{cname:<30} {c} {ons:14.2f}  {unit:<12} {r}  {oname}')

if __name__ == '__main__':
    main()
