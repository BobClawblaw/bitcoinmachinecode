#!/usr/bin/env python3
"""fuzz_bip39.py -- independent pure-Python BIP39 differential fuzz vs the
AArch64 port (bitcoin_bip39.S: bip39_generate / bip39_validate /
bip39_mnemonic_to_entropy / bip39_mnemonic_to_seed).

Builds a small C driver in a temp dir (links bitcoin_bip39.o + its deps
sha256 / bitcoin_hmac / sha512 from THIS dir) and compares every mnemonic,
entropy and 64-byte seed byte-exactly against an INDEPENDENT pure-Python BIP39
reference (11-bit group codec + SHA-256 checksum + PBKDF2-HMAC-SHA512 with
c=2048 via hashlib -- a different implementation than the asm's in-loop HMAC).

The wordlist is parsed from bip39_words.S.inc (the 9-byte .byte records the asm
actually links), so the oracle and the port index the SAME 2048 words.

Coverage:
- generate: random entropy of every legal BIP39 size (128/160/192/224/256 bits)
  -> mnemonic string equality (rc + bytes).
- validate: on valid + corrupted mnemonics (bad checksum, unknown word, wrong
  word count, swapped words, repeated word) -> exact wordcount or -1.
- mnemonic_to_entropy: round-trip to the ORIGINAL entropy for valid; -1 for
  invalid.
- mnemonic_to_seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+pass, 2048, 64)
  for random empty + non-empty passphrases.

Requires: host aarch64 gcc + bitcoin_bip39.S (+ sha256, hmac, sha512) in THIS
dir. Usage: python3 fuzz_bip39.py [seeds] [iters]
"""
import subprocess, sys, tempfile, os, hashlib, random, re

# ---------------- build the word list from the ported .S.inc ----------------
HERE = os.path.dirname(os.path.abspath(__file__))
WORDS = []
with open(os.path.join(HERE, 'bip39_words.S.inc')) as f:
    for ln in f:
        m = re.match(r'\s*\.byte\s+(.+)', ln)
        if not m:
            continue
        bs = [int(x) for x in m.group(1).split(',')]
        bs = bytes(x for x in bs if x != 0)
        WORDS.append(bs.decode('utf-8'))
assert len(WORDS) == 2048, f"expected 2048 words, got {len(WORDS)}"
WI = {w: i for i, w in enumerate(WORDS)}

# ---------------- pure-Python BIP39 oracle ----------------
VALID_SIZES = {128, 160, 192, 224, 256}

def entropy_to_mnemonic(eb, ent):
    CS = eb // 32
    csbits = ''.join(f'{b:08b}' for b in hashlib.sha256(ent).digest())[:CS]
    stream = ''.join(f'{b:08b}' for b in ent) + csbits
    assert len(stream) == eb + CS and (eb + CS) % 11 == 0
    idxs = [int(stream[i:i+11], 2) for i in range(0, eb + CS, 11)]
    return ' '.join(WORDS[i] for i in idxs)

def mnemonic_indexes(mn):
    ws = mn.split(' ')
    if not all(w in WI for w in ws):
        return None
    return [WI[w] for w in ws]

def mnemonic_wordcount(mn):
    # BIP39 parse + checksum validation -> wordcount (12..24) or -1
    ws = mn.split(' ')
    if len(ws) % 3 != 0 or len(ws) < 12 or len(ws) > 24:
        return -1
    if not all(w in WI for w in ws):
        return -1
    idxs = [WI[w] for w in ws]
    bits = ''.join(f'{i:011b}' for i in idxs)
    CS = len(ws) // 3
    ent_bits = len(bits) - CS
    ent = int(bits[:ent_bits], 2).to_bytes(ent_bits // 8, 'big')
    csbits = ''.join(f'{b:08b}' for b in hashlib.sha256(ent).digest())[:CS]
    return len(ws) if bits[ent_bits:] == csbits else -1

def mnemonic_to_entropy(mn):
    ws = mn.split(' ')
    if len(ws) % 3 or len(ws) < 12 or len(ws) > 24 or not all(w in WI for w in ws):
        return (-1, b'')
    idxs = [WI[w] for w in ws]
    bits = ''.join(f'{i:011b}' for i in idxs)
    CS = len(ws) // 3
    ent_bits = len(bits) - CS
    ent = int(bits[:ent_bits], 2).to_bytes(ent_bits // 8, 'big')
    csbits = ''.join(f'{b:08b}' for b in hashlib.sha256(ent).digest())[:CS]
    if bits[ent_bits:] != csbits:
        return (-1, b'')
    return (ent_bits, ent)

def mnemonic_to_seed(mn, pass_):
    # asm hashes RAW UTF-8 bytes (no NFKD), matching hashlib for ASCII words
    return hashlib.pbkdf2_hmac('sha512', mn.encode('utf-8'),
                               b'mnemonic' + pass_.encode('utf-8'), 2048, 64)

# ---------------- C driver ----------------
DRIVER = r"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
extern int bip39_generate(char* out, const unsigned char* entropy, long ent_bits);
extern int bip39_validate(const char* mnemonic);
extern int bip39_mnemonic_to_entropy(unsigned char out[32], const char* mnemonic);
extern int bip39_mnemonic_to_seed(unsigned char seed[64], const char* mnemonic,
                                  const char* passphrase, long passlen);
static int hx(int c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return 0; }
static int dec(const char* s, unsigned char* o){ int n=(int)strlen(s)/2; for(int i=0;i<n;i++)o[i]=(hx(s[2*i])<<4)|hx(s[2*i+1]); return n; }
static void phex(const unsigned char* d, int n){ for(int i=0;i<n;i++)printf("%02x",d[i]); }
int main(void){
    char line[4096];
    while(fgets(line,sizeof line,stdin)){
        if(line[0]=='\n')continue;
        char cmd[16]; char* save; char* tok=strtok_r(line," \n",&save);
        if(!tok)continue; strcpy(cmd,tok);
        if(strcmp(cmd,"G")==0){
            long eb=strtol(strtok_r(NULL," \n",&save),0,10);
            const char* eh=strtok_r(NULL," \n",&save);
            unsigned char ent[32]; int en=dec(eh,ent);
            char mn[600];
            int rc=bip39_generate(mn,ent,eb);
            int n=(int)strlen(mn); printf("G %d ",rc);
            for(int i=0;i<n;i++)printf("%02x",(unsigned char)mn[i]);
            printf("\n"); (void)en;
        } else if(strcmp(cmd,"V")==0){
            const char* mh=strtok_r(NULL," \n",&save);
            char mn[600]; int n=dec(mh,(unsigned char*)mn); mn[n]=0;
            printf("V %d\n",bip39_validate(mn));
        } else if(strcmp(cmd,"E")==0){
            const char* mh=strtok_r(NULL," \n",&save);
            char mn[600]; int n=dec(mh,(unsigned char*)mn); mn[n]=0;
            unsigned char out[32]; int rc=bip39_mnemonic_to_entropy(out,mn);
            printf("E %d ",rc); if(rc>0)phex(out,rc/8); printf("\n");
        } else if(strcmp(cmd,"S")==0){
            const char* ph=strtok_r(NULL," \n",&save);
            const char* mh=strtok_r(NULL," \n",&save);
            char pass[300]; int pn;
            if(strcmp(ph,"-")==0) pn=0; else pn=dec(ph,(unsigned char*)pass);
            pass[pn]=0;
            char mn[600]; int n=dec(mh,(unsigned char*)mn); mn[n]=0;
            unsigned char seed[64]; int rc=bip39_mnemonic_to_seed(seed,mn,pass,(long)pn);
            printf("S %d ",rc); phex(seed,64); printf("\n");
        }
        fflush(stdout);
    }
    return 0;
}
"""

def build_driver(d):
    drv = os.path.join(d, 'b39_driver.c')
    with open(drv, 'w') as f:
        f.write(DRIVER)
    srclist = ['bitcoin_bip39.S', 'sha256.S', 'bitcoin_hmac.S', 'sha512.S']
    cmd = ['gcc', '-O2', '-I', HERE, '-o', os.path.join(d, 'b39_driver'), drv] + \
          [os.path.join(HERE, s) for s in srclist]
    r = subprocess.run(cmd)
    if r.returncode != 0:
        sys.exit('driver build failed: ' + ' '.join(cmd))
    return os.path.join(d, 'b39_driver')

def hx(b): return b.encode('utf-8').hex() if isinstance(b, str) else b.hex()

def main():
    nseeds = int(sys.argv[1]) if len(sys.argv) > 1 else 8
    per    = int(sys.argv[2]) if len(sys.argv) > 2 else 400
    d = tempfile.mkdtemp(prefix='bmcb39_')
    binp = build_driver(d)
    total = 0
    for seed in range(nseeds):
        rng = random.Random(seed)
        inputs = []
        # --- generate: random entropy of random legal size ---
        for _ in range(per):
            eb = rng.choice(sorted(VALID_SIZES))
            ent = bytes(rng.getrandbits(8) for _ in range(eb // 8))
            mn = entropy_to_mnemonic(eb, ent)
            inputs.append(("G", f"G {eb} {hx(ent)}", mn))
        # --- validate + round-trip on valid + corrupted mnemonics ---
        # Expected values come from the ORACLE itself (independent recompute),
        # because a randomly "corrupted" mnemonic can COINCIDENTALLY pass the
        # BIP39 checksum (~1/16 for a 4-bit CS), so corruption != -1 in general.
        for _ in range(per):
            eb = rng.choice(sorted(VALID_SIZES))
            ent = bytes(rng.getrandbits(8) for _ in range(eb // 8))
            mn = entropy_to_mnemonic(eb, ent)
            mode = rng.random()
            if mode >= 0.5:                    # apply some corruption
                ws = mn.split()
                if mode < 0.65:                # bad checksum: replace last word
                    last = WI[ws[-1]]
                    ws[-1] = WORDS[(last + 1 + rng.randrange(2046)) % 2048]
                elif mode < 0.78:              # unknown word
                    ws[rng.randrange(len(ws))] = 'nonsenseword'
                elif mode < 0.90:              # wrong word count (drop/dup)
                    if rng.random() < 0.5 and len(ws) > 1:
                        del ws[rng.randrange(len(ws))]
                    else:
                        ws.insert(rng.randrange(len(ws) + 1), ws[rng.randrange(len(ws))])
                else:                           # shuffled
                    rng.shuffle(ws)
                mn = ' '.join(ws)
            wc = mnemonic_wordcount(mn)
            erc, eent = mnemonic_to_entropy(mn)
            inputs.append(("V", f"V {hx(mn)}", str(wc)))
            inputs.append(("E", f"E {hx(mn)}", f"{erc} {hx(eent)}" if erc > 0 else "-1 food"))
        # --- seed: random passphrases (incl. empty) over generated mnemonics ---
        for _ in range(per):
            eb = rng.choice(sorted(VALID_SIZES))
            ent = bytes(rng.getrandbits(8) for _ in range(eb // 8))
            mn = entropy_to_mnemonic(eb, ent)
            if rng.random() < 0.5:
                pass_ = ''.join(rng.choice('abcdefghijklmnopqrstuvwxyz0123456789 -_.') for _ in range(rng.randrange(0, 40)))
            else:
                pass_ = ''
            seedv = mnemonic_to_seed(mn, pass_)
            passtok = '-' if pass_ == '' else hx(pass_)
            inputs.append(("S", f"S {passtok} {hx(mn)}", seedv))

        r = subprocess.run([binp], input=("\n".join(c for _, c, _ in inputs) + "\n"),
                           capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            print(f"BINARY CRASH rc={r.returncode}: {r.stderr[-1500:]}"); sys.exit(1)
        out = [ln for ln in r.stdout.splitlines() if ln.strip()]
        if len(out) != len(inputs):
            print(f"count mismatch {len(out)} vs {len(inputs)}"); sys.exit(1)
        fails = 0
        for (kind, _c, exp), got in zip(inputs, out):
            p = got.split()
            if kind == "G":
                ok = p[0] == "G" and p[1] == "1" and p[2] == hx(exp.encode())
            elif kind == "V":
                ok = p[0] == "V" and p[1] == exp
            elif kind == "E":
                if exp.startswith("-1"):
                    ok = p[0] == "E" and p[1] == "-1"
                else:
                    eb, ent = exp.split()
                    ok = p[0] == "E" and p[1] == eb and p[2] == ent
            else:  # S
                ok = p[0] == "S" and p[1] == "1" and p[2] == hx(exp)
            if not ok:
                fails += 1
                if fails <= 5:
                    print("FAIL", kind, "got", got, "exp", exp[:80])
        total += len(inputs)
        print(f"seed={seed} cases={len(inputs)} fails={fails}")
        if fails:
            sys.exit(1)
    print(f"TOTAL cases={total} across {nseeds} seeds: 0 fail")
    sys.exit(0)

if __name__ == "__main__":
    main()
