# Bitcoin Machine Code

> ## ⚠️ WARNING — UNTRUSTED, EXPERIMENTAL CODE
>
> **This is actively developed, highly experimental software.** It implements
> Bitcoin node functionality as hand-rolled x86-64 assembly produced by an AI. It
> has NOT been audited by any independent third party. **You should treat this
> code as untrusted and dangerous.** A bug in consensus, cryptographic, or
> networking logic can cause loss of funds, chain divergence, resource
> exhaustion, or exposure of your machine to the network. Do **not** run it with
> real funds, on a production machine, or on an internet-exposed host, and do
> not rely on it for any security-sensitive purpose — until it has undergone an
> independent security audit. Use at your own risk.

A Bitcoin node for Linux built as **100% AI-generated machine code** — every line of
assembly is authored by an AI assistant, none by a human. The security-critical
crypto (SHA-256, secp256k1 field/point/scalar/ECDSA) is written directly in x86-64
assembly.

## Status

**Delivered and verified:**
- **SHA-256 core** (`asm/sha256.asm`) — passes the canonical FIPS-180-4 vectors
  plus the multi-block and extra-length-block padding cases Bitcoin requires.
- **secp256k1 field arithmetic** (`asm/secp256k1_fe.asm`) — `fe_add`, `fe_sub`,
  `fe_mul` (256-bit multiply + secp256k1-prime reduction), verified against
  24 fixed vectors and 50,000+ random cases vs Python's big-int oracle.
- **secp256k1 point / scalar / ECDSA** (`asm/secp256k1_point.asm`,
  `asm/secp256k1_scalar.asm`, `asm/secp256k1_ecdsa.asm`) — Jacobian point ops,
  scalar arithmetic mod n, and low-S ECDSA signature verification, all verified
  against a Python big-int oracle.
- **Node-layer hashing** (`asm/bitcoin_hash.asm`) — `sha256d`, `block_hash`,
  `diff_target`, `pow_check`, and `merkle_root`, verified against the genesis
  block, fixed vectors, and a Python oracle (10/10 assertions in `test_block`).
- **Node-layer tx parser** (`asm/bitcoin_tx.asm`) — `tx_parse` deserializes a
  transaction (version, varint counts, inputs, outputs, locktime) and ALSO skips
  the SegWit (BIP141) witness stack, so it walks both legacy and modern on-wire
  txs and returns the full serialized length. `tx_txid(out32, tx, txlen, buf,
  buflen)` rebuilds the unwitnessed form and returns the BIP141 txid. Verified
  against the serialized genesis coinbase (18/18 in `test_tx`), cross-checked
  against a clean Python walker, and validated on REAL mainnet blocks: the
  community `cons_verify` accepts both pre-SegWit block 400000 and SegWit-era
  block 962043.
- **P2P networking core** (`asm/bitcoin_net.asm`) — raw-syscall POSIX sockets
  plus the Bitcoin message framer (magic + command + length + SHA-256d checksum).
  Verified offline (19/19 assertions in `test_net`) and against a **live Bitcoin
  peer** (version/verack handshake succeeded, `live_handshake.c`).
- **P2P message codecs** (`asm/bitcoin_p2p.asm`) — getheaders / getdata /
  ping builders and a headers parser, byte-exact vs `validation/p2p_oracle.py`;
  the whole IBD header-download path is proven end-to-end as machine code
  (`test_p2p` offline + `fakepeer_headers` loopback IBD test).
- **Block consensus** (`asm/bitcoin_cons.asm`) — `cons_verify` validates a full
  block in machine code: PoW + per-tx parsing + coinbase-first + merkle-root
  recheck over the txids. Verified against a Python-built 2-tx block
  (`test_cons`, 6/6): valid accepted (root matches the oracle), and bad merkle /
  trailing garbage / truncation / non-coinbase / over-cap all rejected.
- **Persistent header chain** (`asm/bitcoin_headers.asm`) — a restart-safe,
  positional append-only store of `(80-byte header, block_hash)` pairs
  (`headers.dat`, 112 B/entry). `hst_init/reload/append/get_at/count` verified
  by `test_headers` (on-disk layout, reload resume, chain continuity).
- **Paged headers-first IBD** (`asm/bitcoind.asm` `node_ibd_headers`) — the
  persistent download loop: repeatedly fetch a 2000-header `headers` page at the
  running locator, verify chain continuity for every header, compute each
  block_hash, persist it, and advance the locator to the new tip; stops on a
  short/empty page. Verified by `test_ibd_headers` over a real loopback socket:
  a 2500-header chain (full page + short page), locator advance to tip,
  restart-resume, tip detection, and rejection of a tampered chain.
- **Block-body download off the persisted header chain** (`asm/bitcoind.asm`
  `node_ibd_blocks`) — the second half of full IBD: walks every stored header in
  the header store, requests its block via getdata, validates it (PoW + merkle +
  tx walk via `cons_verify`), re-derives the block hash and requires it to equal
  the stored header hash (wrong-block guard), and persists it. Verified by
  `test_ibd_blocks` over loopback (4-block chain stored byte-exact, plus a
  negative case rejecting a peer that serves the wrong body).
- **Full initial-block-download as one assembly pass** (`asm/bitcoind.asm`
  `node_ibd`) — chains `node_ibd_headers` (persist the whole header chain from
  genesis in 2000-header pages) then `node_ibd_blocks` (walk every stored
  header -> getdata -> `cons_verify` + re-derived-hash guard -> store) over a
  single peer connection. Verified by `test_ibd_full` over a real loopback
  socket: a 1200-block chain downloaded, validated and stored byte-exact in one
  call — the entire headers-first IBD tail as machine code.
- **Node CLI** (`asm/bitcoin_cli.asm`) — `cli_main` answers queries in pure
  machine code over the persistent store: `getblockcount`, `getbestblockhash`,
  `getblockhash <h>`, `getblock <h|hash64>`, `gettx <txid64>`, `getbalance`,
  `stop`, `help` (hashes in Bitcoin display order). Thin driver `daemon/cli.c`;
  verified by `test_cli` (all commands against expected values from the proven
  asm hashes). The assembly hashing/tx stack also reproduces the real genesis
  block hash + coinbase txid (test_block/test_tx) and a live-downloaded real
  mainnet block-1 hash (manual `test/live_blocks.c`).

All assembly is authored by AI; C/Python harnesses exist only to prove the
machine code is correct against trusted references. Real-mainnet validation
status: the full asm consensus stack accepts the REAL genesis block (285 byte
header + tx-count + coinbase, real nBits 0x1d00ffff, real merkle root) via
test_block_genesis (offline, in make test); pow_check/diff_target implement the
real Bitcoin difficulty algorithm and are proven against real mainnet nBits;
and the node reproduces a live-downloaded real block-1 hash. **The block-body
download + store tail is now exercised end to end against a REAL node: real
mainnet block bodies are downloaded, cons_verify-validated as VALID, and
stored.** (The initial live proof used the cooperative local node
192.168.5.69:8333, but the production download no longer depends on it — block
bodies come from a large pool of verified **internet** peers via distinct-peer
selection, and while a local node is still tried first only as a *header* source,
the bulk of the chain is pulled in parallel from internet peers.) The
long-standing "seeds drop block-body getdata" wall was root-caused to our own
malformed getdata: `p2p_getdata_block`
emitted a 34-byte message (type as a 1-byte varint) that real nodes silently
ignore. The canonical Bitcoin getdata/inv inventory is `[count varint][type int32
LE][hash32]` = 37 bytes with the hash at +5 (the p2p_oracle always encoded this;
a prior stage wrongly "fixed" it -- corrected and confirmed live). Public seeds
still serve the real header chain reliably; with the corrected getdata they also
serve block bodies to a cooperative/unchained peer. The inbound (server) role is
now real too: a new asm `node_accept_handshake` answers a genuine inbound node's
`version` and serves stored blocks (verified end to end), where the old serve
path reused the outbound handshake and hung on an inbound peer.

**ASM inbound server serves the REAL chain over TCP — getdata AND getheaders**
(from commit `32279a0`): `bitcoind serve <dir> <port>` answers a peer entirely
in assembly (`node_accept_handshake` -> `node_serve_loop`) against the on-disk
archive. Verified LIVE over loopback against real mainnet data:
- **getdata** — a real block by hash served verbatim (height-1 215 B, height-2
  215 B, height-50000 647 B, plus multi-KB blocks at h=100k/200k),
  `requested-hash-match=YES`.
- **getheaders** — a *canonical* `headers` message whose CompactSize count
  equals the payload length, whose headers form a contiguous chain (each
  header's prev is the double-SHA256 of the previous header), starting from the
  requested locator (verified for locators at h=1, h=200000, h=293300, 2000
  headers each). The server stays alive after serving.

The live work exposed and fixed five real bugs that fake-block unit tests could
not catch: (1) the daemon had no Makefile target (ad-hoc stale command);
(2) `server-test` never built the hash index, so getdata couldn't resolve a
hash; (3) `build_hash_index` keyed on display (BE) order while the wire hash is
LE, so getdata missed; (4) the getheaders dispatch checked `cmd[4]/[8]` for
`"head"/"ers"` but getheaders is `g e t h e a d e r s` ("head" is at cmd[3..6])
so it never fired; (5) `open_file` leaked an fd per serve (`EMFILE` at ~1024
serves truncated the chain) — fixed with close-before-open, so serving spans
heights 0..309998. **The crash** was the getheaders header copy passing the
length in `r8` while `memcpy_len` reads its length from `RDX` (verified by
disassembly): it copied `[s_p]` bytes instead of 80, sweeping through `.bss`
into the relocated `stdout`/`stderr` copies (0x143e6a0) and segfaulting `main`'s
printf. Found with a hardware write watchpoint on the stdout slot; fixed by
loading the length into `RDX`. The test suite stays 33/33 green throughout.


**Full-chain download into ONE directory (>= 8 DISTINCT peers, NO worker dirs):**
`daemon/unified_ibd.c` downloads the whole chain in parallel — the asm
`node_ibd_headers` persists the header chain, then each worker runs
`node_ibd_blocks_s` (asm) to download / `cons_verify` / validate per block. Every
block is written **directly into the single archive** in `data/` via the
concurrent-safe asm `store_append_shared`: each append is flock-serialized on
`append.lock`, the block lands at the true file end of the rolling
`blkNNNNN.dat`, and the index record goes positionally at `height*48` (index.dat
pre-sized). No per-worker block directories exist — the archive is one
directory holding only `blk00000.dat`..`blkNNNNN.dat`, `index.dat`, `headers.dat`.
Workers each keep a private `/tmp` header-store file (never touching
`data/headers.dat`), which fixed a deterministic worker-boundary corruption bug.
Peer distinctness is guaranteed across the whole run via a flock-locked
`peerclaims` table (no two workers on the same peer). Real-mainnet
header-continuity bug found and fixed (see LOG #12). `daemon/chainctl.c` drives
the whole chain forward in audited chunks (16k, resumable from the archive tip,
per-chunk `check_chain` audit + throughput/ETA). **Backfill:** because the
forward pass resumes from the existing tip, the missing early heights can be
fetched by a `unified_ibd <dir> N <lo> <hi>` run whose range lies BELOW the tip:
the loader detects this as a backfill, preserves the requested range, keeps the
index grow-only (never truncates the forward archive), uses a per-process
peerclaims table, and reuses the existing `headers.dat` (no rewrite) so it can
run CONCURRENTLY with the forward chainctl — the two fill the archive from both
ends with zero duplicate blocks.

**Wallet / validation bridge (complete)** — the node now validates and signs real
transactions in machine code, on top of the verified asm crypto. All of this was
built as part of the same AI-authored assembly / C-verified work as the node:

- **secp256k1 pubkey parse** (`asm/bitcoin_pubkey.asm`) — `fe_pow` +
  `pubkey_parse`: recover affine curve coords (Qx,Qy) from a compressed (02/03) or
  uncompressed (04) secp256k1 public key. Verified on G, non-residue rejection,
  bad length, off-curve.
- **Legacy SIGHASH_ALL preimage builder** (`asm/bitcoin_sighash.asm`) — builds
  the unsigned-tx preimage for a target input, verified byte-exact vs Python on
  1-in/1-out and 2-in/1-out txs.
- **DER ECDSA sig parsing** (`asm/bitcoin_script.asm`) — `der_parse_sig`
  (canonical DER sig -> r,s LE limbs via `be_to_limbs` + trailing SIGHASH type
  byte), verified against a real `cryptography`-generated DER sig.
- **End-to-end P2PKH spend validation** (`bitcoin_script.asm` `verify_p2pkh`) —
  validates one P2PKH input in assembly: build SIGHASH_ALL, walk the scriptSig,
  DER-parse the sig, parse the pubkey, `ecdsa_verify`. Valid spend -> 1, tampered
  sig -> 0 (the `validation CAPSTONE`).
- **UTXO set** (`asm/bitcoin_utxo.asm`) — in-memory Unspent-Transaction-Output
  store: txid(32)+index(u32) -> (value, scriptPubKey) open-addressing table +
  value/script blob. `utxo_init/put/get/del/count`. Verified: put/get round-trip,
  dedup, distinct outpoints, spend/delete -> miss and double-spend -> miss, and a
  300-entry probing/collision-wrap bulk round-trip.
- **Whole-transaction validator** (`tests/test_txval.c`) — validates a full
  serialized tx against the UTXO set: every input outpoint present+unspent
  (double-spend guard), every input's P2PKH signature verifies via asm
  `verify_p2pkh`, and sum(in) >= sum(out) (valid fee). Signed vectors are genuine
  ECDSA spends (gen_txval_vectors.py). 6 cases: 2 valid multi-input txs +
  double-spend / fee / sig(empty) / sig(wrong-key) negatives. Suite 40/40.
- **Policy + RBF / fee handling** (`asm/bitcoin_mempool_policy.c`) — policy layer
  over the structural mempool + UTXO set: fee computation + min-relay-fee floor,
  double-spend rejection, BIP125 RBF (replacement fee math + eviction), ancestor/
  descendant limits, and an EMA fee estimator. Verified against an independent
  pure-Python oracle (4 scenarios / 21 steps). Full offline suite 35/35 green.
- **Wallet CLI** (`asm/wallet_core.c` + `asm/daemon/wallet_cli.c`) —
  `wallet_cli gen` (random keypair + P2PKH mainnet address), `addr <keyhex>`
  (compressed pubkey + address), and `sign <tx><key><i>` (legacy SIGHASH_ALL P2PKH
  sign, deterministic nonce k=sha256d(z||priv), low-S DER). `test_wallet` 9/9,
  plus an independent Python verification of the signature.
- **BIP32 full-path derivation + extended keys (xprv/xpub)** (`asm/bitcoin_bip32.asm`)
  — three new functions on top of the verified `bip32_master`/`bip32_ckd_priv`:
  `bip32_derive_path` (derive a full path `m/44'/0'/0'/0/0` from a seed in one
  call), `bip32_fingerprint` (HASH160(pub)[0..4], the BIP32 parent fingerprint),
  and `bip32_extkey_serialize` (build the 78-byte xprv/xpub payload). Combined
  with the verified base58check encoder this yields real `xprv`/`xpub` strings,
  tying key -> address -> extended key together. `test_bip32_extkey` verifies the
  BIP32 vector-1 chain end, a BIP44 and a BIP84 path, and the master extended
  keys byte-exact against an independent `bip32` Python oracle. (The base58
  encoder's digit-work buffers were enlarged to hold 78-byte payloads; the
  25-byte address path is unchanged and still green.)
- **BIP39 mnemonic <-> seed** (`asm/bitcoin_bip39.asm`) — full mnemonic
  generation/validation + PBKDF2 seed derivation, pairing with BIP32 for
  recoverable wallets. Embedded 2048-word English wordlist (`asm/wordlist.inc`,
  9-byte fixed-width records, official order abandon..zoo); entropy (128..256
  bits, 12..24 words) -> 11-bit groups with the trailing SHA-256 checksum
  (CS = ENT/32); validation re-derives the checksum and rejects bad word
  count, unknown words, and checksum mismatches; and seed derivation is
  PBKDF2-HMAC-SHA512(P=mnemonic, S="mnemonic"||pass, c=2048, dkLen=64) built on
  the verified asm `hmac_sha512`. `test_bip39` (24 vectors) verifies
  generate/validate/mnemonic->entropy and both empty- and "TREZOR"-passphrase
  seeds byte-exact against the official bip-0039 vectors via the independent
  Python oracle (`asm/validation/gen_bip39_vectors.py`, cross-checked with
  `hashlib.pbkdf2_hmac`). The wallet CLI now reports a recoverable seed end to
  end: `wallet_cli mnemonic` `->` `wallet_cli seed "<words>" [pass]` yields the
  mnemonic, 64-byte seed, master `xprv`, and `m/44'/0'/0'/0/0` address.
- **bech32 / bech32m codec** (`asm/bech32.asm`) — BIP173/350 address codec
  (`bech32_polymod` 30-bit CRC, create/verify checksum with the XOR-1 vs
  0x2bc830a3 switch, 8<->5 bit regroup, encode/decode), verified against every
  authoritative BIP173/BIP350 vector plus exact real mainnet segwit addresses
  (P2WPKH bc1qw508..., P2WSH bc1qrp33..., P2TR bech32m bc1p...).
- **P2SH / multisig** (`asm/bitcoin_multisig.asm`) — `p2sh_hash`
  (RIPEMD160(SHA256(redeemScript))) and `multisig_verify` (OP_CHECKMULTISIG
  evaluation: walk the scriptSig pushes, take the push before the target
  pubkey as that signer's DER sig, and ECDSA-verify it against the legacy
  SIGHASH_ALL preimage with the redeem script as the signing script).
  `test_multisig` (8/8) is cross-checked by the independent pure-Python
  `ecdsa` oracle (`asm/validation/p2sh_oracle.py`): known p2sh hashes, a
  self-consistent spend that verifies, and tampered-sig / wrong-pubkey
  negatives.

**Peer discovery layer (self-contained, full-client):** `asm/bitcoin_addrmgr.asm`
is a persisted peer address book (`peers.dat`) plus byte-exact `addr` v1 codecs
(verified by `test_addrmgr`). `daemon/crawler.c` / `daemon/addrgather.c` harvest
peers via getaddr->addr/addrv2 and fold them into the book; `daemon/peertest.c`
verifies which peers actually serve block bodies. Combined with the distinct-peer
selection this is the basis for self-directed discovery.

**The durable archive** is a single unified store (`data/blk00000.dat`.. + `index.dat` +
`headers.dat` — one directory, no worker shards) that is queryable via the asm CLI
and **served entirely in assembly**. Serving was rebuilt around an **O(1) in-memory
hash→height index** built in assembly (`asm/bitcoin_idx.asm`: `idx_init/put/get`,
open-addressing, full 32-byte keys) — a linear per-height scan never finished on a
large archive and a single hole aborted it. `asm/bitcoin_serve.asm`
(`node_serve_loop`) is the per-connection server message loop in pure machine
code: ping→pong, getaddr→addr (address book), getdata→block (O(1) lookup +
`node_serve_block`), getheaders (2000x81B pages), inv. The serve daemon
(`./bitcoind serve`) calls it after `node_accept_handshake`, so both halves of the
node's core run in assembly (outbound download `node_ibd_*` + inbound server
`node_serve_loop`). Verified live against the daemon: 8 real mainnet blocks served
byte-exact on one connection, each hashing back to the requested hash. The buffer
sizing is hardened for modern (up to 4 MB) blocks. One-shot health:
`daemon/nodecheck.sh` (audit + progress + serve round-trip) and
`daemon/chainprogress.sh` (coverage toward a complete 0..tip archive). As the
forward pass and the early-height backfill converge, the archive reaches **block 0
(the 2009 genesis block)** upward — `verify` on contiguous runs reports 100%
hash-match / chain-link / PoW / consensus (`CHAIN VERIFIED`).

## Layout

```
bitcoinmachinecode/
+-- asm/
|   +-- sha256.asm            # SHA-256: init, block compression, one-shot (x86-64 NASM)
|   +-- secp256k1_fe.asm      # field add/sub/mul/sqr/inv mod secp256k1 prime p
|   +-- secp256k1_point.asm   # Jacobian point double/add/scalar-mul over secp256k1
|   +-- secp256k1_scalar.asm  # scalar add/sub/mul/sqr/inv mod curve order n
|   +-- secp256k1_ecdsa.asm   # low-S ECDSA signature verification
|   +-- bitcoin_hash.asm      # sha256d / block_hash / merkle_root / pow_check
|   +-- bitcoin_tx.asm        # transaction deserializer (tx_parse)
|   +-- bitcoin_net.asm       # POSIX sockets + P2P framing (raw syscalls)
|   +-- bitcoin_p2p.asm       # getheaders/getdata/ping builders + headers parser
|   +-- bitcoin_store.asm      # persistent blk file + positional block index
|   +-- bitcoin_headers.asm    # persistent header chain (hdr, block_hash) store
|   +-- bitcoin_cons.asm       # full-block consensus check (cons_verify)
|   +-- bitcoin_cli.asm        # S6 CLI: query the store (cli_main)
|   +-- bitcoin_addrmgr.asm    # persisted peer address book + addr v1 codecs
|   +-- bitcoin_idx.asm        # O(1) block hash->height index for serving (idx_*)
|   +-- bitcoin_serve.asm      # inbound server message loop (node_serve_loop)
|   +-- bitcoin_pubkey.asm     # fe_pow + pubkey_parse: secp256k1 pubkey de/compress
|   +-- bitcoin_sighash.asm    # legacy SIGHASH_ALL preimage builder
|   +-- bitcoin_script.asm     # der_parse_sig + verify_p2pkh (end-to-end P2PKH validate)
|   +-- bitcoin_utxo.asm       # in-memory UTXO set (prevout value/script)
|   +-- bech32.asm             # BIP173/350 bech32/bech32m address codec
|   +-- bitcoin_bip32.asm      # BIP32 master/CKD/derive_path + xprv/xpub
|   +-- bitcoin_bip39.asm      # BIP39 mnemonic<->seed (PBKDF2-HMAC-SHA512)
|   +-- wordlist.inc           # 2048-word BIP39 English wordlist (9-byte records)
|   +-- bitcoin_multisig.asm   # p2sh_hash + multisig_verify (OP_CHECKMULTISIG)
|   +-- wallet_core.c          # wallet primitives glue over asm crypto
|   +-- bitcoin_mempool_policy.c # policy/RBF/fee layer over mempool + UTXO
|   +-- build.sh              # assemble + build + run every verification harness
|   +-- Makefile              # make asm | test | clean
|   +-- tests/                # C harnesses proving the machine code correct
|   +-- validation/           # Python big-int oracles (trusted reference)
|   +-- daemon/               # C orchestration + peer discovery/serving tools
|       +-- wallet_cli.c      # wallet CLI: gen/addr/sign + mnemonic/seed (recoverable)
|       +-- unified_ibd.c     # full-chain download into a unified single store (forward + backfill)
|       +-- chainctl.c        # chunked full-chain orchestrator (resume/audit/ETA)
|       +-- check_chain.c     # integrity audit (dups/holes/corruption, chain-breaks)
|       +-- verify.c          # full chain validation (hash/chain/PoW/consensus)
|       +-- dumpblock.c       # inspect a stored block (raw bytes / header summary)
|       +-- nodecheck.sh      # one-shot health: audit + progress + serve round-trip
|       +-- chainprogress.sh  # coverage toward a complete 0..tip archive
|       +-- crawler.c         # parallel getaddr peer harvester
|       +-- addrgather.c      # getaddr -> addr/addrv2 -> peers.dat address book
|       +-- peertest.c        # verify which peers serve block bodies
|       +-- main.c            # daemon: sync / ibd / follow / serve / server-test
|       +-- cli.c             # thin driver for the asm cli_main
+-- data/                    # durable chain storage: ONE unified archive
|                           # (blk00000.dat..blkNNNNN.dat + index.dat + headers.dat)
+-- README.md
```

## Storing the chain

Blocks persist to the current working directory as `blk00000.dat` (append-only
framed blocks) + `index.dat` (positional height index) + `bitcoind.log`. The
durable home is **`data/`** under the project root, on the `/storage` NVMe
mount (ext4, ~2.6 TB free — room for a full archive node; pruned mode fits in
just a few GB). Point the daemon/CLI there:

```bash
cd /storage/bitcoinmachinecode/asm/daemon
./bitcoind sync /storage/bitcoinmachinecode/data     # download + validate + store
./bitcoind ibd /storage/bitcoinmachinecode/data      # FULL IBD as one asm pass
                                                     # (headers-first persist +
                                                     # getdata block bodies +
                                                     # validate + store)
# full-chain download into a UNIFIED single store (parallel, >=8 DISTINCT peers,
# no shard dirs, resumable from the store tip):
./unified_ibd /storage/bitcoinmachinecode/data 8 <start_h> <end_h>
# chunked full-chain orchestrator (forward to tip, resuming + auditing each chunk):
./chainctl /storage/bitcoinmachinecode/data 8 16000 20
# backfill early heights below the existing tip (runs safely alongside chainctl):
./unified_ibd /storage/bitcoinmachinecode/data 8 0 29999
# health / progress / audit / serve round-trip:
./nodecheck.sh /storage/bitcoinmachinecode/data        # audit + progress + serve
./chainprogress.sh /storage/bitcoinmachinecode/data    # coverage toward 0..tip
./check_chain /storage/bitcoinmachinecode/data         # dups/holes/corruption audit
./verify /storage/bitcoinmachinecode/data <lo> <hi>    # hash/chain/PoW/consensus
./cli /storage/bitcoinmachinecode/data getblockcount   # query the stored chain
```

## Build & verify

```bash
./asm/build.sh
# or
cd asm && make test
```

Requires `nasm` and `gcc`. Exit code 0 means the assembly hash is correct.

## API (System V AMD64, ELF64)

```
// sha256.asm
void sha256_init (u32 state[8]);                                    // hash init
void sha256_block(u32 state[8], const u8 block[64]);                // one block
void sha256_full (u8 out[32], const void *msg, unsigned long len);  // one-shot

// bitcoin_hash.asm (node-layer hashing, built on sha256)
void sha256d      (u8 out[32], const void *msg, long len);          // double SHA-256
void block_hash   (u8 out[32], const u8 hdr[80]);                   // sha256d(hdr,80)
void diff_target  (u8 target[32], u32 bits);                        // compact nBits->target
int  pow_check    (const u8 hdr[80]);                               // PoW holds?
void merkle_root  (u8 out[32], u8 hashes[], unsigned long n);       // tx merkle (in place)

// bitcoin_tx.asm (transaction deserializer)
int tx_parse(u64 info[8], const void *tx, unsigned long txlen);    // 1 if fully parsed (legacy + SegWit)
int tx_txid (u8 out[32], const void *tx, long txlen, void* buf, long buflen); // BIP141 txid

// bitcoin_net.asm (POSIX sockets + P2P framing)
long fd_write_all(int fd, const void* buf, size_t n);            // n or -1
long fd_read_full (int fd, void* buf, size_t n);                 // n / <n on eof / -1
int  tcp_connect_ip(u32 ip_le, u16 port_be);                     // fd or -errno
long p2p_write(int fd, const char* cmd, const void* pl, u32 plen);  // total or -1
int  p2p_read(int fd, char cmd_out[12], void* pl, u32 cap, u32* len_out);
                                                            // 1 ok / 0 eof / -1 err / -2 trunc

// bitcoin_p2p.asm (message payload codecs)
long p2p_getheaders(u8* out, const u8 locator[32], long count, const u8 stop[32]);  // 69
long p2p_getdata_block(u8* out, const u8 hash[32]);         // 37 (MSG_BLOCK)
long p2p_ping(u8* out, u64 nonce);                          // 8
long p2p_headers_count(const u8* payload, long plen);       // #header entries or -1

// bitcoin_cons.asm (full-block consensus validation)
int cons_verify(const u8* block, u64 len, u8* txid_scratch, u64 cap); // 1 valid / 0 invalid

// bitcoin_headers.asm (persistent header-chain store)
int  hst_init(void* hst);                                  // open headers.dat
int  hst_reload(void* hst);                                // count from file size
long hst_append(void* hst, const u8 hdr[80], const u8 hash[32]);  // new count / -1
int  hst_get_at(void* hst, u64 height, u8 out[112]);       // 1 / 0 / -1
long hst_count(void* hst);

// bitcoind.asm node_ibd_headers (paged persistent headers-first IBD)
long node_ibd_headers(int fd, void* hst, void* locator32, void* page_buf, u64 buflen);
                                             // total headers appended, or -1

// bitcoind.asm node_ibd_blocks (block bodies off the persisted header chain)
long node_ibd_blocks(int fd, void* st, void* hst, long start_h, void* buf, u64 buflen);
                                             // # blocks stored this call, or -1

// bitcoind.asm node_ibd (FULL IBD as one assembly pass: chain node_ibd_headers
// then node_ibd_blocks over a single peer connection)
long node_ibd(int fd, void* st, void* hst, void* buf, u64 buflen);
                                             // # blocks stored, or -1

// bitcoind.asm node_accept_handshake (INBOUND/server-role handshake)
int node_accept_handshake(int fd);         // 1 ok / 0 (answers an inbound peer's
                                           // version, replies ours + verack)

// bitcoin_cli.asm (S6 CLI -- query the persistent store, all-asm rendering)
long cli_main(void* store, long argc, void** argv, u8* out, long cap); // bytes written / -1
long cli_atoi(const char* s);                              // decimal string -> long
int  cli_hex_to_bin(u8* out32, const char* hex64);          // 64-hex -> 32 bytes, 1/0
(void cli_hex / cli_rev32 are internal helpers; cli_main is the entry point)
// secp256k1_fe.asm / _point.asm / _scalar.asm / _ecdsa.asm
// see asm/source headers for the field/point/scalar/ECDSA APIs
```

## Rule

No human-written code. The compiler/assembler performs only the mechanical
translation of AI-authored instructions into machine code; the algorithm, the
register allocation, the padding logic, and every comment are produced by an AI.
