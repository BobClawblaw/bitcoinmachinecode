# Bitcoin Machine Code

A Bitcoin node for Linux built as **100% AI-generated machine code** — every line of
assembly is authored by an AI assistant, none by a human. Per the chosen approach
(Option B), the security-critical crypto is written directly in x86-64 assembly.

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
download + store tail is now exercised end to end against a REAL node
(192.168.5.69:8333): real mainnet block bodies are downloaded, cons_verify-
validated as VALID, and stored.** The long-standing "seeds drop block-body
getdata" wall was root-caused to our own malformed getdata: `p2p_getdata_block`
emitted a 34-byte message (type as a 1-byte varint) that real nodes silently
ignore. The canonical Bitcoin getdata/inv inventory is `[count varint][type int32
LE][hash32]` = 37 bytes with the hash at +5 (the p2p_oracle always encoded this;
a prior stage wrongly "fixed" it -- corrected and confirmed live). Public seeds
still serve the real header chain reliably; with the corrected getdata they also
serve block bodies to a cooperative/unchained peer. The inbound (server) role is
now real too: a new asm `node_accept_handshake` answers a genuine inbound node's
`version` and serves stored blocks (verified end to end), where the old serve
path reused the outbound handshake and hung on an inbound peer.

**Parallel full-chain download (>= 8 distinct internet peers) + all-asm receive
loop:** Peer discovery (`daemon/peertest.c` / `daemon/discover.c`, scanning a
26,895-node snapshot) finds many distinct internet nodes that serve block bodies;
`daemon/paribd.c` and `daemon/paribd_asm.c` download the full chain in parallel.
The per-worker receive loop (`bitcoind.asm node_ibd_headers` + `node_ibd_blocks_x`)
downloads / `cons_verify`s / stores each block entirely in assembly. Verified:
962,208 real headers persisted, real blocks downloaded/stored and re-served to an
inbound peer. A real-mainnet header-continuity bug was found and fixed (see LOG
#12). A resumable full-chain download runs into `data/`.

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
|   +-- build.sh              # assemble + build + run every verification harness
|   +-- Makefile              # make asm | test | clean
|   +-- tests/                # C harnesses proving the machine code correct
|   +-- validation/           # Python big-int oracles (trusted reference)
+-- data/                    # durable chain storage (blk00000.dat, index.dat, log)
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
./cli /storage/bitcoinmachinecode/data getblockcount # query the stored chain
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
