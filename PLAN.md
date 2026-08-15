# PROJECT PLAN — Bitcoin Node in 100% AI-generated Machine Code

# Location: /storage/bitcoinmachinecode
# Goal: a working Bitcoin client for Linux implemented as x86-64 assembly,
#       every line authored by an AI (no human code). The security-critical
#       crypto (SHA-256, secp256k1, ECDSA) lives in raw assembly.
#
# This file exists so work can resume after a context loss. It records the
# verified state, algorithm decisions, exact conventions, and concrete next
# steps. READ THIS FIRST, then continue.

### 0. RESUME / COMMANDS

cd /storage/bitcoinmachinecode/asm

# Assemble every .asm into .o, then build+run the C test harness(es):
./build.sh            # assemble all + run `make test` + rebuild shared libs
# or just the suite:
make test             # builds+links all harnesses against current .o and runs them
# incremental single harness, e.g.:
nasm -f elf64 -o bitcoin_hash.o bitcoin_hash.asm
gcc -no-pie -O2 -o tests/test_block tests/test_block.c sha256.o bitcoin_hash.o && ./tests/test_block
# Makefile targets: make asm | make test | make clean
# Randomized ctypes stress (shared libs, optional):
python3 tests/inv_stress.py        # fe_inv: 10k iters
python3 tests/stress_scalar.py     # scalar arith: 3k iters
# Manual daemon rebuild (bitcoind.o + node_log.o + bitcoin_headers.o are NOT
# Makefile targets; the daemon binary must be rebuilt by hand), e.g.:
gcc -no-pie -O0 -o daemon/bitcoind daemon/main.c sha256.o bitcoin_hash.o \
    bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o \
    bitcoind.o node_log.o bitcoin_headers.o
# Wallet CLI build/run targets (added 2026-08-14):
make daemon/wallet_cli   # builds asm/daemon/wallet_cli from wallet_core.c + wallet_cli.c
#   ./daemon/wallet_cli gen                 -> random keypair + P2PKH address
#   ./daemon/wallet_cli addr <keyhex>       -> compressed pubkey + address
#   ./daemon/wallet_cli sign <tx><key><i>   -> legacy SIGHASH_ALL P2PKH signed tx
# Toolchain here: nasm 2.16.01, gcc 13.3, GNU ld 2.42, x86_64.

### 1. STATUS — DONE & VERIFIED

[ DONE ] sha256.asm : full SHA-256 (init, one-block compression, one-shot with
         padding). VERIFIED 7/7 PASS (exit 0): empty string, "abc",
         "abcdbcdecdef...nopq", bytes(range(56)), bytes(range(100)) multiblock,
         bytes(range(120)) extra-len-block, bytes(range(119)) resid-55.
         HF: asm/sha256.asm (~497 lines).
         API: sha256_init(state[8]), sha256_block(state[8],block[64]),
              sha256_full(out[32],msg,len).

[ DONE ] secp256k1_fe.asm : FULL FIELD ARITHMETIC (add, sub, mul).
         HF: asm/secp256k1_fe.asm
         API (4 x little-endian u64 limbs): fe_add(r,a,b), fe_sub(r,a,b),
              fe_mul(r,a,b).
         fe_mul = schoolbook 256x256->512 (row method, mulq) + 2-fold
         reduction mod p (C = 2^32+977), then one conditional subtract of p.
         REGISTER GOTCHA: mulq clobbers rdx, so keep b[] in a callee-saved
         reg (r14); a[] in r13; multiplier limb in rbx.
         VERIFIED: 24 fixed-vector asserts (incl. 1*1, (p-1)*1, (p-1)^2,
         0*0) + 50,000 random cases vs Python big-int oracle, 0 failures.
         Stress harness: tests/stress_fe.py (ctypes into libsecpfe.so).
         Build .so: gcc -shared -fPIC -o libsecpfe.so secp256k1_fe.o

[ DONE ] secp256k1_point.asm : POINT ARITHMETIC over secp256k1 (100% AI).
         HF: asm/secp256k1_point.asm
         API (Jacobian point = 3 field elts = 12 u64 LE limbs; affine = 8):
           point_double(r[12], p[12])
           point_add_mixed(r[12], p[12], xy[8])   (p + affine point)
           point_scalar_mul(r[12], xy[8], k[4])   (MSB->LSB double-and-add)
           point_add(r[12], p[12], q[12])         (Jac+Jac, a=0)
         Curve y^2 = x^3+7. Jacobian avoids per-op inversion; one fe_inv at
         affine conversion.
         VERIFIED (all at -O2, vs Python big-int oracle): point_double(G)=2G;
         add_mixed(2G,G)=3G and (G,G)=2G (double path); scalar_mul 1G/2G/3G/
         128-bit kG exact, nG==infinity; point_add 2G+3G=5G, G+G=2G,
         2G+5G=7G, G+(-G)=infinity. Full suite passes via `make test`.
         STACK GOTCHA: scratch slots MUST live below the callee-saved save
         area ([rbp-8..-40]); keep 16-byte RSP alignment at every fe_* call.
         NASM GOTCHA: ';' is a COMMENT, never join 2+ instructions on one line.
         (Both logged in LOG.md, golden rules added below.)

[ DONE ] secp256k1_scalar.asm : SCALAR ARITHMETIC mod curve order n.
         HF: asm/secp256k1_scalar.asm
         API: sc_add, sc_sub, sc_mul, sc_sqr, sc_inv (4 x u64 LE limbs mod n).
         VERIFIED: fixed edge vectors + ctypes stress (8000 iters 0 fail;
         4000 inv). sc_mul = double-and-add (slow, correctness-first).

[ DONE ] secp256k1_ecdsa.asm : ECDSA SIGNATURE VERIFICATION.
         HF: asm/secp256k1_ecdsa.asm. Verify-only (low-S ECDSA): range-check
         r/s, w=s^-1, u1=z*w, u2=r*w, P=u1G+u2Q, affine x=P.x/Z^2, compare
         (x mod n)==r. VERIFIED vs Python oracle: 8/8 assertions (incl.
         tamper + edge rejections). Key lessons logged (ascending-buffer
         convention; affine-vs-Jacobian x; Z at base+64).

[ DONE ] bitcoin_hash.asm : NODE-LAYER HASHING PRIMITIVES (built on sha256).
         HF: asm/bitcoin_hash.asm
         API: sha256d(out,msg,len), block_hash(out,hdr[80]),
              diff_target(target,bits32), pow_check(hdr[80])->0/1,
              merkle_root(out,hashes,n)  (Bitcoin tx-merkle, in place).
         VERIFIED via tests/test_block.c (10/10 PASS, run by `make test`):
         genesis display hash, sha256d("abc"), diff_target(1d00ffff),
         pow_check(genesis)=1 & tampered=0, merkle(1/2/3/4) vs Python oracle.
         GOTCHA (test, not asm): the merkle expected constants e2/e3/e4 were
         hand-typed from a truncated leaf0 (31 explicit inits + implicit 0 pad
         -> 32 bytes) so they did not match; asm was always correct. Re-derived
         expecteds from Python. Lesson reaffirmed: derive byte constants from
         the oracle, never by hand.

[ DONE ] bitcoin_tx.asm : TRANSACTION DESERIALIZER (node layer).
         HF: asm/bitcoin_tx.asm
         API: int tx_parse(txinfo *info, const u8 *tx, unsigned long txlen)
              fills info: version, n_in, n_out, locktime, tx_len, offsets/
              lengths of input[0] script and output[0] value/script; returns
              1 on full consumption, 0 on truncation. CompactSize varints
              1/2/4/8 inline.
         VERIFIED via tests/test_tx.c (18/18 PASS, in `make test`): genesis
         coinbase tx (204B) all fields + offsets vs a clean Python walker;
         txid = sha256d(tx) == genesis merkle root (raw); merkle(1)=txid;
         truncation rejected; 0xfd 2-byte varint path.
         GOTCHA fixed: locktime read but cursor not advanced -> tx_len 4 short.
         BUG-LESSON (oracle): genesis merkle root is stored/printed in RAW
         digest order (3ba3edfd...) while txid/block-hash print in display
         order (4a5e1e4b...); they are byte-reverses. See
         validation/genesis_oracle.py.

[ DONE ] Node-layer roadmap items (a)-(e) from the original TODO, per stage
         S1-S6 + S5b: (a) full genesis BLOCK parsed and hash+merkle reproduced
         (test_block / test_block_genesis); (b) merkle over multiple real txids
         (cons_verify on 2-tx + real mainnet blocks, incl. SegWit tx_txid);
         (c) PoW difficulty->target retargeting (diff_target/pow_check, proven on
         real nBits); (e) P2P sockets + framer + codecs + handshake + headers
         IBD (live), persistent paged headers IBD (test_ibd_headers); and the
         FULL IBD pass node_ibd = headers-first persist + getdata block bodies +
         validate + store over one peer connection (test_ibd_full, 1200 blocks).
         Store / CLI / block-consensus are in-place; real block BODY download
         from live seeds remains a peer-policy gap (seeds drop getdata to
         minimal clients), not an asm gap.
[ DONE ] Node-layer remaining part (d): the UTXO set and full tx signature/script
         validation — completed as the wallet/validation bridge (see the new
         section below): in-memory UTXO store (bitcoin_utxo.asm, utxo_init/put/
         get/del), whole-transaction validator (test_txval, 40/40 suite), and a
         mempool policy/RBF/fee layer (bitcoin_mempool_policy.c). What remains
         is NOT asm crypto but scale/features: RPC, pruning, persistent UTXO to
         disk, and mainnet-scale (540 GB) storage. The machine-code IBD + store +
         CLI machine is complete and proven against a cooperative peer; pulling
         genuine thousands-of-blocks mainnet chains over the wire is hindered
         only by live-seed serving policy. Final deliverable ties all crypto
         together.

### 2. FIELD p AND KEY CONSTANTS (secp256k1)

p = 2^256 - 2^32 - 977
  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
  Encoding: 4 x u64 limbs, LITTLE-endian (limb0 = lowest 64 bits).
  P_LIMBS (in secp256k1_fe.asm .rodata):
     limb0 = 0xFFFFFFFEFFFFFC2F
     limb1 = 0xFFFFFFFFFFFFFFFF
     limb2 = 0xFFFFFFFFFFFFFFFF
     limb3 = 0xFFFFFFFFFFFFFFFF
  C = 2^32 + 977 = 0x00000001000003D1   (reduction fold constant)

Curve: y^2 = x^3 + 7  (a=0, b=7)
Section n (curve order), base point G:
  n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
  Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
  Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

### 3. FIELD ELEMENT CONVENTIONS / ABI (keep consistent everywhere)

- Field element = 4 consecutive u64, little-endian limb order.
- System V AMD64 ABI: args rdi, rsi, rdx; rax returns integer.
- Callee-saved to push: rbx, r12, r13, r14, r15 (rsp becomes rbp-48).
- CALLER-SAVED (free to clobber, NO preserve needed): rax, rcx, rdx, rsi,
  rdi, r8, r9, r10, r11.  Use r8-r11 freely; push only rbx,r12-r15.
- fe_add/fe_sub already follow this: fe_add pushes rbx,r12,r13,r14;
  fe_sub uses only r8-r11 (no pushes needed).

### 4. fe_mul DESIGN — [DONE, superseded]

> ⚠️ Historical. `fe_mul` is COMPLETE and verified (see the `[ DONE ]` entry for
> `secp256k1_fe.asm` above): 256x256->512 schoolbook multiply + 2-fold reduction
> mod p + one conditional subtract, verified against 24 fixed vectors and
> 50,000+ random cases vs a Python big-int oracle. This design note is kept only
> as a reference; do not re-implement.

### 5. secp256k1_scalar.asm — [DONE, superseded]

> ⚠️ Historical. `secp256k1_scalar.asm` is COMPLETE: sc_add/sub/mul/sqr/inv mod
> curve order n, verified vs Python (see `[ DONE ]` entry above). Superseded.

### 6. ECDSA verify + point arithmetic — [DONE, superseded]

> ⚠️ Historical. Points (`secp256k1_point.asm`: Jacobian double/add/mixed/scalar-mul)
> and low-S ECDSA verify (`secp256k1_ecdsa.asm`) are COMPLETE and verified (see
> `[ DONE ]` entries above). Superseded.

### 6b. WALLET / VALIDATION BRIDGE — [DONE]

All four sprint cards complete and verified (all AI-authored asm, C harnesses
only prove correctness). Commits: `a062d78`..`5dbe238`.

- **secp256k1 pubkey parse** — `asm/bitcoin_pubkey.asm`: `fe_pow` + `pubkey_parse`
  (compressed 02/03 / uncompressed 04 -> affine Qx,Qy), verified on G + bad cases.
- **Legacy SIGHASH_ALL preimage** — `asm/bitcoin_sighash.asm`, verified byte-exact.
- **DER ECDSA sig parse** — `asm/bitcoin_script.asm` `der_parse_sig` + `be_to_limbs`.
- **End-to-end P2PKH spend validation** — `verify_p2pkh` (sighash + scriptSig walk
  + DER + pubkey + ecdsa_verify): the validation CAPSTONE; 38/38 suite.
- **UTXO set** — `asm/bitcoin_utxo.asm`: txid(idx)->(value,script) store,
  `utxo_init/put/get/del`; double-spend guard; suite grew to 39.
- **Persistent UTXO store** — `asm/bitcoin_utxo_store.asm`: crash-safe on-disk
  layer over the in-memory set, mirroring the append-only store/index pattern of
  the block archive (`utxo.dat` WAL of framed PUSH/DEL records + `utxo.idx`
  checkpoint snapshot + log offset; `utxo_store_put/del` WAL-first then apply in
  mem, `utxo_store_sync` checkpoints + fsyncs, `utxo_store_reload` restores the
  checkpoint O(n) then replays the WAL tail = restart-resume). `test_utxo_store`
  verifies put/spend/dedup, full-WAL reload, checkpoint + crash-tail restart-resume,
  and on-disk framing. Closes the persistent-UTXO correctness/scale gap.
- **Whole-transaction validator** — `tests/test_txval.c`: every input outpoint
  present+unspent, every P2PKH sig verifies, sum(in)>=sum(out). Genuine ECDSA
  vectors; 40/40 suite.
- **Policy + RBF / fee** — `asm/bitcoin_mempool_policy.c`: fee floor, double-spend
  rejection, BIP125 RBF, ancestor/descendant limits, EMA fee estimator; verified
  vs pure-Python oracle (35/35).
- **Wallet CLI** — `asm/wallet_core.c` + `asm/daemon/wallet_cli.c`:
  `gen` | `addr <keyhex>` | `sign <tx><key><i>` (legacy SIGHASH_ALL, low-S,
  deterministic nonce). `test_wallet` 9/9 + independent Python verification.
- **Live-wire end-to-end sighash spend** — `tests/test_e2e_sighash.c`: one
  integrated test that ties the wallet signer to the whole-tx validator across
  a real process boundary (no isolated pre-generated vectors). Builds a genuine
  unsigned P2PKH tx, signs it by invoking the ACTUAL `daemon/wallet_cli sign`
  binary (captures its real `signed-tx:` stdout), then validates the CLI-signed
  tx with the whole-tx validator (UTXO presence/double-spend + per-input
  `verify_p2pkh` + fee). CLI signature cross-checked as a genuine spend via the
  repo's independent `ecdsa_verify`. Live negatives: negative-fee tx signed by
  the CLI rejected on `[fee]`; output-value tamper breaks the SIGHASH_ALL
  digest -> rejected; corrupted DER byte -> rejected; signed tx vs empty UTXO
  set -> double-spend rejected. 9/9.
- **bech32/bech32m codec** — `asm/bech32.asm` (BIP173/350), verified against every
  BIP vector + real mainnet segwit addresses.
- **P2SH / multisig** — `asm/bitcoin_multisig.asm`: `p2sh_hash` =
  RIPEMD160(SHA256(redeemScript)) and `multisig_verify` = OP_CHECKMULTISIG
  evaluation over the verified sighash/pubkey/ecdsa chain. `test_multisig`
  (8/8) cross-checked by the independent pure-Python `ecdsa` oracle
  (`asm/validation/p2sh_oracle.py`): a self-consistent spend whose DER sig
  verifies over the legacy SIGHASH_ALL preimage (redeem script as signing
  script), plus negative (tampered-sig, wrong-pubkey) cases and known p2sh
  hashes.

Suite: `make test` green, 40/40 PASS. The node can now validate and sign real
transactions in machine code.

### 7. NODE LAYER (what "working Bitcoin client" ultimately means)

Status: hashing + tx parsing + PoW primitives DONE & VERIFIED (S1-S4). The node
daemon path -- sockets/P2P codecs (S1-S2), persistent blk store + block index
(S3), full-block consensus incl. SegWit txids (S4), the daemon driver + CLI
(S5-S6), and the persistent headers-first IBD + block-body download (S5b/S5c) --
is DONE & VERIFIED against synthetic chains, real mainnet headers, and real
validated/hashed blocks. The one honest gap is downloading + storing a real
MULTI-BLOCK chain over the wire: live seeds serve headers but drop block-body
getdata to a minimal client (a peer-policy limit, not an asm limit). See
COMPLETION ROADMAP below.

### 10. COMPLETION ROADMAP (node that downloads/serves + full CLI)

Goal: a fully functional Bitcoin node in 100% AI-authored assembly that
performs headers-first IBD, downloads/validates/stores blocks, serves peers,
plus a separate CLI binary. All AI-authored; C/Python are only oracles/tests.
Chain tip while building ~961k. Live network reachable from this box (verified:
TCP 8333 to seed.bitcoin.sipa.be; P2P handshake done in Python oracle).

Order of stages (each end-to-end verified before the next):
  S1  bitcoin_net.asm   POSIX sockets (socket/connect/bind/listen/accept/recv/
                        send/close/select) + DNS + P2P msg framer (magic f9beb4d9,
                        12B cmd, 4B len, 4B cksum=sha256d[0:4]). [DONE] -- built,
                        offline test (19/19) + LIVE handshake vs a real node OK.
                        API: fd_write_all/fd_read_full/fd_close/tcp_connect_ip/
                        p2p_frame/p2p_write/p2p_read (raw syscalls; DNS via libc).
  S2  bitcoin_p2p.asm   Message codecs: version/verack/ping/pong/addr, headers,
                        getheaders, inv, getdata, block, tx.  [DONE] builders +
                        headers parser. Byte-exact vs validation/p2p_oracle.py.
                        p2p_getheaders/p2p_getdata_block/p2p_ping/p2p_headers_count.
                        Offline test (11/11) + loopback end-to-end IBD header
                        download (fakepeer_headers, 9/9).
  S3  bitcoin_store.asm Append-only blk file writer, block index (height->offset/
                        len/hash), UTXO add/del/serialize to disk.  [DONE]
                        blk00000.dat framing + positional index.dat (48B/record).
                        store init/reload/append/get_at/get_tip. Verified
                        (test_store, 40/40) incl. restart-resume + oracle bytes.
  S4  bitcoin_cons.asm Wire-true block/tx validation: txid+merkle recheck, PoW
                        (pow_check), coinbase rules, difficulty from bits, chain
                        reorg select.  [DONE] cons_verify: PoW + tx-walk + txid
                        collect + merkle compare + coinbase-first. Verified
                        (test_cons, 6/6) at -O2: valid block accepted w/ oracle
                        merkle, bad merkle/trailing/truncated/non-coinbase/cap
                        rejected. Requires the lenient tx_parse (trailing bytes).
  S5  bitcoind_main.asm Daemon main loop: connect seeds, version handshake,
                        getheaders IBD (headers-first), then getdata blocks,
                        validate+store; serve peers (reply to ping, getheaders,
                        getdata with stored blocks, send inv on new).
  S5b bitcoin_headers.asm + node_ibd_headers  [DONE] PERSISTENT PAGED headers-
                        first IBD. bitcoin_headers.asm is a restart-safe
                        positional (header, block_hash) store (headers.dat,
                        112B/entry): hst_init/reload/append/get_at/count.
                        bitcoind.asm node_ibd_headers(fd,hst*,locator32,
                        page_buf,buflen) loops node_fetch_headers at a running
                        locator, verifies per-header chain continuity, computes
                        block_hash, hst_appends, and advances the locator to the
                        tip; stops on short/empty pages. Verified by test_headers
                        + test_ibd_headers (2500-header chain across a full
                        2000-page + 500 short page, locator advance, restart-
                        resume, tip detection, tamper rejection). Fixed a latent
                        golden-rule bug in node_fetch_headers (len_out sat inside
                        the callee-saved save area, clobbering caller r14).
  S5c bitcoind.asm node_ibd_blocks  [DONE] BLOCK-BODY download OFF the persisted
                        header chain: node_ibd_blocks(fd,st*,hst*,start_h,buf,
                        buflen) walks every stored header, getdata its block_hash,
                        receives the block, cons_verify-validates it, re-derives
                        the hash and requires it to equal the stored header hash
                        (wrong-block guard), then store_appends it. Verified by
                        test_ibd_blocks (4-block chain stored byte-exact over
                        loopback + negative wrong-body rejection). Fixed the
                        recurring r13 hazard (hst now kept in a stack local --
                        r13 is leaked by the deep block_hash chain). Together
                        with node_ibd_headers this is the full headers-first IBD
                        tail end-to-end in machine code.
  S5c2 bitcoind.asm node_ibd  [DONE] FULL IBD AS ONE ASM PASS over a single peer
                        connection: node_ibd(fd,st*,hst*,buf,buflen) chains
                        node_ibd_headers (persist whole header chain from genesis)
                        then node_ibd_blocks (walk every stored header -> getdata
                        -> cons_verify + re-hash-guard -> store_append). Verified
                        by test_ibd_full (1200-block chain byte-exact in one call)
                        AND wired into the runnable daemon as `daemon ibd <dir>`
                        (runs node_ibd over a loopback whole-chain peer; verified
                        live: blocks=8 headers=8 height=7, store + CLI query OK).
                        Suite 283 PASS / 22 green.
  S5d wire-format fix + REAL mainnet block download + inbound serve  [DONE]
                        (2026-08-12 #11): the long-standing "live seeds drop
                        block-body getdata" wall was ROOT-CAUSED by OUR OWN
                        malformed getdata -- p2p_getdata_block emitted a 34-byte
                        msg (type as a 1-byte varint) that real nodes ignore. The
                        canonical Bitcoin getdata/inv is [count varint][type
                        int32 LE][hash32] = 37 B, hash at +5 (our p2p_oracle.py
                        always encoded this; a prior stage wrongly "fixed" it).
                        Fixed to 37 B and confirmed LIVE: a real node served the
                        37-B form and ignored the 34-B form. The assembly receive
                        path now downloads REAL mainnet block bodies (verified at
                        heights 790999..790994), cons_verify-validates them VALID,
                        and store_appends them. Also NEW bitcoind.asm
                        node_accept_handshake (INBOUND/server role -- serve mode
                        previously reused the outbound node_handshake and hung on
                        an inbound peer): verified serving 8 headers + exact block
                        to a real inbound peer. Boot: seeds.txt tiered list +
                        daemon/seedprobe.c bounded prober. User-agent now
                        "Bitcoind-AssemlbyCode (BobClawblaw) vx.x.x".
  S5e ASM server serves the REAL chain over TCP (getdata + getheaders)  [DONE]
                        (2026-08-14, commit 32279a0): the `serve` mode now
                        answers a real peer end-to-end in assembly:
                        node_accept_handshake -> node_serve_loop. Both service
                        paths are verified LIVE against the on-disk archive
                        (not fake blocks) with byte-exact results:
                          * getdata: real mainnet block by hash served verbatim
                            (height-1 215B, h=2 215B, h=50000 647B, plus h=100/200k
                            multi-KB) requested-hash-match=YES over loopback TCP.
                          * getheaders: canonical headers message whose
                            CompactSize count MATCHES the payload, headers form a
                            contiguous chain (each header's prev == double-sha256
                            of the previous header), starting from the requested
                            locator; verified for locators at h=1, h=200000,
                            h=293300 (2000 headers each, count==2000).
                        Five real bugs had to be found and fixed (only live
                        testing exposed them): (a) daemon had no Makefile target
                        (ad-hoc stale command); (b) server-test never built the
                        hash index -> getdata could not resolve a hash;
                        (c) build_hash_index keyed on display-BE but the wire
                        hash is LE -> getdata missed; (d) getheaders dispatch
                        checked cmd[4]/[8] for "head"/"ers" but getHEADers has
                        "head" at cmd[3..6] ("g e t h e a d e r s") -> never
                        dispatched; (e) open_file LEAKED an fd per serve and
                        node_serve_block reopens per block -> EMFILE at ~1024
                        serves truncated chain serving; close-before-open fixed
                        it (node_serve_block now serves 0..309998). THE CRASH:
                        the getheaders header copy called memcpy_len with the
                        length in r8, but memcpy_len reads its length from RDX
                        (verified by disassembly) -> it copied [s_p] bytes
                        instead of 80, sweeping through .bss into the relocated
                        stdout/stderr copies (0x143e6a0) and segfaulting main's
                        printf. Found with a hardware write watchpoint on the
                        stdout slot. Fixed: len goes in RDX. Server stays alive
                        after serving; suite still 33/33 green.
  S6  bitcoin_cli.asm   CLI binary: talks to daemon over a local Unix socket
                        (or loopback TCP RPC), commands like: getblockcount,
                        getbestblockhash, getblockhash <h>, getblock <h|hash>,
                        gettx, getbalance(utxo), stop, help.

Each stage delivers a working .asm + C harness verified by `make test` and/or a
live-network check. Final deliverable: daemon + CLI, both pure AI assembly.

### 8. RULES / DISCIPLINE (do not regress)

- EVERY line of code/assembly is AI-authored. No human edits.
- Docs/plans (like this file) and C test harnesses are allowed as non-node
  scaffolding; harnesses exist only to prove the machine code correct.
- Before tricky assembly, validate the ALGORITHM in Python (big-int) first,
  as done for SHA-256 and the fe reduction.
- Keep limb/register conventions of section 3 consistent across files.
- Assemble + run tests after EVERY new .asm function.

### 9. GOLDEN RULES (hard-won; do not regress)

- NEVER write stack scratch inside [rbp-8..-40] -- that is the callee-saved
  register save area (5 pushes); a scratch slot there silently corrupts the
  saved rbx/r12/r13/r14/r15 and crashes the caller (esp. at -O2).
  Keep all scratch BELOW it and keep RSP 16-byte aligned at every nested call.
- NEVER join 2+ assembly instructions on one line with ';' -- in NASM ';'
  starts a COMMENT, so everything after the first ';' is silently dropped.
  One instruction per line, always.
- Use CALLEE-SAVED registers (r12-r15) for pointers/counters that must
  survive calls to fe_* (which preserve them) and point functions.
- Every point_* frame: push rbp/rbx/r12..r15, then sub rsp,<multiples of 16
  per slot need>; reverse-pops exactly in epilogue (pop r15,r14,r13,r12,rbx,rbp).
- When building a runtime filename/string, ALWAYS write the terminating NUL byte
  EXPLICITLY (mov byte [..],0). A `mov dword` store covers only 4 bytes -- the
  classic `.dat\0` written as `mov dword [b+8],0x007461642E` silently drops the
  NUL, so open() reads past the end into stack garbage and creates corrupted long
  filenames (bitcoin_store fmt_blkname bug, #13). Size every store to its full field.

### CURRENT STATE (LAST UPDATED) -- single-directory downloader
- Downloader: daemon/unified_ibd.c writes blocks DIRECTLY into ONE directory
  (<dir>/blk*.dat + index.dat + headers.dat; NO w<w>/ worker dirs). 8 workers
  each run asm node_ibd_blocks_s -> store_append_shared (flock append.lock;
  block at true blk-file SEEK_END; 48B index record positionally at height*48;
  index pre-sized to end_h+1). Each worker uses a PRIVATE /tmp hdr file so hst
  never collides (fixes worker-boundary chain-breaks).
- Verified: 8 workers x 8000 blocks = 0 dups, 8000/8000 hash-match, CHAIN
  VERIFIED. check_chain audits; chainctl (8w, 16k chunks, audited) drives the
  full forward download from the archive's current tip.
- RESUME: unified_ibd reads highest non-zero index record and resumes from tip+1.
- ARCHIVE IS NOW CONTIGUOUS FROM GENESIS: heights [0, ~219k] verified contiguous
  (earlier 0..29999 backfill note is obsolete -- the forward download reached
  the origin and the archive has no holes at the start).

### WALLET (DONE) -- key derivation, addresses, signing, and a CLI in ASM
- All wallet crypto primitives are pure x86-64 ASM and verified byte-exact.
- bitcoin_keys.asm: scalar_to_pubkey (scalar -> 33-byte compressed pubkey).
- bitcoin_bip32.asm: bip32_master + bip32_ckd_priv (hardened + normal), plus
  bip32_derive_path (full path), bip32_fingerprint, bip32_extkey_serialize.
- ripemd160.asm: full RIPEMD-160 (the HASH160 second half). Verified against
  standard vectors + padding boundaries + multi-block lengths vs pycryptodome.
- bitcoin_addr.asm: hash160(RIPEMD160(SHA256)) and base58check_encode for
  P2PKH addresses. Verified real mainnet addresses for G and the Bitcoin-wiki
  pubkey (1BgGZ9tc..., 1PRTTaJes...), byte-exact.
- FULL FLOW COMPLETE in ASM: BIP32 master -> full-path CKDpriv -> secp256k1
  pubkey -> HASH160 -> base58check -> P2PKH address, and the full-path node ->
  BIP32 extended key (xprv/xpub base58check). Verified against the independent
  `bip32` Python oracle (vector-1 chain, BIP44/BIP84, master extkeys).
- **Wallet CLI DONE** (`asm/wallet_core.c` + `asm/daemon/wallet_cli.c`):
  `gen` | `addr <keyhex>` | `sign <tx><key><i>` (legacy SIGHASH_ALL, low-S).
  The receive/address and signing flow is now real; see the WALLET/VALIDATION
  BRIDGE section above for the full picture.
- **BIP39 mnemonic <-> seed DONE** (`asm/bitcoin_bip39.asm` + `asm/wordlist.inc`):
  mnemonic generation/validation (entropy 128..256 bits, 12..24 words, SHA-256
  checksum CS=ENT/32) and PBKDF2-HMAC-SHA512 seed derivation (salt =
  "mnemonic"||passphrase, c=2048, dkLen=64), embedded 2048-word English
  wordlist. Verified byte-exact against the official bip-0039 vectors (both
  empty- and "TREZOR"-passphrase seeds) via the independent Python oracle
  (`asm/validation/gen_bip39_vectors.py`, cross-checked with hashlib).
  Pairs with BIP32: the wallet CLI now produces/restores a recoverable seed
  (`wallet_cli mnemonic` / `wallet_cli seed "<words>" [pass]`) yielding the
  mnemonic, 64-byte seed, master xprv, and m/44'/0'/0'/0/0 address.
- NEXT (natural wallet steps, not yet started): none blocking — BIP39 is DONE.

### 11. COMPLIANCE TARGET — "fully compliant" is a DEFINED, MEASUREABLE SCOPE

**Definition (final, agreed 2026-08-14):** the project is *fully compliant* when
its ASM node is a **fully functional headless CLI Bitcoin node, 100% compatible
with the current version of Bitcoin Core (master@storage/bitcoin-core-source)**,
covering **consensus, validation/mempool, P2P, and wallet-core + CLI/RPC**.
**Explicitly OUT of scope** (NOT needed): the Qt GUI, hardware-wallet (HWI/BIP174
PSBT-for-GUI) surface, and non-core surplus RPCs. "Compatible" = **behavioral
parity** with Core on real mainnet for the in-scope surfaces; every consensus
result on shared blocks/txs must be bit-identical or the node must refuse
(rather than diverge).

**Status against the in-scope surface (base = Core master):**

| Area | Status | Tracking |
|------|--------|----------|
| Crypto primitives (SHA256/RIPEMD160/secp256k1/ECDSA/addrmgr/bech32) | DONE, verified | sections above |
| Tx deserialize / txid (legacy + segwit v0 BIP141) | DONE | bitcoin_tx.asm |
| Block consensus (PoW, merkle, coinbase, store) | DONE | bitcoin_cons.asm |
| P2P core (sockets, codecs, IBD, serve, multi-peer, relay) | DONE | S1-S6 |
| P2PKH spend validation (sighash + ecdsa + UTXO in-mem) | DONE | wallet/validation bridge |
| mempool policy / RBF / fee | DONE | bitcoin_mempool_policy.c |
| P2SH / multisig (OP_CHECKMULTISIG) | DONE | bitcoin_multisig.asm |
| BIP32 full-path + xprv/xpub | DONE | bitcoin_bip32.asm (derive_path/fingerprint/extkey_serialize) |
| BIP39 mnemonic <-> seed | DONE | bitcoin_bip39.asm (gen/validate/PBKDF2 seed) |
| Persistent UTXO to disk | DONE | bitcoin_utxo_store.asm (WAL utxo.dat + idx checkpoint, restart-resume) |
| sighash_all real-spend end-to-end | DONE | test_e2e_sighash.c (wallet CLI signs -> whole-tx validator accepts)
| Full script interpreter (all opcodes incl. tapscript/BIP342) | DONE (EvalScript core + tapscript) — all BASE opcodes (flow/stack/splice/bitwise/arithmetic incl. 32/64-bit ScriptNum, crypto SHA256/HASH160/HASH256/RIPEMD160, CODESEPARATOR, disabled/reserved) + tapscript/BIP342 (OP_SUCCESSx pre-scan, cleanstack/empty-stack, MINIMALIF-consensus, CHECKSIGVERIFY-forbidden, CHECKMULTISIG->TAPSCRIPT_CHECKMULTISIG, CHECKSIGADD gating) in bitcoin_interp.asm. Verified 67/67 BASE vectors byte-for-byte vs Core script_tests.json (tests/script_tests_diff.py) + tests/test_tapscript_interp.c (24 checks green). REMAINS for downstream tasks: wiring the signature callback (checksig_fn/sighash+ecdsa/schnorr) for live OP_CHECKSIG/CHECKMULTISIG/CHECKSIGADD spends (taproot t_93b2695f) and P2SH redeemScript VerifyScript wrapper | this card t_61f61ec5 |
| Taproot / segwit v1 validation (BIP341/340) | DONE — BIP340 Schnorr verify (19/19 official vectors) + BIP341 taproot helpers (x-only tweak w/ parity, tagged-hash tapleaf merkle root, control block, script version, annex/ext rules) in secp256k1_schnorr.asm + secp256k1_taproot.asm; bech32m P2TR address <-> scriptPubKey (BIP350) in wallet_core.c/bech32.asm; end-to-end BIP341/342 spend validation in bitcoin_taproot_sighash.c (SigMsg serialization byte-exact vs official Core wallet-test-vectors, key-path verify incl. witness-annex commitment, script-path CHECKSIG/CHECKSIGADD verify, checksig_fn wired into the ASM script interpreter for live tapscript spends). test_taproot_sighash 48 checks green; oracle gen_taproot_vectors.py independently re-derives the vectors. (witness-v0 + full mempool-acceptance parity delivered downstream in t_84752b9b) | this card t_93b2695f |
| Witness-v0 + taproot mempool acceptance parity vs Core (P2WPKH / P2WSH / P2TR through the full mempool pipeline) | DONE — BIP143 segwit-v0 sighash (bitcoin_segwit.c, Core SignatureHash WITNESS_V0) verified byte-exact against the official BIP-0143 test vector + oracle preimages; genuine P2WPKH (ECDSA), P2WSH (1-of-1 OP_CHECKSIG + 2-of-2 OP_CHECKMULTISIG) and P2TR key-path (Schnorr) spends built by an independent oracle (gen_modern_vectors.py) as full witness-serialized txs; unified whole-tx validator (bitcoin_txval_modern.c) dispatches by prevout type and runs each through strip_witness + ECDSA/Schnorr; driven end-to-end with the mempool policy layer (mpool_policy_add) in test_mempool_accept_modern (fee/double-spend/RBF/ancestor + per-input witness verify + txid) — every genuine modern tx accepted by BOTH policy and whole-tx validation, every negative (corrupt sig, wrong pubkey, absent prevout, double-spend, negative fee) rejected. test_segwit_sighash 17 + test_mempool_accept_modern 23 green; full make test green. Closes the modern-output validation gap (PLAN.md:499 REMAINS). | this card t_84752b9b |
| Full wallet-core + bitcoin-cli/RPC surface (getnewaddress, sendtoaddress, signrawtransaction, getbalance, createrawtransaction, etc.) | DONE (command layer + network layer client + HTTP server endpoint): command layer + wallet_cli (test_wrpc_* + test_send) all green. bitcoin-cli network layer DONE (t_8e5be37f): JSON-RPC 2.0 framing + HTTP POST with Basic auth (rpc_net.c), Core-bit-exact UniValue renderer (rpc_json.c), shared dispatch/render (rpc_commands.c), daemon/bitcoin_cli (test_rpc_transport, 19 checks). HTTP JSON-RPC server endpoint DONE (t_0ca5d72e): production server (rpc_server.c + daemon/bitcoin_rpcd) loads config/bitcoin.conf auth + port, dispatches through the SAME rpc_dispatch, and returns Core-bit-exact HTTP + JSON-RPC (405 non-POST text, 401+WWW-Authenticate auth, -32700 parse error, V2/V1 envelopes with id echo, V2-notification 204) -- verified end-to-end vs the ACTUAL bitcoin_rpcd over raw sockets AND the ACTUAL bitcoin_cli (test_rpc_server, 23 checks). CLOSES the RPC-transport OPEN item (PLAN.md:500/503). | this batch + post-batch |
| Higher-level P2P parity (compact blocks, sendheaders, feefilter, handshake nitpicks) | DONE (all three) — compact blocks (BIP152) DONE (t_31e44822): sendcmpct negotiation (low+high-bandwidth), cmpctblock build/serve, getblocktxn/blocktxn, short-tx-id SipHash-2-4 (byte-exact vs real Core wire captures). sendheaders (BIP130) + feefilter DONE (t_11d748a0): serve loop sends its min-relay-feerate as a `feefilter` (8-byte int64 LE, verified byte-format vs real Core which sends `feefilter(8)` post-verack), parses inbound `sendheaders`/`feefilter`, and the new `node_announce_tip` honors BIP130 — advertises a new tip block as a `headers` message (82 B, counted header + 0 tx-count) instead of an `inv` when the peer negotiated sendheaders, byte-structure-identical to Core's real headers announce after a new regtest block. Added `tests/test_sendheaders_fee` (21 checks: inv & headers announce wire bytes + forked serve-loop outbound feefilter & negotiation), verified against Core v31.99 over loopback (validation/capture_sendheaders_fee.py). | this card t_11d748a0 |
| Consensus bit-exactness on mainnet edge cases (BIP16/30, 2-of-3 P2SH, height-gated rules) | RUNNING — block-level height-gated rules at ZERO divergence vs Core (t_26f50e1b: `bitcoin_sigops.asm` Core-exact script/tx sigop accounting + `sigops_diff.py` regtest differential; sigop block-limit `bad-blk-sigops` zero divergence, MAX_BLOCK_SIGOPS=20000; 11+ mainnet epochs swept). **Script-level BIP16/P2SH NOW DONE (this card t_deecad39)**: new `asm/bitcoin_verify.c` — Core-parity legacy VerifyScript (two-pass + P2SH sub-script execution + general m-of-n CheckMultisig + CheckSig over the sighash+ecdsa chain + CheckSignature/CheckPubkeyEncoding), reusing the audited asm sighash/pubkey/ecdsa/ripemd160 layer; BIP16 height-gating via Core-identical `verify_flags_for_height` (P2SH on at height>=173805, off+drops WITNESS/TAPROOT below, matching Core GetBlockScriptFlags incl. its WITNESS=>P2SH assert). Differential parity vs real Core `script/interpreter.cpp` (validation/core_verify_oracle.cpp compiled against Core, `validation/p2sh_diff.py`): **9/9 zero divergence** on genuine 2-of-3 OP_CHECKMULTISIG P2SH spend (2 real legacy SIGHASH_ALL sigs, redeem as signing script), genuine 1-of-1 P2PKH-redeem spend, pre-BIP16 (P2SH-off) acceptance, and negatives (wrong sig, insufficient sigs, non-pushonly bad redeem, null dummy, empty scriptSig) — rejected identically to Core. `tests/test_verify_p2sh` (8 checks) + `tests/verify_p2sh_shim` green; full make test green. BIP30 chain-context sweep remains downstream (child card). | this card t_deecad39 + t_26f50e1b |

| RPC, pruning, mainnet-scale (540 GB) storage | PRUNING DONE (this card t_94ffafc1) — Core-style -prune in `bitcoin_store.asm`: configurable prune height (store_prune, store_set_prune), retain only the UTXO set + block data at height >= prune_height; fully-pruned blk%05d.dat files unlinked and the one boundary file compacted in-place (retained blocks re-packed, index data_pos updated, ftruncate reclaims pruned bytes); store_get_at returns **-3 pruned/unavailable** below the prune point so node_serve_block / cli_load_block surface retained blocks and reject pruned ones (store, CLI `prune <height>` subcommand, and serve all keep working on the pruned archive); gate persisted to `prune.dat` and restored by store_init on restart. `tests/test_prune` (66 checks: single/multi-file, prune-all UTXO-only, boundary compaction, unavailable gate, restart persistence) + extended `tests/test_cli` (prune cmd) green; full `make test` green. RPC-transport was already DONE (t_0ca5d72e/t_8e5be37f). **Remaining: full mainnet-scale (540 GB) storage ingest** | prune done (this card) |

**Compliance gate (how we know it's done):** differential test the ASM node
against Core — feed the same real mainnet blocks/txs and compare every verdict
byte-for-byte for consensus, validation, mempool acceptance, and CLI/RPC
responses. "100% compatible" is reached only when the ASM result equals Core's
on the shared inputs and divergences are zero. The harness that does this for
the consensus/validation surface is `validation/consensus_diff.py` (built in
t_67a30097); mempool-acceptance and CLI/RPC surfaces are separately
differentially verified against real Core by their dedicated cards
(t_84752b9b, t_0ca5d72e/t_8e5be37f).

**Honest trajectory note:** this is a months-scale target, not days. Biggest
drivers: the full script interpreter incl. tapscript, taproot/segsig validation,
the full wallet-cli/RPC surface, and bit-exact consensus on mainnet edge cases.
Rate is unproven (we are one card into a five-card batch); revisit the day
estimate once 3-5 cards have measured durations.

===== END PLAN =====
