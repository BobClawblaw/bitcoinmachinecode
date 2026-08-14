# ============================================================================
# Makefile - 100% AI-generated build driver for the assembly crypto core.
#
#   make asm  : assemble all .asm sources into .o objects
#   make test : build every C harness against the objects and run them
#   make clean: remove generated objects and binaries
#
# Point arithmetic (secp256k1_point.asm) depends on the field primitives
# (secp256k1_fe.asm), so point test binaries link both objects.
# ============================================================================

NASM       := nasm
NASMFLAGS  := -f elf64
CC         := gcc
CFLAGS     := -no-pie -O2 -Wall

OBJS := sha256.o sha512.o bitcoin_hmac.o bitcoin_keys.o ripemd160.o bitcoin_addr.o bech32.o secp256k1_fe.o secp256k1_point.o secp256k1_scalar.o secp256k1_ecdsa.o bitcoin_hash.o bitcoin_tx.o bitcoin_net.o bitcoin_p2p.o bitcoin_store.o bitcoin_cons.o node_log.o bitcoin_cli.o bitcoind.o bitcoin_headers.o bitcoin_addrmgr.o bitcoin_idx.o bitcoin_serve.o bitcoin_mempool.o bitcoin_pubkey.o bitcoin_sighash.o bitcoin_script.o bitcoin_utxo.o bitcoin_multisig.o
# bitcoin_hash.asm (sha256d/block-hash/merkle/pow) depends on sha256.o
HASHOBJS := sha256.o bitcoin_hash.o
# bitcoin_tx.asm parser harness also exercises sha256d/merkle_root.
TXOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o
# bitcoin_net.asm framing needs sha256d (checksum).
NETOBJS := sha256.o bitcoin_hash.o bitcoin_net.o
# P2P codec harness needs the net framing (framer uses sha256d).
P2POBJS := sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o
# store harness is standalone (no deps).
# cons_verify (block consensus) uses pow_check/merkle_root/sha256d + tx_parse.
CONSOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o bitcoin_cons.o

.PHONY: all asm test clean

all: test

asm: $(OBJS)

%.o: %.asm
	$(NASM) $(NASMFLAGS) -o $@ $<

tests/test_sha256: tests/test_sha256.c sha256.o
	$(CC) $(CFLAGS) -o $@ tests/test_sha256.c sha256.o

tests/test_fe: tests/test_fe.c secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_fe.c secp256k1_fe.o

tests/test_point: tests/test_point.c secp256k1_point.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_point.c secp256k1_point.o secp256k1_fe.o

tests/test_addm: tests/test_addm.c secp256k1_point.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_addm.c secp256k1_point.o secp256k1_fe.o

tests/test_scalarmul: tests/test_scalarmul.c secp256k1_point.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_scalarmul.c secp256k1_point.o secp256k1_fe.o

tests/test_add: tests/test_add.c secp256k1_point.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_add.c secp256k1_point.o secp256k1_fe.o

tests/test_scalar: tests/test_scalar.c secp256k1_scalar.o
	$(CC) $(CFLAGS) -o $@ tests/test_scalar.c secp256k1_scalar.o

tests/test_ecdsa: tests/test_ecdsa.c secp256k1_ecdsa.o secp256k1_scalar.o secp256k1_point.o secp256k1_fe.o
	$(CC) $(CFLAGS) -o $@ tests/test_ecdsa.c secp256k1_ecdsa.o secp256k1_scalar.o secp256k1_point.o secp256k1_fe.o

tests/test_block: tests/test_block.c $(HASHOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_block.c $(HASHOBJS)

tests/test_tx: tests/test_tx.c $(TXOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_tx.c $(TXOBJS)

tests/test_net: tests/test_net.c $(NETOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_net.c $(NETOBJS)

tests/test_p2p: tests/test_p2p.c $(P2POBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_p2p.c $(P2POBJS)

tests/fakepeer_headers: tests/fakepeer_headers.c $(P2POBJS)
	$(CC) $(CFLAGS) -o $@ tests/fakepeer_headers.c $(P2POBJS)

tests/test_store: tests/test_store.c bitcoin_store.o
	$(CC) $(CFLAGS) -o $@ tests/test_store.c bitcoin_store.o

tests/test_cons: tests/test_cons.c $(CONSOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_cons.c $(CONSOBJS)

# cons_verify on the REAL mainnet genesis block (offline, deterministic).
tests/test_block_genesis: tests/test_block_genesis.c $(CONSOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_block_genesis.c $(CONSOBJS)

# bitcoind: handshake + version builder (networked). node_sync also calls
# cons_verify + store_append, so DAEMONOBJS must include those objects.
# node_ibd_headers references hst_append (bitcoin_headers.asm), so include it.
DAEMONOBJS := sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o bitcoind.o bitcoin_headers.o

tests/test_bitcoind: tests/test_bitcoind.c $(DAEMONOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_bitcoind.c $(DAEMONOBJS)

# Full IBD client (node_sync): handshake + headers + getdata + validate + store.
# Built at -O0: the deep asm hash call chain (node_sync -> cons_verify ->
# pow_check -> block_hash -> sha256d -> sha256_full) provably works at -O0, but
# gcc -O2's main register/stack layout triggers a latent sha256_full deep-frame-
# overlap crash in this specific networked harness. The asm is identical.
tests/test_bitcoind_sync: tests/test_bitcoind_sync.c $(DAEMONOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bitcoind_sync.c $(DAEMONOBJS)

# all-asm leveled logger (uses fd_write_all from bitcoin_net.asm)
# Built at -O0: same gcc -O2 vs deep-asm-call-chain interaction as the sync
# harness; the asm logger is identical and correct at -O0.
LOGOBJS := node_log.o bitcoin_net.o bitcoin_hash.o sha256.o
tests/test_log: tests/test_log.c $(LOGOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_log.c $(LOGOBJS)

# S6 CLI (bitcoin_cli.asm): queries the store + hashing/tx primitives.
CLIOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o bitcoin_store.o bitcoin_cli.o
tests/test_cli: tests/test_cli.c $(CLIOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_cli.c $(CLIOBJS)

# Persistent header-chain store (bitcoin_headers.asm): appends a (header, block_hash)
# pair per entry; the harness checks continuity by computing block_hash of chain
# predecessors via the proven block_hash asm.
HEADOBJS := sha256.o bitcoin_hash.o bitcoin_headers.o
tests/test_headers: tests/test_headers.c $(HEADOBJS)
	$(CC) $(CFLAGS) -o $@ tests/test_headers.c $(HEADOBJS)

# Paged persistent headers-first IBD (bitcoind.asm node_ibd_headers) over the
# asm header store. Built at -O0: same gcc -O2 vs deep-asm-call-chain interaction
# as the bitcoind sync harness; the asm is identical and correct at -O0.
# bitcoind.o bundles node_sync/node_serve_block/node_drain which reference the
# cons/store/tx symbols, so link the full DAEMONOBJS superset.
IBDOBJS := sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o bitcoind.o bitcoin_headers.o
tests/test_ibd_headers: tests/test_ibd_headers.c $(IBDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_ibd_headers.c $(IBDOBJS)

# Block-body download off the persisted header chain (bitcoind.asm node_ibd_blocks).
# node_ibd_blocks calls cons_verify/block_hash/store_append/hst_*; bitcoind.o pulls
# the transitive cons/tx symbols too. Built at -O0 (deep-asm-call-chain convention).
tests/test_ibd_blocks: tests/test_ibd_blocks.c $(IBDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_ibd_blocks.c $(IBDOBJS)

# FULL initial-block-download as one asm pass (bitcoind.asm node_ibd =
# node_ibd_headers + node_ibd_blocks) over a whole NB-block loopback chain.
tests/test_ibd_full: tests/test_ibd_full.c $(IBDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_ibd_full.c $(IBDOBJS)

# bitcoin_addrmgr.asm: peer address book + addr v1 codec (standalone deps).
ADMRGOBJS := bitcoin_addrmgr.o
tests/test_addrmgr: tests/test_addrmgr.c $(ADMRGOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_addrmgr.c $(ADMRGOBJS)

# bitcoin_keys.asm (secp256k1 pubkey derivation for wallet/BIP32).
KEYSOBJS := secp256k1_fe.o secp256k1_point.o secp256k1_scalar.o bitcoin_keys.o
tests/test_keys: tests/test_keys.c $(KEYSOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_keys.c $(KEYSOBJS)

# bitcoin_idx.asm: O(1) hash->height index for serving (standalone deps).
IDXOBJS := bitcoin_idx.o
tests/test_idx: tests/test_idx.c $(IDXOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_idx.c $(IDXOBJS)

# bitcoin_serve.asm: inbound (server) message loop over p2p + idx + serve_block.
SERVEOBJS := bitcoin_serve.o bitcoin_idx.o bitcoin_net.o bitcoin_p2p.o bitcoin_store.o bitcoind.o bitcoin_headers.o bitcoin_hash.o bitcoin_addrmgr.o node_log.o bitcoin_tx.o bitcoin_cons.o sha256.o bitcoin_mempool.o
tests/test_serve: tests/test_serve.c $(SERVEOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_serve.c $(SERVEOBJS)

# SHA-512 (FIPS 180-4, wallet/BIP32+bech32 foundation).
tests/test_sha512: tests/test_sha512.c sha512.o
	$(CC) -no-pie -O0 -o $@ tests/test_sha512.c sha512.o

# HMAC-SHA512 (RFC 4231 / RFC 2104, BIP32+BIP39 primitive, on asm SHA-512).
HMACOBJS := sha512.o bitcoin_hmac.o
tests/test_hmac: tests/test_hmac.c $(HMACOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_hmac.c $(HMACOBJS)

# bitcoin_bip32.asm (BIP32 master + CKDpriv; secp256k1 + HMAC + SHA-512).
BIP32OBJS := bitcoin_bip32.o bitcoin_hmac.o sha512.o bitcoin_keys.o secp256k1_fe.o secp256k1_point.o secp256k1_scalar.o
tests/test_bip32_master: tests/test_bip32_master.c $(BIP32OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip32_master.c $(BIP32OBJS)
tests/test_bip32_chain: tests/test_bip32_chain.c $(BIP32OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip32_chain.c $(BIP32OBJS)

# ripemd160.asm (HASH160 half; needed for P2PKH address generation).
tests/test_ripemd160: tests/test_ripemd160.c ripemd160.o
	$(CC) -no-pie -O0 -o $@ tests/test_ripemd160.c ripemd160.o

# bitcoin_addr.asm (hash160 = RIPEMD160(SHA256), base58check P2PKH addresses).
ADDROBJS := bitcoin_addr.o sha256.o bitcoin_hash.o ripemd160.o
tests/test_addr: tests/test_addr.c $(ADDROBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_addr.c $(ADDROBJS)

# bech32.asm (BIP173) / bech32m (BIP350) address codec: polymod checksum,
# convert_bits + encode/decode, verified against the authoritative BIP173
# and BIP350 vectors plus real mainnet segwit (P2WPKH/P2WSH/P2TR) addresses.
BECH32OBJS := bech32.o
tests/test_bech32: tests/test_bech32.c $(BECH32OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bech32.c $(BECH32OBJS)

MEMPOOLOBJS := bitcoin_mempool.o
tests/test_mempool: tests/test_mempool.c $(MEMPOOLOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_mempool.c $(MEMPOOLOBJS)

# Mempool POLICY layer (bitcoin_mempool_policy.c -- pure C glue over the asm
# mempool + asm UTXO): fee/relay floor, double-spend, BIP125 RBF, ancestor/
# descendant limits, fee estimator. Vectors generated by an independent Python
# oracle (tests/gen_mempool_policy_vectors.py -> tests/mempool_policy_vec.h).
POLICYOBJS := bitcoin_mempool.o bitcoin_utxo.o
tests/test_mempool_policy: tests/test_mempool_policy.c tests/mempool_policy_vec.h bitcoin_mempool_policy.c $(POLICYOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_mempool_policy.c bitcoin_mempool_policy.c $(POLICYOBJS)

# regenerate the policy vectors from the independent Python oracle
tests/mempool_policy_vec.h: tests/gen_mempool_policy_vectors.py
	cd tests && python3 gen_mempool_policy_vectors.py

TXIDOBJS := sha256.o bitcoin_hash.o bitcoin_tx.o
tests/test_txtxid: tests/test_txtxid.c $(TXIDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_txtxid.c $(TXIDOBJS)

# secp256k1 public-key parsing/decompression (affine-limb recovery for ecdsa_verify).
PUBKEYOBJS := bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o
tests/test_pubkey: tests/test_pubkey.c $(PUBKEYOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_pubkey.c $(PUBKEYOBJS)

# legacy SIGHASH_ALL preimage builder (tx signature digest).
SIGHASHOBJS := bitcoin_sighash.o sha256.o bitcoin_hash.o
tests/test_sighash: tests/test_sighash.c $(SIGHASHOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_sighash.c $(SIGHASHOBJS)

# script layer: DER sig parsing + full P2PKH verification.
SCRIPTOBJS := bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o secp256k1_ecdsa.o secp256k1_point.o bitcoin_hash.o sha256.o
tests/test_script: tests/test_script.c $(SCRIPTOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_script.c $(SCRIPTOBJS)

# end-to-end P2PKH spend validation (same object set).
tests/test_p2pkh: tests/test_p2pkh.c $(SCRIPTOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_p2pkh.c $(SCRIPTOBJS)

# UTXO set (unspent txout store for spend validation).
UTXOOBJS := bitcoin_utxo.o
tests/test_utxo: tests/test_utxo.c $(UTXOOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_utxo.c $(UTXOOBJS)

# Whole-transaction validator (test_txval.c): tx_parse + UTXO store +
# P2PKH spend verification (verify_p2pkh + its sighash/pubkey/ecdsa chain).
TXVALOBJS := bitcoin_utxo.o bitcoin_tx.o bitcoin_script.o bitcoin_sighash.o \
             bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o \
             secp256k1_ecdsa.o secp256k1_point.o bitcoin_hash.o sha256.o
tests/test_txval: tests/test_txval.c tests/txval_vec.h $(TXVALOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_txval.c $(TXVALOBJS)

# P2SH / multisig: p2sh_hash (RIPEMD160 of SHA256 of redeem script) +
# OP_CHECKMULTISIG verification over the existing sighash/pubkey/ecdsa chain.
MULTISIGOBJS := bitcoin_multisig.o bitcoin_script.o bitcoin_sighash.o \
                bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o \
                secp256k1_ecdsa.o secp256k1_point.o bitcoin_hash.o sha256.o ripemd160.o
tests/test_multisig: tests/test_multisig.c $(MULTISIGOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_multisig.c $(MULTISIGOBJS)

# Wallet CLI: generate key, show address, sign a P2PKH tx.
# asm/wallet_core.c glues the VERIFIED asm primitives (scalar_to_pubkey,
# hash160, base58check_encode, sighash_all, ecdsa_verify) plus the verified
# scalar/point/field ops (sc_*, point_scalar_mul, fe_*) used to construct
# ECDSA signatures.
WALLETPRIMS := secp256k1_fe.o secp256k1_point.o secp256k1_scalar.o secp256k1_ecdsa.o \
               bitcoin_keys.o bitcoin_addr.o bitcoin_pubkey.o bitcoin_sighash.o \
               bitcoin_hash.o sha256.o ripemd160.o
daemon/wallet_cli: daemon/wallet_cli.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ daemon/wallet_cli.c wallet_core.c $(WALLETPRIMS)

tests/test_wallet: tests/test_wallet.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ tests/test_wallet.c wallet_core.c $(WALLETPRIMS)


# bitcoin_p2p.asm inv parsers (incoming protocol codecs).
P2PINVOBS := bitcoin_p2p.o bitcoin_net.o bitcoin_hash.o sha256.o
tests/test_p2p_inv: tests/test_p2p_inv.c $(P2PINVOBS)
	$(CC) -no-pie -O0 -o $@ tests/test_p2p_inv.c $(P2PINVOBS)

# daemon/bitcoind -- the runnable core node driver (sync/ibd/follow/serve/
# server-test). This is a REAL target so the daemon never goes stale or suffers
# a missing-object link, unlike the old ad-hoc manual gcc command. -O0 required
# (an -O2 rebuild regressed lsock's bind to EFAULT).
DAEMONOBJS := sha256.o bitcoin_hash.o bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o \
              bitcoin_cons.o bitcoin_store.o bitcoind.o node_log.o \
              bitcoin_headers.o bitcoin_addrmgr.o bitcoin_idx.o bitcoin_serve.o \
              bitcoin_mempool.o
daemon/bitcoind: daemon/main.c $(DAEMONOBJS)
	$(CC) -no-pie -O0 -o $@ daemon/main.c $(DAEMONOBJS)

# pverify -- parallel block-chain verifier, machine-adaptive worker count.
# Built at -O1 (not -O2/-O3): the deep asm call chain (cons_verify -> tx_parse
# / sha256d) misparses a block when the C driver is compiled at aggressive -O2+,
# a documented codegen interaction. -O1 is safe; the speed comes from the
# parallel workers, not C-codegen.
daemon/pverify: daemon/pverify.c $(CONSOBJS)
	$(CC) -O1 -o $@ daemon/pverify.c $(CONSOBJS) -lpthread

# bitcoin_store.asm shared-append: concurrent-safe single-store write (standalone).
tests/test_shared: tests/test_shared.c bitcoin_store.o
	$(CC) -no-pie -O0 -o $@ tests/test_shared.c bitcoin_store.o
tests/test_shared2: tests/test_shared2.c bitcoin_store.o
	$(CC) -no-pie -O0 -o $@ tests/test_shared2.c bitcoin_store.o

test: tests/test_sha256 tests/test_sha512 tests/test_hmac tests/test_fe tests/test_point tests/test_addm tests/test_scalarmul tests/test_add tests/test_scalar tests/test_ecdsa tests/test_keys tests/test_bip32_master tests/test_bip32_chain tests/test_ripemd160 tests/test_addr tests/test_bech32 tests/test_mempool tests/test_mempool_policy tests/test_txtxid tests/test_block tests/test_tx tests/test_net tests/test_p2p tests/fakepeer_headers tests/test_store tests/test_cons tests/test_block_genesis tests/test_bitcoind tests/test_bitcoind_sync tests/test_log tests/test_cli tests/test_headers tests/test_ibd_headers tests/test_ibd_blocks tests/test_ibd_full tests/test_addrmgr tests/test_shared tests/test_shared2 tests/test_idx tests/test_serve tests/test_p2p_inv tests/test_pubkey tests/test_sighash tests/test_script tests/test_p2pkh tests/test_utxo tests/test_txval tests/test_multisig tests/test_wallet \
	./tests/test_sha256
	./tests/test_sha512
	./tests/test_hmac
	./tests/test_fe
	./tests/test_point
	./tests/test_addm
	./tests/test_scalarmul
	./tests/test_add
	./tests/test_scalar
	./tests/test_ecdsa
	./tests/test_keys
	./tests/test_bip32_master
	./tests/test_bip32_chain
	./tests/test_ripemd160
	./tests/test_addr
	./tests/test_bech32
	./tests/test_mempool
	./tests/test_mempool_policy
	./tests/test_txtxid
	./tests/test_pubkey
	./tests/test_sighash
	./tests/test_script
	./tests/test_p2pkh
	./tests/test_utxo
	./tests/test_wallet
	./tests/test_txval
	./tests/test_multisig
	./tests/test_block
	./tests/test_tx
	./tests/test_net
	./tests/test_p2p
	./tests/fakepeer_headers
	./tests/test_store
	./tests/test_cons
	./tests/test_block_genesis
	./tests/test_bitcoind
	./tests/test_bitcoind_sync
	./tests/test_log
	./tests/test_cli
	./tests/test_headers
	./tests/test_ibd_headers
	./tests/test_ibd_blocks
	./tests/test_ibd_full
	./tests/test_addrmgr
	./tests/test_shared
	./tests/test_shared2
	./tests/test_idx
	./tests/test_serve
	./tests/test_p2p_inv

clean:
	rm -f $(OBJS) bitcoind.o sha512.o bitcoin_hmac.o bitcoin_keys.o bitcoin_bip32.o ripemd160.o bitcoin_addr.o tests/test_pubkey tests/test_sighash tests/test_script tests/test_p2pkh tests/test_utxo tests/test_sha256 tests/test_sha512 tests/test_hmac tests/test_fe tests/test_point tests/test_addm tests/test_scalarmul tests/test_add tests/test_scalar tests/test_ecdsa tests/test_keys tests/test_bip32_master tests/test_bip32_chain tests/test_ripemd160 tests/test_addr tests/test_bech32 tests/test_mempool tests/test_txtxid tests/test_block tests/test_tx tests/test_net tests/test_p2p tests/fakepeer_headers tests/test_store tests/test_cons tests/test_block_genesis tests/test_bitcoind tests/test_bitcoind_sync tests/test_log tests/test_cli tests/test_headers tests/test_ibd_headers tests/test_ibd_blocks tests/test_ibd_full tests/test_addrmgr tests/test_shared tests/test_shared2 tests/test_idx tests/test_serve tests/test_p2p_inv tests/test_pubkey tests/test_sighash tests/test_script tests/test_p2pkh tests/test_utxo tests/test_txval tests/test_multisig tests/test_wallet daemon/wallet_cli
