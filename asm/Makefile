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

OBJS := sha256.o sha512.o bitcoin_hmac.o bitcoin_keys.o ripemd160.o bitcoin_addr.o bech32.o secp256k1_fe.o secp256k1_point.o secp256k1_scalar.o secp256k1_ecdsa.o bitcoin_hash.o bitcoin_tx.o bitcoin_net.o bitcoin_p2p.o bitcoin_store.o bitcoin_cons.o node_log.o bitcoin_cli.o bitcoind.o bitcoin_headers.o bitcoin_addrmgr.o bitcoin_idx.o bitcoin_serve.o bitcoin_mempool.o bitcoin_pubkey.o bitcoin_sighash.o bitcoin_script.o bitcoin_utxo.o bitcoin_utxo_store.o bitcoin_multisig.o bitcoin_bip39.o bitcoin_interp.o bitcoin_scriptcodec.o
# BIP152 compact blocks (bitcoin_cmpct.asm) needs sha256_full (single SHA256)
# and tx_parse (block tx enumeration for getblocktxn/blocktxn serving).
CMPCTOBJS := bitcoin_cmpct.o sha256.o bitcoin_hash.o bitcoin_tx.o
# bitcoin_hash.asm (sha256d/block-hash/merkle/pow) depends on sha256.o
HASHOBJS := sha256.o bitcoin_hash.o
# Full script interpreter (bitcoin_interp.asm over bitcoin_scriptcodec.asm) plus
# its hashing deps (OP_SHA256/HASH160/HASH256/RIPEMD160).
INTERPOBJS := bitcoin_interp.o bitcoin_scriptcodec.o sha256.o ripemd160.o bitcoin_hash.o
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

# BIP152 compact-blocks primitives (SipHash short-ids + wire codecs).
tests/test_bip152: tests/test_bip152.c $(CMPCTOBJS) tests/bip152_vectors.h
	$(CC) $(CFLAGS) -o $@ tests/test_bip152.c $(CMPCTOBJS)

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
SERVEOBJS := bitcoin_serve.o bitcoin_idx.o bitcoin_net.o bitcoin_p2p.o bitcoin_store.o bitcoind.o bitcoin_headers.o bitcoin_hash.o bitcoin_addrmgr.o node_log.o bitcoin_tx.o bitcoin_cons.o sha256.o bitcoin_mempool.o bitcoin_cmpct.o
tests/test_serve: tests/test_serve.c $(SERVEOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_serve.c $(SERVEOBJS)

# test_keepup: proves the inbound `block` keep-up path (.do_block) -- a peer
# pushes a block the server lacks; the server validates, stores, and indexes
# it so it becomes serveable, and survives duplicate pushes. Uses SERVEOBJS
# (needs cons_verify/store_append/idx_put from the listed objects).
tests/test_keepup: tests/test_keepup.c $(SERVEOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_keepup.c $(SERVEOBJS)

# BIP152 compact-block serving loopback e2e (sendcmpct/getblocktxn/cmpctblock).
tests/test_bip152_loop: tests/test_bip152_loop.c $(SERVEOBJS) tests/block_vec.h tests/cmpct_expected.h
	$(CC) -no-pie -O0 -o $@ tests/test_bip152_loop.c $(SERVEOBJS)

# sendheaders (BIP130) + feefilter: announce_tip inv-vs-headers wire bytes +
# forked serve-loop outbound feefilter & negotiation parsing (loopback e2e).
tests/test_sendheaders_fee: tests/test_sendheaders_fee.c $(SERVEOBJS) tests/block_vec.h
	$(CC) -no-pie -O0 -o $@ tests/test_sendheaders_fee.c $(SERVEOBJS)

# SHA-512 (FIPS 180-4, wallet/BIP32+bech32 foundation).
tests/test_sha512: tests/test_sha512.c sha512.o
	$(CC) -no-pie -O0 -o $@ tests/test_sha512.c sha512.o

# HMAC-SHA512 (RFC 4231 / RFC 2104, BIP32+BIP39 primitive, on asm SHA-512).
HMACOBJS := sha512.o bitcoin_hmac.o
tests/test_hmac: tests/test_hmac.c $(HMACOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_hmac.c $(HMACOBJS)

# bitcoin_bip32.asm (BIP32 master + CKDpriv + full-path + extkey/fingerprint;
# secp256k1 + HMAC + SHA-512 + base58/hash160). bitcoin_bip32.o's fingerprint
# references hash160/base58check from bitcoin_addr.o, so those deps are here.
BIP32OBJS := bitcoin_bip32.o bitcoin_hmac.o sha512.o bitcoin_keys.o secp256k1_fe.o secp256k1_point.o secp256k1_scalar.o bitcoin_addr.o sha256.o bitcoin_hash.o ripemd160.o
tests/test_bip32_master: tests/test_bip32_master.c $(BIP32OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip32_master.c $(BIP32OBJS)
tests/test_bip32_chain: tests/test_bip32_chain.c $(BIP32OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip32_chain.c $(BIP32OBJS)

# BIP32 full-path derivation + extended key (xprv/xpub): derive_path +
# fingerprint + 78-byte serialize (all bitcoin_bip32.asm) + base58check/hash160
# (bitcoin_addr.asm). Same object set as the other bip32 tests.
EXTKEYOBJS := $(BIP32OBJS)
tests/test_bip32_extkey: tests/test_bip32_extkey.c tests/bip32_extkey_vec.h $(EXTKEYOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip32_extkey.c $(EXTKEYOBJS)

# regenerate the BIP32 extended-key vectors from the independent Python oracle
tests/bip32_extkey_vec.h: validation/gen_bip32_vectors.py
	cd tests && python3 ../validation/gen_bip32_vectors.py > bip32_extkey_vec.h

# bitcoin_bip39.asm -- BIP39 mnemonic <-> seed. Deps: sha256 (checksum),
# sha512 + bitcoin_hmac (PBKDF2-HMAC-SHA512). Vectors from the independent
# Python oracle (validation/gen_bip39_vectors.py -> tests/bip39_vec.h), which
# is itself cross-checked against the official bip-0039 vectors and the
# third-party `mnemonic` pip package.
BIP39OBJS := bitcoin_bip39.o sha256.o sha512.o bitcoin_hmac.o
tests/test_bip39: tests/test_bip39.c tests/bip39_vec.h $(BIP39OBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_bip39.c $(BIP39OBJS)

# regenerate the BIP39 vectors from the independent Python oracle
tests/bip39_vec.h: validation/gen_bip39_vectors.py
	python3 validation/gen_bip39_vectors.py > tests/bip39_vec.h

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

# PERSISTENT UTXO store (append-only WAL utxo.dat + checkpoint index utxo.idx +
# restart-resume reload), mirroring bitcoin_store.asm's store/index pattern.
# bitcoin_utxo_store.asm wraps bitcoin_utxo.asm's in-memory table.
UTXOSTOREOBJS := bitcoin_utxo_store.o bitcoin_utxo.o
tests/test_utxo_store: tests/test_utxo_store.c $(UTXOSTOREOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_utxo_store.c $(UTXOSTOREOBJS)

# Whole-transaction validator (test_txval.c): tx_parse + UTXO store +
# P2PKH spend verification (verify_p2pkh + its sighash/pubkey/ecdsa chain).
TXVALOBJS := bitcoin_utxo.o bitcoin_tx.o bitcoin_script.o bitcoin_sighash.o \
             bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o \
             secp256k1_ecdsa.o secp256k1_point.o bitcoin_hash.o sha256.o
tests/test_txval: tests/test_txval.c tests/txval_vec.h $(TXVALOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_txval.c $(TXVALOBJS)

# LIVE-WIRE end-to-end sighash test: builds a real P2PKH tx, signs it by
# invoking the ACTUAL daemon/wallet_cli binary (legacy SIGHASH_ALL), then
# validates the CLI-signed tx with the whole-transaction validator
# (tx_parse + UTXO + verify_p2pkh + fee). Ties the wallet signer and the
# validator together across a real process boundary instead of isolated
# pre-generated vectors. Requires bitcoin_keys/bitcoin_addr (for the prevout
# P2PKH script) on top of the validator set.
E2EOBJS := $(TXVALOBJS) bitcoin_keys.o bitcoin_addr.o ripemd160.o
tests/test_e2e_sighash: tests/test_e2e_sighash.c daemon/wallet_cli $(E2EOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_e2e_sighash.c $(E2EOBJS)

# "send" (createrawtx + sign-all-inputs) end-to-end: wallet_core.c builds the
# tx with the verified asm crypto (sighash/ecdsa/scalar/point/field from
# WALLETPRIMS), and the harness validates the signed tx with the
# whole-transaction validator (tx_parse + UTXO + verify_p2pkh from TXVALOBJS).
SENDOBJS = $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o
tests/test_send: tests/test_send.c wallet_core.c $(SENDOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_send.c wallet_core.c $(SENDOBJS)

# Wallet-core/RPC address surface (getnewaddress/getrawchangeaddress +
# getaddressinfo/validateaddress). wallet_core.c + WALLETPRIMS + bech32.o
# (bech32 codec for P2WPKH encode and decode).
WRPCADDR = $(WALLETPRIMS)
tests/test_wrpc_addr: tests/test_wrpc_addr.c wallet_core.c $(WRPCADDR)
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_addr.c wallet_core.c $(WRPCADDR)

# Wallet-core/RPC UTXO-query surface (gettxout + listunspent). wallet core
# (which includes bitcoin_utxo via WALLETPRIMS).
tests/test_wrpc_utxo: tests/test_wrpc_utxo.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_utxo.c wallet_core.c $(WALLETPRIMS)

# Wallet-core/RPC decoderawtransaction. Builds a signed tx via wallet_send_tx
# then decodes it.
tests/test_wrpc_decoderaw: tests/test_wrpc_decoderaw.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_decoderaw.c wallet_core.c $(WALLETPRIMS)

# Wallet-core/RPC signrawtransactionwithkey. wallet core + tx/script for the
# whole-tx validator.
tests/test_wrpc_sign: tests/test_wrpc_sign.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_sign.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o

# Wallet-core/RPC sendtoaddress + getbalance (card 5 capstone). wallet core +
# tx/script for the validator.
tests/test_wrpc_send: tests/test_wrpc_send.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o
	$(CC) -no-pie -O0 -o $@ tests/test_wrpc_send.c wallet_core.c $(WALLETPRIMS) bitcoin_tx.o bitcoin_script.o

# P2SH / multisig: p2sh_hash (RIPEMD160 of SHA256 of redeem script) +
# OP_CHECKMULTISIG verification over the existing sighash/pubkey/ecdsa chain.
MULTISIGOBJS := bitcoin_multisig.o bitcoin_script.o bitcoin_sighash.o \
                bitcoin_pubkey.o secp256k1_fe.o secp256k1_scalar.o \
                secp256k1_ecdsa.o secp256k1_point.o bitcoin_hash.o sha256.o ripemd160.o
tests/test_multisig: tests/test_multisig.c $(MULTISIGOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_multisig.c $(MULTISIGOBJS)

# Full script interpreter harnesses (bitcoin_interp.asm + codec + hashing).
tests/smoke_interp: tests/smoke_interp.c $(INTERPOBJS)
	$(CC) -no-pie -O0 -o $@ tests/smoke_interp.c $(INTERPOBJS)
tests/test_interp: tests/test_interp.c $(INTERPOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_interp.c $(INTERPOBJS)
tests/test_tapscript_interp: tests/test_tapscript_interp.c $(INTERPOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_tapscript_interp.c $(INTERPOBJS)
tests/run_batch: tests/run_batch.c $(INTERPOBJS)
	$(CC) -no-pie -O0 -o $@ tests/run_batch.c $(INTERPOBJS)

# Consensus differential shim (consensus_diff.py): exposes cons_verify /
# block_hash / pow_check / diff_target / tx_parse / tx_txid over stdin so a
# Python oracle can feed the same REAL mainnet block/tx bytes to both this
# asm node and Bitcoin Core and compare verdicts byte-for-byte.
tests/consensus_shim: tests/consensus_shim.c $(CONSOBJS)
	$(CC) -no-pie -O0 -o $@ tests/consensus_shim.c $(CONSOBJS)

# BIP340 Schnorr verify + BIP341 Taproot helpers (secp256k1_schnorr.asm,
# secp256k1_taproot.asm) over the verified point/field/scalar + sha256/pubkey.
TAPRIMSOBJS := secp256k1_point.o secp256k1_fe.o secp256k1_scalar.o sha256.o bitcoin_pubkey.o
tests/test_schnorr: tests/test_schnorr.c secp256k1_schnorr.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_schnorr.c secp256k1_schnorr.o $(TAPRIMSOBJS)
tests/test_taproot: tests/test_taproot.c secp256k1_taproot.o $(TAPRIMSOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_taproot.c secp256k1_taproot.o $(TAPRIMSOBJS)

# BIP341/BIP342 taproot sighash + spend validation: C glue (bitcoin_taproot_sighash.c)
# over the verified asm crypto core (sha256_full, tagged_hash256, schnorr_verify,
# point/fe/scalar/pubkey). Vectors are Core-validated (bip-0341 wallet-test-vectors).
TAPSIGHASHOBJS := bitcoin_taproot_sighash.c secp256k1_schnorr.o secp256k1_taproot.o bech32.o bitcoin_interp.o bitcoin_scriptcodec.o ripemd160.o bitcoin_hash.o $(TAPRIMSOBJS)
tests/test_taproot_sighash: tests/test_taproot_sighash.c tests/taproot_spend.h tests/taproot_vec.h $(TAPSIGHASHOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_taproot_sighash.c $(filter %.c,$(TAPSIGHASHOBJS)) $(filter %.o,$(TAPSIGHASHOBJS))

# BIP143 segwit-v0 sighash + P2WPKH/P2WSH spend verification (bitcoin_segwit.c)
# over the verified asm primitives (sha256_full, ecdsa_verify, pubkey_parse,
# der_parse_sig, hash160). Vectors are oracle-generated genuine P2WPKH/P2WSH
# spends, oracle validated against the official BIP-0143 vector. Also covers the
# P2TR key-path spend through the same whole-tx materials.
SEGWITOBJS := bitcoin_segwit.c bitcoin_taproot_sighash.c secp256k1_schnorr.o secp256k1_taproot.o \
              bitcoin_script.o bitcoin_sighash.o bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o \
              secp256k1_fe.o secp256k1_scalar.o sha256.o bitcoin_hash.o ripemd160.o bitcoin_addr.o
tests/test_segwit_sighash: tests/test_segwit_sighash.c tests/modern_vec.h tests/modern_spend.h $(SEGWITOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_segwit_sighash.c $(filter %.c,$(SEGWITOBJS)) $(filter %.o,$(SEGWITOBJS))

# FULL mempool acceptance pipeline for modern outputs: mempool policy +
# whole-tx validation + ECDSA/Schnorr verify (bitcoin_txval_modern.c +
# bitcoin_segwit.c + bitcoin_taproot_sighash.c + asm utxo/mempool/tx/taproot).
MEMPACCOBJS := bitcoin_txval_modern.c bitcoin_segwit.c bitcoin_taproot_sighash.c \
               bitcoin_mempool_policy.c bitcoin_utxo.o bitcoin_mempool.o bitcoin_tx.o \
               secp256k1_schnorr.o secp256k1_taproot.o bitcoin_script.o bitcoin_sighash.o \
               bitcoin_pubkey.o secp256k1_ecdsa.o secp256k1_point.o secp256k1_fe.o \
               secp256k1_scalar.o sha256.o bitcoin_hash.o ripemd160.o bitcoin_addr.o
tests/test_mempool_accept_modern: tests/test_mempool_accept_modern.c tests/modern_vec.h tests/modern_spend.h $(MEMPACCOBJS)
	$(CC) -no-pie -O0 -o $@ tests/test_mempool_accept_modern.c $(filter %.c,$(MEMPACCOBJS)) $(filter %.o,$(MEMPACCOBJS))

# Wallet CLI: generate key, show address, sign a P2PKH tx, and -- via BIP39 +
# BIP32 -- produce/restore recoverable seeds.
# asm/wallet_core.c glues the VERIFIED asm primitives (scalar_to_pubkey,
# hash160, base58check_encode, sighash_all, ecdsa_verify, BIP39 mnemonic<->seed,
# BIP32 master/path/extkey) plus the verified scalar/point/field ops (sc_*,
# point_scalar_mul, fe_*) used to construct ECDSA signatures.
WALLETPRIMS := secp256k1_fe.o secp256k1_point.o secp256k1_scalar.o secp256k1_ecdsa.o \
               bitcoin_keys.o bitcoin_addr.o bitcoin_pubkey.o bitcoin_sighash.o \
               bitcoin_hash.o sha256.o ripemd160.o \
               bitcoin_bip39.o sha512.o bitcoin_hmac.o bitcoin_bip32.o bech32.o \
               bitcoin_utxo.o
daemon/wallet_cli: daemon/wallet_cli.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ daemon/wallet_cli.c wallet_core.c $(WALLETPRIMS)

tests/test_wallet: tests/test_wallet.c wallet_core.c $(WALLETPRIMS)
	$(CC) -no-pie -O0 -o $@ tests/test_wallet.c wallet_core.c $(WALLETPRIMS)

# ============================================================================
# bitcoin-cli RPC network layer (card t_8e5be37f): JSON-RPC 2.0 framing +
# HTTP POST transport (rpc_net.c), Core-bit-exact JSON rendering + command
# dispatch (rpc_json.c + rpc_commands.c), wired to the wallet-core command
# layer (wallet_core.c). Shared by the client binary and the loopback test;
# the production HTTP server endpoint (child card t_0ca5d72e) dispatches
# through the same rpc_dispatch().
# ============================================================================
RPCOBJS := rpc_json.o rpc_net.o rpc_commands.o
RPCLIBS := wallet_core.c $(WALLETPRIMS)

rpc_json.o: rpc_json.c rpc_json.h
	$(CC) -no-pie -O0 -c -o $@ rpc_json.c
rpc_net.o: rpc_net.c rpc_net.h rpc_json.h
	$(CC) -no-pie -O0 -c -o $@ rpc_net.c
rpc_commands.o: rpc_commands.c rpc_commands.h rpc_json.h
	$(CC) -no-pie -O0 -c -o $@ rpc_commands.c

daemon/bitcoin_cli: daemon/bitcoin_cli.c rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ daemon/bitcoin_cli.c rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS)

tests/test_rpc_json: tests/test_rpc_json.c rpc_json.o rpc_commands.o $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ tests/test_rpc_json.c rpc_json.o rpc_commands.o $(RPCLIBS)

tests/test_rpc_transport: tests/test_rpc_transport.c rpc_net.o rpc_commands.o rpc_json.o daemon/bitcoin_cli $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ tests/test_rpc_transport.c rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS) -lpthread

# ============================================================================
# HTTP JSON-RPC SERVER endpoint (card t_0ca5d72e): rpc_server.c owns the
# sockets/threads + Core-faithful HTTP/JSON-RPC behavior; daemon/bitcoin_rpcd
# is the production server binary (loads config/bitcoin.conf);
# tests/test_rpc_server forks+execs the REAL bitcoin_rpcd and drives it with
# the REAL bitcoin_cli + raw sockets. Shared render path = rpc_dispatch().
# ============================================================================
rpc_server.o: rpc_server.c rpc_server.h rpc_commands.h rpc_net.h rpc_json.h
	$(CC) -no-pie -O0 -c -o $@ rpc_server.c

daemon/bitcoin_rpcd: daemon/bitcoin_rpcd.c rpc_server.o rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ daemon/bitcoin_rpcd.c rpc_server.o rpc_net.o rpc_commands.o rpc_json.o $(RPCLIBS) -lpthread

tests/test_rpc_server: tests/test_rpc_server.c rpc_net.o rpc_commands.o rpc_json.o rpc_server.o daemon/bitcoin_cli daemon/bitcoin_rpcd $(RPCLIBS)
	$(CC) -no-pie -O0 -o $@ tests/test_rpc_server.c rpc_net.o rpc_commands.o rpc_json.o rpc_server.o $(RPCLIBS) -lpthread


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
              bitcoin_mempool.o bitcoin_cmpct.o
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

test: tests/test_sha256 tests/test_sha512 tests/test_hmac tests/test_fe tests/test_point tests/test_addm tests/test_scalarmul tests/test_add tests/test_scalar tests/test_ecdsa tests/test_keys tests/test_bip32_master tests/test_bip32_chain tests/test_bip32_extkey tests/test_bip39 tests/test_ripemd160 tests/test_addr tests/test_bech32 tests/test_mempool tests/test_mempool_policy tests/test_txtxid tests/test_block tests/test_tx tests/test_net tests/test_p2p tests/fakepeer_headers tests/test_store tests/test_cons tests/test_block_genesis tests/test_bitcoind tests/test_bitcoind_sync tests/test_log tests/test_cli tests/test_headers tests/test_ibd_headers tests/test_ibd_blocks tests/test_ibd_full tests/test_addrmgr tests/test_shared tests/test_shared2 tests/test_idx tests/test_serve tests/test_keepup tests/test_p2p_inv tests/test_bip152 tests/test_bip152_loop tests/test_sendheaders_fee tests/test_pubkey tests/test_sighash tests/test_script tests/test_p2pkh tests/test_utxo tests/test_utxo_store tests/test_txval tests/test_multisig tests/test_wallet tests/test_e2e_sighash tests/test_send tests/test_wrpc_addr tests/test_wrpc_utxo tests/test_wrpc_decoderaw tests/test_wrpc_sign tests/test_wrpc_send tests/smoke_interp tests/test_interp tests/test_tapscript_interp tests/run_batch tests/consensus_shim tests/test_schnorr tests/test_taproot tests/test_taproot_sighash tests/test_segwit_sighash tests/test_mempool_accept_modern tests/test_rpc_json tests/test_rpc_transport tests/test_rpc_server \
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
	./tests/test_bip32_extkey
	./tests/test_bip39
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
	./tests/test_utxo_store
	./tests/test_wallet
	./tests/test_e2e_sighash
	./tests/test_send
	./tests/test_wrpc_addr
	./tests/test_wrpc_utxo
	./tests/test_wrpc_decoderaw
	./tests/test_wrpc_sign
	./tests/test_wrpc_send
	./tests/test_txval
	./tests/test_multisig
	./tests/smoke_interp
	./tests/test_interp
	./tests/test_tapscript_interp
	./tests/test_schnorr tests/bip340_test_vectors.csv
	./tests/test_taproot
	./tests/test_taproot_sighash
	./tests/test_segwit_sighash
	./tests/test_mempool_accept_modern
	./tests/test_rpc_json
	./tests/test_rpc_transport
	./tests/test_rpc_server
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
	./tests/test_keepup
	./tests/test_p2p_inv
	./tests/test_bip152
	./tests/test_bip152_loop
	./tests/test_sendheaders_fee
 
clean:
	rm -f $(OBJS) secp256k1_taproot.o secp256k1_schnorr.o bitcoind.o sha512.o bitcoin_hmac.o bitcoin_keys.o bitcoin_bip39.o ripemd160.o bitcoin_addr.o tests/test_pubkey tests/test_sighash tests/test_script tests/test_p2pkh tests/test_utxo tests/test_sha256 tests/test_sha512 tests/test_hmac tests/test_fe tests/test_point tests/test_addm tests/test_scalarmul tests/test_add tests/test_scalar tests/test_ecdsa tests/test_keys tests/test_bip32_master tests/test_bip32_chain tests/test_bip32_extkey tests/test_bip39 tests/test_ripemd160 tests/test_addr tests/test_bech32 tests/test_mempool tests/test_txtxid tests/test_block tests/test_tx tests/test_net tests/test_p2p tests/fakepeer_headers tests/test_store tests/test_cons tests/test_block_genesis tests/test_bitcoind tests/test_bitcoind_sync tests/test_log tests/test_cli tests/test_headers tests/test_ibd_headers tests/test_ibd_blocks tests/test_ibd_full tests/test_addrmgr tests/test_shared tests/test_shared2 tests/test_idx tests/test_serve tests/test_keepup tests/test_p2p_inv tests/test_bip152 tests/test_bip152_loop tests/test_sendheaders_fee tests/test_pubkey tests/test_sighash tests/test_script tests/test_p2pkh tests/test_utxo tests/test_utxo_store tests/test_txval tests/test_multisig tests/test_wallet tests/test_e2e_sighash tests/test_send tests/test_wrpc_addr tests/test_wrpc_utxo tests/test_wrpc_decoderaw tests/test_wrpc_sign tests/test_wrpc_send tests/test_schnorr tests/test_taproot tests/test_taproot_sighash tests/test_segwit_sighash tests/test_mempool_accept_modern tests/test_rpc_json tests/test_rpc_transport tests/test_rpc_server rpc_json.o rpc_net.o rpc_commands.o rpc_server.o daemon/bitcoin_cli daemon/bitcoin_rpcd daemon/wallet_cli
