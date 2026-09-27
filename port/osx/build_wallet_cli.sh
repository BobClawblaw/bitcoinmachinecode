#!/bin/bash
# bmc_wallet_cli for the osx port -- mirrors asm/Makefile's
# daemon/bmc_wallet_cli rule (wallet_cli + wallet_core + store + crypter +
# book/txlog/msgsign + WALLETPRIMS + bitcoin_script), with the osx twins
# in place of the x86 asm objects.
set -u
cd "$(dirname "$0")/../../asm"
OUT=../port/osx/daemon_out
mkdir -p "$OUT"
CC="cc -O2 -arch arm64 -I. -Idaemon -I../port/osx/compat -D_DARWIN_C_SOURCE -Dst_mtim=st_mtimespec"
$CC -o "$OUT/bmc_wallet_cli" \
    daemon/wallet_cli.c wallet_core.c wallet_store.c daemon/wallet_crypter.c \
    bitcoin_aes.c wallet_book.c wallet_txlog.c wallet_msgsign.c \
    ../port/osx/bitcoin_script.S \
    ../port/osx/secp256k1_fe.S ../port/osx/secp256k1_point.S ../port/osx/secp256k1_point_ct.S \
    ../port/osx/secp256k1_ecdsa.S ../port/osx/bitcoin_pubkey.S ../port/osx/secp256k1_schnorr.S \
    ../port/osx/secp256k1_scalar.S \
    secp256k1_scalar_c.c secp256k1_glv_c.c ../port/osx/g_comb_table_data.c \
    ../port/osx/bitcoin_sighash.S \
    ../port/osx/bitcoin_hash.S ../port/osx/sha256.S ../port/osx/ripemd160.S \
    ../port/osx/bitcoin_bip39.S ../port/osx/sha512.S ../port/osx/bitcoin_hmac.S \
    ../port/osx/bitcoin_bip32.S ../port/osx/bitcoin_keys.S ../port/osx/bitcoin_addr.S \
    ../port/osx/bech32.S ../port/osx/bitcoin_utxo.S \
    ../port/osx/darwin_stubs.c ../port/osx/bmcshim.c -lpthread
