# Bitcoin Machine Code — Kanban

Project board (plain text columns). Update after each task lands.
Status legend: [ ] todo · [~] in-progress · [x] done · [!] blocked

## Validation / Wallet bridge (current sprint)
| Status | Task |
|--------|------|
| [x] | secp256k1 field + scalar + curve arith (fe/point/scalar) verified |
| [x] | ecdsa_verify (standalone) verified |
| [x] | pubkey_parse: comp/uncomp aff coords + fe_pow sqrt (bitcoin_pubkey.asm) |
| [x] | legacy SIGHASH_ALL preimage builder (bitcoin_sighash.asm)            |
| [x] | der_parse_sig + be_to_limbs (bitcoin_script.asm, toward P2PKH)        |
| [ ] | verify_p2pkh: full signature check (sighash+der+pubkey+ecdsa)         |

## Node (complete)
| Status | Task |
|--------|------|
| [x] | headers-first IBD + parallel block download + consensus verify |
| [x] | getdata/getheaders/getblocks/inv serving |
| [x] | mempool + tx relay (MSG_TX) |
| [x] | multi-peer (fork per conn) |
| [x] | inv keep-up + inv-announce + reorg/chain-link guard |

## Wallet primitives (complete)
| Status | Task |
|--------|------|
| [x] | sha256/sha512/hmac-sha512, RIPEMD-160 |
| [x] | secp256k1 ecdsa sign+verify, scalar_to_pubkey |
| [x] | BIP32 master+CKDpriv, known-vector verified |
| [x] | hash160 + base58check P2PKH addresses |
| [x] | pubkey decompression (this sprint) |

## Backlog / later
- [ ] P2SH / multisig (OP_CHECKMULTISIG) script + hash
- [ ] bech32/bech32m (BIP173/350) address codec
- [ ] sighash_all flow tied to a real spend
- [ ] wallet CLI: generate key, show address, sign a tx
