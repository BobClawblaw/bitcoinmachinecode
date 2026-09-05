# The mined-transaction corpus

Seventeen real transactions taken from the main chain, each replayed
against the script flags of *its own block*. The full-archive replay,
reduced to a test that runs in milliseconds.

17 transactions, 26 KB of vectors, 8,695 bytes of transaction across 32
resolved inputs, heights 170 through 850,000. 17/17 accepted, 68 checks,
0 failures.

Every transaction here was mined into the main chain, so each is
consensus-valid under the flags active at its own height. That is the
entire claim, and it is deliberately a narrow one. The transactions were
chosen because they broke someone's assumption, not because they are
common: a thousand ordinary P2PKH spends would test less than any one of
the odd ones below.

## Scope

This asserts **consensus** acceptance only. It does not assert mempool
standardness. Several of these are consensus-valid and non-standard today
— bare multisig, uncompressed keys, high-S signatures — and Core cannot be
asked for a policy verdict on a transaction whose inputs are long spent.
Conflating the two would produce a confident wrong answer, so policy is
tested separately.

## The transactions

Height is load-bearing, not decoration. DERSIG activates at 363,725, CLTV
at 388,381, CSV at 419,328, segwit at 481,824, taproot at 709,632; P2SH
took effect at 173,805. A transaction from 2011 must be judged by 2011's
rules, and two of these are rejected outright under today's. Each vector
therefore carries its own height.

"Spends" is the script type of the *inputs* — what the verifier actually
had to execute. It is not always what the transaction is famous for, and
that distinction turned out to matter (see below).

| Height | Transaction | Spends | What makes it unique |
|---|---|---|---|
| 170 | [`f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16`](https://mempool.space/tx/f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16) | P2PK | **First P2PK spend in history.** Satoshi to Hal Finney. A bare public key in the output, no hash. The oldest spend the chain has. |
| 728 | [`6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516`](https://mempool.space/tx/6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516) | P2PKx2 | **Creates the P2PKH shape.** Spends two bare P2PK outputs. The novelty is in the output, not the input — on the spend side this is P2PK. |
| 124,276 | [`fb0a1d8d34fa5537e461ac384bac761125e1bfa7fec286fa72511240fa66864d`](https://mempool.space/tx/fb0a1d8d34fa5537e461ac384bac761125e1bfa7fec286fa72511240fa66864d) | P2PKH | **Non-minimal DER: 34-byte r AND s.** Two leading zero pad bytes on each of r and s. A parser that strips only one rejects this real, mined transaction. The case the 2026-08-19 signature fix exists for. |
| 163,685 | [`eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb`](https://mempool.space/tx/eb3b82c0884e3efa6d8b0be55b4915eb20be124c9766245bcc7f34fdac32bccb) | P2PKH+NOP-script | **Anyone-can-spend NOP script.** Creates a bare multisig output; its second input spends PUSH20 <data> OP_NOP2 OP_DROP — valid because OP_NOP2 was still a NOP here. CLTV only claimed that opcode at 388,381. |
| 164,467 | [`60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1`](https://mempool.space/tx/60a20bd93aa49ab4b28d514ec10b06e1829ce6818ec06cd3aabd013ebcdc4bb1) | P2PKHx3 | **FindAndDelete.** A signature that appears inside its own scriptCode and must be removed before hashing. Three P2PKH inputs, 759 bytes. |
| 170,052 | [`9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6`](https://mempool.space/tx/9c08a4d78931342b37fd5f72900fb9983087e6f46c4a097d8a1f52c74e28eaf6) | P2PK | **Creates an early P2SH output.** It cannot be a P2SH spend: BIP16 activated at 173,805, after this block. It spends P2PK. |
| 247,939 | [`315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f`](https://mempool.space/tx/315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f) | P2PKHx2 | **The SIGHASH_SINGLE bug.** Input index ≥ output count, so the sighash is the literal value 1. Mined, and must still validate forever. |
| 481,824 | [`461e8a4aa0a0e75c06602c505bd7aa06e7116ba5cd98fd6e046e8cbeb00379d6`](https://mempool.space/tx/461e8a4aa0a0e75c06602c505bd7aa06e7116ba5cd98fd6e046e8cbeb00379d6) | P2PKHx2 | **Creates a P2WSH output.** In the segwit activation block. Spends two P2PKH inputs — no witness of its own. |
| 481,824 | [`8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1c`](https://mempool.space/tx/8f907925d2ebe48765103e6845c06f1f2bb77c6adc1cc002865865eb5cfd5c1c) | P2SH | **P2SH-wrapped P2WPKH.** scriptSig AND witness both populated, the only shape where both are non-empty. |
| 481,824 | [`dfcec48bb8491856c353306ab5febeb7e99e4d783eedf3de98f3ee0812b92bad`](https://mempool.space/tx/dfcec48bb8491856c353306ab5febeb7e99e4d783eedf3de98f3ee0812b92bad) | P2SH | **The first segwit spend in history.** In the activation block itself. |
| 481,824 | [`f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd`](https://mempool.space/tx/f91d0a8a78462bc59398f2c5d7a84fcff491c26ba54c4833478b202796c8aafd) | P2WPKH | **Native P2WPKH spend.** Activation block. |
| 550,000 | [`73965c0ab96fa518f47df4f3e7201e0a36f163c4857fc28150d277caa8589259`](https://mempool.space/tx/73965c0ab96fa518f47df4f3e7201e0a36f163c4857fc28150d277caa8589259) | P2WSH | **Native P2WSH multisig.** Four witness items. |
| 550,000 | [`9cf007aa4ed2216c6ca42ba593558cb6ce4df9c5417677d7ca96a7b2be6d807b`](https://mempool.space/tx/9cf007aa4ed2216c6ca42ba593558cb6ce4df9c5417677d7ca96a7b2be6d807b) | P2SH | **P2SH-wrapped P2WSH.** Four witness items, redeemed through the P2SH wrapper. |
| 550,000 | [`bdcb08cd977e229482f295345893405882a08132f1675beb844de8548007915f`](https://mempool.space/tx/bdcb08cd977e229482f295345893405882a08132f1675beb844de8548007915f) | P2PKH | **Creates a bare multisig output.** Consensus-valid, non-standard to relay today. Spends P2PKH. |
| 750,000 | [`4c9fe4ad5923fd41074da3f92da6359cbafbd96ecbb758481d6c1f106242703e`](https://mempool.space/tx/4c9fe4ad5923fd41074da3f92da6359cbafbd96ecbb758481d6c1f106242703e) | P2TR | **Taproot key-path (BIP341).** A single witness item. The cheapest spend the chain allows. |
| 800,000 | [`965f866bf8623bbf956c1b2aeec1efc1ad162fd428ab7fb89f128a0754ebbc32`](https://mempool.space/tx/965f866bf8623bbf956c1b2aeec1efc1ad162fd428ab7fb89f128a0754ebbc32) | P2TR | **Taproot script-path (BIP342).** With a real 33-byte control block. |
| 850,000 | [`b10c0000004da5a9d1d9b4ae32e09f0b3e62d21a5cce5428d4ad714fb444eb5d`](https://mempool.space/tx/b10c0000004da5a9d1d9b4ae32e09f0b3e62d21a5cce5428d4ad714fb444eb5d) | P2PK+P2PKH+P2MS+P2SHx3+P2WPKH+P2WSH+P2TRx2 | **Seven script types in one transaction.** 10 inputs spending P2PK, P2PKH, bare multisig, P2SH×3, P2WPKH, P2WSH and P2TR×2; 9 outputs covering nine types including the P2A anchor and nulldata. The widest vector in the corpus — and the only one that spends bare multisig. |

Every txid above is real and on the main chain and links to
mempool.space; each can equally be looked up with
`getrawtransaction <txid>` against any archival node.

## What the corpus actually covers

Counting by the script type each vector *spends*:

| Spend type | Vectors exercising it |
|---|---|
| P2PKH | 7 |
| P2PK | 4 |
| P2SH | 4 |
| P2TR | 3 |
| P2WPKH | 2 |
| P2WSH | 2 |
| bare multisig (P2MS) | **1** |
| `OP_NOP2 OP_DROP` anyone-can-spend | 1 |

Two things follow, and neither was visible before the txids were laid out
this way:

**Four vectors are output-shape only.** `6f7cf958`, `9c08a4d7`,
`bdcb08cd` and `461e8a4a` are named for a type that appears in their
*outputs*; on the input side they spend ordinary P2PK or P2PKH. They
assert that a transaction creating that output is accepted — they do not
exercise redemption of it.

**Bare multisig redemption rests on a single vector.** Two vectors are
named "bare multisig" and neither spends one; the only P2MS input in the
whole corpus is one of the ten in `b10c0000…`. Drop that transaction and
P2MS verification loses all coverage while the corpus still appears to
have two vectors for it.

`b10c0000…` is the most valuable transaction here by a wide margin: ten
inputs across seven script types, nine outputs across nine, spanning
every consensus era from bare P2PK to the P2A anchor in one 3,500-byte
transaction.

## Labels that were wrong

Three vectors carried descriptions that did not survive checking the
prevouts, and are corrected in the generator:

| Vector | Said | Actually |
|---|---|---|
| `9c08a4d7` (170,052) | "an early pay-to-script-hash spend" | spends **P2PK**. It cannot be a P2SH spend — BIP16 activated at 173,805, *after* this block. It creates a P2SH output |
| `6f7cf958` (728) | "early P2PKH" | spends two bare **P2PK** outputs; P2PKH is the output shape |
| `eb3b82c0` (163,685) | "h=170060-ish" | is at **163,685**, and its second input is an anyone-can-spend `PUSH20 <data> OP_NOP2 OP_DROP` |

These were descriptive strings, not assertions, so no test was passing on
a false premise — but the report built on them, and a reader would have
concluded P2SH redemption was covered from block 170,052 when it is not.

## One wanted transaction is not in the corpus

[`da917699942e4a96272401b534381a75512eeebe8403084500bd637bd47168b3`](https://mempool.space/tx/da917699942e4a96272401b534381a75512eeebe8403084500bd637bd47168b3)
(h=481,824, an OP_RETURN nulldata output) is in the generator's `WANTED`
list but skipped: its prevouts are unresolvable from the oracle. The list
asks for 18; 17 ship. Nulldata output creation is still covered
incidentally, as one of the nine outputs of `b10c0000…`.

## The controls

A corpus that accepts everything is indistinguishable from a verifier that
accepts everything. Both controls below revert something real and confirm
the corpus notices.

| Control | Result |
|---|---|
| **wrong height** — verify every transaction at h=900,000 instead of its own | 2 of 17 rejected. Both are pre-BIP66, refused under modern DERSIG with `legacy script verification failed`. Height is not decoration |
| **DER regression** — remove the leading-zero tolerance from the signature parser | 8 of 17 rejected, spanning P2WPKH, P2WSH *and* legacy paths. The corpus reaches all three verifier arms, not just one |

### The first version of this corpus was too weak, and the control proved it

Before the 124,276 vector existed, the DER control rejected **nothing**:
all sixteen transactions still passed with the tolerance narrowed. The
corpus looked thorough and covered that fix not at all.

The tree's own comment named a real mined transaction with a 34-byte `r`
and `s`. Finding it (`fb0a1d8d…`, height 124,276) and adding it is what
gave the corpus its second set of teeth. Without running the control, a
corpus that tested nothing of the sort would have shipped.

### One control was itself faulty

The first attempt at the DER control narrowed the strip bound from 32 to
33 and was described as reverting the pre-2026-08-19 behaviour. It is not:
stripping to 33 bytes still works downstream, so it rejected nothing.

The honest reading is that **that specific off-by-one remains uncovered**.
What the corpus does catch is the wholesale loss of leading-zero
tolerance. A gap named is worth more than a gap implied.

## How it runs

| | |
|---|---|
| [`../../validation/gen_txaccept_vectors.py`](../../validation/gen_txaccept_vectors.py) | pulls each transaction and its spent prevouts from the oracle (txindex, 965,629 blocks) and freezes them with the height they were mined at |
| [`../../asm/tests/txaccept_vec.h`](../../asm/tests/txaccept_vec.h) | the 17 vectors, 25 KB |
| [`../../asm/tests/test_txaccept_corpus.c`](../../asm/tests/test_txaccept_corpus.c) | gated; asserts each transaction verifies at its own height, and that every input was resolved |

One supporting addition was needed. `tx_verify_at_height()` is the
consensus verifier at a given height, driven by a caller-supplied
resolver: `tx_verify_block_connect` needs a live LSM handle, and
`tx_verify_mempool` takes a resolver but applies policy flags. Neither
shape lets a test judge a historical transaction by its own block's rules.

The resolver hands prevouts back *in input order*, and the harness asserts
every input was resolved, so a verifier that silently skipped one fails
rather than passing with less work done.

Vectors regenerate from the oracle; the corpus is extended by adding a
txid and a reason to the generator's `WANTED` list.

---

Also published as [`mined_tx_corpus.html`](mined_tx_corpus.html) and, for
forum posting, [`mined_tx_corpus.bbcode`](mined_tx_corpus.bbcode).
