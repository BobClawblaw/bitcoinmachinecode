# The mined-transaction corpus

Seventeen real transactions taken from the main chain, each replayed
against the script flags of *its own block*. The full-archive replay,
reduced to a test that runs in milliseconds.

17 transactions, 25 KB of vectors, heights 170 through 850,000, 17/17
accepted.

Every transaction here was mined into the main chain, so each is
consensus-valid under the flags active at its own height. That is the
entire claim, and it is deliberately a narrow one. The transactions were
chosen because they broke someone's assumption, not because they are
common: a thousand ordinary P2PKH spends would test less than the eleven
odd ones below.

## Scope

This asserts **consensus** acceptance only. It does not assert mempool
standardness. Several of these are consensus-valid and non-standard today
— bare multisig, uncompressed keys, high-S signatures — and Core cannot be
asked for a policy verdict on a transaction whose inputs are long spent.
Conflating the two would produce a confident wrong answer, so policy is
tested separately.

## What is in it

Height is load-bearing, not decoration. DERSIG activates at 363,725, CLTV
at 388,381, CSV at 419,328, segwit at 481,824, taproot at 709,632. A
transaction from 2011 must be judged by 2011's rules, and several of these
are rejected under today's. Each vector therefore carries its own height.

| Height | What makes it interesting |
|---|---|
| 170 | first P2PK→P2PK spend, Satoshi to Hal Finney: a bare public key, no hash |
| 728 | early P2PKH, the shape that became ordinary |
| 124,276 | non-minimal DER: a 34-byte `r` *and* `s`, two leading zero pad bytes each. A parser that strips only one rejects this real, mined transaction |
| 163,685 | bare multisig (P2MS): consensus-valid, non-standard to relay today |
| 164,467 | `FindAndDelete`: a signature appearing inside its own scriptCode |
| 170,052 | early P2SH, shortly after BIP16 |
| 247,939 | the `SIGHASH_SINGLE` bug: input index ≥ output count, so the sighash is the literal value 1. Mined, and must still validate |
| 481,824 | the segwit activation block, four vectors: native P2WPKH, P2SH-wrapped P2WPKH (scriptSig *and* witness), and P2WSH |
| 550,000 | witness script paths, three vectors: native P2WSH multisig, P2SH-wrapped P2WSH, bare multisig output |
| 750,000 | taproot key-path (BIP341), a single witness item |
| 800,000 | taproot script-path (BIP342), with a real 33-byte control block |
| 850,000 | anchor output (P2A), Core v28's new output type: exactly one instance in the entire survey |

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
