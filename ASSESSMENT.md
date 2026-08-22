# Honest assessment: capability and speed vs Bitcoin Core

Written 2026-08-22, with the Stage D replay at height ~721,000 of a 963,000-block
chain. Speed numbers and their methodology live in `BENCHMARKS.md`; this document
is the judgement that the numbers alone do not carry.

The short version, stated before the detail so it cannot be skipped:

> **This is a consensus-verification engine, not a node.** It cannot replace
> Bitcoin Core for any real user today. On the one primitive that can be
> compared like-for-like it is within ~1.2× of libsecp256k1. Its end-to-end
> speed against Core has **never been measured**. Its consensus correctness is
> being actively established and is not yet established: twenty-four defects
> have been found in roughly four days of replay, five of them in the
> chain-splitting direction, and the discovery rate is not yet decelerating.

---

## 1. What it can do

Real, and stronger than the project's age suggests:

- **Full script verification** — legacy, P2SH, segwit v0 (native and
  P2SH-wrapped), taproot key-path and script-path (BIP341/342), executed
  through one shared interpreter rather than shape-matched special cases.
- **The activation schedule**, including both of Core's hash-identified
  exception blocks.
- **A full-archive replay** with no `assumevalid`: every historical signature
  actually verified.
- **An LSM UTXO store** with WAL, crash recovery, compaction and an mmap read
  path, sustaining the replay at ~15 blocks/s through the taproot era.
- **P2P depth** — headers-first sync, compact blocks (BIP152), addrman,
  outbound peer management. `FEATURE_GAPS.md` rates this "stronger than
  expected".
- **Mempool acceptance with real policy checks.**

## 2. What it cannot do

From `FEATURE_GAPS.md`, and this list is the reason the headline above says
"not a node":

- **The RPC surface is the largest gap by a wide margin.** One tranche of
  blockchain-query calls exists. Most of Core's API does not.
- **No mining support.** No block template assembly.
- **No PSBT (BIP174).** No descriptor, multi-wallet, or watch-only wallets.
- **No chain selection** — no testnet, signet, or regtest. Mainnet only.
- **No `blockfilterindex` (BIP157/158)**, so no light-client service.
- **No `coinstatsindex`/`gettxoutsetinfo`**, which matters far more than it
  sounds — see §4.
- **No `txindex`.**
- **It has never served a peer at tip.** The keep-up serve path was crashing
  on the first block a peer pushed until today (incident #18), which means it
  had never been exercised in production at all.

## 3. Where it is genuinely fast

The honest ranking of what is known, from strongest evidence to weakest:

1. **`ecdsa_verify` vs libsecp256k1 — measured, same CPU, same moment.** The
   only true apples-to-apples comparison available. The gap has closed from
   5.5× slower to roughly 1.2× slower over two days of work. Our 4×64 field
   multiply now *beats* libsecp's 5×52 on latency and trails it on throughput.
2. **Internal speedups, measured against our own previous code**: the BIP143
   sighash path 27.4× on real blocks, the BIP341 path 18.8×, `ecdsa_verify`
   1.37×, end-to-end replay throughput 1.36× (a floor — see `PERF_SCOPE.md`
   §9). These say nothing about Core.
3. **End-to-end vs Core: unmeasured.** This is the number a reader actually
   wants and we do not have it.

**Why "faster than Core" would be an unsound claim even if the number came out
favourably:** Core with `-assumevalid=0` maintains a mempool, a block index,
chainwork, an addrman, an RPC server, P2P serving, and a chainstate it
obfuscates on disk. Our replay verifies blocks and applies UTXOs. Neither side
is a superset of the other, and the comparison is only meaningful with those
differences enumerated. `BENCHMARKS.md` states them per measurement.

There is also a handicap running the other way that is worth stating plainly:
**our UTXO set is not the same object as Core's.** We store ~22.2 million
provably-unspendable outputs that Core never writes to its chainstate — 77.2M
entries against Core's 55.0M at the same height. We are doing measurably more
storage work for the same chain, and we are not yet able to prove our set
matches Core's contents at all.

## 4. The correctness picture, which matters more than the speed

**Twenty-four numbered defects in roughly four days of replay** (`LOG.md`,
incidents #1–#24). The distribution is the interesting part:

- Most were **false rejects** — the safe direction. They stop the replay
  loudly and cost time, not correctness.
- **At least five were false accepts** — the chain-splitting direction: soft
  forks activating one block late (#6), a 521-byte tapscript stack item (#19),
  two BIP341 sighash shapes (#23, #24), and an unenforced BIP66 signature
  encoding rule found this evening and still being fixed.
- **Several were reachable only by asking Core, never by replaying the chain.**
  No such transaction exists in the chain, because Core-running miners never
  mined one. The replay could have run to tip, clean, with all of them still
  present.

That last point is the most important sentence in this document. **A clean
full-chain replay would not have proven consensus correctness.** It proves the
node accepts what the chain contains; it says nothing about what the node
would accept that Core rejects. The differential corpus work — asking Core for
the answer to thousands of constructed vectors — is what found the false
accepts, and that method has only been applied to a few paths so far.

**The acceptance test is currently weaker than it should be.** Stage D's
criterion is "no block rejected". The criterion it *should* be is "UTXO set
byte-identical to Core's at height H", which is exactly what a
`gettxoutsetinfo`/set-hash comparison would give — and which the 22.2M
unspendable-output divergence currently makes impossible. Closing that is
tracked in `FEATURE_GAPS.md` and is, in my judgement, the single highest-value
correctness work remaining.

**The discovery rate is not decelerating.** Six of the twenty-four were found
today, in the last several hours, in code that had already been reviewed and
tested. Two more consensus divergences were found by a fixture agent in a path
that had just been rewritten. The reasonable inference is that more remain.

## 5. What would change this assessment

In rough order of how much each would move it:

1. **A UTXO set hash matching Core at a given height.** Converts the acceptance
   test from "nothing rejected" to "provably the same state".
2. **The differential corpus method applied to every consensus path**, not the
   three or four it has reached. It is the only method that has ever found a
   false accept here.
3. **A measured, fairly-controlled end-to-end comparison against Core with
   `-assumevalid=0`.** Until then, no end-to-end speed claim should be made.
4. **A full replay to tip, clean** — necessary, and demonstrably not
   sufficient.
5. **Serving at tip without crashing**, which has never happened.

## 6. Summary judgement

The engineering is real and the performance work is real: on the primitive
that can be compared honestly, this is within ~20% of the reference
implementation, having been 5.5× behind two days earlier. The verification
architecture handles the whole modern chain — segwit, taproot, script-path
spends at inscription scale — on real data.

But **"can it replace Bitcoin Core" is not a close question today**: no mining,
no PSBT, no wallets, no testnet, no light-client indexes, a thin RPC surface,
and a node that until today crashed the first time a peer pushed it a block.
And **"is it consensus-correct" is an open question**, not a settled one, with
five known chain-split-direction defects found so far and a discovery rate that
has not levelled off.

The right characterisation is: a fast and increasingly capable **consensus
verification engine**, in the middle of the work that would establish whether
it is actually correct.
