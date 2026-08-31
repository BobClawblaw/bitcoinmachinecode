# Bitcoin Machine Code

> ## ⚠️ WARNING — UNTRUSTED, EXPERIMENTAL CODE
>
> **This is actively developed, highly experimental software.** It implements
> Bitcoin node functionality as hand-rolled x86-64 assembly produced by an AI. It
> has NOT been audited by any independent human reviewer. The project has gone
> through multiple rounds of AI-driven security review (see
> `validation/SECURITY_AUDIT.md`), and issues found that way get fixed as they
> come up — but that internal process is not a substitute for independent human
> sign-off, and no such review has happened yet. **You should treat this code as
> untrusted and dangerous.** A bug in consensus, cryptographic, or networking
> logic can cause loss of funds, chain divergence, resource exhaustion, or
> exposure of your machine to the network. Do **not** run it with real funds, on
> a production machine, or on an internet-exposed host, and do not rely on it
> for any security-sensitive purpose — until it has undergone an independent
> human security audit. Use at your own risk.

A Bitcoin node for Linux built as **100% AI-generated machine code** — every line of
assembly is authored by an AI assistant, none by a human. The security-critical
crypto (SHA-256, SHA-512, secp256k1 field/point/scalar/ECDSA/Schnorr, AES-256) is
written directly in x86-64 assembly.

It is a **full node**, not a demo: it does headers-first IBD and full-signature
block validation (genesis to within a few hundred blocks of the live tip, no
`assumevalid`), maintains a chain-scale LSM UTXO set proven byte-identical to
Bitcoin Core's, follows the mainnet tip unattended, relays transactions through
a Core-style mempool, serves Core's JSON-RPC surface, maintains the
`txindex` / `coinstatsindex` / `blockfilterindex` optional indexes, has an
HD/BIP39 wallet with at-rest encryption, and can run on **mainnet or regtest**.
What it does *not* do — and what it does *differently* from Core on purpose — is
spelled out in **`FEATURE_GAPS.md`** and the *Exactly like Core vs. deliberately
different* section below.

## Where to look

Every document except this one lives under [`docs/`](docs/) — see
[`docs/README.md`](docs/README.md) for the full index.

| document | what it is |
|---|---|
| **[`docs/devlog/ASSESSMENT.md`](docs/devlog/ASSESSMENT.md)** | **An honest assessment of capability and speed vs Bitcoin Core.** Read this before believing any performance claim, including the ones in this README. |
| [`docs/FEATURE_GAPS.md`](docs/FEATURE_GAPS.md) | What this node does **not** implement, kept deliberately unflattering. |
| [`docs/audits/`](docs/audits/) | External security audits and this project's written responses — including the mistakes made while remediating. |
| [`docs/devlog/LOG.md`](docs/devlog/LOG.md) | Narrative of every defect found, including the wrong diagnoses and how they were overturned. |
| [`docs/devlog/PERF_SCOPE.md`](docs/devlog/PERF_SCOPE.md) | Profiles, benchmarks, and the methodology behind each number — including which numbers are contaminated and why. |
| [`docs/devlog/PLAN_SCRIPT_VERIFY.md`](docs/devlog/PLAN_SCRIPT_VERIFY.md) | The consensus-verification plan, and a one-line-per-wall table of every block that stopped the replay. |
| [`docs/devlog/CHAIN_AHEAD_CENSUS.md`](docs/devlog/CHAIN_AHEAD_CENSUS.md) | Survey of the un-replayed chain against verifier limits, with an appended record of what it got right and wrong. |
| [`docs/ENGINEERING_RULES.md`](docs/ENGINEERING_RULES.md) | The rules this project imposes on itself, each one earned by a specific failure. |
| [`docs/PARITY_PLAN.md`](docs/PARITY_PLAN.md) | Method-by-method RPC parity state: what is implemented, how each method was verified, and what is deliberately absent. |
| [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) | How to run the daemon, prefaced by the reasons you should not. |
| `worklog/` | Dated terse action logs. |

## Status

**Current state (2026-08-30). A live full node on mainnet with the Core RPC
surface, all three optional indexes, a Core-style mempool, wallet-at-rest
encryption, BIP324 v2 encrypted transport, and a regtest mode proven
block-for-block against Bitcoin Core.**

Gate at this revision: **265 test binaries, 1,368 assertions, zero failures**,
plus `abi-check` over 1,194 call sites, `prereq-check` over 354 Makefile rules,
and `runlist-check` confirming every test is either gated or declared manual
with a reason.

### Since 2026-08-29

**BIP324 v2 encrypted transport — live on mainnet.** Both directions, verified
against Bitcoin Core v31.99 with byte-identical session IDs, and v1 fallback
that leaves a v1 peer's first message untouched. Pinned by the official BIP324
vectors: 76/76 ElligatorSwift decode, 256/256 reverse-map branch cases, 7/7
end-to-end packet vectors. Outbound is gated on the peer advertising
`NODE_P2P_V2`, as Core does.

**An independent security audit was run against the tree, and answered.** Ten
of its eleven findings are resolved; the responses in [`docs/audits/`](docs/audits/)
record what each fix was verified *against* — real Core, 1,172 real mainnet
transactions, ThreadSanitizer, the deployed binary's own ELF headers — and the
three mistakes made while remediating, including one that briefly disabled the
RPC server and one that leaked a wallet mnemonic into a debugger backtrace.

Notable fixes from that round: a missing consensus `MAX_MONEY` check
(CVE-2010-5139 shape), an unbounded JSON parser recursion that could be driven
to a stack-exhaustion crash, an inbound `inv` count read as a single byte
(silently misparsing any vector above 252 entries), an executable stack, and a
wallet passphrase stored beside the wallet it protected.

The remaining finding is structural and not closeable by a patch: this is
hand-written consensus assembly with a documented false-ACCEPT history, and no
amount of internal review retires that. The warning below stands.

**Erlay (BIP330) is deliberately partial.** The negotiation half is
implemented and tested; the reconciliation rounds are not built, because
Bitcoin Core does not implement them either — there is no running
implementation to test against, and this project verifies against Core rather
than against its own reading of a specification. See
[`docs/FEATURE_GAPS.md`](docs/FEATURE_GAPS.md).

The daemon (`bmc-bitcoind`) follows the mainnet tip unattended and is verified
continuously against a local Core node. On top of the byte-identical UTXO set
and the RPC surface described in the 2026-08-25 note below, the work since then
closes most of what `FEATURE_GAPS.md` still listed as absent:

- **Transaction relay + mempool, the way Core runs it.** Announced txs are
  fetched witness-complete and admitted through the *consensus* verifier
  (`daemon/tx_verify.c`: legacy + full taproot, confirmed set + in-mempool
  parents, tip-anchored maturity), parked in an **orphan pool** when a parent
  is missing, and **re-announced** to peers. The pool is a byte-budgeted
  (`maxmempool`) structure that **evicts** the lowest-feerate transactions when
  full — Core's `TrimToSize` — raises a **dynamic `mempoolminfee`** as it
  evicts, and reclaims freed bytes by compacting its blob
  (`daemon/mempool_compact.c`). Ancestor/descendant limits, `minrelaytxfee`,
  `incrementalrelayfee`, and `mempoolfullrbf` are all read from `bitcoin.conf`
  at Core's own defaults. (This replaced an earlier "reject when full" pool
  that froze production at exactly 4096 entries; both the immediate hotfix and
  the real eviction fix shipped 2026-08-27, `LOG.md`.)
- **All three optional indexes.** `txindex` (offline base build + a
  daemon-maintained tail, so `getrawtransaction <txid>` works with no block
  hash), `coinstatsindex` (a per-block incremental MuHash fold, proven
  character-identical to Core's at a height folded incrementally, so
  `gettxoutsetinfo muhash` answers in ~33 ms instead of a full walk), and
  `blockfilterindex` (whole-chain BIP157/158 basic filters **and** their header
  chain, tip-following).
- **Wallet at-rest encryption.** `encryptwallet` / `walletpassphrase` /
  `walletpassphrasechange` / `walletlock`, sealing the wallet's BIP39 mnemonic
  under Core's `BytesToKeySHA512AES` key derivation over an AES-256-CBC
  container (FIPS-197 block cipher in `asm/bitcoin_aes.c`, proven byte-identical
  to OpenSSL's KDF). The live RPC seed is gated behind an unlock timer.
- **Regtest chain selection.** `chain=regtest` (or `regtest=1`) in
  `bitcoin.conf` switches the node to Core's regtest network — its magic,
  genesis, ports, no-retargeting difficulty rule, 150-block halving, and
  everything-active-from-height-1 script schedule. Each chain lives in its own
  datadir subtree (`<datadir>/regtest/`, logs under `logs/` with a chain-tagged
  filename) so state can never cross chains. **Differentially proven against a
  scratch Core regtest node:** bmc synced 160 Core-mined blocks with all 161
  block hashes byte-identical, its `gettxoutsetinfo muhash` identical to Core's,
  a block built from **bmc's own `getblocktemplate`** was CPU-mined and
  **accepted by Core** via `submitblock`, it followed Core's tip live, and a
  Core wallet transaction relayed into bmc's mempool over the wire.
- **P2P completeness.** BIP339 `wtxidrelay`, `MSG_WITNESS_*` block/tx fetching
  with witness-only peer preference, stripped-block serving to legacy peers,
  and self-address advertisement (`daemon/addr_self.c`).
- **Difficulty-schedule enforcement (`bad-diffbits`).** Every block's `nBits`
  must be exactly what Core's `GetNextWorkRequired` demands for its height,
  checked at apply AND in fork evaluation, through one rule engine
  (`asm/bitcoin_pow_rules.c`) that `getblocktemplate` also uses — so a
  template this node builds is by construction one its own validator accepts.
  Replayed against **every header of the real mainnet chain** (964,265
  heights, 478 retarget boundaries) and the real testnet4 chain (149,954
  heights, 101,009 min-difficulty blocks, 16,491 walk-back re-anchors), exact
  on both. This closed a gap `daemon/reorg.c` had documented against itself.
- **Fee bumping and packages.** `bumpfee`/`psbtbumpfee` follow Core's
  feebumper arithmetic, and `submitpackage` accepts a parent that is below
  the relay floor when its child pays for it (Core's effective feerate).
  Both are proven against a real Core on regtest, which accepts the identical
  replacement and the identical package
  (`validation/bumpfee_regtest_e2e.sh`).
- **`gettxout` answers from the live UTXO set.** The RPC runs in the serve
  parent, which holds no handle on that set, so it asks the download worker
  over a socketpair. Before this it returned `null` for every outpoint —
  which does not mean "unknown", it means "spent".
- **Mempool persistence.** `savemempool`/`importmempool` in Core's
  `mempool.dat` format, verified in **both** directions against a running
  Core: it loads the dump this node writes, and this node loads the dump it
  writes.

Configuration, running modes, and a precise **"exactly like Core vs.
deliberately different"** ledger are documented in their own sections below.
Full test suite: **223 harnesses, 0 failures** (`make -k test`).

---

**Previous state (2026-08-25). The UTXO set is byte-identical to Bitcoin
Core's, with no filter and no overrides.** The comparison the 2026-08-24
entry below promised has been run. The from-genesis rebuild (write-time
unspendable filter, so the stored set IS Core's definition rather than
equal-through-a-filter) completed at 16:31; the daemon was stopped cleanly;
and the quiesced set at height 963,967 was hashed and diffed against a local
Core node's `gettxoutsetinfo muhash 963967`:

    txouts         165,726,554                 == Core, exact
    total_amount   2,007,466,988,462,591 sat   == Core, exact
    bogosize       12,980,678,786              == Core, exact
    muhash         1e3c77ad25f40961f1f757a77960b7c4
                   9a5c7bd091597bd925d561a5c202c118  == Core, identical

No read-time filter, no coin overrides, no corrected fields -- the two
incident-#29 height defects the 08-24 text describes were rebuilt away.
The MuHash equality means every one of 165.7 million entries -- outpoint,
value, height, coinbase flag, script -- is byte-equal to Core's chainstate.
As an independent probe of the same set, `scantxoutset` for the Counterparty
burn address returns **3,135 unspents totalling 2,130.99791495 BTC**, matching
Core's own scan to the satoshi. Two readers computed the numbers (the
standalone tool and the RPC-embedded reader, which share one quiescence
discipline by construction) and agree field-for-field.

**The node now serves most of Core's RPC surface, and says exactly how each
method was verified.** Added 2026-08-25, on top of the existing chain/wallet
methods: the mempool tranche (`getmempoolinfo`, `getrawmempool`,
`getmempoolentry`, `getmempoolancestors`, `getmempooldescendants`,
`prioritisetransaction`, `getprioritisedtransactions`) over a mempool that is
now **one MAP_SHARED, cross-process-locked pool** instead of a copy-on-write
copy per process; `estimatesmartfee` (Core's contract over this node's own
accepted-feerate EMA -- the number is ours and says so); `getblocktemplate`
(deterministic frame diffed against Core at the same tip; the 2016-block
retarget reproduces 8/8 real historical retargets bit-exact);
**`submitblock` end-to-end** -- an 8 MB transport, a 4 MB parent-to-worker
channel, BIP22 reason strings, and a connect step gated on a **dry run of the
real apply path** (every verification phase, stopped at the first mutation);
`gettxoutsetinfo` and `scantxoutset` (the capstone instruments, as RPCs);
PSBT `analyzepsbt`/`joinpsbts`; and journal-backed wallet-state methods
(`listtransactions`, `gettransaction`, `getwalletinfo`) whose verification
bound -- round-trip, no oracle wallet exists -- is stated in the code rather
than implied away. Where this node differs from Core deliberately (muhash as
the default `gettxoutsetinfo` hash, absent coinstatsindex extras, a
lower-bound `sigops` in templates), the divergence is documented at the call
site, never silently approximated. `docs/PARITY_PLAN.md` tracks the method-
by-method state, including what is NOT implemented and why.

**Four production incidents in two days, each with a root cause, a fix and a
regression test (`LOG.md` #43-#46):** chainwork.dat corrupt for the whole
post-segwit chain (found because one RPC float differed from Core's);
`decoderawtransaction` returning a minimal non-Core shape; the LSM live-
counter drifting +7,890,418 during the rebuild -- root cause a kill landing
between a flush's manifest write and its WAL truncate, so reload
double-counted the folded tail (the SET was never wrong; the MuHash proved
that before the counter bug was even diagnosed); and a keep-up race that
appended the same block twice at adjacent heights, now structurally closed by
a prev-linkage check inside the same critical section that assigns the
height. The last two were found *by* the capstone run and *by* the deployed
node within hours of each other, which is the project's verification story
working as designed: instruments first, then claims.

The daemon currently running is built from `main` and carries all of the
above. `DEPLOYMENT.md` describes how to run it, and opens with the only
deployment advice this project stands behind: no sane or rational human
should ever run this software.

---

**Previous state (2026-08-24).** Block-level script verification (Stage D of
`PLAN_SCRIPT_VERIFY.md`) has **completed its acceptance test**: a from-scratch,
full-signature-verification replay of the real mainnet archive, no
`assumevalid`, genesis through **height 963,000** -- within ~700 blocks of the
live chain tip -- finishing 2026-08-23 11:25 with **zero rejects and zero
fatals**. **Thirty-five real defects** were found and fixed along the way, each
with a regression test or a live-node reproduction (`LOG.md` has the narrative
for every one, including the mistakes and the wrong diagnoses).

The UTXO set was then **rebuilt from genesis** so a Core-parity change to what
the set even contains (below) governs every entry, and the node now **follows
the live Bitcoin network unattended**. That last clause is deliberately
understated, because for most of 2026-08-24 it was not true and this file
said it was: the node advanced its tip only when restarted, sat 80 blocks
behind the network for 14.5 hours while reporting `peers=8/8`, and the failing
sync path logged nothing (incident #33). The cause was a consensus-check
scratch buffer told it had room for 64 transactions when tip blocks carry
thousands; auditing that one function found the same units error at three
more call sites, two of them corrupting the stack on peer-supplied block data
(#34). With those fixed the node keeps pace with Core block-for-block, which
is verified continuously against a local Core node rather than asserted.

**What that does and does not prove, stated first because it is the most
important thing on this page.** It proves the node accepts everything the real
chain contains. It says nothing about what the node would accept that Core
*rejects*, and this project has repeatedly found that the two are different:
on the last day alone, a `SETcc` writing eight bits where eleven numeric
opcodes needed sixty-four diverged from Core on 11,780 of 63,036 generated
scripts -- **5,050 of them in the false-ACCEPT direction** -- and BIP30 turned
out not to be implemented in the daemon at all. Neither was reachable by
replaying: no block in the chain exercises them, because Core-running miners
never mined one. A clean replay would have run to tip with both present.

Throughput, measured on an otherwise-quiet box: **~5 blocks/s** in the
806,000-960,000 range — two clean 300-second windows gave 4.84 and 5.67 blk/s, and
that ~15% spread between adjacent windows is itself the point: per-block work
varies enough that a single window is not a figure. An earlier figure of ~15
blocks/s was taken at height ~727,000 and the two are **not comparable** — a
block in the taproot era carries several times the signature work of one from
2021, so a replay rate is only meaningful with its height band attached. Every
end-to-end number in this project is quoted that way, or not quoted.

**The UTXO set has been proved equal to Bitcoin Core's, not merely accepted.**
A replay that rejects nothing proves only that no block was refused; it says
nothing about whether the *state* those blocks built is right. So the live
set is now hashed with **MuHash3072** over a filtered view and diffed against
Core's own `gettxoutsetinfo muhash` at the same height. At height 792,979 —
102,532,574 entries — the txout count, the total amount
(19,393,405.70154310 BTC), the bogosize and the hash all match Core exactly.
Independently re-verified at height 200,000, where correcting the genesis
coinbase and **exactly one height field** reproduces Core's hash byte for byte
across 2,318,056 entries. That one field is a real defect (`LOG.md` incident
\#29): on a BIP30 duplicate coinbase, Core's `AddCoin(possible_overwrite=true)`
overwrites and we decline to. Count, amount and bogosize are all blind to it —
only the hash could see it, which is the entire argument for having one.

**The set now holds what Core's chainstate holds, not a superset (2026-08-24).**
Core's `AddCoin` returns early for provably-unspendable scriptPubKeys (leading
`OP_RETURN`, or longer than `MAX_SCRIPT_SIZE`), so they **never** enter its
chainstate. This node stored them: **252,101,123 of 417,948,516 entries** at
the tip. Nothing was *wrong* -- the differential tooling filtered them at read
time, which is how the comparisons below were already exact -- but the stored
set was a superset of Core's, the heartbeat's live count read ~2.5x Core's
`txouts`, and the equality held only *through a filter*. The filter now runs at
**write** time in both writers, sharing one implementation with the
verification tooling so the writer and the checker cannot disagree about the
definition. The set is being rebuilt from the archive on that basis; the
completed rebuild is what a no-filter, no-override MuHash comparison will be
run against.

**Re-verified at the finish line (height 963,000).** The completed replay's set
was hashed and diffed against Core's `gettxoutsetinfo muhash 963000`:
**165,847,393 txouts, 20,071,648.00979492 BTC and bogosize 12,989,895,997 all
match Core exactly** -- 252,101,123 unspendables filtered out of 417,948,516
raw entries landing on Core's count with zero error in either direction. The
MuHash matches byte for byte once **two height fields** are corrected, on two
outpoints from 2010, both attributable to incident \#29 above and both still
unspent at the tip. Two wrong fields in 165.8 million entries is the entire
difference between this node's chainstate and Bitcoin Core's.

**The C is being converted to assembly, with the C kept as the oracle
(2026-08-24, in progress).** The project's claim is 100% AI-generated machine
code, and `daemon/` plus the script-verification layer were ~16,100 lines of C
-- so the honest description was "all consensus *primitives* in assembly,
orchestration in C". Fourteen modules now have differential-proven assembly
twins (transaction parsing on both paths, per-input consensus classification,
BIP141 witness-program classification, the arenas, canonical witness
stripping, the BIP341 aggregate arena, per-input dispatch, the witness-v0 and
legacy/P2SH drivers, both checksig hooks, and the BIP143 and BIP341 sighash
builders). Each twin is compared against the C it replaces over every field it
writes -- entire preimage buffers, not just digests -- across roughly 80,000
cases with zero mismatches, and every benchmarked module is at or better than
the C's speed. **The daemon still runs the C**: the twins are not deployed
until a replay soak, and that swap is its own change. The campaign's value so
far is not speed (the glue layer is ~0.003% of block-connect time) but the
defects the differentials found -- most sharply a frame-slot overlap that made
assembly reject **every valid signature** while passing every rejection test,
every static gate, and assembling cleanly. `worklog/2026-08-24.md` has the
method and the failures.

**Read `ASSESSMENT.md` before drawing conclusions from any of this.** The
short version: this is a consensus *verification engine*, not a node — no
mining, no PSBT, no wallets, no testnet, no light-client indexes, and a thin
RPC surface. On the primitives comparable like-for-like it is within ~1.0–1.2×
of Core (ECDSA verify ~1.0×, Schnorr ~1.2× down from 3.35×, SHA-256d and
merkle ~1.17× down from 2.24×); its end-to-end speed against Core has never
been measured; and its consensus correctness is being actively established
rather than established.

Those per-primitive ratios are also, on their own, misleading about where the
remaining distance to Core actually is. Profiling the live replay at height
~797,000 on an idle box found **32 worker threads asleep and one thread
running** — taproot inputs are verified in a sequential pass at both block-
connection entry points, while every other input shape fans out across the
worker pool. The main thread is 67% field arithmetic because it is doing all
of the taproot signature work by itself. The cause is process-global scratch
in `secp256k1_taproot.asm`, and the effect is that per-signature tuning has
been optimising a path that runs on one core. `PERF_SCOPE.md` section 14 has
the measurement; parallelising that pass now precedes any further arithmetic
work.

The defects worth knowing: genesis was missing from the archive, so every
buried soft fork activated one block late (a false-ACCEPT, structurally
invisible to a replay that only watches for rejects); two lost carries in the
secp256k1 multiplies that ~2⁻⁶⁴ random testing could never have found; and,
at the first segwit block, the discovery that the archive had been
witness-stripped for the entire segwit era (`getdata` asked for `MSG_BLOCK`,
and the merkle root cannot detect the difference) while this node had no
BIP141 witness-commitment check to catch it. Re-fetching those ~482k blocks
from a local Core oracle then exposed the segwit era one real spend at a
time: the first P2WPKH spend in history, nested P2SH-wrapped segwit not
implemented at all, a 4096-byte sighash buffer overrun by a 500-input
transaction, an 8-item witness cap with no basis in consensus, BIP342
tapscript forbidding `OP_CHECKSIGVERIFY` — an opcode it actually keeps — a
600-byte stack buffer for an output the consensus rules do not bound, and the
SysV stack ABI violated tree-wide, which had the script interpreter one log
line away from crashing.

**The most important thing the replay taught is what it cannot prove.**
Several of those defects were reachable *only* by asking Core for the answer
to constructed vectors, never by replaying the chain — because no such
transaction exists in the chain, since Core-running miners never mined one. A
clean full-chain replay would have run to tip with them still present. It
proves the node accepts what the chain contains; it says nothing about what
the node would accept that Core rejects. Five known defects were in that
chain-splitting direction.

Two methods do the finding. A **census** of the un-replayed chain against
known verifier limits (`CHAIN_AHEAD_CENSUS.md`) predicted the tapscript wall
hours before the replay reached it — though it also classified as "handled"
a path that turned out to be broken, because it read for code presence rather
than behaviour. A **differential corpus** against Core (`validation/`) asks
Core for thousands of real and constructed vectors and compares; that is the
method that has ever found a false accept.

Performance (`PERF_SCOPE.md`, methodology and caveats included): `ecdsa_verify`
121 → ~26 µs against libsecp256k1's 21.8 µs on the same CPU; the BIP143 sighash
path **27.4×** and BIP341 **18.8×** on real blocks after removing an O(n³);
UTXO lookups via an mmap run cache (kernel share 31 % → 3 %); end-to-end replay
throughput **1.36× and rising** — quoted as a floor, because the two bands
compared are 120,000 blocks apart in chain weight. Note that the component
multipliers do **not** compose into the end-to-end figure: Amdahl caps each by
its own share.

Tooling that now guards the work: `make abi-check` (a whole-program SysV
stack-alignment audit that would have caught the interpreter bug the day it
landed), a test suite that is order-independent, concurrency-safe and
identical in a fresh clone (and 2.7× faster in parallel), and guard-page
bounds fuzzers on both sighash paths. `FEATURE_GAPS.md` is the honest list of
what this node still does not do.

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
- **Optional CUDA batch-acceleration tier** (`asm/cuda/`) — an explicit,
  runtime-gated accelerator for batched SHA-256 / SHA-256d (Bitcoin's double
  hash), matching the CPUID/SHA-NI design philosophy but with a *device probe*.
  A single dispatcher (`bmc_sha256d_batch`) auto-detects a usable GPU at runtime
  and uses CUDA only when a device is present AND the batch is large enough to
  amortize launch/copy (>=512) AND not disabled (`BMC_CUDA=0`); on any CUDA
  error, no device, or a small batch it falls back bit-exact to the proven
  assembly `sha256d`. Correctness is the priority: the CUDA digest must equal the
  asm oracle byte-for-byte. Verified against the asm oracle over the FIPS
  vectors, all Bitcoin padding edges, and 10,000 random messages (0 failures);
  routing/digests verified in every mode (default->CUDA, disabled/small/no-GPU
  ->CPU fallback). Measured ~17-18x GPU/CPU wall-clock at N=1,000,000 on an
  RTX 5090 (CPU wins below ~100). Building the kernels needs nvcc + CUDA GPU; the
  dispatcher itself links and runs with zero CUDA installed (falls back to CPU).
  Not yet wired into bitcoind/bitcoin_cli — see WORKING.md for the roadmap.
- **Per-input script verification, wired into block connection**
  (`daemon/tx_verify.c`) — `tx_verify_block_connect_all` runs every
  non-coinbase input's script check (legacy via `sv_verify_script`, P2WPKH/
  P2WSH/P2TR-keypath via the existing witness primitives) from
  `apply_block_inner`, ahead of that block's UTXO puts/dels, plus the
  100-block coinbase-maturity rule and a whole-block duplicate-outpoint
  check. Parallelized across every input in the block (a persistent worker
  pool, not per-block thread spawns) to make a full-archive replay
  affordable — **except taproot inputs, which both entry points still verify
  in a sequential pass** (`PERF_SCOPE.md` section 14; the thread-local
  conversion that unblocks parallelising it has landed, the parallelisation
  itself has not). **Complete**: `bmc-bitcoind.service` ran a from-scratch
  replay of the real chain against this path from genesis to height
  **963,000**, finishing 2026-08-23 with zero rejects. **Thirty-one** real
  defects it surfaced — from an
  LSM compaction manifest-ordering bug and an interpreter `OP_SIZE`
  register-width bug alongside a wholly-missing `OP_SHA1`, through the
  witness-stripped archive and the segwit-era spend bugs underneath it, to
  BIP342 tapscript rejecting `OP_CHECKSIGVERIFY`, to the SysV stack ABI
  being violated tree-wide, to a `SETcc` writing eight bits where eleven
  numeric opcodes needed sixty-four (which diverged from Core in *both*
  directions on 11,780 of 63,036 generated scripts) — were root-caused and
  fixed, each with a regression test proven to fail against the pre-fix
  code on real chain data — including BIP30, which had a differential against
  Core and a smoke test, both green, both driving a shim that implemented the
  rule itself while the daemon implemented it nowhere (incident \#30).
  One is **found but not yet fixed**: incident \#29, a BIP30 duplicate
  coinbase keeping the pre-overwrite height where Core's
  `AddCoin(possible_overwrite=true)` replaces it. See `LOG.md` for the
  narratives,
  `PLAN_SCRIPT_VERIFY.md`'s Stage D table for the one-line-per-wall index,
  and the dated files in `worklog/`. Not yet reached chain tip.

All assembly is authored by AI; C/Python harnesses exist only to prove the
machine code is correct against trusted references. Real-mainnet validation
status: the full asm consensus stack accepts the REAL genesis block (285 byte
header + tx-count + coinbase, real nBits 0x1d00ffff, real merkle root) via
test_block_genesis (offline, in make test); pow_check/diff_target implement the
real Bitcoin difficulty algorithm and are proven against real mainnet nBits;
and the node reproduces a live-downloaded real block-1 hash. **The block-body
download + store tail is now exercised end to end against a REAL node: real
mainnet block bodies are downloaded, cons_verify-validated as VALID, and
stored** — block bodies come from a large pool of verified **internet** peers
via distinct-peer selection, discovered entirely through the node's own DNS-seed
bootstrap (no cooperative/local test peer involved). The
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

**BIP152 compact blocks** (`asm/bitcoin_cmpct.asm`, serve integration in
`asm/bitcoin_serve.asm`): SipHash-2-4 short-tx-ids and the compact-block wire
codecs (`sendcmpct` negotiation incl. high-bandwidth, `cmpctblock` build/serve,
`getblocktxn`/`blocktxn`). Verified byte-exact against REAL Bitcoin Core v31.99:
short-ids captured from Core's actual wire `cmpctblock` messages over loopback
(`validation/bip152_vectors.h`, 12 vectors; `tests/test_bip152` 35 checks) and a
loopback e2e over the asm server (`tests/test_bip152_loop`, 16 checks).

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


**Built-in multi-peer catch-up (`bitcoind serve`, no external tooling needed):**
the daemon now self-heals on its own — `main.c`'s `dl_catchup` runs
synchronously at boot, before the node ever opens for service: it discovers
peers via the existing DNS-seed bootstrap (`dl_bootstrap`/`dl_pool_from_book`,
the same discovery `serve_download_worker` already used), extends
`headers.dat` incrementally to the real chain tip, computes the current archive
gap directly from `index.dat` (any hole below the stored tip, plus everything
missing up to the real tip, as ONE combined span), and forks `>=8` chunk-claiming
worker processes to fill it. Workers pull 200-block chunks from a shared
`mmap`'d atomic counter (work-stealing — a worker that lands fast peers just
keeps claiming more chunks instead of idling on a static pre-split share),
skip any chunk that's already fully archived (so the same span safely covers
both real gaps and already-filled heights in one pass), and reuse a persistent
peer connection across chunks instead of reconnecting per chunk. Peer liveness
is checked via a bounded non-blocking-connect probe (several rounds, never a
blind blocking connect to an unconfirmed host — that has no connect-phase
timeout and can hang for minutes on a black-holed peer). Self-throttling: a
node that's already caught up returns from `dl_catchup` almost instantly (pure
disk reads, no network), so it's safe to run unconditionally on every boot.

Since 2026-08-31 the same downloader also runs for a node that falls far behind
while RUNNING (a long outage, a slow link): the download worker hands the gap to
`dl_catchup` whenever a live peer announces a tip >= 2000 blocks past the
archive and the node is not apply-bound (`dl_should_parallel_fetch`,
`tests/test_parallel_trigger`), re-armed at most every 10 minutes. Measured on
signet: 1903 s -> 245 s to the first 10,000 blocks. `bmc.bootcatchup=0` skips
the boot-time run (the runtime trigger still covers the gap).

**`index.dat` scans, in asm (`asm/bitcoin_idxscan.asm`):** `dl_catchup` reruns
its archive-gap scan every status tick and every worker chunk-claim, so this
logic used to be reimplemented separately in C at each of the 4 call sites
(plus twice more in `hole_ranges.py`). Consolidated into one canonical asm
module — `idxscan_tip`, `idxscan_first_hole`, `idxscan_all_present`,
`idxscan_progress` — buffered `pread64` over a 192KB static window (4096
records/read) instead of one syscall per 48-byte record. Verified
byte-identical to the C originals on the live ~810k-record archive
(`asm/tests/bench_idxscan.c`, which snapshots `index.dat` first so it's safe
to run against a concurrently-writing daemon) and benchmarked 4-48x faster.
A naive first cut (one `pread64` per record) was actually *slower* than the C
`stdio` baseline — `fread`'s own ~4KB buffering already amortizes its
syscalls, so beating it required a bigger window, not just moving the same
per-record loop into asm.

**Standalone bulk-download tool (`daemon/unified_ibd.c`):** the same
chunk-claiming/work-stealing engine as a manual ops tool, useful for a very
large initial catch-up or offline reindexing outside the daemon's own
boot path. Every block is written **directly into the single archive** in
`data/` via the concurrent-safe asm `store_append_shared`: each append is
flock-serialized on `append.lock` (each worker opens its own fd — `flock()`
locks belong to the open file description, so a fork-inherited fd would not
actually exclude sibling workers from each other), the block lands at the true
file end of the rolling `blkNNNNN.dat`, and the index record goes positionally
at `height*48` (index.dat pre-sized, grow-only). No per-worker block
directories exist — the archive is one directory holding only
`blk00000.dat`..`blkNNNNN.dat`, `index.dat`, `headers.dat`. Peer distinctness
is guaranteed via a flock-locked `peerclaims` table, with a deep peer pool
(all of `good_internet_peers.txt`, not just a small prefix) and a live-retry
fallback for peers that looked down at the one-time startup probe. Driver
scripts: `hole_ranges.py` (finds gaps in `index.dat`), `backfill_holes.sh`
(one combined-span `unified_ibd` call over them), `sync_chain.sh` (chains
hole-fill into extending to the real tip). Real-mainnet header-continuity bug
found and fixed (see LOG #12).

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
- **createrawtransaction + send** (`asm/wallet_core.c`, `tests/test_send.c`) —
  the wallet now *builds and sends* a real tx, not just signs a supplied one.
  `wallet_createrawtx` selects our prevouts, pays a destination P2PKH output and
  returns change (`sum(inputs) − amount − fee`; rejects underfunded / zero-fee,
  omits the change output when change is 0); `wallet_sign_all_inputs` signs
  EVERY input (legacy SIGHASH_ALL over the pure-unsigned form, low-S DER);
  `wallet_send_tx` is the one-call send; `wallet_get_balance` sums the wallet's
  unspent prevouts. CLI: `wallet_cli send <priv> <dest_h160> <amount> <fee>
  <txid:idx:value>...` prints the signed tx, `wallet_cli balance <v> [v...]`
  prints the wallet UTXO sum. `test_send` (48th harness) feeds the signed tx
  through the SAME whole-tx validator as test_txval (UTXO presence/double-spend
  + per-input verify_p2pkh + fee): multi-input send VALID with correct
  outpoint/amount/change/fee, exact-balance send (no change output),
  underfunded and zero-fee REJECTED, send-vs-empty-UTXO rejected, and balance
  math — 6 cases / 18 checks ALL PASS.
- **Wallet-core + CLI/RPC surface (bitcoin-cli parity, batch complete)** —
  five cards (`t_wrpc_getaddr`..`t_wrpc_send`) delivered a coherent
  Core-aligned command layer on top of the verified asm crypto (in
  `asm/wallet_core.c` + `asm/daemon/wallet_cli.c` + harnesses
  `test_wrpc_addr/utxo/decoderaw/sign/send`):
  - `getnewaddress` / `getrawchangeaddress` — BIP84 `m/84'/0'/0'/i/0` and `.../1`
    P2WPKH bech32 receive/change addresses from a seed.
  - `getaddressinfo` / `validateaddress` — parse + classify base58check
    (P2PKH/P2SH) and bech32 (P2WPKH/P2WSH) addresses, report version + hash.
  - `listunspent` / `gettxout` — enumerate a wallet's unspent outputs and query
    an outpoint, each with value + scriptPubKey + address.
  - `decoderawtransaction` — full human-readable decode of a raw tx (version,
    every input outpoint/scriptSig/sequence, outputs value/scriptPubKey/address,
    locktime).
  - `signrawtransactionwithkey` — sign selected inputs with provided private
    keys (legacy SIGHASH_ALL, low-S), per-input key-ownership matching,
    already-signed inputs left untouched, signed-input masking.
  - `sendtoaddress` + `getbalance` — greedy input selection over the wallet's
    own UTXOs, build + sign a send, report change/fee/new-balance; getbalance
    sums the wallet UTXOs.
  All five harnesses ALL PASS (known-vector addresses/base58 decode round-trip,
  corrupt-checksum rejection, gettxout found/absent, full tx decode, two-key
  sign ACCEPT/wrong-key REJECT/partial REJECT, greedy send + insufficient-funds +
  exact-balance). This is the in-scope wallet-core + bitcoin-cli/RPC surface
  (behavioral parity target); the full RPC transport and the remaining
  address/UTXO-resolver commands remain for a later RPC/bitcoin-cli layer.
- **bitcoin-cli network layer / JSON-RPC transport** (`t_8e5be37f`) — wired the
  command layer onto a REAL JSON-RPC 2.0 transport. New shared RPC layer:
  `asm/rpc_json.c` — Core-bit-exact UniValue serializer (`write(pretty=2)`,
  2-space indent, Core field order + escape set) and strict parser;
  `asm/rpc_net.c` — JSON-RPC 2.0 request/reply framing + HTTP POST over a local
  socket with HTTP Basic auth (rpcuser/rpcpassword), a minimal HTTP/1.1 request
  parser, and the reply-envelope parser; `asm/rpc_commands.c` — the shared
  dispatch/render path that maps a parsed request (method+params) to the
  wallet-core command layer and emits Core-shaped result JSON
  (`rpc_amounts` reproduces Core `ValueFromAmount` exactly). Client binary
  `asm/daemon/bitcoin_cli` behaves like bitcoin-cli: string results print raw,
  objects/arrays via `write(2)`, RPC errors print `error code:`/`error message:`
  and exit non-zero. Verified end-to-end over a real loopback HTTP socket by
  `asm/tests/test_rpc_transport` (execs the actual `daemon/bitcoin_cli` binary
  against a thread-spawned HTTP JSON-RPC responder that dispatches through the
  same `rpc_dispatch`) — 19 checks byte-exact (wire framing, getnewaddress /
  getrawchangeaddress / getbalance / validateaddress / listunspent / gettxout /
  decoderawtransaction rendering, method-not-found + transport-error paths);
  `asm/tests/test_rpc_json` (28 checks) pins the renderer + `rpc_amounts`
  byte-exact. **HTTP JSON-RPC server endpoint** (child card `t_0ca5d72e`)
  added the production server side: `asm/rpc_server.c` (loopback listen socket +
  accept thread, Core-bit-exact HTTP + JSON-RPC: 405 on non-POST, 401 +
  `WWW-Authenticate` auth, `-32700` parse error, V2/V1 envelopes with id echo,
  V2-notification 204) and `asm/daemon/bitcoin_rpcd` (loads rpcport/rpcuser/
  rpcpassword from `config/bitcoin.conf`, serves until SIGINT/SIGTERM), both
  dispatching through the same `rpc_dispatch()`. `asm/tests/test_rpc_server`
  proves the production path end-to-end — forks+execs the REAL `bitcoin_rpcd`
  and drives it with the REAL `bitcoin_cli` plus raw sockets — 23 checks
  byte-exact. Together the client and server close the RPC-transport OPEN item.
- **Read-side + util + live-node RPC surface at Core parity** (2026-08-24/25) —
  the blockchain-query layer (`asm/rpc_chain.c`) and a live-node layer
  (`asm/rpc_node.c`) verified BYTE-FOR-BYTE against a scratch Bitcoin Core
  oracle by differential harnesses in `validation/`. Added, each proven
  identical to Core (divergences documented, not fudged): `getdifficulty`;
  `gettxoutproof`/`verifytxoutproof` (BIP37 partial merkle tree — proofs are
  byte-identical and each node verifies the other's); `decodescript` (incl. the
  inferred `desc` — Core's `InferDescriptor` no-keystore rules); `createmultisig`
  (incl. the descriptor with Core's 8-char checksum); `validateaddress`
  (fixing three field bugs the differential caught: a garbage P2WSH
  `witness_program`, `P2TR isscript=false`, a stray `ischange`); and `desc` on
  `getblock`/`getrawtransaction` scriptPubKey output. **The RPC server is now
  embedded in the serve daemon** (`daemon/main.c`), bridging its fork model with
  a `MAP_SHARED` status region the download worker publishes into, so the
  live-node RPCs `getconnectioncount`, `getnetworkinfo`, `getpeerinfo` (real
  peer addr/version/subver/services, plus per-socket byte/last-activity meters
  from the kernel's `TCP_INFO`), `getmempoolinfo`, `getrawmempool` and
  `getchaintips` answer from a running node — verified live in production. A
  **descriptor engine** (`asm/bip32_ckdpub.c`) adds `getdescriptorinfo` and
  `deriveaddresses` — BIP32 public derivation (CKDpub over the verified secp/
  hmac asm) building `pkh`/`wpkh`/`sh(wpkh)` addresses, verified byte-for-byte
  against Core's own `deriveaddresses`. `getblock` verbosity 2 now also emits a
  per-tx `fee` where undo data exists. **`sendrawtransaction`** is wired through
  the fork model: the RPC parent stages the raw tx into the `MAP_SHARED` region
  and the download worker (which owns the peer legs) validates + mempool-accepts
  it and relays it to peers — the plumbing is unit-tested over a socketpair
  (`tests/test_tx_submit.c`); the live peer-relay proof lands once the UTXO
  rebuild completes (a real tx can't validate against a partial UTXO set). Still
  absent: wallet and mining RPCs.
- **Live-wire end-to-end sighash spend** (`tests/test_e2e_sighash.c`) — the
  full wallet->validator path exercised as ONE integrated test across a real
  process boundary, not isolated pre-generated vectors: it builds a genuine
  unsigned P2PKH tx in memory, hands it to the ACTUAL `daemon/wallet_cli sign`
  binary (legacy SIGHASH_ALL, low-S, deterministic nonce) and captures its
  real `signed-tx:` stdout, then feeds that CLI-signed tx through the whole-tx
  validator (UTXO presence/double-spend + `verify_p2pkh` per input + fee) and
  requires it to pass. The CLI signature is additionally cross-checked as a
  genuine spend through the repo's independently-verified `ecdsa_verify`. Live
  negative cases round it out: the CLI signs a negative-fee tx (valid sig) that
  the validator rejects on `[fee]`; an output-value tamper invalidates the
  SIGHASH_ALL digest -> rejected; a corrupted DER byte -> rejected; and the
  same signed tx against an empty UTXO set -> double-spend rejected. 9/9.
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
- **Persistent UTXO store** (`asm/bitcoin_utxo_store.asm`) — a crash-safe,
  reloadable on-disk layer over the in-memory UTXO set, mirroring the proven
  append-only store/index pattern of the block archive: a write-ahead operation
  log `utxo.dat` (framed PUSH/DEL records; the durable source of truth) plus a
  checkpoint index `utxo.idx` (a snapshot of the live set + the log offset it
  covers). `utxo_store_put/del` append the op to the WAL first, then apply it in
  memory; `utxo_store_sync` writes a checkpoint and fsyncs both files;
  `utxo_store_reload` restores the checkpoint O(n) and replays the WAL tail past
  it (restart-resume), recovering a crash between checkpoints exactly like the
  block store's resume. `test_utxo_store` verifies put/spend/dedup, full-WAL
  reload, checkpoint + crash-tail restart-resume, and on-disk framing.
- **LSM-tree UTXO store** (`asm/bitcoin_utxo_lsm.asm`) — replaces
  `bitcoin_utxo_store.asm`'s single pre-sized in-memory table as the
  chain-scale UTXO set: that table has to be sized upfront for the FINAL
  total live-UTXO count (~408M), so a full-archive replay write-amplified
  ~13x (scattered writes across a 51GB structure regardless of how few
  entries are actually live at that point in the replay). The LSM store
  instead uses a small BOUNDED memtable (`bitcoin_utxo.asm`'s table,
  reused unchanged) that flushes to sorted, Bloom-filtered, immutable run
  files and periodically compacts via a streaming k-way merge — mirroring
  Core's LevelDB-behind-bounded-`dbcache` design, built from scratch (no
  external libraries). `bitcoin_utxo_store.asm` itself is untouched and
  still does real work here: its WAL format is reused verbatim as the
  LSM's own per-generation write-ahead log. `daemon/build_utxo.c` replays
  the whole archive into it (full-archive rate now stays flat instead of
  collapsing); `daemon/utxo_live.c` is the live daemon's own instance
  (single writer = the download worker, persisted-applied-height catch-up
  so it also picks up blocks an inbound peer connection wrote); each
  inbound connection gets its own read-only snapshot
  (`daemon/tx_accept.c`) for tx acceptance (below). `tests/test_utxo_lsm`
  (100+-trial randomized stress incl. compaction, crash-recovery
  simulation) and `tests/test_tx_accept_e2e` (real pipeline end-to-end)
  both green.
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
- **Full script interpreter** (`asm/bitcoin_interp.asm` built on the verified
  support layer `asm/bitcoin_scriptcodec.asm`) — a complete Bitcoin Script
  EvalScript engine covering the full opcode set with Bitcoin Core semantics:
  flow control (`OP_IF/ELSE/ENDIF/VERIFY/RETURN`, `vfExec` condition stack),
  stack/splice (`DUP/DROP/SWAP/ROT/PICK/ROLL/2DUP/2OVER/2ROT/...`),
  bitwise (`SIZE/EQUAL[VERIFY]`), arithmetic (monadic `1ADD/1SUB/NEGATE/ABS/
  NOT/0NOTEQUAL` + binary `ADD/SUB/BOOLAND/BOOLOR/NUMEQUAL[VERIFY]/
  NUMNOTEQUAL/LESSTHAN/GREATERTHAN/.../MIN/MAX/WITHIN` over clamped 32-bit and
  64-bit ScriptNum), crypto (`OP_SHA256/OP_HASH160/OP_HASH256/OP_RIPEMD160`,
  `OP_CODESEPARATOR`, and the `OP_CHECKSIG` family host via a callback),
  disabled opcodes returning **false**, reserved->bad-opcode, `OP_CLTV/OP_CSV`
  handling, and **tapscript/BIP342** semantics: `OP_SUCCESSx` pre-scan
  (short-circuit success / `DISCOURAGE_OP_SUCCESS`), cleanstack +
  empty-stack treatment (`CLEANSTACK`/`EVAL_FALSE`), tapscript-minimal-IF as an
  unconditional consensus rule, `OP_CHECKSIGVERIFY` valid (re-specified for
  schnorr, like `OP_CHECKSIG`), `OP_CHECKMULTISIG(VERIFY)` ->
  `TAPSCRIPT_CHECKMULTISIG` (the only checksig-family opcodes tapscript
  disables), and `OP_CHECKSIGADD` gating
  (valid only under tapscript). Verified differentially against Bitcoin Core's
  `script_tests.json` (`tests/script_tests_diff.py`: 67/67 BASE opcode vectors
  byte-for-byte, exit 0) plus a dedicated 24-check tapscript harness
  (`tests/test_tapscript_interp.c`) and `tests/smoke_interp`/`test_interp`.
  The taproot/schnorr signature callback layer is wired downstream
  (t_93b2695f, taproot/segwit v1).
- **Taproot / segwit v1 validation (BIP341/340/342)** — BIP340 Schnorr
  signature verify + signing (`asm/secp256k1_schnorr.asm`, verified against all
  19 official `bip-0340` test vectors), BIP341 taproot helpers
  (`asm/secp256k1_taproot.asm`: x-only tweak with parity, tagged-hash tapleaf/
  branch/merkle-root, control-block parsing), bech32m P2TR
  address<->scriptPubKey (BIP341/350), and end-to-end spend validation in
  `asm/bitcoin_taproot_sighash.c`: BIP341 SigMsg serialization + TapSighash for
  key-path and script-path (BIP342 ext) with every hash type, key-path schnorr
  verify against the output key (including witness-annex commitment),
  script-path `OP_CHECKSIG`/`OP_CHECKSIGADD`
  verify, and the `checksig_fn` callback that drives live tapscript
  `OP_CHECKSIG`/`CHECKSIGADD` spends through the ASM script interpreter.
  Verified byte-for-byte against the official Bitcoin Core
  `wallet-test-vectors` (keyPathSpending) + Core-validated reference preimages,
  cross-checked by the independent pure-Python oracle
  (`asm/validation/gen_taproot_vectors.py`). `test_taproot_sighash` 48 checks
  green; `make test` suite green.
- **Witness-v0 + taproot full mempool acceptance parity vs Core** —
  modern-output transactions (P2WPKH / P2WSH / P2TR) through the entire
  mempool-acceptance pipeline. BIP143 segwit-v0 sighash
  (`asm/bitcoin_segwit.c`, mirroring Core `SignatureHash WITNESS_V0`) verified
  byte-exact against the official BIP-0143 test vector via the independent
  Python oracle (`asm/validation/gen_modern_vectors.py`); a unified whole-tx
  validator (`asm/bitcoin_txval_modern.c`) dispatches by prevout type and runs
  each genuine spend through strip-witness + per-input ECDSA (P2WPKH, P2WSH
  `OP_CHECKSIG` + 2-of-2 `OP_CHECKMULTISIG`) / Schnorr (P2TR key-path) verify on
  top of the verified ASM secp256k1; driven end-to-end with the mempool policy
  layer (`mpool_policy_add`: fee, double-spend, RBF, ancestor limits) in
  `test_mempool_accept_modern`. Every genuine modern tx is accepted by BOTH
  policy and whole-tx validation; every negative (corrupted sig, wrong pubkey,
  absent prevout, double-spend, negative fee) rejected in agreement with Core.
  `test_segwit_sighash` 17 + `test_mempool_accept_modern` 23 checks green;
  `make test` suite green. Closes the modern-output validation gap.
- **Live-daemon mempool acceptance (2026-08-18)** — the above validation
  pipeline is now actually wired into the running P2P daemon, not just
  exercised standalone in tests. `bitcoin_serve.asm`'s inbound `.do_tx`
  handler used to accept any syntactically-minimal tx with zero
  validation; it now calls a new per-connection dispatcher
  (`asm/daemon/tx_accept.c`) that runs every inbound tx through
  `mpool_policy_add` + `txval_modern` against a read-only LSM UTXO
  snapshot (one `utxo_lsm_reload()` per forked connection) before storing
  anything for relay — rejecting on either check, and specifically
  ordered so a signature failure never triggers the policy layer's own
  mempool insert (it has no public rollback API). New permanent test
  `tests/test_tx_accept_e2e.c` proves the real pipeline end-to-end
  (valid spend accepted+stored; corrupted-signature spend rejected with
  no phantom mempool entry). Full `make test` suite (~80 harnesses)
  green. Remaining: soak test against live real peers.
- **Differential consensus harness vs Bitcoin Core (compliance gate)** —
  `validation/consensus_diff.py` + `asm/tests/consensus_shim` feed the SAME real
  mainnet block/tx bytes to (a) the ASM consensus stack (`cons_verify` /
  `block_hash` / `pow_check` / `diff_target` / `tx_txid` via the shim) and
  (b) a real Bitcoin Core node's RPC, and compare every verdict byte-for-byte.
  Two differential passes: an **ACCEPT path** (every real mainnet block the
  active chain accepted must be `cons_verify`-valid AND its ASM block_hash must
  equal Core's height->hash — a rejection/`hash mismatch is a false-negative
  consensus bug), and a **REJECT path** (deterministic mutations of real blocks
  — flipped merkle/tx/nonce/prev bytes, txcount corruption, truncation — are
  fed as identical bytes to `cons_verify` and Core `submitblock`; both must
  reject together). A per-tx **txid differential** verifies the ASM BIP141
  txid against Core's canonical txid for up to 120 real txs per sampled block.
  Verified clean (zero divergences) across the consensus-critical epochs:
  genesis, BIP16 activation (173805), BIP34 (227931), SegWit (481824),
  Taproot (709632), recent mainnet (918000). `tests/consensus_shim` builds via
  `make`; drive with `python3 validation/consensus_diff.py --start H --count N`.

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
large archive and a single hole aborted it. The boot-time bulk load
(`idx_build_from_file`) is buffered `pread64` (same 192KB-window approach as
`bitcoin_idxscan.asm`) instead of a per-record C loop — was ~186s on the real
archive, now a fraction of a second, and fixing it surfaced a real bug in
`idx_hash` itself (not the load loop): it only hashed a key's first 8 bytes,
and every real block hash's leading bytes are near-zero by proof-of-work
construction, so real data collided catastrophically (independent of C vs
asm — the old C loop had the exact same slowdown, just harder to see under
its own overhead) while synthetic random keys were fine. Fixed by hashing
the full 32 bytes; also speeds up `idx_get`, used for every live
`getdata`-by-hash lookup, not just the boot-time build. `asm/bitcoin_serve.asm`
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

- **Wallet message signing / verification** (`asm/wallet_msgsign.c`,
  `asm/daemon/wallet_cli.c`) — `signmessage <priv_hex> <message>` and
  `verifymessage <pub_hex|address> <message> <sig>` using only the verified asm
  crypto. Two encodings, both over the byte-exact BIP137 digest
  (double-SHA256 of `"\x18Bitcoin Signed Message:\n" || varint || msg`): a plain
  `r||s` hex form (verify against a pubkey), and a **Core-compatible recoverable**
  form (`msg_sign_core`/`msg_verify_core`) that emits the 65-byte base64 compact
  signature `[27+4+recid(+low-s bit)]||r||s` via hand-rolled ECDSA **public-key
  recovery** (recid search over the asm `fe`/`point`/`scalar` primitives) and
  verifies from an **address alone** — the exact Core `verifymessage` flow.
  Pinned by `tests/test_msg_sign.c`: 120-message recoverable round-trip +
  tamper reject + wrong-message reject (all recovery-ids and both low-s states).
- **Persistent transaction history journal** (`asm/wallet_txlog.c`) —
  `wallet_cli history` / `listtransactions` render an append-only, versioned,
  own-format journal (BMCTX v1, 0600 perms, one record per sent tx: ts, txid,
  amount, fee, dest-h160, inputs, rawlen). `cmd_send`/`cmd_sendtoaddress` record
  each sent tx; `test_wallet_txlog` (11 checks) covers path derivation, perms,
  versioned header, list round-trip and append-only behavior.
- **Fast block store read path** (`asm/bitcoin_store_fast.asm`,
  `asm/bench_store_read.c`) — cuts the per-block serve cost from six syscalls to
  two (positioned `pread` of index + body via a direct-mapped 8-slot read-only fd
  cache), and to zero-copy via a guarded `mmap` path (`store_map_*`) with
  remap-on-growth and SIGBUS-past-EOF protection. Verified byte-exact vs the old
  path on 4000 blocks incl. random-access, mmap, append-while-mapped remap; ~1.1x
  (pread) and ~2.1x (mmap) at page-cache speeds. Removes the shared-index-fd
  race making concurrent reads safe; `store_prune_safe` invalidates both caches
  before unlink.
- **Security audit status** (`validation/SECURITY_AUDIT.md`) — two completed
  audit passes, 2026-08-15 (PASS 1) and 2026-08-16 (PASS 2), of the assembly
  crypto + consensus + wallet core, following an internal line-by-line review
  method and backed by regression harnesses committed to the suite.
  - PASS 1 findings all **FIXED**: the CRITICAL non-constant-time signing path
    (FINDING 1 — fixed via a constant-time `point_scalar_mul_ct` repointed onto
    the two secret-scalar call sites; field arithmetic made branch-free per
    FINDING 3), and the legacy-sighash out-of-bounds read / write-cap defects
    (FINDING 2 / 2b, both with `test_sighash_oob.c` regression).
  - PASS 2 (2026-08-16, post-delta review) found **no new CRITICAL or HIGH**
    issue across the newest crypto/networking surfaces; two hardening items are
    recorded as open (INFO/LOW — journal durability, recovery-scan efficiency /
    Core-header extension bit).
  - With FINDING 1 fully landed the **signing path is constant-time
    end-to-end**. The README warning above remains because the code has not
    undergone an *independent third-party* audit; the internal audit is complete,
    tracked in-repo, and green.

## Running modes

`daemon/bitcoind <mode> <datadir> [args]` — the datadir is where the chain,
UTXO store, indexes, wallet, and `logs/` live (see *Storing the chain*).

| mode | arguments | what it does |
|---|---|---|
| `serve` | `<datadir> [port] [nwant] [workers]` | **The normal way to run.** Self-healing: discovers peers, fills any archive gap and catches up to the real tip (built-in `dl_catchup`, ≥8 chunk-claiming workers), then opens for inbound service. `port` defaults to the chain's P2P port; `nwant` outbound peers (default 3); `workers` catch-up threads (default 16). |
| `follow` | `<datadir>` | Extend the chain from a peer and keep following the tip; no inbound serving. |
| `ibd` | `<datadir>` | One assembly pass: headers-first persist → `getdata` block bodies → validate → store. |
| `sync` | `<datadir>` | Loopback-fakepeer sync smoke test (the `test_bitcoind_sync` harness path). |
| `server-test` / `serve-test` | `<datadir> …` | Inbound-serve test harnesses. |

## Configuration

Durable tuning is read from **`bitcoin.conf`** in the datadir (or the path in
`$BITCOIN_CONF`), `key=value`, `#` comments, unknown keys ignored — the same
file the standalone RPC daemon reads, so the two can share it. Every key below
is a real Bitcoin Core option honoured by name and unit; defaults equal Core's
except where the node is deliberately more conservative. Parsed in
`asm/daemon/node_config.c`.

**Chain selection**

| key | default | meaning |
|---|---|---|
| `chain` | `main` | `main`, `signet`, `testnet4` or `regtest`. Legacy `testnet`/`test` (testnet3) is recognised and **refused** — the node will not start on a chain whose rules it does not implement. |
| `signetchallenge` | *(default signet)* | Hex block challenge for a CUSTOM signet. It also determines the network magic, so two signets with different challenges cannot hear each other. Core drops the chain-work floor and DNS seeds for a custom signet; so does this node. |
| `regtest` | `0` | `regtest=1` is the boolean form of `chain=regtest`. |

Each non-main chain runs in its own datadir subtree (`<datadir>/regtest/`) with
its own logs (`logs/bitcoind.regtest.log`); `bitcoin.conf` stays shared at the
datadir root. See *Storing the chain*.

**Network / peers**

| key | default | meaning |
|---|---|---|
| `port` | `8333` (main) / `18444` (regtest) | P2P listen/dial port. An explicit `port=` overrides the chain default. |
| `bind` | any | listen address, `addr[:port]`. |
| `listen` | `1` | accept inbound connections. |
| `connect` | — | connect ONLY to these peers (repeatable); disables discovery, `dnsseed`, and `listen` unless those are set explicitly. Loopback/RFC1918 addresses are honoured here (they are an operator instruction), unlike gossiped peers. |
| `addnode` / `seednode` | — | add a peer / seed to the pool (repeatable). |
| `dnsseed` | `1` (main), `0` (regtest) | use DNS seeds for bootstrap. |
| `maxconnections` | `200` | total connection budget. |
| `timeout` | `5000` | connect timeout, ms. |
| `peertimeout` | `60` | peer inactivity timeout, s. |
| `maxreceivebuffer` | `5000` | per-peer receive cap, ×1000 bytes. |
| `blocksonly` | `0` | do not relay transactions. |

**Mempool policy** (all Core defaults)

| key | default | meaning |
|---|---|---|
| `maxmempool` | `300` | mempool byte budget, MB. Full pool → feerate eviction. |
| `mempoolexpiry` | `336` | drop txs older than this, hours. |
| `minrelaytxfee` | `0.00001` | relay/mempool floor, BTC/kvB. |
| `incrementalrelayfee` | `0.00001` | RBF / dynamic-minfee increment, BTC/kvB. |
| `limitancestorcount` | `25` | max in-mempool ancestors. |
| `limitancestorsize` | `101` | max ancestor set, kvB. |
| `limitdescendantcount` | `25` | max in-mempool descendants. |
| `limitdescendantsize` | `101` | max descendant set, kvB. |
| `mempoolfullrbf` | `1` | allow full-RBF replacement. |

**UTXO / validation / storage**

| key | default | meaning |
|---|---|---|
| `dbcache` | `1024` | UTXO memtable sizing, MiB. |
| `par` | `0` (auto) | script-verification worker threads. |
| `prune` | `0` (off) | pruning target, MiB. |
| `checkblocks` | `6` | blocks to verify at startup. |
| `checklevel` | `3` | startup verification depth. |
| `assumevalid` | Core default | skip signature checks up to this block. |
| `stopatheight` | `0` (off) | stop syncing at this height. |
| `txindex` | `0` | maintain the full transaction index tail. |
| `maxuploadtarget` | `0` (none) | upload budget, MB. |
| `bmc.utxocompactthreshold` | `12` | runs in the UTXO manifest that trigger a compaction (x4 in bulk catch-up). Which runs merge is decided by size ratio (leveled); see `docs/DEPLOYMENT.md`. |
| `bmc.bootcatchup` | `1` | run the parallel block downloader at boot. `0` skips it; the runtime trigger still runs it when the node falls >= 2000 blocks behind. |

**Other**

| key | default | meaning |
|---|---|---|
| `signer` | — | external signer command (Core `-signer` / HWI). |
| `zmqpubhashblock` / `zmqpubhashtx` / `zmqpubrawblock` / `zmqpubrawtx` / `zmqpubsequence` | — | ZMQ publisher endpoints (`tcp://…`), one per topic. `tcp://*` is **refused**: a ZMQ publisher has no authentication, so the bind address is the whole access-control decision. Name an interface (`127.0.0.1`, or `0.0.0.0` if you mean it). |
| `v2transport` | `1` | Accept inbound BIP324 v2 connections, and dial v2 to peers advertising `NODE_P2P_V2`. Off means v1 only. |
| `walletpassfile` | — | Absolute path, **outside the datadir**, to a file holding the wallet passphrase. Refused if world-accessible, group-writable, or inside the datadir. |

### RPC authentication

`rpcport` defaults to `8332` (main) / `18443` (regtest) and the listener is
loopback-only.

**The cookie is the default credential.** `<datadir>/.cookie` is written 0600
at startup, deleted on shutdown, and is what `bitcoin-cli` picks up
automatically — no configuration needed.

`rpcauth` (salted HMAC) is the right choice for a fixed credential.
`rpcuser`/`rpcpassword` still work but store the secret in plaintext on disk;
Core warns against them for that reason, and so does this node's own audit
response. The server starts on **any** of the three and refuses to start only
when none is available, since a listener nothing can authenticate against is
worse than no listener.

## Exactly like Core vs. deliberately different

This node is built to agree with Bitcoin Core **byte-for-byte where agreement is
consensus-visible**, and to diverge only where Core relies on machinery this
project has not built — never silently. Every divergence below is documented at
its call site in the code, and the "like Core" claims are backed by the
differential tests named.

### Byte-for-byte / behaviour-identical

- **Script-verification flags** are *generated from Core's own source*
  (`validation/gen_script_flags.py` parses `kernel/chainparams.cpp` and
  `script/interpreter.h`), never hand-transcribed — including the two historical
  BIP16/Taproot exception blocks matched by hash. Re-run after a Core upgrade.
- **The UTXO set is byte-identical.** At mainnet height 963,967 the MuHash3072
  over the whole set equals Core's `gettxoutsetinfo muhash` exactly — no filter,
  no coin overrides — which means every one of ~165.7M entries (outpoint, value,
  height, coinbase flag, script) matches. Re-proven on regtest against a scratch
  Core node.
- **Consensus validation:** legacy + segwit (BIP143) + taproot key-path and
  script-path (BIP341/342) sighash and verification, P2SH/CSV/CLTV/NULLDUMMY at
  Core's exact activation heights, BIP30, BIP141 witness-commitment. Full-chain
  replay from genesis to ~h963k rejected nothing the real chain contains.
- **Difficulty retarget** arithmetic reproduces **8/8 real historical retarget
  boundaries bit-exact**; `getblocktemplate`'s `bits` field is diffed against
  Core at the same tip.
- **Genesis** for both chains is hashed and *asserted* against Core's own
  `hashGenesisBlock` string before the chain can be selected (regtest is
  derived from the mainnet block exactly as Core's `CreateGenesisBlock` does).
- **JSON-RPC** shapes follow Core's `blockchain.cpp` / `rawtransaction.cpp` /
  `core_io.cpp` field-for-field with Core-exact error codes and messages; merkle
  proofs (`gettxoutproof`) are byte-identical and cross-verify bidirectionally;
  `decodescript` / `validateaddress` / `createmultisig` diff byte-for-byte
  against a scratch-Core oracle including descriptor checksums.
- **Config defaults** equal Core's (the tables above), and the mempool honours
  Core's `TrimToSize` semantics, dynamic `mempoolminfee`, and ancestor/
  descendant limits.

### Deliberately different (documented, never silent)

- **Storage format is our own**, not Core's. Blocks live in one append-only
  framed archive (`blk00000.dat` + a positional `index.dat` + `headers.dat`),
  and the UTXO set is a custom Bloom-filtered LSM — not `blk*.dat` + a LevelDB
  chainstate. The archive container marker is a constant, not chain-tagged
  (chains never share a datadir, so isolation comes from the directory, not the
  marker).
- **Mempool eviction is per-leaf, not per-package.** Core evicts whole
  descendant packages by descendant feerate; this evicts the lowest-feerate
  *leaf* and works inward. The two coincide for the common no-children case
  (`bitcoin_mempool_policy.c`).
- **Wallet is a single implicit HD wallet.** No multi-wallet, no descriptor
  *engine*, no watch-only — `createwallet` / `loadwallet` / `importdescriptors`
  and friends are dispatched but return an honest "unsupported", and
  `descriptorprocesspsbt` refuses rather than guessing.
- **`gettxoutsetinfo` defaults to `muhash`.** `hash_serialized_3` is *refused*
  (Core itself refuses it for an arbitrary height; only muhash is stored by the
  index and answerable off-tip). Coinstats "extras" beyond the core fields are
  omitted, stated in the result.
- **Chains: `main`, `signet`, `testnet4`, `regtest`.** Legacy `testnet`
  (testnet3) is refused outright rather than run under the wrong chain's
  rules. On signet the block SIGNATURE is the consensus rule in place of
  meaningful proof of work (BIP325), and it is enforced: the node syncs the
  public signet and holds the same chain as Core, and under a challenge
  differing by one hex character it rejects real block 1 as
  `bad-signet-blksig`.
- **Not present at all** (also in `FEATURE_GAPS.md`): Tor/I2P/onion, REST
  interface, UPnP/NAT-PMP, GUI. Mining is `getblocktemplate`/`submitblock` with
  a *lower-bound* `sigops` and valid-but-not-fee-optimal tx ordering, no
  longpoll, no BIP23 proposal mode, no stratum.
- **Header nBits retarget is not consensus-enforced** on incoming headers: the
  node relies on cumulative-work fork choice (a low-difficulty header chain
  scores near zero and can never outweigh the real chain), documented in
  `daemon/reorg.c`. Harmless on regtest (one chain) and on mainnet (real work).
- **One quiet edge in tx relay:** a transaction announced exactly once during a
  leg's sync pass can be drained unexamined; Core's periodic re-announcement
  delivers it on the next pass. Lossless on mainnet traffic; on a silent regtest
  the *first* inv may wait for Core's ~10-minute re-announce.

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
|   +-- bitcoin_idx.asm        # O(1) block hash->height index for serving (idx_*, idx_build_from_file)
|   +-- bitcoin_idxscan.asm    # buffered index.dat positional scans (idxscan_*, used by dl_catchup)
|   +-- bitcoin_serve.asm      # inbound server message loop (node_serve_loop)
|   +-- bitcoin_pubkey.asm     # fe_pow + pubkey_parse: secp256k1 pubkey de/compress
|   +-- bitcoin_sighash.asm    # legacy SIGHASH_ALL preimage builder
|   +-- bitcoin_script.asm     # der_parse_sig + verify_p2pkh (end-to-end P2PKH validate)
|   +-- bitcoin_utxo.asm       # in-memory UTXO set (prevout value/script); also the LSM store's memtable engine
|   +-- bitcoin_utxo_store.asm # WAL utxo.dat + idx checkpoint; also the LSM store's per-generation WAL engine
|   +-- bitcoin_utxo_lsm.asm   # CHAIN-SCALE persistent UTXO: bounded memtable + sorted Bloom-filtered runs + leveled compaction (runs in a forked child)
|   +-- bech32.asm             # BIP173/350 bech32/bech32m address codec
|   +-- bitcoin_bip32.asm      # BIP32 master/CKD/derive_path + xprv/xpub
|   +-- bitcoin_bip39.asm      # BIP39 mnemonic<->seed (PBKDF2-HMAC-SHA512)
|   +-- wordlist.inc           # 2048-word BIP39 English wordlist (9-byte records)
|   +-- bitcoin_multisig.asm   # p2sh_hash + multisig_verify (OP_CHECKMULTISIG)
|   +-- bitcoin_script_flags.asm # per-height script-verify flag schedule (generated from Core; runtime chain selector)
|   +-- bitcoin_aes.c          # AES-256 (FIPS-197 block + CBC): wallet-at-rest cipher
|   +-- wallet_core.c          # wallet primitives glue over asm crypto (address encodings are chain-selected)
|   +-- bitcoin_mempool_policy.c # policy/RBF/fee layer + TrimToSize feerate eviction + dynamic minfee
|   +-- version.inc            # SINGLE SOURCE OF TRUTH for node wire identity (app version, user-agent, protocol version)
|   +-- gen_version_header.py  # build tool: derives C version_gen.h from version.inc
|   +-- version_gen.h          # GENERATED from version.inc (git-ignored)
|   +-- build.sh              # assemble + build + run every verification harness
|   +-- Makefile              # make asm | test | clean
|   +-- cuda/                 # optional CUDA batch-acceleration tier (crypto)
|   |   +-- cuda_sha256.cu    #   batch SHA-256 / SHA-256d kernel + host ABI
|   |   +-- cuda_sha256.h     #   opaque batch ABI header
|   |   +-- cuda_autodetect.c #   runtime auto-detect + CPU-fallback dispatcher
|   |   +-- cuda_verify.cu    #   correctness gate vs the asm oracle (PASSES)
|   |   +-- cuda_bench.cu     #   GPU/CPU throughput comparison
|   |   +-- cuda_autodetect_test.c # routing/digest matrix (all modes)
|   |   +-- Makefile          #   make verify | bench | detect | all
|   |   +-- WORKING.md        #   feasibility analysis + roadmap
|   +-- tests/                # C harnesses proving the machine code correct
|   +-- validation/           # Python big-int oracles (trusted reference)
|   +-- daemon/               # C orchestration + peer discovery/serving tools
|       +-- wallet_cli.c      # wallet CLI: addr/sign/send/sendtoaddress/balance/getnewaddress/getrawchangeaddress/getaddressinfo/validateaddress/gettxout/listunspent/decoderawtransaction/signrawtransactionwithkey + mnemonic/seed
|       +-- unified_ibd.c     # standalone bulk-download tool: chunk-claiming/work-stealing engine (same design bitcoind's own built-in dl_catchup uses)
|       +-- hole_ranges.py    # find gaps in index.dat (unified_ibd's driver)
|       +-- backfill_holes.sh # one combined-span unified_ibd call over current holes
|       +-- sync_chain.sh     # chains hole-fill into extending to the real tip
|       +-- peerstats.sh      # tail -f the live dl_catchup peer/bandwidth status log
|       +-- chainctl.c        # chunked full-chain orchestrator (resume/audit/ETA)
|       +-- check_chain.c     # integrity audit (dups/holes/corruption, chain-breaks); dup detector uses bitcoin_idx.asm's idx_put (was O(n^2), ~680x on the real archive)
|       +-- verify.c          # full chain validation (hash/chain/PoW/consensus)
|       +-- dumpblock.c       # inspect a stored block (raw bytes / header summary)
|       +-- nodecheck.sh      # one-shot health: audit + progress + serve round-trip
|       +-- chainprogress.sh  # coverage toward a complete 0..tip archive
|       +-- crawler.c         # parallel getaddr peer harvester
|       +-- addrgather.c      # getaddr -> addr/addrv2 -> peers.dat address book
|       +-- peertest.c        # verify which peers serve block bodies
|       +-- main.c            # daemon: sync / ibd / follow / serve (self-healing built-in catch-up) / server-test
|       +-- build_utxo.c      # one-shot: replay the whole archive into the LSM UTXO store
|       +-- utxo_walk.h       # shared block input/output walker (build_utxo.c + utxo_live.c)
|       +-- utxo_live.c       # live daemon's own LSM UTXO instance: single-writer catch-up in the download worker
|       +-- tx_accept.c       # live daemon's inbound tx acceptance: per-connection read-only LSM snapshot + mempool policy/txval dispatch
|       +-- tx_verify.c       # consensus verifier used for mempool admission (legacy + full taproot, confirmed set + mempool parents)
|       +-- tx_relay.c        # receive-side tx relay: fetch announced txs witness-complete, orphan pool, re-announce
|       +-- tx_index_tail.c   # daemon-maintained txindex tail over the offline base build
|       +-- coinstats_index.c # per-block incremental MuHash fold -> instant gettxoutsetinfo, continuous Core parity
|       +-- bfilter_index.c   # whole-chain BIP157/158 basic filters + filter-header chain, tip-following
|       +-- block_strip.c     # serve the witness-stripped form of a block to legacy (non-witness) peers
|       +-- addr_self.c       # self-address advertisement (external IP from agreeing peers, configured port)
|       +-- mempool_compact.c # reclaim freed bytes in the mempool blob after eviction
|       +-- chainparams.h/.c  # runtime chain selection (main / regtest): magic, genesis, ports, script schedule, address encodings
|       +-- wallet_crypter.c  # Core's BytesToKeySHA512AES KDF + AES-256-CBC sealed wallet container (seal/open/rewrap)
|       +-- wallet_enc_state.c # encryptwallet/walletpassphrase{,change}/walletlock lock-state machine
|       +-- cli.c             # thin driver for the asm cli_main
+-- data/                    # durable chain storage: ONE unified archive
|                           # (blk00000.dat..blkNNNNN.dat + index.dat + headers.dat),
|                           # the LSM UTXO store, the optional indexes, the wallet,
|                           # and logs/. Non-main chains live in data/<chain>/ .
+-- README.md
```

## Storing the chain

Blocks persist to the datadir as `blk00000.dat` (append-only framed blocks) +
`index.dat` (positional height index) + `headers.dat`, alongside the LSM UTXO
store, the optional indexes, the wallet, and a `logs/` directory. The durable
home is **`data/`** under the project root, on the `/storage` NVMe mount (ext4,
~2.6 TB free — room for a full archive node; pruned mode fits in just a few GB).

**Per-chain isolation.** Mainnet uses the datadir root; every other chain gets
its own subtree — `<datadir>/regtest/` — so a regtest run can never touch
mainnet state. `bitcoin.conf` is shared at the datadir root; logs are per-chain
and chain-tagged (`logs/bitcoind.log` on mainnet, `logs/bitcoind.regtest.log`
under the regtest subtree). A fresh non-main datadir self-seeds its own genesis
at archive index 0.

Point the daemon/CLI there:

```bash
cd /storage/bitcoinmachinecode/asm/daemon
./bitcoind sync /storage/bitcoinmachinecode/data     # download + validate + store
./bitcoind ibd /storage/bitcoinmachinecode/data      # FULL IBD as one asm pass
                                                     # (headers-first persist +
                                                     # getdata block bodies +
                                                     # validate + store)
# self-healing: discovers peers, fills any archive gap AND catches up to the
# real chain tip on its own (dl_catchup, >=8 chunk-claiming workers), THEN
# opens for inbound service -- no external tooling needed for normal operation:
./bitcoind serve /storage/bitcoinmachinecode/data 8333

# regtest: set `chain=regtest` (or `regtest=1`) in the datadir's bitcoin.conf,
# then run against a local Core -regtest node. State lands in data/regtest/:
./bitcoind serve /storage/bitcoinmachinecode/data     # port/dir/logs auto-select regtest

# standalone bulk-download tool (same chunk-claiming engine as dl_catchup),
# for a very large initial catch-up or offline reindexing:
./unified_ibd /storage/bitcoinmachinecode/data 8 <start_h> <end_h>
./backfill_holes.sh /storage/bitcoinmachinecode/data 8   # fill every current gap
./sync_chain.sh /storage/bitcoinmachinecode/data 8       # gaps, then extend to real tip
# chunked full-chain orchestrator (forward to tip, resuming + auditing each chunk):
./chainctl /storage/bitcoinmachinecode/data 8 16000 20
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

## Versioning & user-agent

The node's advertised wire identity (application version, P2P user-agent, and
Bitcoin protocol version) is defined in exactly one place:

```
asm/version.inc        # the ONLY file you edit: NODE_VERSION_{MAJOR,MINOR,PATCH},
                       # NODE_PROTOCOL_VER, and the UA prefix/suffix
```

Everything else is **derived** from it:

- `asm/bitcoind.asm` (`node_make_version`) builds the version payload the node
  sends, computing the UA string and its length at assembly time (NASM
  `%strcat`/`%strlen`) -- there are no hand-synced length/payload magic
  numbers left.
- `asm/bitcoin_p2p.asm` (getheaders) and `daemon/main.c` (level-logger HSHK
  event) read the protocol version from the same source.
- The Makefile regenerates `asm/version_gen.h` (git-ignored) from
  `version.inc` for the C consumers; the affected objects, the daemon, and the
  byte-exactness test rebuild automatically when `version.inc` changes.

**To change the version or protocol number, edit ONLY `asm/version.inc`** and
rebuild (`make daemon/bitcoind`). The current identity is
`/BitcoinMachineCode:0.0.1/` speaking protocol 70016.

> The standalone peer-masquerade tools in `asm/daemon/` (peertest, discover,
> seedprobe, crawler, addrgather, etc.) still advertise their own `/Satoshi:*`
> / `/btcasm:*` / `/peer:*` strings on purpose -- they impersonate *other*
> Bitcoin clients during probing, so they are intentionally NOT tied to this
> node's own identity.

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
