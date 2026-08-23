# EXPERIMENT LOG — Working Bitcoin Client in 100% AI-generated Machine Code

This file is the running record of the experiment. It captures every step,
hypothesis, bug, and fix so that a full engineering report can be written once
success is reached. Update it after every meaningful event.

================================================================================
LOG
----------------------------------------------------------------------------
## 2026-08-23 -- the UTXO set hash: the LIVE replay's set is Bitcoin Core's, at height 792,979

Stage D's acceptance test was "no block was rejected". It is now "the UTXO set
is provably identical to Bitcoin Core's", and the answer -- measured on the
production datadir, not a fixture -- is **yes**:

    height 792,979   ours                    Core (`gettxoutsetinfo muhash 792979`)
    txouts           102,532,574             102,532,574                    MATCH
    total_amount     19,393,405.70154310     19,393,405.70154310 BTC        MATCH
    bogosize         7,739,642,957           7,739,642,957                  MATCH
    muhash           e7e65c06...649e776a     e7e65c06...649e776a            MATCH

with **two entries' `height` field** re-hashed to the values Core's BIP30
overwrite gives them (incident #29 below). Everything else -- 102.5 million
coins, their outpoints, values, scripts, heights and coinbase flags -- agrees
exactly.

Read that count again against the one from incident #17: our raw live set at
this height is 155,001,147 entries, of which **52,468,573 are provably
unspendable** and are filtered out while iterating. The remaining 102,532,574
match Core's `txouts` to the unit. A filter that was wrong in either direction
by a single entry would have broken that.

Three independent heights, three separate UTXO sets (one of them the live
replay's own datadir), all four fields each:

    height   txouts        total_amount (BTC)      bogosize       muhash   unspendable filtered
    91,721       63,394       4,586,050.00000000     6,916,533     match          0
    200,000   2,318,056       9,999,889.98361183   175,620,421     match          0
    400,000  34,820,275      15,249,861.13306633 2,645,813,199     match    777,587
    792,979 102,532,574      19,393,405.70154310 7,739,642,957     match 52,468,573

91,721 needs NO adjustment of any kind -- it is before the first BIP30
duplicate. The other three need exactly the two-entry height correction below,
and nothing else. Height 400,000 is the first one where the unspendable filter
does real work (777,587 nulldata entries removed) and the count still lands on
Core's to the unit; 792,979 does it 52 million times.

The height-91,721 set, in full:

    height 91,721   ours                        Core (`gettxoutsetinfo muhash 91721`)
    txouts          63,394                      63,394
    total_amount    4,586,050.00000000 BTC      4,586,050.00000000 BTC
    bogosize        6,916,533                   6,916,533
    muhash          0ec1016a3232...d9b5c65b     0ec1016a3232...d9b5c65b     IDENTICAL

(with `--exclude-genesis-coinbase`, needed only because `build_utxo` built that
one; the production set does not contain the genesis coinbase, and reports
`genesis_excluded=0`.)

At height 200,000, three of those four still match exactly -- txouts
2,318,056, total_amount 9,999,889.98361183 BTC, bogosize 175,620,421 -- and the
set hash does not. The whole of that difference is **two entries**, and finding
which two is the point of the exercise. It is the same two entries at height
792,979.

### Which hash, and why the obvious one was wrong twice over

`hash_serialized_3` was the obvious target and is unusable here, for two
independent reasons:

1. **Core will not answer for it.** `gettxoutsetinfo hash_serialized_3 <height>`
   returns "hash type cannot be queried for a specific block". Only `muhash` is
   answerable at an arbitrary height, because `muhash` is what `coinstatsindex`
   stores. Our replay is never at the oracle's tip, so hash_serialized_3 had no
   ground truth at all.
2. **Our iteration order is not Core's, and not even numeric.** `mac_cmp_key`
   compares the output index with `bswap` over a NATIVE-ENDIAN u32 -- i.e. by
   its little-endian bytes. Index 256 (`00 01 00 00`) therefore sorts BEFORE
   index 1 (`01 00 00 00`). Core hashes a txid's outputs in NUMERIC index order
   (`ComputeUTXOStats` buffers them in a `std::map<uint32_t, Coin>`, which
   re-sorts regardless of the VARINT-encoded leveldb key order). Every
   transaction with 256 or more simultaneously-live outputs -- routine for pool
   payouts -- would have hashed in the wrong order, and the result would have
   looked exactly like a data corruption bug.

MuHash3072 is a multiset hash: order-independent, so reason 2 evaporates. It
is implemented in `asm/bitcoin_muhash.asm` (ChaCha20 keystream + 48-limb
modular arithmetic mod 2^3072-1103717), and it matched Core's own
`muhash.cpp` on every layer -- keystream, ToNum3072, Multiply, and whole-set
hash -- on the first run, against vectors generated from Core's code by
`validation/gen_muhash_vectors.py`. No modular inverse was needed: a snapshot
only ever inserts, so Core's denominator is permanently 1 and its `Divide(1)`
reduces to `Multiply(1)`.

One cheap trap on the way: Core renders the muhash with `uint256::GetHex()`,
which prints the digest **byte-reversed**. Our first comparison at height
91,721 looked like a total mismatch and was in fact an exact match printed
backwards.

### The 22M-entry blocker, solved without a rebuild

Our set stores provably-unspendable outputs and Core's does not (77,191,281
against 54,953,225 at height 575,833; incident #17). Filtering at write time
would only affect outputs applied afterwards, so it needs a from-scratch
rebuild to mean anything. `bitcoin_utxo_stats.asm` applies Core's
`CScript::IsUnspendable` -- leading `OP_RETURN`, or size > 10,000 -- while
ITERATING instead. Storage is untouched, the running replay pays nothing, and
the figure is directly comparable today.

### Incident #28: a BIP30 duplicate coinbase keeps the WRONG height

At height 200,000 our set hash differed from Core's while every other figure
agreed. Bisecting on height (`validation/utxo_setdiff.py`, which needs nothing
but read-only `gettxoutsetinfo`) put the first divergence at **block 91,722** --
the first BIP30 duplicate-coinbase block on mainnet.

Core's BIP30 exception path calls `AddCoin(..., possible_overwrite=true)`:
the later block's coinbase OVERWRITES the earlier identical one, so Core's
chainstate ends up holding the coin at height **91,880** (txid `e3bf3d07...`)
and **91,842** (txid `d5d27987...`). `utxo_lsm_put` returns 0 ("duplicate")
and keeps the EARLIER copy -- heights 91,722 and 91,812. `build_utxo` had been
printing `put_dup=2` for this all along.

Same txid, same index, same value, same script. Cardinality, value and
bogosize are all blind to it. **Only the set hash can see it** -- which is the
entire argument for having one. Proven rather than argued: re-hashing exactly
those two outpoints with Core's heights (`utxo_setinfo --override-coin`)
reproduces Core's muhash byte for byte at BOTH heights measured --
`169c05b5...fa3c8ced` at 200,000 and `e7e65c06...649e776a` at 792,979. Two
outpoints, one field each, and that is the entire difference between our
102.5-million-entry chainstate and Core's.

**This is a false-accept shape, not just an accounting one.** The coin's
height feeds the 100-block coinbase maturity rule. Our copy looks 158 blocks
older than Core's, so between heights 91,880 and 91,980 we would have accepted
a spend of `e3bf3d07...:0` that Core rejects as immature. It is long past, no
such transaction exists, and the coins are still unspent -- but the mechanism
(a duplicate put silently declining to overwrite) is live code, and the class
is exactly the one ASSESSMENT.md warns cannot be found by replaying the chain.

### And a second, smaller one: the two writers disagree about genesis

`daemon/utxo_live.c` excludes the genesis coinbase, with a comment saying
precisely why: Core never writes it to the chainstate, and keeping it "would
leave this node one UTXO richer than Core forever, surfacing the first time our
set is compared against `gettxoutsetinfo`". `daemon/build_utxo.c` does not.
The two writers for the same set disagree. It surfaced exactly as predicted --
+1 txout, +50.00000000 BTC, +117 bogosize -- the first time the comparison was
run. `utxo_setinfo --exclude-genesis-coinbase` compensates at read time; the
source disagreement is still there.

### Reading a datadir that is being written

`data/` is the live replay's and changes continuously: WAL appends per block,
a rewritten height file, and flushes/compactions that publish a new manifest
and unlink run files. A read that straddles any of those mixes states and
produces a plausible wrong number. `daemon/utxo_setinfo` therefore fingerprints
every UTXO file's inode/size/nanosecond-mtime plus the directory itself, twice
before the read and once after, and REFUSES on any change instead of guessing.
`utxo_lsm_reload_ro` / `utxo_store_init_ro` make the read genuinely read-only:
the ordinary reload path's `O_RDWR|O_CREAT` on utxo.dat/utxo.idx was the only
write in the entire chain, and it is now the one thing substituted.

`mac_lsm_recount`'s k-way merge was reused rather than re-implemented -- it
already visits exactly the live set, newest generation wins, memtable- and
tombstone-aware -- with an optional visitor invoked at the exact instruction
that increments the counter, so the visited set and the counted set cannot
drift apart.

----------------------------------------------------------------------------

## 2026-08-23 -- schnorr_verify was not thread-safe: a LATENT false-reject, armed for the moment taproot verification is parallelised

> **Correction, 2026-08-23 02:40.** This entry was first written -- and first
> reported to the user -- as a *live* bug corrupting concurrent taproot
> verification in production. That was wrong. `schnorr_verify` is reachable
> only via `bitcoin_taproot_sighash.c` -> `taproot_verify_input`, and **both**
> call sites in `daemon/tx_verify.c` (`:593`, `:1220`) run in a sequential pass
> *after* the worker threads join -- the workers skip `TXV_SHAPE_P2TR`
> outright. Nothing in production calls `schnorr_verify` concurrently today,
> so nothing was being corrupted. The bug, the reproducer and the fix below
> are all real, and the fix was worth deploying: it disarms a trap that fires
> the instant the P2TR skip is removed -- which PERF_SCOPE.md section 14 now
> argues is the single largest performance win available. What follows
> describes a hazard, not an outage. The lesson is the one this log keeps
> re-learning: a call-graph claim needs the call graph checked, not inferred
> from the callee.

Found while optimising `secp256k1_schnorr.asm` (PERF_SCOPE.md section 13), by
reading the file rather than by a failing test -- nothing in the suite called
`schnorr_verify` from more than one thread. Then reproduced, because "I read
the code" is not a measurement.

### The bug

`schnorr_verify` built the BIP340 challenge preimage --
`tagged_hash("BIP0340/challenge", r || pk || m)` -- in a **process-global
`.data` buffer**, `schnorr_preimg`. `asm/daemon/tx_verify.c` verifies a block's
inputs on worker threads (`bmc_pthread_create` at `tx_verify.c:451` and
`:955`). Two taproot key-path inputs verified at the same moment therefore
wrote over each other's preimage, and each computed the OTHER's challenge `e`.

A wrong `e` gives a wrong `R = s*G - e*P`, so `x(R) != r` and **a perfectly
valid signature is rejected**. A rejected valid signature inside a block is a
rejected valid block.

### Reproduced, not inferred

8 threads x 20,000 verifications of the official BIP340 vectors -- signatures
the same binary accepts single-threaded:

    all 4 fixtures verify single-threaded
    8 threads x 20000 verifications of KNOWN-GOOD signatures: 1982 FALSE REJECTS

After moving the preimage into `schnorr_verify`'s own stack frame: **0**.

### Direction of the failure, and why that matters

False REJECT, not false accept. For a corrupted preimage to make a signature
verify, the corrupted challenge would have to be the one that particular
signature commits to -- a ~2^-256 accident. So this is a liveness / chain-split
bug rather than a "coins can be stolen" bug. It is also exactly the shape that
surfaces in a replay as an unexplained "block rejected" and gets blamed on
something else, which is why it is written down here in full.

### Why the existing tests missed it

The 2026-08-19 thread-local-storage conversion (`bitcoin_scriptverify.c`'s 8
`__thread` buffers, `bitcoin_interp.asm`'s 6 TLS labels,
`bitcoin_sighash.asm`'s `legacy_sighash_scfbuf`) went through the interpreter's
scratch state and had `tests/test_scriptverify_thread_stress.c` written for it.
It did not reach the secp256k1 layer.

### Fix, and what is NOT fixed

Fixed: the preimage now lives in `schnorr_verify`'s frame (320 bytes), and the
message length is bounds-checked against that capacity and REJECTED cleanly if
it does not fit -- previously an over-long message silently overflowed the
`.data` buffer, the same failure mode `tap_leaf_hash` was hardened against on
2026-08-21. Consensus only ever passes 32 bytes; BIP340 allows any length and
the official vectors go to 100.

Regression test: `tests/test_schnorr_thread_stress.c`, in `make test`, and
`scripts/mutate_check.py`'s `schnorr-preimg-back-to-a-global` mutation, which
puts the global buffer back and confirms the test fails.

**NOT fixed, same bug class, still live:** `secp256k1_taproot.asm` keeps
`tagh_buf` (32 B) and `tap_preimg` as process-global scratch -- its own header
calls them "single-threaded global" -- and they are on the taproot verify path
(`tagged_hash256`, `tap_branch_hash`, `tap_leaf_hash`, `tap_merkle_root`),
which the same worker threads reach for every script-path spend. That is a
separate change with its own tests and is not folded into a performance
branch.

## 2026-08-23 -- incident #28: SETcc writes eight bits, and eleven numeric opcodes pushed the OPERAND back

The live replay stopped dead at height 792,980:

    REJECT h=792980 tx=2941: p2wsh script verification failed

Transaction `c85311c12c70351948bf15c76963c9e5ae54831733bfa267692888b780a70876`
is a P2WSH 1-of-7 built out of CHECKSIG + OP_ADD instead of OP_CHECKMULTISIG:
seven `OP_CHECKSIG`s -- six of them deliberately fed an EMPTY signature so they
push false -- summed with `OP_ADD`, then

    OP_IF <400000> OP_CHECKLOCKTIMEVERIFY OP_0NOTEQUAL OP_ELSE OP_0 OP_ENDIF
    OP_ADD OP_2 OP_EQUAL

Everything about that description invites the wrong hypothesis. The empty
signatures look like incident #25's strict-DER work; the seven separate CHECKSIG
call sites look like a place a `-1` hard error could leak from one of them; the
CLTV-inside-OP_IF looks like incident #16's zeroed tapscript context. All three
were wrong. The interpreter's own error code was **SCRIPT_ERR_EVAL_FALSE** --
nothing aborted, the script ran to the end with exactly one element on the stack
and that element was false. The arithmetic was simply wrong.

### The mistake

`bitcoin_interp.asm`, `.mono_common` / `.bin_common`. r14 (and r15) hold the
**decoded 64-bit operand**. The result was computed straight on top of it:

    .mo6:  test  r14, r14
           setnz r14b            ; <- writes EIGHT BITS

`SETcc` has an 8-bit destination. The other 56 bits of the operand survive into
what gets pushed. 400000 is `0x061A80`; `setnz` made it `0x061A01` = **400129**,
not 1. `OP_ADD` then gave 400130 and the `OP_2 OP_EQUAL` was false.

For operands 0..255 the answer comes out right by accident, which is why this
survived 792,979 blocks, `tests/test_interp`, `tests/test_script` and every
synthetic vector in the tree: nobody had written a test whose numeric operand
reached 256. The real chain did it at 792,980.

Eleven handlers had the same shape -- `OP_NOT`, `OP_0NOTEQUAL`, `OP_BOOLAND`,
`OP_BOOLOR`, `OP_NUMEQUAL`, `OP_NUMEQUALVERIFY`, `OP_NUMNOTEQUAL`,
`OP_LESSTHAN`, `OP_GREATERTHAN`, `OP_LESSTHANOREQUAL`, `OP_GREATERTHANOREQUAL`.
Wrong for **every operand of magnitude >= 256 and every negative operand**.

### It was a FALSE ACCEPT too, and that is the worse half

A false reject stops the replay and announces itself. This bug also went the
other way, silently:

    <256> OP_NOT                  we pushed 256 (TRUE)   Core pushes 0 (false)
    <256> <512> OP_NUMEQUAL       we pushed 256 (TRUE)   Core pushes 0
    <256> <512> OP_NUMEQUALVERIFY we left 256, OP_VERIFY cast it to true and the
                                  script PASSED; Core fails it
    <-1>  OP_NOT                  we pushed 0xFF..FF00 (TRUE)   Core pushes 0

Measured, not argued: 63,036 scripts driven through Core's own `VerifyScript`
and this interpreter side by side gave **11,780 divergences on main -- 5,050
FALSE ACCEPTS and 6,730 false rejects** -- and 0 after the fix. A fix that only
made block 792,980 pass would have left the false-accept half of a chain split
wide open.

### The fix

`movzx r14, r14b` after every `SETcc`, in all eleven arms. Core's every one of
these opcodes is a bool: exactly 0 or 1.

`OP_WITHIN` writes `SETcc` the same way and is **correct** -- it ANDs against a
register it zeroed first, which masks the answer back down to 0/1. Correct by
construction rather than by intent, so it is left alone and swept by the new
test instead, where a future edit that removes the mask will be caught.

### The reproducer

`tests/test_scriptnum_bool` (8 assertions), fixtures from
`validation/fetch_scriptnum_bool.py`:

  * the real mainnet transaction at its real height and block hash -> ACCEPT;
  * the same transaction with one byte of its ONE real signature flipped ->
    REJECT with the exact reason string the replay printed, so "accept
    everything" cannot pass this file;
  * a sweep of **4,683 pure-arithmetic P2WSH scripts** across the 255/256 and
    0/-1 boundaries -- 2,149 that Core ACCEPTS and 2,534 that Core REJECTS,
    every verdict taken from Core's own `VerifyScript` before being baked --
    asserted in **both directions**.

All of it at **both** block-connection entry points, `tx_verify_block_connect`
and `tx_verify_block_connect_all`, per incident #22's lesson.

FAIL-THEN-PASS against main's `asm/bitcoin_interp.asm`: 6 of 8 assertions fail
-- the real block rejected at both entry points, and at each entry point **497
false rejects + 402 false accepts** out of the sweep. 8/8 with the fix.

    make -k test : MAKE_RC=0, zero failures, 151 binaries
    make abi-check : OK, 1029 external call sites, RSP == 0 mod 16
    make callee-saved-check : OK, 353 functions

### What to take from it

The bug is one instruction wide and it is a **register-width** bug, not a
consensus-rule bug. `make abi-check` and `make callee-saved-check` audit frames;
nothing audits "did this 8-bit write want to be a 64-bit one". Every other
`SETcc` in the tree was checked by hand while this was written --
`bitcoin_scriptcodec.asm`, `bitcoin_sighash.asm`, `bech32.asm`,
`bitcoin_bip32/39.asm`, `bitcoin_chainwork.asm`, `sha256.asm` -- and all of them
either write to an already-zeroed register, to a byte-typed memory location, or
feed a mask; the interpreter's numeric arms were the only instances.

## 2026-08-23 -- incident #27: twenty-one functions returned the caller's callee-saved registers full of their own locals

`make abi-check` passed. `make test` passed. The consensus interpreter had been
handing every caller five wrong registers for as long as it had existed, and the
only thing standing between that and corrupted script evaluation was a `-O0` in
the Makefile that nobody had recorded as load-bearing.

### The mistake, once, in twenty-one places

    push rbp
    mov  rbp, rsp
    push rbx / r12 / r13 / r14 / r15    <- save area at rbp-0x08 .. rbp-0x28
    sub  rsp, N
    ...
    lea  rdi, [rbp-0x30]                <- a 32-byte buffer that grows UP
    call sha256_full                    <- ... straight through the save area

Putting the callee-saved pushes AFTER `mov rbp,rsp` places the save area
*between* `rbp` and the locals. Every local at `[rbp-N]` for small N is then
sitting on a saved register, and every buffer addressed from the low end grows
into one. The epilogue's `pop`s hand the caller digest bytes, interpreter state
or log text.

`script_eval` (`bitcoin_interp.asm`) was the worst: it pushes all five and then
documents locals at exactly those five offsets -- `-0x08 fExec, -0x10 pc,
-0x18 pend, -0x20 pbegincodehash, -0x28 nOpCount`. It is entered for every input
of every transaction in every block.

`node_log_str` (`node_log.asm`) was the only one firing in the LIVE daemon.
Its 48-byte line buffer at `[rbp-48]` had 16 usable bytes before the save area;
`daemon/main.c` logs lines of up to 42 characters. Every log line the node wrote
destroyed the caller's rbx, r12, r13 and r14 and corrupted the low bytes of
saved rbp. Measured, not inferred: a 22-byte message returns CLOBBERS r13 r14, a
42-byte one CLOBBERS rbx r12 r13 r14.

### The fix

Move the pushes above `push rbp` in all twenty-one. The save area moves to
`[rbp+8 ...]`, every `[rbp-N]` local is inside the function's own reservation,
and the aliasing becomes structurally impossible rather than currently-harmless.

Nineteen of the twenty-one were demonstrably defective -- nine measured
directly with `tests/bench_abi_guard.S`, ten proved by arithmetic (a write of
known size onto a save slot at a known offset). The other two,
`node_log_event` and `cmd_getbalance`, share the frame shape and the same
epilogue but had enough slack not to be firing; they are converted with their
neighbours rather than left as the one remaining instance of the pattern in
their file.

**No frame was resized** except `node_log_str`, whose buffer went 48 -> 128 (a
multiple of 16, so the parity is unchanged) because at 48 the longest current
log line fitted exactly with zero slack.

**Alignment is untouched.** Reordering pushes is parity-neutral: the same six
pushes and the same reservation, so RSP has the same value mod 16 at every
instruction after the prologue. Proof obligation discharged mechanically -- the
full 253-line per-function table from `scripts/abi_stack_audit.py --format
functions` is BYTE-IDENTICAL before and after, including all 215 call sites in
`script_eval` and the compensated `siphash24_uint256.sipround2`. Incidents #18
and #20 are undisturbed.

### Why `make abi-check` never saw it

Because it audits a different property. RSP *alignment* at call sites (#20) and
callee-saved register *preservation* are independent; the tree was clean on one
and broken on the other. Two guards now, both in `make test`:

- `make callee-saved-check` -- `scripts/abi_callee_saved_audit.py`, static,
  whole tree, 353 functions. Abstract-interprets each frame and fails on any
  register left unrestored at a `ret` or any provable write into a live save
  slot. It also prints a ranked "headroom" risk list (frame buffers that grow
  toward a save area, ordered by how little slack they have). Twelve of the
  twenty-one came out of that list; `node_log_str` was the smallest headroom in
  the tree.
- `asm/tests/bench_abi_audit` -- runtime, six sentinels, real arguments. Now
  reports **14 clean, 0 violating**, and exits non-zero otherwise.

Mutation-tested both, on instructions rather than comments. Reverting
`script_eval`'s prologue to the aliasing order: `bench_abi_audit` -> `CLOBBERS
rbx r12 r13 r14 r15`, exit 1; the static check -> `SAVE-AREA-ALIAS`, exit 1;
`make abi-check` -> still OK, which is the point. Reverting `node_log_str`, a
function `bench_abi_audit` does not probe: only the static check catches it.
The static check also caught a mistake made DURING this fix -- an over-broad
epilogue substitution that rewrote `cmd_getbalance`'s pops without its pushes.

### The Makefile's optimisation folklore was this bug

`daemon/pverify` is pinned to `-O1` with the comment that the `cons_verify ->
tx_parse / sha256d` chain "misparses a block when the C driver is compiled at
aggressive -O2+, a documented codegen interaction". There is no codegen
interaction. A harness replaying that chain over `block413567.raw`:

| build | pre-fix | post-fix |
|---|---|---|
| `-O0` | 400 blocks, 0 bad, acc 121800 | 400 blocks, 0 bad, acc 121800 |
| `-O1` | 400 blocks, 0 bad, **acc 504** | 400 blocks, 0 bad, acc 121800 |
| `-O2` | **400 blocks, 400 bad** | 400 blocks, 0 bad, acc 121800 |
| `-O3` | **400 blocks, 400 bad** | 400 blocks, 0 bad, acc 121800 |

`-O2` put a live value in `r13`; `pow_check` destroyed it; the verifier called
every block invalid. `-O1` was not safe either -- right verdict, corrupted
accumulator, which is the worse failure mode. Post-fix all four levels agree.

**The build flags are deliberately NOT changed here.** Changing the optimisation
level of consensus code deserves its own change, its own differential and its
own deploy. What is established is only that the stated reason for the pins no
longer holds.

### Still open

`scripts/abi_callee_saved_audit.py --format exposed` lists ~600 sites where a
frame buffer still grows toward a save area with the pushes below `rbp`. None
of them is a proven defect -- whether a buffer reaches depends on its length,
which is not statically knowable -- and the smallest remaining headroom is 20
bytes against an 8-byte write. They are the risk list, not the failure list, and
they are cheap to eliminate one file at a time with the same edit.

## 2026-08-22 -- test infrastructure: the suite shared one working directory; now every harness owns its own

The storage layer opens its files by BARE RELATIVE NAME -- `index.dat`,
`blk%05u.dat`, `prune.dat`, `utxo.dat`, `utxo.idx`, `utxo_manifest.dat`,
`utxo_run_%06u.dat`, `headers.dat`, `chainwork.dat`, `peers.dat` (see
`bitcoin_store.asm:1798`, `bitcoin_utxo_store.asm:102`,
`bitcoin_utxo_lsm.asm:237`, `bitcoin_headers.asm:223`,
`bitcoin_chainwork.asm:771`, `bitcoin_addrmgr.asm:343`). That is a deliberate
property of a daemon that is pointed at a datadir and runs there. It is a trap
for a test harness, which `make` runs with CWD = `asm/`.

### What was actually shared

Measured, not guessed: every one of the 142 `make test` invocations was run
individually with a before/after snapshot of `asm/`.

- **Writes into the source tree.** `test_serve` left `index.dat`,
  `blk00000.dat`, `utxo.dat`, `utxo.idx`; `test_keepup`, `test_bip152_loop` and
  `test_sendheaders_fee` left `index.dat` + `blk00000.dat`. Those files persist
  between runs, so `make test` in a used tree is not `make test` in a fresh
  clone.
- **Absolute paths into the MAIN checkout.** `test_archive_check` built its
  fixture in `/storage/bitcoinmachinecode/asm/t_archchk` and `chdir`ed back to
  `/storage/bitcoinmachinecode/asm` at the end -- so a run from a git worktree
  reached across into the main tree, and two concurrent runs `rm -rf`'d each
  other's fixture. `test_node_config` wrote 21 `bmc_t*.conf` fixtures the same
  way, and read the main checkout's `config/bitcoin.conf` -- a file with 21
  uncommitted lines in it at the time -- to decide a PASS.
- **Fixed names outside the tree.** `/tmp/clitest`, `/tmp/amrtest`,
  `/tmp/shared_test`, `/tmp/shared_test2`, `/tmp/test_log.txt`,
  `/tmp/b30shim.out` -- one copy for all runs on the box.
- **Leaks.** 34 harnesses `mkdtemp`'d and never removed the directory;
  `test_reorg` leaked 13 per run (one per forked case). `/tmp` had accumulated
  thousands.

### The order dependence was real, and it was invisible

`test_keepup` builds 7 blocks, has a peer push an 8th, and checks the node
stores it. Before this change it logged `stored height=8`; after, `height=7`.
The 8 was `test_serve`'s leftover archive: `store_init` found the stale
`index.dat`, and keepup appended past it. **The test passed either way** -- 9
PASS lines in both -- because no assertion pinned the height. That is the shape
of the hazard: not a flaky red, an invisible green.

### The fix

`asm/tests/test_tmpdir.h`: `tt_isolate()` as the first statement of `main()`
`mkdtemp`s a private directory, `chdir`s into it, and removes it on **every**
exit path -- `atexit` plus `SIGSEGV`/`SIGABRT`/`SIGBUS`/`SIGILL`/`SIGFPE`/
`SIGTERM`/`SIGINT`/`SIGHUP`/`SIGQUIT`/`SIGPIPE`, re-raising with the default
disposition so the wait status a parent sees is unchanged. Two details that
matter:

- **The cleanup is PID-guarded.** A forked child inherits the `atexit` list and
  the handlers; without the guard a child that `exit()`s or crashes would
  delete the *parent's* working directory out from under it. Several harnesses
  (`test_serve`, `test_keepup`, `test_utxo_crash_recovery`, `test_reorg`) fork
  children that die on purpose.
- **The removal walk is `getdents64`/`unlinkat` on a descriptor**, not `nftw()`
  and not `system("rm -rf")`: no allocation, no fork, safe from a `SIGSEGV`
  handler, and structurally incapable of escaping the directory it was handed.

`tt_src("...")` rebases fixture/daemon/shim paths onto the launch directory so
they still resolve past the `chdir`; `tt_workdir()` hands the absolute path to a
spawned daemon that takes a datadir argument (`test_outbound_mux`,
`test_redial`); `tt_subdir()` gives a multi-phase harness a fresh empty datadir
per phase. `BMC_TEST_TMPDIR` moves the root off `/tmp` (these write real block
data); `BMC_TEST_KEEP` preserves a directory for post-mortem. 51 harnesses
converted, 34 hand-rolled `mkdtemp` blocks deleted.

### Proofs, not assertions

Every whole-suite figure below is over the 144 invocations this branch's own
work covers; the rebase onto `0832d54` brought in two more (`test_point_repr`,
`test_taproot_bounds_fuzz`, neither of which touches a file), so the count in
the tree is **146**, re-verified after the rebase.

- **Order.** Two full shuffled runs (seeds 1701 and 90210): 144/144, zero
  failures.
- **Fresh clone.** The tracked files copied to a tree that has never held a
  `.dat`, built from scratch, full suite: 144/144, and the tree is bit-identical
  to its checkout afterwards.
- **Concurrency.** `test_serve` + `test_keepup` + `test_bip152_loop` started
  simultaneously in `asm/`: on `main` `test_serve` fails with 2 assertion
  failures, three trials out of three. On this branch all three pass, three out
  of three. And the whole suite now runs in parallel: `-P 8` gives 144/144 in
  **2m21 against 6m12 serial, 2.7x** -- a property that did not exist before.
- **The failure mode that started this.** Deleting `index.dat`/`blk00000.dat`
  every 20 ms while `test_serve` runs: `main` -> `rc=1`, `FAIL all served blocks
  byte-exact`, `FAIL multi-inv getdata`. This branch -> `rc=0`, 0 failures.
- **Suite.** `make -k test` MAKE_RC=0, zero failures; `make abi-check` OK;
  `asm/` contains no generated data file afterwards and `/tmp` holds no
  leftover directory.

### Two tests were built and never run

`tests/test_node_config` and `tests/test_sigops` were listed as prerequisites of
the `test` target -- so they compiled, and a break in them would have been
caught -- but no line of the recipe invoked them. Both pass, and both are now in
the recipe. That is why this commit adds 2 to the invocation count. The count is
now documented in `docs/ENGINEERING.md`, with the one-line command to check it:
a test that stops running looks exactly like a test that passes, and this is the
third instance today.
## 2026-08-22 -- Incidents #6-#25; verify path 5.7x faster end-to-end; genesis was never in the archive; every stop had been a SIGKILL

A continuous ~16 h session (08-21 evening into 08-22 morning), the second
half under a standing "deploy, restart, drop and rebuild as needed, update
the docs at the end" authorization with the user asleep. Terse action log
with hashes: `worklog/2026-08-21.md`, `worklog/2026-08-22.md`. Profiles and
benchmark tables: `PERF_SCOPE.md`. This entry is the narrative, including
the mistakes.

### Real production incident #6: genesis was not in the archive, so every buried soft fork activated one block late (false-accept)
Found while wiring blockchain-query RPCs (`090a109`): `index.dat` record 0
was `00000000839a8e...` -- block 1. Confirmed against the scratch Core
oracle across the whole archive: record index == real height - 1,
everywhere. `utxo_live_catchup` hands that index to `apply_block_at` ->
`script_flags_for_block`, so linking the real `bitcoin_script_flags.o` and
asking it directly showed DERSIG (363725), CLTV (388381), CSV (419328) and
NULLDUMMY (481824) each MISSING their flag bit at their own activation
block. For exactly one block per boundary we applied looser rules than
Core: a chain-split in the accept direction. It is also structurally
invisible to Stage D's replay -- looser rules accept a superset, and real
chain data is valid under the strict rules anyway -- which is a genuine
limit on what a clean replay proves. The user's proposed fix (re-download
the chain) could never have worked: the P2P "from the beginning" locator is
the all-zero hash and peers answer from block 1; genesis is never
transmitted (`bitcoind.asm:1247` already documents the symptom). Fixed by
injecting genesis from its constant: 285 bytes appended to the last blk
file, `index.dat`/`headers.dat` shifted one record, `chainwork.dat`
dropped and rebuilt (963,447 records). The 1.5 TB of block bodies never
moved. Re-verified: index hash, body, header record and `getblockhash`
agree at 12 heights including 0. `apply_block_inner` now skips genesis's
coinbase (Core never adds it to the chainstate) -- matched by HASH, because
a `height == 0` guard broke two synthetic-chain tests whose height 0 has
spendable outputs. `5f36dee`. The in-flight replay was invalidated and
restarted from block 0.

### Incident #7 (latent, found by a differential): two lost carries in `sc_mul` and `fe_mul`
Building the 4.2 variable-time inverse's differential fed `sc_inv`
structured inputs for the first time. `sc_mul`'s MULACC propagated a carry
two limbs and dropped it when limb k+2 was 0xFFFF...; `fe_mul`'s fold-2
dropped the carry out of limb 3. On the OLD code `sc_inv(6)` is wrong
outright (checked against `pow(6,-1,n)`), `sc_inv(n-k)` wrong for
4095/4096 small k, `fe_inv(p-k)` for 1607/4096 -- and 200,000 random
`a*inv(a)==1` trials pass on that same old code, because random operands
hit the condition at ~2^-64 and ~2^-190. That is the whole story of why
the random differentials that have guarded this code since 08-11 never
saw it. Direction: fail-closed (a wrong `s^-1` rejects a valid signature;
it cannot forge one). `54cc988`, with the exact operand pairs pinned in
`tests/test_mul_carry_regression.c`.

### Incident #8: the mmap "bug" that was a SIGKILL, and a destroyed reproducer
`e199952` (PERF_SCOPE 4.1) replaced `mac_run_lookup`'s per-lookup,
per-run "open, read the ENTIRE 4 MiB bloom to test 3 bits, lseek/read,
close" with a per-thread cache of read-only mmaps: 88 % fewer syscalls.
Deployed 02:29. On its very first checkpoint resume (02:32, from 318147)
the daemon rejected 318148 with "input references a missing/already-spent
UTXO". The coordinator attributed it to the new read path, set the
`BMC_LSM_MMAP=0` kill switch -- and, 45 seconds later, dropped the UTXO
state to start the from-scratch run the user had asked for. That
destroyed the only reproducer. Mistake, recorded as a gate: snapshot
utxo_*/undo_* before any drop.

The investigation then could not reproduce anything: the C path was read
line-by-line against the assembly (u64 offsets, record advance,
`mac_cmp_key`'s bswap == `memcmp`, identical FNV bloom/seeds/bit index);
a real coverage gap was found (the differential used `fill_threshold=1`,
so no run had ever had a sparse index and the C binary search had never
run) and closed with sparse/compaction/reload/bloom-saturated
differentials and a 180k-lookup soak -- all 0 mismatches; and a new
read-only `tests/diff_real_run` was pointed at the four real production
runs the rebuild had produced by then (18M records each, bloom at the
4 MiB cap, sparse_n ~70k): 80,000 keys, 0 mismatches. `b41f711`.

The actual cause came from `journalctl -u bmc-bitcoind.service`: EVERY
stop during a replay -- 21:24:39, 01:16:00, 02:30:44, 02:37:18, 02:40:12
-- ended in `State 'final-sigterm' timed out. Killing ... SIGKILL` at
systemd's 90 s default. The replay is one `utxo_live_catchup()` call that
runs for hours, and its per-block loop never read `g_shutdown_requested`.
The 02:30:44 kill hit the OLD (pre-mmap) worker between "block 318148's
spends are in the WAL" and "checkpoint 318148 persisted"; the new process
reloaded state one block ahead of its checkpoint and correctly reported
318148's inputs as spent. `2fd4a14`'s comment that re-applying is safe
("duplicate put / redundant tombstone are non-error") was true of the
storage layer and false once Stage D verifies BEFORE applying. mmap was
innocent; the resume path was the bug, and it had been since Stage D.

Two fixes: `f2faf3b` -- the loop polls the flag per block, finishes the
block, persists, starts no compaction, returns (`systemctl stop` went from
90.23 s + SIGKILL to 10.05 s, measured, no "Killing" in the journal);
`96b555e` -- on boot, `undo_<applied+1>.dat` existing means that block
began and never checkpointed, so restore its captured prevouts, delete
its created outputs, let catch-up re-apply it. Three crash-injection
scenarios incl. flush-mid-block give a set byte-identical to a
never-crashed reference; the negative control reproduces the production
line verbatim. The fix then proved itself unplanned: the deploy's own stop
was the last 90 s SIGKILL, it landed mid-block 343087, and boot logged
`RECOVERY: rolled back partially-applied block 343087 ... 147 prevout(s)
restored` and resumed with zero rejects.

### Incident #9 (caught by the suite before deploy): GLV segfault from stack misalignment on the CHECKMULTISIG path
GLV + wNAF (`5023fdf`..`127ae2b`) passed 102,056 projective point cases,
the 113,315-case verify campaign and 30,240 switch cases, then
`test_scriptverify_parity` segfaulted: `glv_wnaf` (gcc-compiled C) entered
with `rsp == 8 mod 16` from the all-asm `interp_checkmultisig ->
sv_checksig -> ecdsa_verify` chain, and a `movaps` spill faulted. The
direct-call harnesses had been aligned by luck. `and rsp, -16` after the
frame (`3b00f63`), robust to either caller parity. Lesson, same as the
earlier `utxo_lsm_mm.c` hook: any asm frame that calls C must align
itself, not trust its caller.

### Also this session
- 4.2 A+B (`9e11146`): `ecdsa_verify` 115 -> 56 us; 4.3 GLV (`da3e683`):
  56 -> ~39 us (44 vs 69 on the loaded box). libsecp256k1 on this CPU,
  measured: 21.8 us. Gap 5.2x -> 2.6x -> ~1.65x.
- End-to-end, identical heights 343087->363086 vs the 08-21 14:37 baseline:
  7.8 -> 34.1 blk/s, **4.39x**. Almost all of that is the mmap fix: with
  mmap off, 300-340k had collapsed to 1.04-1.08x as bloom copies grew.
  GLV moved verify 1.56x and the replay 0x -- post-GLV profile: kernel 5 %
  (was 31-38 %), crypto 74 %, `fe_mul` 56 %. The field multiply is the
  last wall.
- `test_scalarmul_ct` was a wall-clock coin flip (1.001/1.177/0.996/0.743
  on unchanged main) AND could not detect an injected 4 % timing leak;
  now CPU-time min-of-40 at +-3 %, 70/70 under load, catches the leak
  3/3 (`879554b`). Seven test binaries were tracked in git and ran stale
  after `git checkout --` (`860630c`).
- Taproot: `OP_CODESEPARATOR` position in the tapscript sighash
  (`b2ccb2d`); the old byte-level `0xab` scan also rejected pubkeys
  containing that byte.
- 9 blockchain-query RPCs (`090a109`). Scratch Bitcoin Core at
  `/storage/core-oracle` is now an authorized development oracle (the
  production install stays off-limits).

### Incident #10: the archive was witness-stripped for the entire segwit era (~482,000 blocks)

At 06:13 the from-scratch replay -- every fix of the night deployed --
rejected the first segwit block, 481824, tx 562: `p2wpkh needs exactly 2
witness items`. The Core oracle shows that input has exactly 2. So the bytes
we verify differed from the bytes Core has, and block 481824 is the first
block in history where a witness-bearing transaction could possibly be
parsed. Comparing `index.dat`'s `data_size` against Core `getblock`: ours
equals Core's `strippedsize` -- never `size` -- at 481824, 481900, 500000,
550000. **Every block from segwit activation to tip was stored without its
witness data.**

Cause: `p2p_getdata_block` (`bitcoin_p2p.asm:103`) requested inventory type
`MSG_BLOCK` (2). Per BIP144 a peer answers that with the non-witness
serialization. The merkle root commits to txids, which are computed over
that same stripped form, so `cons_verify` accepted every stripped block,
"integrity OK" was true of headers and hashes and hollow for bodies, and
`cuda_txid_reindex`'s "merkle OK" never could have caught it. Core *would*
have rejected each of those blocks on arrival -- `bad-witness-nonce-size`
-- because Core validates the BIP141 coinbase witness commitment. This node
did not. Two bugs, then: the request type, and a missing consensus check.

Three more turned up while fixing the first. `test_serve` failed the moment
the client asked with `MSG_WITNESS_BLOCK`: the **server** dispatch compared
the raw type against 1/2/4, so a witness request matched nothing and was
silently ignored -- this node could not serve a block to any current peer.
And the inbound-inv keep-up path built its own getdata inline with type 2,
so even after an archive repair every *new* tip block would have arrived
stripped again. All in `bitcoin_serve.asm`.

Fixes: `31eac9a` (`MSG_WITNESS_BLOCK` in `p2p_getdata_block` + the
byte-exact test), `fe3addb` (server masks the witness flag before dispatch;
keep-up requests `MSG_WITNESS_BLOCK`), `191df6c` (BIP141 witness-commitment
validation in `daemon/block_witness.c`, called before any signature work --
mirrors `validation.cpp` `CheckWitnessMalleation`, gated on the segwit
deployment height as Core does). Its decisive test feeds it the **exact
stripped bytes of 481824 that our archive held** and gets
`bad-witness-nonce-size`; one flipped witness byte gets
`bad-witness-merkle-match`; a commitment removed with witnesses kept gets
`unexpected-witness`.

Recovery, without a from-scratch replay: the UTXO checkpoint at 481823 is
valid (no witness data exists below segwit). `index.dat` and `chainwork.dat`
were truncated to 481824 records (backups `*.pre-witness-truncate` in
`/storage/bmc-archive-backup-20260822`); 359.8 GB of stripped bodies became
dead space in the blk files (reclaimable later by the file-granular prune).
Re-downloading 482k blocks over the internet would take days, so the local
Core oracle was moved to loopback 8333 (`listen=1`, bound to 127.0.0.1 only
-- the downloader hardcodes 8333, `paribd.c:58`) and the node configured
`connect=127.0.0.1`. First re-fetched block: 481824 at 989,323 bytes ==
Core's `size`. One peer meant one download worker (~14 MB/s); the oracle now
binds sixteen loopback aliases and the node connects to each, one worker
per peer. `stopatheight` tracks the oracle's own IBD height and must be
raised as it advances, then removed with `connect=` once the archive is
complete.

Not fixed yet, in `FEATURE_GAPS.md`: prefer `NODE_WITNESS` peers; serve the
stripped form to a bare `MSG_BLOCK` request (no such peers exist any more);
`MSG_WITNESS_TX` for transaction relay -- the mempool path has the same
shape of bug.

The lesson is the one from #6 again, sharper: a replay that runs clean is
evidence only about the checks that exist. Every tool that "verified the
archive against Core" compared headers and txids -- exactly the fields that
do not change when witnesses are stripped.

### Incident #11: the first real P2WPKH spend failed -- our BIP143 scriptCode was the witness program

With the archive witness-complete, the replay resumed at 481823 and rejected
481824 tx 562 again, now with `p2wpkh signature invalid`. The block bytes
are identical to Core's and the new commitment check passed, so the data was
right and the verifier was wrong. `p2wpkh_verify` (`bitcoin_segwit.c`) handed
`segwit_v0_sighash` the 22-byte program `0014<hash160>` as the scriptCode.
BIP143 -- and Core's `VerifyWitnessProgram` -- use the implied P2PKH script
`76a914<hash160>88ac`, so the preimage carries `1976a914...88ac`. Every other
field was correct.

Why nothing caught it: the synthetic vectors were made by
`validation/gen_modern_vectors.py`, which made the *same* assumption, and a
second fixture (`tests/multi_p2wpkh_vec.h`, 10 genuine P2WPKH inputs) came
from a `/tmp` script that copied it. A verifier and its vector generator
agreeing byte-for-byte proves nothing if they share a premise. No real
P2WPKH input had ever reached this code -- the archive was stripped.

Root-caused differentially: `validation/bip143_ref.py` reproduces BIP143's
own worked example first, then computes the real tx's sighash both ways;
the real signature verifies only with the P2PKH scriptCode. Fixes `b3800f0`
(verifier, generator, `test_segwit_sighash` helper; `modern_vec.h`
regenerated -- P2WSH/P2TR unchanged, as they should be) and `b6c92fa`
(`validation/gen_multi_p2wpkh.py` now lives in the repo and reuses the main
generator's helpers; the regenerated fixture is rejected by the old verifier
and the old fixture by the new one). `tests/test_p2wpkh_real.c` pins the
real transaction: sighash `32f2913c...a9a6`, verify == 1. Blocks below
481824 cannot contain P2WPKH inputs, so nothing already validated moves.

Operationally: the Claude session itself died at ~07:25 (no OOM, no crash
dump, no reboot -- client/API side), with the fix committed in its worktree
and the daemon idle; resumed at 09:56. The session's background deploy chain
had survived and was still waiting; killed.

### Incident #12: nested segwit was not implemented, and three bugs underneath it

Block 481824 -- the first real native P2WPKH spend -- passed. Block 481825,
tx 1668, failed `legacy script verification failed`. Its input 1 is a P2SH
prevout whose scriptSig is one push of `0014<hash160>` with a two-item
witness: **P2SH-P2WPKH**, the form nearly every wallet used from 2017 to
2019. The dispatch (`daemon/tx_verify.c`) classified any P2SH prevout as
legacy and ran the redeemScript as an ordinary script; it never executed the
wrapped witness program. `FEATURE_GAPS.md`'s survey had checked native
P2WPKH/P2WSH/P2TR and never asked about the nested forms.

Before fixing one block at a time, a census of the segwit era from the
oracle (every 3000th block, 484000 to 762875): P2SH-P2WPKH 129k inputs,
native P2WPKH 67k, P2WSH multisig for some fifteen distinct m-of-n pairs
native and wrapped (2-of-3 dominant; first 2-of-3 at 481945, 120 blocks
after the wall), and ~1,100 "other" P2WSH scripts combining CSV, CLTV,
OP_IF and hash locks -- HTLC and Lightning shapes -- from ~508000 on. Our
P2WSH verifier handled exactly two hard-coded shapes. So the scope became
**general witness-v0 execution through `script_eval`**, native and wrapped,
rather than nested-segwit alone (`bitcoin_witness_v0.c`, `11f7aa9`;
Core's `VerifyScript` P2SH-witness branch incl. `WITNESS_MALLEATED_P2SH`,
`VerifyWitnessProgram` v0, `ExecuteWitnessScript`).

Three genuine bugs surfaced under it, none reachable before:
1. `bitcoin_interp.asm` `OP_CHECKMULTISIG` ran FindAndDelete of the
   signatures from the scriptCode **unconditionally**. Core does it only
   under `SigVersion::BASE`; under WITNESS_V0 it corrupted the scriptCode
   and would have rejected every valid witness multisig. Gated on BASE; the
   real h=290328 decoy-pubkey regression still passes.
2. A transaction mixing a legacy input and a segwit input is
   witness-serialized, so the **legacy** input's sighash must be computed
   over the witness-stripped form. First possible at 481825; it would have
   rejected most early-segwit-era transactions.
3. The synthetic 2-of-2 vectors used a one-byte `0x00` CHECKMULTISIG dummy
   (NULLDUMMY requires empty) and had the two signatures reversed relative
   to pubkey order -- the old index-matching verifier did not care, the
   interpreter does. Same lesson as #11.

Nine real mainnet spends are pinned through the actual block dispatch
(`tests/test_segwit_real.c`): P2SH-P2WPKH, P2SH-P2WSH 2-of-3/2-of-2/1-of-1/
3-of-4, native P2WSH 1-of-2/5-of-7, and native and wrapped HTLC scripts --
which means CLTV, OP_IF branches and HASH160-of-preimage executed inside a
witness script under the BIP143 sighash for the first time, against real
chain data. Plus three negatives. The mempool path
(`bitcoin_txval_modern.c`) had the same gap and shares the fix.

### Incident #13: the worker segfaulted on block 481827 -- a 4096-byte BIP143 buffer, and threads with almost no stack

Thirty-five seconds after the replay resumed past 481826, the download
worker died on 481827 with `segfault at <addr> ... sp <same addr> ... in
ld-linux` -- fault address equal to the stack pointer, inside the dynamic
loader. That signature says "stack overflow", and the first diagnosis went
there: `readelf` showed **12.0 MB of static thread-local storage**, and
glibc carves static TLS out of every pthread's stack mapping. Worse, under
`LimitSTACK=infinity` (the unit's setting) glibc's default thread stack is
**2 MB**, measured -- it only becomes 8 MB when the rlimit is finite. So
every verify-pool thread had been running on a few kilobytes of real stack
for the entire session. That was real, and it is fixed: `bmc_thread.h`
gives every daemon thread an explicit 64 MB stack, and the 1 MiB per-thread
buffers (three `sv_work` plus the `stripped` copy added by #12) and the C
script stacks moved from static TLS to lazily heap-allocated per-thread
pointers -- TLS 12.0 MB -> 4.4 MB (the remaining 4 MiB is
`lsm_get_scratch` in assembly, unused by the mmap path, left as a
follow-up).

But the **proximate** cause was simpler and worse: `segwit_v0_sighash`
(`bitcoin_segwit.c`) assembled `hashPrevouts`/`hashSequence`/`hashOutputs`
into fixed `uint8_t buf[4096]` / `obuf[4096]` stack arrays, 36 bytes per
input. Block 481827 carries two **500-input** transactions: 18,000 bytes
into 4,096 -- a 4x overrun that smashed the thread's stack into its guard
page, which is exactly what the loader then tripped on. Reachable by any
transaction with more than ~113 inputs or outputs from segwit activation
on, and trivially by a crafted block. The BIP341 taproot aggregate hashes
had the identical latent bug. Both now use a bounded per-thread heap
buffer sized to the block cap. Proven load-bearing: with the old 4096 cap
restored, the regression test crashes; with the fix it passes.

The regression test runs the real block 481827 -- 1,377 transactions,
4,855 prevouts seeded from the archive and the oracle
(`validation/fetch_block_prevouts.py`) -- through the full apply path on
the real pool threads. A third defect fixed alongside: the serve parent had
sat "active" for thirteen minutes with no worker; it now records the
worker's exit status and exits itself so systemd restarts the unit.

Two lessons. The dmesg signature was consistent with both diagnoses, and
the first plausible one (TLS) was a genuine bug that was not the cause;
measuring the deepest frame found the real one. And the 500-input
transaction is ordinary chain data -- this was the first witness-era block
with one, 3 blocks after the verifier first ran on witness data at all.

### Incident #14: the witness program was a dangling pointer into a reused buffer
The replay verified 481824..482565 and then rejected 482566 tx 1499 -- an
ordinary 1-in/2-out native P2WPKH spend -- with "p2wpkh signature invalid".
Phase-1 classification stored `in->wprog = spk + 2`, a pointer INTO
`g_txv_in[i].spk`, which is a per-input scratch buffer that Phase 1 keeps
refilling for later inputs before Phase 2 ever runs a signature. By verify
time those bytes were whatever a later input's scriptPubKey had written
there, so the BIP143 program -- and with it the P2WPKH scriptCode and the
P2WSH witnessScript hash -- was wrong.

It had "worked" for 742 blocks only because the clobbering bytes did not
happen to matter until 482566's particular input layout. That is the
signature of this whole bug class: intermittent by construction, and
data-dependent in a way no synthetic test would have found. It failed
closed here (a wrong program cannot satisfy a real signature), which is the
safe direction, but the same defect in a validator that compares rather
than verifies would fail open.

Fix: for the native case the program lives inside the spk, so store a
stable `wprog_off` and recompute `spk + off` at verify time; the
P2SH-wrapped case points at the redeemScript, which lives in the (stable)
tx bytes, so that pointer stays. `sv_classify_segwit` was also being handed
a stale local `spk` and now gets `g_txv_in[i].spk`.
`tests/test_txvb_wprog_stable.c` reproduces it with a two-input tx whose
second input overwrites the region the first input's wprog aimed at, and
482566:1499 is pinned as a real fixture in `test_p2wpkh_real.c`. This is the
third dangling-pointer-into-a-growable-buffer bug in this codebase (cf.
incident #2); the offset-not-pointer discipline it established is what
incident #15 then applied pre-emptively.

### Incident #15: an 8-item witness cap rejected ordinary multisig spends
Block 498787 tx 2420 -- a routine P2SH-P2WSH spend carrying a 17-item
witness stack -- was rejected with "too many witness items".
`TXV_MAX_WIT_ITEMS` was 8, chosen when nothing real had been parsed yet, and
each input held its items in inline `wit[8]`/`witlen[8]` arrays.

No consensus rule caps the witness item COUNT at parse time. The real
bounds are the per-item size limit (520) and the 1000-element execution
stack: a P2WSH witness's items BECOME the initial stack, so beyond ~1001
items no spend can satisfy MAX_STACK/cleanstack anyway. The cap is now
1004 (1001 + tapscript's script/control/annex), which rejects nothing Core
would execute.

Simply enlarging the inline arrays was not available: `g_txv_in` is
`[TXV_MAX_INPUTS]` = 20000, so `wit[1004]` inline is ~240 MB of mostly-empty
storage per block. Witness items now live in a growable pool (`g_wit_pool`,
parallel ptr/len arrays) addressed by a per-input OFFSET that is resolved to
a pointer only after parsing stops growing the pool -- deliberately the same
discipline `g_spk_pool`/`spk_off` uses, because a realloc mid-parse would
dangle a pointer already handed to an earlier input. That is incident #14's
lesson applied before the bug could happen rather than after.

Fixtures: 498787:2420 (17 items, the block that tripped it) and 750500 (21
items -- the deepest real witness in a 499k-780k census of the oracle, so
the bound is proven against the real maximum rather than against the first
failure), plus a synthetic 1005-item stack that must reject cleanly instead
of crashing. A pre-existing Makefile bug surfaced alongside:
`test_segwit_real` and `test_block_481827_pool_stack` were in the `test:`
RUN recipe but not its prerequisites, so `make -k test` never built them and
exited 127 with zero reported failures -- a suite that was silently not
running two of its tests.

### Incident #16: BIP342 forbade an opcode it actually keeps -- and my diagnosis was wrong
A census of the un-replayed chain (`CHAIN_AHEAD_CENSUS.md`, written to find
walls BEFORE the replay hit them) predicted a tapscript reject wall around
775k-826k. A fork fetched a real Core-accepted fixture -- the tapscript CSV
spend at height 806500, txid `e5dd172b...47d7` -- and confirmed it: rejected
with "p2tr tapscript execution failed".

I diagnosed it inline as the zeroed script-eval context in
`taproot_verify_input` (`st.flags = 0`, `tx_locktime`/`in_sequence`/
`tx_version` never populated). **That diagnosis was wrong, and the fork's
differential test overturned it.** That bug is real, but it is
too-PERMISSIVE: with the CLTV/CSV flags off, both opcodes degrade to silent
NOPs, which would wrongly ACCEPT rather than reject. The actual wall was in
`bitcoin_interp.asm`: `OP_CHECKSIGVERIFY` (0xad) was routed to
`.bad_opcode` under `SIGVERSION_TAPSCRIPT`. BIP342 keeps CHECKSIG *and*
CHECKSIGVERIFY (re-specified for schnorr) and disables only
CHECKMULTISIG(VERIFY). Real HTLC-style leaves (`<pk> OP_CHECKSIGVERIFY ...
OP_1 OP_CSV`) died on the CHECKSIGVERIFY and never reached the timelock at
all.

Both are fixed: the opcode falls through to normal handling (the
CHECKMULTISIG tapscript guards are untouched), and the C side now sets
`CHECKLOCKTIMEVERIFY|CHECKSEQUENCEVERIFY` (0x600) and threads the real tx
version/locktime/nSequence, mirroring the witness-v0 path. A stale test
assertion that ENCODED bug #1 ("CHECKSIGVERIFY forbidden in tapscript") was
corrected to Core-exact behavior -- a test that had been faithfully
protecting a consensus bug.

The lesson is the one worth keeping from this whole session: a confident
inline root-cause is a hypothesis, not a finding. Two separate times today
(here and in #13's TLS red herring) the first plausible explanation was a
genuine bug that was not the cause. Handing the hypothesis to a differential
check against a real fixture -- fails on old code, passes on new -- is what
distinguished them. After being corrected here I re-verified the fix
personally rather than accepting the fork's word: checked out main's two
consensus files in the worktree, watched the 806500 fixture reject, restored
the branch files, watched it accept.

### Incident #17 (telemetry only, no consensus impact): the live-UTXO counter went negative
Production logged `live_utxo=-2610837`. The count is informational -- it
never gates validation -- but a negative UTXO count is nonsense, and the
cause was worth finding.

`total_live` was re-derived on every reload as `u->n`: the live entries of
the current unflushed memtable generation ONLY. The tens of millions of
UTXOs sitting in older flushed and compacted runs were never counted, so
the counter came back ~51M too low after every resume. Deletes then made it
worse in the obvious way: an LSM del just appends a tombstone and
decrements unconditionally, so every spend of a pre-existing key pushed the
number further down until it crossed zero. A from-scratch build kept it
accurate (symmetric +1/-1 from empty) -- only reload was broken, which is
why it had been meaningless since the very first resume and nobody noticed.

The fix persists ground truth instead of re-deriving a guess. The manifest
gains `MAGIC_MANIFEST2` ("UMN2", a 20-byte header carrying `total_live`)
alongside the old 12-byte "UMAN", mirroring the run-file MAGIC_RUN->RUN2
versioning already in the codebase. Flush persists the count at the exact
moment it means "all runs, WAL empty" -- the memtable has just been folded
into a run and the WAL is about to be truncated -- so reload restores that
base and adds only the WAL tail's net (PUSHes - DELs), double-counting
nothing. A full compaction persists the merged run's own live-entry count,
which is authoritative and heals any accumulated drift. An old-format
manifest (which is what production had) triggers `mac_lsm_recount`: a
one-time, read-only k-way dedup merge over every run, newest generation
winning, counting a key live iff its newest run record is a PUSH and it is
not shadowed by the memtable or a tombstone. Bounded, one-time, and never
on the per-op hot path -- which the diff confirms is byte-for-byte unchanged
(still a single inc/dec).

Two details worth recording. The displayed value is now clamped at 0 in
`daemon/main.c` as a backstop, deliberately NOT as the fix -- clamping alone
would have hidden the drift rather than corrected it. And the counter was
positive again (`live_utxo=25053084`) by the time the fix was deployed,
having drifted up as the replay added UTXOs: proof that the value was a
free-drifting wrong seed rather than a fixed offset, and a good argument
against ever "fixing" a symptom whose sign happens to look plausible today.

**And then the fixed counter immediately earned its keep.** The first boot
on the new code ran the one-time recount over the production set (10 runs,
13 GB, 133 s of reload) and reported `live=77191281` at height 575,833. The
oracle, asked the same question, disagrees: `gettxoutsetinfo none 575833`
gives **54,953,225** `txouts`. We hold **22,238,056** more entries than
Core.

The cause is `daemon/utxo_live.c:339` -- `live_on_output` puts every output
into the set with no script inspection at all, while Core never writes a
provably-unspendable output to the chainstate (leading `OP_RETURN`, or a
script over `MAX_SCRIPT_SIZE`). Verified by magnitude rather than assumed:
sampling the oracle every 25,000 blocks to 575,833 gives ~37.7 nulldata
outputs per block, extrapolating to ~21.7M -- the observed delta to within
2.5 %.

This is not a consensus divergence. An `OP_RETURN` output is unspendable on
both sides; Core rejects a spend of one for a missing prevout, we find the
entry and fail the script. Same verdict by a different route. What it does
cost is storage, compaction amplification, and the Stage D acceptance test
itself -- set-hash parity with Core is unreachable while the two sets differ
by 22M entries. It is left unfixed for now on purpose: the filter is a few
lines, but it only affects outputs applied after it lands, so it is worth
little without a from-scratch rebuild, and a rebuild costs the entire
replay. See `FEATURE_GAPS.md`.

The sharpest detail is that the codebase had already made this argument --
once, correctly, and only for a single output. `utxo_live.c:548` excludes
the genesis coinbase precisely because applying it "would leave this node
one UTXO richer than Core forever, surfacing the first time our set is
compared against `gettxoutsetinfo`". The same sentence describes twenty-two
million other outputs. Getting a rule right in one place is not the same as
holding it as an invariant, and only an external oracle showed the
difference -- a broken telemetry counter had been hiding it all along.

### Incident #18: the serve path violated the SysV stack ABI, and a wrong comment defended it
`test_keepup` had been failing 2/2 for most of the day, filed as "a tip
keep-up serve-path regression, not on the replay's critical path, fix it
later". Both halves of that description were wrong.

The two assertions were not two failures. They were one crash: the serve
child died of SIGSEGV the instant a peer pushed it a block, after which the
getdata read returns -1 (indistinguishable from "wrong bytes" to the
harness) and the later ping gets no pong. The evidence chain ran: child
wait status `sig=11`; an `SA_SIGINFO` handler placing the fault inside
glibc, reached from `log_block_stored_inbound` -> `log_fprintf` ->
`snprintf`, with `si_addr = NULL`; and a disassembly of the faulting
address showing `movaps %xmm0,-0xc0(%rbp)` -- a 16-byte-aligned SSE store
against an `rbp` that was 8 mod 16. **That NULL fault address is the tell:
a misalignment trap, not a null-pointer dereference.**

Back-derived, `rbp` 8 mod 16 in the callee means RSP was 8 mod 16 at the
`call`, and the ABI requires 0. `node_serve_loop`'s prologue pushes rbp
plus five callee-saved registers, leaving RSP 8 mod 16, and then reserved
`0x50` -- which is 0 mod 16 and therefore preserves the violation at every
nested call in the function.

The instructive part is the comment that had been sitting above that
reservation, asserting `0x50` was correct because this codebase's asm
callees "require" 8 mod 16. They do not: every `movdqa` in `sha256.asm`,
`sha256_nia.asm` and `secp256k1_point.asm` is register-to-register, with no
16-byte-aligned stack operand anywhere in the tree. The convention is
visible two ways in the codebase itself -- `node_announce_tip`, the other
global in the same file with an identical prologue, uses `sub rsp, 8`; and
`mac_run_lookup` in `bitcoin_utxo_lsm.asm` brackets its C call with a
`sub`/`add 0x28` pair for precisely this reason. So the file contained both
the bug and, a few hundred lines away, the correct pattern.

The violation dates to `dfa8690`, the file's original commit. What made it
lethal was `5aea7c0`, which added the `log_block_stored_inbound` call --
the first C callee on that path that reaches `vsnprintf`. For as long as
the misaligned frame only ever called assembly, nothing noticed. **My own
attribution to `fe3addb` (the MSG_WITNESS serve change) was wrong and was
disproven directly: checking that file out at `fe3addb^` and rebuilding
still fails 2/2.** That is three inline diagnoses overturned by
differential test in one session (#13, #16, #18). The pattern is stable
enough to be a rule: a root cause that has not been reproduced is a
hypothesis.

The fix reserves `0x58` and pairs the four `push rbx` / `call` / `pop rbx`
sites with a padding push -- those four had been the only *correctly*
aligned calls beforehand, and would have become the only misaligned ones
after. It is safe against the frame resize because every "local" the old
comment listed actually lives in `.data`; nothing in the function is
rbp-relative, so no operand moves.

**And the failure was hiding far more than itself.** A failing command
aborts the remainder of a make recipe, so those two assertions had been
truncating the suite: baseline `make -k test` on `main` executed 103 of 137
tests and stopped. With the fix, 137/137 pass. The 34 that had never been
running include `test_bip152`, `test_bip152_loop`, `test_p2p_inv`,
`test_segwit_real`, `test_reorg`, `test_undo_log`, `test_chainwork` and
four `test_utxo_*` crash/checkpoint tests. That is the second time in one
day that a green-looking suite was not running what it claimed (cf. #15's
missing prerequisites) -- and the second failure mode of the same kind: not
a test that passes wrongly, but a test that never executes.

Two things deliberately left alone, both recorded rather than folded in. A
repo-wide alignment audit found the same violation in `utxo_lsm_init` and
`utxo_lsm_reload`, which call `lsm_mm_invalidate_all` at RSP 8 mod 16; it
is harmless *today* only because that C function compiles to five
instructions with no stack frame and no SSE (verified by disassembly), and
its sibling `mac_run_lookup` gets the alignment right, which is why the
`movaps`-containing `lsm_run_lookup_mm` call does not fault. Latent, not
live -- but this incident is the proof that "latent" here means "waiting
for someone to add a `printf`". Separately, the serve path genuinely does
ignore which type a getdata requested: after `fe3addb` masks the BIP144
flag, both `MSG_BLOCK` and `MSG_WITNESS_BLOCK` return the full witness
serialization, where Core answers a bare `MSG_BLOCK` with the stripped
form. That deviation is documented as intentional in `fe3addb`'s own
comment and deserves its own decision, not a silent ride-along in an
alignment fix.
### Incident #19: the tapscript initial stack had no 520-byte limit at all
*(Committed as `1e80eb8`, whose subject line reads "incident #18". The number
was reassigned at merge: the serve-path ABI fix `b18114b` had already taken
#18 while this work was in flight. The commit message is left as-is rather
than rewriting pushed history; #19 is the correct number and the one used
everywhere else.)*
Chasing `CHAIN_AHEAD_CENSUS.md`'s last two open rows -- "real inscription
untested at scale" and "`tap_leaf_hash`'s 4 MB leaf cap" -- turned up
something the census had not predicted and the replay would never have found.

The scale question itself came out clean. Real fixtures pulled from the
oracle and driven through `tx_verify_block_connect` all pass: the
**3,938,182-byte** leaf at height 774628 (`0301e048...c0ae`, a 3,938,383 B
transaction inside a 3.94 MB block -- the largest leaf located, and within
1.5% of the ~3,999,000 that MAX_BLOCK_WEIGHT allows at all, so nothing on
the chain can be materially bigger), the 371,967-byte leaf at 779500 that
the census recorded as
its maximum, the census's own ~775000 evidence txid (`4cc72b13...4057`, a
42,594-byte leaf) with its full txid finally resolved from block data, a
21-node/705-byte control block at 850000, and a 12-item script-path witness
at 860500. The 4 MB cap is not a wall either, and now provably so:
`tap_leaf_hash` bounds `slen` at `TAP_PREIMG_CAP-70` = 4,194,234, while
MAX_BLOCK_WEIGHT = 4,000,000 caps any real leaf near 3,999,000 -- ~195 KB of
headroom no valid block can consume. Measured, not assumed: the test sweeps
`tap_leaf_hash` from 0 to 4,194,235 bytes against BIP341 hashes computed
independently in Python, and every fixture also has its leaf's LAST byte
flipped and must then reject -- a silent truncation anywhere would sail
through the unmodified fixture untouched.

The bug was next door. `taproot_verify_input` built the tapscript's initial
stack by handing each witness item straight to `stack_push`, which bounds the
stack DEPTH (`MAX_STACK_SIZE`) and **not the element LENGTH** -- it copies
`len` bytes into a 528-byte element record with no check
(`bitcoin_scriptcodec.asm:162`). `bitcoin_witness_v0.c:192` has the
`MAX_SCRIPT_ELEMENT_SIZE` guard for witness v0; the tapscript path never got
one. A witness item can be nearly a whole block, so a script-path spend
carrying a >524-byte initial-stack item overran `ts_main_e`, a 528,000-byte
heap buffer, by up to ~3.4 MB. Whether that SIGSEGVs or silently scribbles
over neighbouring buffers is pure heap-layout luck -- both were observed on
the same binary, the fault only when glibc's mmap threshold was pinned low.

And the shape is not merely hostile input. Core's `ExecuteWitnessScript` runs
its OP_SUCCESSx pre-scan BEFORE both the stack-size and element-size limits,
with the comment "OP_SUCCESSx processing overrides everything, including
stack element size limits" -- so a spend with a 3.9 MB witness item under an
OP_SUCCESSx leaf is consensus-VALID and mineable today. We ran that scan too,
but inside `script_eval`, i.e. AFTER the stack was already built and the
damage done. The fix hoists the scan out (`ts_has_op_success`) and applies
the count and size limits after it, in Core's exact order.

None of this is reachable from the chain: 47,578 real script-path inputs
sampled across 68 blocks in 775,000-869,000 have a maximum initial-stack item
of **79 bytes** and not one OP_SUCCESSx leaf. So the fixture had to be
synthetic -- and the honest way to stop a synthetic vector inheriting the
author's blind spot is to let Core decide the answer.
`validation/core_verify_oracle.cpp` gained a `TAPVERIFY` command (real
`VerifyScript`, real `PrecomputedTransactionData`, the real
`GetBlockScriptFlags` set) and all four vectors agree with Core: 520-byte
item ACCEPT, 521-byte REJECT (`Push value size limit exceeded`), 3.9 MB item
REJECT, 3.9 MB item under an OP_SUCCESS leaf **ACCEPT**. That last one is why
the obvious one-line fix would have been wrong, and it is in the suite
precisely to fail against it. Fail-then-pass on the real thing: against
unmodified `main`, `init_item_521` and `init_item_3900000` are both falsely
ACCEPTED; with the fix, 33/33.

One divergence is knowingly LEFT in place, and named here so it is not
mistaken for an oversight. Because Core's OP_SUCCESSx scan also precedes the
`stack.size() > MAX_STACK_SIZE` check, a script-path spend with more than
1000 initial stack items under an OP_SUCCESSx leaf is valid to Core, while
`TXV_MAX_WIT_ITEMS = 1004` rejects it at parse time, before
`taproot_verify_input` is ever reached. That cap is a deliberate per-input
pool bound (incident #15), and removing it means unbounded witness-pool
growth driven by wire data; the shape has never occurred, and the trade is
worth making consciously rather than silently.

The lesson is the mirror image of #16's. There the census said "handled" and
meant "a code path exists". Here it said "untested at scale", the scale
turned out fine -- and reading the path against Core to find out *why* it was
fine is what surfaced a memory-corruption bug three feet to the left, in a
shape the chain has never produced and therefore would never have taught us.

### Incident #20: the SysV stack ABI was violated tree-wide, not just on the serve path; the script interpreter was crashing the same way

Incident #18 (`b18114b`) fixed one function. The obvious next question --
"is `node_serve_loop` the only one?" -- turned out to have an uncomfortable
answer, so this entry records a full audit rather than a patch.

### The tool, because a hand audit of this size would be wrong
`scripts/abi_stack_audit.py` abstract-interprets RSP mod 16 (and RBP mod 16,
so `leave` / `mov rsp,rbp` / `lea rsp,[rbp-N]` / `and rsp,-16` are modelled)
over the control-flow graph of every function in every `.asm` source, from
every entry point, and reports the parity at each `call` and each tail `jmp`.

The load-bearing design decision is that it analyses each function **twice**:
once with the ABI-correct entry parity (8 mod 16, what a correct `call`
delivers) and once with the abnormal one (0 mod 16, what a *violating* caller
delivers). That distinction is the whole point. A function whose calls are
aligned only under the abnormal entry has been tuned against a broken caller,
and "fixing" that caller breaks it. Without that check a global fix converts
a set of latent bugs into a set of live ones. It then runs a whole-program
fixed point over the asm call graph, so every function's *actual* entry
parities are known rather than assumed.

C callees are classified empirically, not from source: `objdump -d` the `.o`
and look for `movaps`/`movdqa`/`movntdq` against an `rbp`/`rsp` operand. That
is what actually faults; nothing else about the C matters.

### The result: the violation is the majority convention, not an outlier
Across 339 assembly functions reachable from the exported entry points, at
`cb20051`:

| verdict (analysed in isolation)      | count |
|--------------------------------------|-------|
| ABI-CORRECT (aligned under entry 8)  |    97 |
| NEEDS-ENTRY-0 (aligned only under 0) |    43 |
| MIXED (no entry parity works)        |    15 |
| SELF-ALIGNING (`and rsp,-16`)        |     8 |
| NO-CALLS                             |   176 |

1141 reachable call sites: 625 correct, **516 misaligned**.

The dominant idiom in this tree is `push rbp` / `mov rbp,rsp` / five
callee-saved pushes / `sub rsp, <multiple of 16>`. That leaves RSP at 8 mod 16
at every nested `call`. `ripemd160`, `idx_get`, `idx_put`, `node_log_event`,
`node_handshake`, `node_accept_handshake`, `utxo_store_put`, `multisig_verify`,
`verify_p2pkh`, `script_eval` and ~30 more all have it. Where a function *is*
correct it is usually because the push count happened to come out even, not
because anyone chose it. **#18 was not an outlier; it was the first instance
that mattered.**

### The live one: the script interpreter, crashing exactly like #18
`script_eval` reserved `0x100` after the six-push prologue, so all **215** of
its call sites ran at 8 mod 16 -- including `call qword [r12+96]` inside
`interp_checksig` / `interp_checksig_add` / `interp_checkmultisig`. That slot
is `checksig_fn`, the C callback: `sv_checksig` (bitcoin_scriptverify.c) on the
legacy path, `taproot_checksig_fn` (bitcoin_taproot_sighash.c) on tapscript.
Assembly calling C, on a misaligned frame, on the consensus script path.

Measured rather than argued. A probe returning the caller's RSP, installed as
`checksig_fn`, reported `rsp%16 == 8`. Swapping in a callback that does one
`snprintf` reproduced #18 byte for byte:

```
Program received signal SIGSEGV
=> 0x7ffff7c8fd6c <__vsnprintf_internal+60>: movaps %xmm0,-0xc0(%rbp)
   si_addr = 0x0
   #4 log_cs   #5 interp_checksig
```

Same instruction, same NULL fault address, different subsystem. It had not
been noticed because every C file on that path is compiled `-O0` (the daemon
itself is `-O0`), and at `-O0` GCC does not emit the 16-byte-aligned spills
that `-O2` does. The bug was one optimisation flag, or one log line, away.

### What was fixed, and what deliberately was not
Fixed, smallest blast radius first, each proven by re-running the analyser and
diffing the violation set:

* `script_eval` `0x100` -> `0x108`. All locals are rbp-relative, so the frame
  grows and no operand moves.
* `interp_checkmultisig`'s unpaired `push rdx` around the `.pop_all` loop gets
  a padding push -- the same correction `b18114b` made to `node_serve_loop`'s
  four `push rbx`/`call`/`pop rbx` sites.
* `bitcoin_scriptcodec.asm`: `stack_swap_two` `sub rsp,16` -> `24`, and padding
  pushes in `stack_erase_index` / `stack_insert_index`. These three are called
  only from `script_eval`, so the subtree closes. Their comment claimed 16 was
  "alignment-neutral, preserves whatever call-site alignment already existed" --
  which is the #18 mistake stated as a principle. Preserving an 8-mod-16 RSP is
  not neutral.
* `utxo_lsm_init` and `utxo_lsm_reload` bracket their `lsm_mm_invalidate_all`
  call with `sub rsp,8` / `add rsp,8`. Deliberately *not* a frame resize: that
  would flip the entry parity delivered to `utxo_store_init`,
  `mac_tomb_hash_reset` and everything under them, on the UTXO path. The
  bracket fixes the one call that leaves assembly and changes nothing else.

Result: 254 misaligned call sites removed, **zero call sites that leave
assembly are misaligned**, and a line-shift-immune diff of the before/after
site sets confirms no call site anywhere got worse.

Not fixed, on purpose: 262 asm->asm misaligned sites remain. They are latent --
every `movdqa` in this tree is register-to-register, with no 16-byte-aligned
stack operand anywhere -- and clearing them is a coordinated tree-wide change,
not a set of independent one-liners. The audit found exactly one true
**compensated** site, and it is the proof that the coordination matters:
`siphash24_uint256.sipround2` (bitcoin_cmpct.asm) has no prologue and is only
ever entered at 0 mod 16, so its two `call .sipround`s are currently correct
*because* its caller is broken. Fixing `siphash24_uint256` alone would break it.

### The guard
Two halves, both wired into `make test`:

* `make abi-check` runs the analyser over the sources and fails if any call
  site that leaves assembly is misaligned. Run against `b18114b^` it flags
  `node_serve_loop`'s `log_block_stored_inbound` call directly -- **it would
  have failed on `5aea7c0`, the commit that made #18 lethal, the day it
  landed.**
* `tests/test_abi_stack_align` drives the one place assembly calls back out to
  C through a function pointer, asserts the measured parity, and then does a
  printf from that callback. Linked against the pre-fix objects it SIGSEGVs;
  against the fixed ones it passes.

The lesson generalises past alignment: a bug that is invisible because nothing
currently exercises it is not a bug that is fixed, and "the tests pass" is not
evidence that an ABI is being honoured. The tests passed for the whole time the
interpreter was one log line from dying.

### Incident #21: a 600-byte stack buffer for an output with no size limit -- and the chain is already past it
`sw_ser_txout` (`bitcoin_segwit.c`) serialized one CTxOut -- 8 bytes of value,
a compactsize, then the scriptPubKey verbatim -- into a caller-supplied buffer
with **no bound check of any kind**, and both call sites in
`segwit_v0_sighash` handed it `uint8_t tmp[600]` on the stack. The arithmetic
gives the exact cliff: 8 + 3 + 589 = 600, so a 589-byte output scriptPubKey is
the last one that fits and **590 is the first that overruns**. One call site is
the `hashOutputs` loop, which runs over *every* output of the spending
transaction; the other is the `SIGHASH_SINGLE` branch. Both were affected.

Bitcoin consensus places **no limit on an output's scriptPubKey size**. Only
relay standardness does, and nothing in this codebase's block path bounds it
either -- `TXV_SPK_CAP` and the taproot 0xfd limit apply to *prevout* scripts
coming out of the UTXO set, never to the spending transaction's own outputs.
So the overflow is reachable straight from `sv_verify_witness_v0`, which
`daemon/tx_verify.c` hands the full spending transaction, and it happens
*before* anything has decided the transaction is invalid.

The part that was supposed to make this theoretical is where it went wrong.
A sparse census -- 481,824..950,000 sampled every 5,000 blocks -- reports a
maximum output scriptPubKey of **105 bytes**, and that reading is what framed
this as a synthetic-only, defence-in-depth fix. It is a sampling artifact.
Sampling the same shape densely (a segwit-v0 input, not taproot, in a
transaction with a >589-byte output):

| range | step | blocks | blocks with the shape |
|---|---|---|---|
| 481,824..900,000 | 1,000 | 419 | 0 |
| 900,000..946,400 | 100 | 464 | 1 (927,500) |
| 940,000..963,000 | 25 | 920 | 7 |

Multi-hundred-byte `OP_RETURN` outputs start appearing around **927,500** and
are routine past ~946,000. The earliest located is height 927,500, a 1-in/1-out
**P2WPKH** spend whose single output is a **2,019-byte** `OP_RETURN`
(`98850f2b...b4b1`); 952,224 carries a 1,198-byte one, 952,325 a 1,694-byte
one. Every one of these is a mined, consensus-valid mainnet transaction that
writes past the end of a 600-byte stack array on unmodified `main`. This is not
a hardening exercise: the replay would have died on it, roughly the same way
incident #13 died on block 481,827.

Fix: `sw_ser_txout` takes a `cap`, computes `8 + cs_size(sl) + sl` in 64-bit
unsigned, and returns -1 **before writing anything** if it does not fit. The
staging buffer is gone -- both call sites serialize directly into `mbuf`, the
4 MiB per-thread heap buffer incident #13 already introduced for the aggregate
hashes, which is above `MAX_BLOCK_SERIALIZED_SIZE` and so cannot false-reject
anything a valid block can carry (proven: a 3,900,000-byte output scriptPubKey
hashes to Core's answer). The `hashOutputs` loop also loses one `memcpy` per
output. `read_cs` was unbounded too and is now bounded: a compactsize's width
is chosen by its own first byte, so every walk in the file could read up to
8 bytes past the transaction whenever it landed on the last one -- read-only
and small, but wire-driven. The `q + sl > end` bound tests became
`avail(q) < sl` for the same reason: a 2^63 length made the pointer form
overflow into a passing test.

Proof, in the order it was built. Ground truth is Bitcoin Core:
`validation/core_verify_oracle.cpp` gained a `BIP143` command running Core's
own `SignatureHash(..., SigVersion::WITNESS_V0)`, which reproduces BIP-0143's
published worked example (`c37af311...8cb670`) before any of its answers are
used. `tests/test_segwit_txout_bound.c` carries 120 sighash vectors plus a
3-entry scale set and an over-cap refusal, 124 in all: 75 ordinary mainnet
transactions across all five hashtypes, 14 from the seven real over-the-bound
mainnet spends, and the rest synthetic -- a boundary sweep, both call sites,
ANYONECANPAY/NONE/SINGLE, and a scale set reaching 3.9 MB.

Fail-then-pass, on the real thing. Against unmodified `main`, 27 of the 124
vectors abort the process -- `-fsanitize=address` reports
`stack-buffer-overflow, WRITE of size 2019 ... in sw_ser_txout` for the
927,500 fixture and `WRITE of size 590` for the boundary vector, at
`bitcoin_segwit.c:304` (hashOutputs) and `:309` (SIGHASH_SINGLE) respectively;
without ASAN, gcc's default `-fstack-protector-strong` turns it into a
deterministic `*** stack smashing detected ***` at exactly 590 bytes and not
at 589. With the fix, 124/124 match Core.

And the equivalence half, which is what says this changed bounds and not
behaviour: the 97 vectors the old code could compute at all produce
**byte-identical** sighashes before and after -- all 75 ordinary mainnet
transactions among them. Full `make -k test` green.

One cost, stated rather than buried. `df48257` landed while this was in
flight and profiles exactly these functions: `read_cs` at 22.4% of verify
cycles, `sw_seq` and `sw_prevout` behind it, 34% together, with a
single-pass BIP143 precompute named as the next lever. Bounding all three
is not free. Measured on `segwit_v0_sighash` alone (-O2, min of 12-15 runs,
the census's 1,372-input shape with 100 outputs): 2.44 ms/call before,
2.54 with only the bounded reader (+4%), 2.84 as shipped (+16%). Most of
the cost is the per-iteration bound in `sw_prevout`/`sw_seq`, which is
redundant given that `swtx_parse` has already validated the identical byte
range -- and it was kept anyway, because "a distant function already checked
this" is how #13 and this bug both happened. `read_cs`'s hot path was
restructured to return on the single-byte encoding before computing any
width, so the common case costs one compare. `PERF_SCOPE.md` carries the
table and the constraints the precompute rewrite has to preserve.

Two lessons. The first is that a census is a claim about its sampling
interval, not about the chain: 105 bytes was the honest answer to "every
5,000th block" and the wrong answer to "does this happen". The second is
#19's, repeated: this was found by reading the buffer against the consensus
rule that governs it -- there is no limit on an output script -- and only
afterwards did the chain turn out to agree.

### Incident #22: taproot rules applied at the one block Core exempts by hash
The replay stopped dead at height 692,261 -- `REJECT h=692261 tx=193: p2tr
empty witness` -- and then sat in a retry loop, failing the same block six
times as the backoff grew. The transaction is
`b10c007c60e14f9d087e0291d4d0c7869697c6681d979c6639dbd960792b4d41`, and its
four inputs spend real witness-v1 taproot outputs carrying **no witness at
all**: invalid under taproot rules, valid without them.

Block 692,261's hash is
`0000000000000000000f14c35b2d841e986ab5441de8c585d5ffe55ea1e395ad`, and that
is not a coincidence -- it is Core's Taproot `script_flag_exception`
(`kernel/chainparams.cpp`), the single mainnet block that violates the
taproot rules. It was mined well before activation at 709,632. Core's
`GetBlockScriptFlags` keeps `P2SH|WITNESS|TAPROOT` on for *every* block --
its comment says "for simplicity, always leave P2SH+WITNESS+TAPROOT on
except for the two violating blocks" -- and then overrides the flags down to
`P2SH|WITNESS` for this one hash.

**This project already had that right.** `script_flags_for_block` implements
the exception, and `tests/test_script_flags` covers it 13/13, including a
near-miss hash that must NOT trigger the override. The defect was that the
two P2TR dispatch sites in `daemon/tx_verify.c` never consulted the flags
they had already computed -- `if (is_p2tr(spk, spklen))`, unconditionally,
with `flags` sitting in scope and the very next branch correctly gating on
`flags & TXV_FLAG_WITNESS`. The right answer was worked out and thrown away.

The fix gates both sites on `TXV_FLAG_TAPROOT`. With the flag clear, a
witness-v1 program falls through to the existing classifier and lands on
`TXV_SHAPE_WPASS` ("unknown version: valid under consensus flags"), which is
exactly what Core's `VerifyWitnessProgram` does -- it returns success for
witness v1 without ever inspecting the stack when `SCRIPT_VERIFY_TAPROOT` is
clear. Blast radius is one block in the entire chain.

Two things worth keeping. First, the diagnosis went wrong before it went
right: the obvious reading is "taproot is height-gated at 709,632 and we
missed the gate", and that is false -- Core does not height-gate taproot at
all. Reading Core's actual source rather than trusting the recollection is
what turned an activation-height theory into an exception-block finding.
Second, this is a FALSE REJECT, the safe direction. It stopped the replay
loudly instead of quietly accepting something Core would not. The
false-accept version of the same mistake -- enforcing *too little* -- is the
one that splits a chain silently, and three of those were found and fixed
earlier the same day (#19, and the two in #21's sibling path).


### Performance: the BIP143 sighash was O(n^3) per transaction; one bounded pass makes it linear

`PERF_SCOPE.md` section 7's re-profile of the live replay at height ~617,000
(132,785 samples, no call graph) found `read_cs` at **22.44%** of all cycles,
with `sw_seq` (5.92%) and `sw_prevout` (5.71%) behind it -- **34% together,
larger than the field multiply**, and all three inside `bitcoin_segwit.c`.
That is not a constant factor. `sw_prevout(t,i)` and `sw_seq(t,i)` each walked
the input list from the start to reach input `i`, parsing a compactsize per
step, and BIP143's hashPrevouts/hashSequence call them once per input:
O(nin^2) per call. `sw_ser_txout(t,i)` was worse -- it re-walked every input
*and* the first `i` outputs, so hashOutputs was O(nin*nout + nout^2). And
because `segwit_v0_sighash` is called once per executed OP_CHECKSIG, i.e. once
per input, the whole thing was **O(nin^3) per transaction**. Core has never
paid any of this: `PrecomputedTransactionData` walks the transaction once.

### The fix
One bounded pass records the offset of every input and every output; every
accessor afterwards is an array index.

- `in_off[0..nin]` -- input `i`'s outpoint is at `in_off[i]`, and because
  inputs are contiguous its 4-byte nSequence is the last 4 bytes before
  `in_off[i+1]` (exact for the final input too, since `in_off[nin]` is one
  past the last one). `sw_prevout` and `sw_seq` become one load each, with no
  compactsize read at all.
- `out_off[0..nout]` -- and here the part worth stating plainly: **a CTxOut's
  BIP143 serialization is byte for byte its wire encoding**, so there is
  nothing to build. hashOutputs is a `sha256d` over the contiguous slice
  `[out_off[0], out_off[nout])` **in place**, and SIGHASH_SINGLE's is one over
  `[out_off[n_in], out_off[n_in+1])`. `sw_ser_txout` is deleted; no output is
  copied anywhere and the hashOutputs staging loop goes with it.

The table is a per-thread heap buffer (`BMC_TLS_BUF`, 600,000 `uint32`
entries = 2.29 MiB), not a stack array -- incident #13 is what a size-dependent
stack buffer does in this file. Its capacity is an arithmetic bound, not a
guess: an input costs >= 41 wire bytes and an output >= 9, so
`(nin+1)+(nout+1) <= 0.13550*txlen + 2`, and MAX_BLOCK_SERIALIZED_SIZE (4 MiB)
gives <= 568,335 entries -- nothing a valid block can carry is refused.

### The bounds from incident #21 are intact, and the walk they guarded is gone
Section 7's amendment measured #21's bound fix at +16% on this path and said
most of it was the per-iteration bound in `sw_prevout`/`sw_seq` -- redundant
given `swtx_parse` had already validated the same bytes, kept anyway because
"a distant function already checked this" is how #13 and #21 both happened,
and to be removed by deleting the loops rather than the checks. That is what
happened: those loops no longer exist, so there is nothing left to re-check.
What survives unchanged:

- `read_cs` still takes `end`, and still returns on the single-byte encoding
  before computing any width;
- every step of the single pass is a "remaining >= wanted" comparison on
  `sw_avail()`, never `q + n > end`;
- the `sw_ser_txout` `cap` -- a consensus-safety bound, not a policy one -- is
  now the caller's `olen > SW_MIDSTATE_CAP` test, and the accept/reject
  boundary is **identical**, not merely similar: the old running
  `cap = SW_MIDSTATE_CAP - written` refused exactly when the sum of the CTxOut
  record lengths passed 4 MiB, and that sum is precisely this range's length.
  `tests/test_segwit_txout_bound` still passes 125/125, including the
  3,900,000-byte scale vector and the 5 MB over-cap refusal.

One bound is *strengthened*: `avail(q) < sl + 4` wraps for `sl` within 4 of
2^64 (`read_cs` can return any 64-bit value the wire supplies), so it is split
into `avail < sl || avail - sl < 4`.

### One real behaviour change, and it is toward Core
Hashing a CTxOut in place is only equivalent to re-serializing it if the
transaction's compactsizes are **minimally encoded**. The old `sw_ser_txout`
wrote `put_cs(len)`, i.e. the canonical form, so a padded length (`fd 00 00`
for zero, say) was silently rewritten before hashing; raw bytes are not
rewritten, and the two answers differ. This was found by a differential fuzz,
not by reasoning -- 12 cases out of 3.8 M, all of them a poisoned compactsize.

Neither answer is Core's. Core's `ReadCompactSize()` throws "non-canonical
ReadCompactSize()" and refuses to deserialize such a transaction at all, so it
cannot appear in any block Core accepts. So `read_cs` now enforces minimality
-- Core's exact rule -- and refuses. That makes in-place hashing *provably*
identical to canonical re-serialization for every transaction not refused,
rather than merely identical on the transactions that happen to exist, and it
costs the hot path nothing (the single-byte encoding returns first).

Found while proving this and NOT fixed here: nothing else in the tree enforces
minimality -- `bitcoin_tx.asm`'s compactsize readers do not -- so a peer's
non-canonical transaction is still mis-parsed everywhere else. That is a
pre-existing divergence from Core at block-acceptance level, not something
this path introduced.

### New test, and it has teeth
`tests/test_segwit_bounds_fuzz.c`: the transaction is copied so its last byte
abuts a **PROT_NONE guard page**, so a read one byte past the end is a SIGSEGV
rather than a silent success -- no sanitizer needed, which matters because
this path links hand-written asm that ASAN cannot instrument. Every real
mainnet transaction in `segwit_txout_vec.h`, at every truncation from 0 to
full length, under all five hashtypes and three input indices, plus every
single-byte position poisoned to 00/fd/fe/ff: **3,184,330 calls**. It passes
on this tree and on `main`, and **SEGVs on `bf673d0~1`** -- the pre-#21 tree --
which is the whole point of writing it. Three bounds incidents (#13, #19, #21)
came out of this file and every one was found by reading rather than by a
test; now there is a test.

### Byte-identical, against Core, on 461 real mainnet transactions
This is a performance change and it must not move a single hash.

Corpus: **4,974 vectors** -- 461 real mainnet transactions pulled from the
Core oracle across heights **481,824 to 962,625** (the first segwit block
through the incident-#21 census window), each driven at three input indices
under **six hashtypes** (ALL, NONE, SINGLE, and each with ANYONECANPAY).

- old build vs new build: **4,974/4,974 byte-identical**, 0 refusals;
- and, more to the point, **both** match Bitcoin Core's own
  `SignatureHash(..., SigVersion::WITNESS_V0)` on **4,974/4,974**, via
  `validation/core_verify_oracle.cpp`'s `BIP143` command, which self-checks
  against BIP-0143's published worked example first. Ground truth is Core,
  never our own previous answer.
- The same corpus under `-fsanitize=address,undefined` gives byte-identical
  output with zero diagnostics.
- Differential fuzz, old and new linked into one binary over every truncation
  and single-byte poisoning of the fixture transactions: **3,821,196 cases,
  3,820,122 identical (hash AND preimage AND return), 1,074 where the new
  build refuses a non-canonical compactsize, 0 unexplained.** The
  canonicality verdict comes from an independent walker, not from the
  implementation under test.

`validation/diff_bip143_corpus.py` + `validation/bip143_corpus_dump.c` are new
and reproduce the corpus half on demand (`--baseline main`).

### Measured
`tests/bench_segwit_sighash` is new and permanent so the next change to this
path has something to be compared against; both earlier figures for it were
taken with throwaway harnesses. `-O2`, CPU time, min of 15, both builds back
to back:

| shape | before | after | factor |
|---|---|---|---|
| 1 in / 2 out (189 B) | 0.3960 us | 0.3718 us | 1.07x |
| 2 in / 2 out (304 B) | 0.4364 us | 0.4052 us | 1.08x |
| 100 in / 5 out | 16.830 us | 2.510 us | 6.7x |
| 1,372 in / 100 out | 2.633 ms | 30.57 us | **86x** |
| 2 in / 3,000 out | 5.115 ms | 42.14 us | **121x** |

The common case is not pessimised -- that was the thing to check.

On the real thing: 20 mainnet blocks at heights 616,980-617,018, the exact
window section 7 profiled, all **53,400 witness inputs** driven through
`segwit_v0_sighash` -- **5,735.90 ms -> 209.00 ms**, i.e. 107.41 us -> 3.91 us
per witness input, **27.4x**. `read_cs` calls over the same blocks:
4,340,010,792 -> 32,889,389, **131.9x**. Of the old total, `strip_witness` --
untouched by this change -- is 0.010%, so essentially all of section 7's
`read_cs` share is this and essentially all of it goes.

Projection, with the bound stated: the three symbols are 34.07% of profiled
cycles, so **the Amdahl ceiling is 1/(1-0.3407) = 1.517x** and nothing here
can beat it. Residual 1.24% (whole-function, 27.4x) or ~0.2% (`read_cs`
counts, 131.9x) gives **1.49-1.51x end-to-end**. Do not believe that without
re-profiling: section 7 exists because a projection off a 227,000-block-stale
profile said 1.40x and delivered 1.15x, and this share was measured at
~617,000 while the replay has moved on. The figure that does not depend on the
share is the 27.4x on the component.

Corroboration that the benchmark drives the profiled work: the old path costs
107.41 us per witness input against section 1's measured 120.9 us for
`ecdsa_verify`, and 96.4% of the sighash cost is removed here, predicting the
three symbols at 45.3% of that pair's cycles. The profile has them at 34.07%
against 42.07% for the field/EC symbols -- 44.75%. Two routes, 0.6 points
apart.

No post-change profile of the daemon was taken: the change is not deployed
(the replay has not reached tip), and `perf_event_paranoid` is 4 on this host,
which blocks `perf` for a non-root user.

### Deliberately not done
A per-transaction cache of the three hashes across one transaction's inputs
(Core's `PrecomputedTransactionData` proper). `segwit_v0_sighash` is called
from inside the interpreter with no transaction-scoped context, so the cache
would be a thread-local keyed on (address, length) -- not sound, since a
different transaction can reuse an address at the same length, and making it
sound needs a full byte-compare against a retained copy per call. Priced: on
the 1,372-input shape that compare costs about half of what the rebuild now
costs, so it buys ~2x on the rarest shape and ~0 on the common one, against a
wrong-sighash failure mode if the key ever aliased. At 3.91 us against
`ecdsa_verify`'s 120.9 us the path is now 3.1% of a witness input. Recorded in
`PERF_SCOPE.md` section 8.6 so it is not re-litigated from scratch.

### Found while measuring, NOT fixed here
`bitcoin_taproot_sighash.c` has the identical O(n^2) -- `tx_seq`,
`tx_outpoint`, `ser_txout` and `ser_txout_len` all walk from the start on
every call, and `ser_txout_len` walks the output list twice -- **and its own
`read_cs` is unbounded** (it takes no `end`), with bound tests written in the
`q + sl > end` pointer form that incident #21 had to remove from
`bitcoin_segwit.c` because a wire-derived length near 2^64 overflows it. That
path goes hot at height **709,632** and is script-path-heavy from ~775,000
(`CHAIN_AHEAD_CENSUS.md` sampled one block with 44,933 script-path inputs).
Same fix, same bounds class, deliberately not in this commit: a performance
restructure and a consensus-path bounds fix should not land together.

### Full suite
`make -k test` MAKE_RC=0, 0 failures. `make abi-check` OK.

### Incident #23 and #24 (found by corpus differential, not by the replay): the BIP341 sighash accepted two shapes Core rejects
*(Numbered after #22 although found before it: #22 was committed and pushed
while this section was still being written. Both are FALSE ACCEPTS -- Core
rejects these spends and we returned a usable sighash -- and neither was
reachable by replaying the real chain, because no such transaction is IN the
chain: Core-running miners would not include one. They were found by asking
Core for the answer to 19,721 vectors and comparing, which is the only method
that finds a false accept at all. #23 is the unvalidated `hash_type`; #24 is
SIGHASH_SINGLE past the end of the output list. Fixed in `0a3127d`.)*

`fc4bd67` ended with a note that `bitcoin_taproot_sighash.c` carried the
identical defects one file over, and that a performance restructure and a
consensus-path bounds fix should not land together. Taproot activates at
709,632 and the live replay is a few hours away from it, so this is that work.
All three diagnoses in that note are **confirmed**. Two further problems were
found while proving the result, and they are worse than either.

### 1. CONFIRMED: the O(n^3), same shape as BIP143's

- `tx_seq(t,i)` and `tx_outpoint(t,i)` each re-walked the input list from the
  start to reach input `i`, parsing a compactsize per step. BIP341's
  `sha_sequences` calls `tx_seq` once per input: **O(nin^2)** varint reads.
- `ser_txout(t,i)` re-walked the first `i` outputs, and `ser_txout_len(t,i)`
  did the same walk **twice** -- literally twice, the first result computed
  into a local and then discarded and the loop re-run. `sha_outputs` called
  both once per output: **three O(nout^2) walks**.
- And `taproot_sighash()` is called once per input (once per executed
  OP_CHECKSIG/OP_CHECKSIGADD via `taproot_checksig_fn`), while BIP341's
  aggregates depend only on the transaction and not on which input is being
  signed -- so the whole thing was redone from scratch `nin` times.
  **O(nin^3) per transaction.**

Three of the four aggregates did not need any of it. `c->prevouts`,
`c->amounts` and `c->spks` are ALREADY the contiguous concatenations BIP341
asks for; the old loops copied a buffer onto itself 36/8/n bytes at a time into
a 4 MiB staging buffer and hashed the copy. They are now hashed where they lie.
Only `sha_sequences` genuinely has to be gathered, because nSequences are 41+
bytes apart in the transaction, and with `in_off[]` that is one indexed load
per input.

### 2. CONFIRMED: the OOB read is real, and a plain truncation is enough

`read_cs` took no `end`. A compactsize's width is chosen by its own first
byte, which is wire data, so any walk landing on the last byte read up to 8
bytes past it -- and `tx_parse` read each length BEFORE checking that it fit.
Every bound was the pointer-overflow form `q + (int64_t)sl + 4 > t->tx +
t->txlen`, which additionally casts an unsigned wire length through `int64_t`,
so any `sl >= 2^63` went negative and the comparison passed unconditionally.

`tests/test_taproot_bounds_fuzz.c` is new: the transaction is copied so its
LAST byte abuts a `PROT_NONE` page, so a read one byte past the end is a
deterministic SIGSEGV. No sanitizer, because this path links hand-written asm
that ASAN cannot instrument.

    on this tree   ALL PASS (8,601,700 calls, 0 faults)      3.9 s
    on main        FAILURES (8,601,700 calls, 36,712 faults)

Minimal reproducer, and it is exactly the predicted one -- `01000000ffb21282f7a2`,
10 bytes: `txlen < 10` passes, the version is read, then the unbounded
`read_cs` at `tx+4` sees `0xff`, selects the 9-byte form and reads `tx[5..12]`.
Standalone with no handler installed: **SIGSEGV, exit 139, core dumped.**

The part worth keeping: **14,579 of the 36,712 faults needed no byte poisoning
at all.** They are plain truncations of real mainnet transactions. The smallest
is the first 41 bytes of `4cc72b13218183d4a6b13e79ef3e0a73c7987688dd0334866a8398b03e514057`
(block 775,000), where `q + 36 > tx + txlen` is `tx+41 > tx+41`, i.e. false, so
the walk advances to `q == end` and `read_cs(&q)` dereferences `*end`. A peer
truncating a real transaction on a byte boundary was sufficient. Nothing had to
be crafted.

### 3. NEW, and the reason this is urgent: two consensus divergences, both FALSE ACCEPT

Neither was in fc4bd67's note. Both are pre-existing, both are in the class
that splits the chain rather than merely stalling it, and both were found by
asking Core about the corpus rather than by reading the code.

**(a) `hash_type` was never validated.** Core, `SignatureHashSchnorr`:

    if (!(hash_type <= 0x03 || (hash_type >= 0x81 && hash_type <= 0x83))) return false;

which `CheckSchnorrSignature` turns into `SCRIPT_ERR_SCHNORR_SIG_HASHTYPE` --
the input is invalid. Nothing here checked it at all, and `hash_type` is the
LAST BYTE OF A 65-BYTE SCHNORR SIGNATURE, entirely attacker-chosen. A spend
signed with hash_type `0x04` is rejected by Core and was accepted here (`0x04 &
3 == 0`, so it took the plain `sha_outputs` path and produced a perfectly good
hash for the spender to have signed).

**(b) SIGHASH_SINGLE past the end of the output list.** Core:

    if (output_type == SIGHASH_SINGLE) {
        if (in_pos >= tx_to.vout.size()) return false;

BIP143 substitutes a zero hash in this position; BIP341 deliberately does not,
and this file had carried the BIP143 behaviour over -- it wrote 32 zero bytes
and returned a usable sighash. This is not a corner that needs constructing:
**1,710 of the 945-vector first smoke run were exactly this case on real
mainnet transactions**, before any invalid hash types were added.

Both are now Core's rule exactly, and the accept/reject boundary is checked as
strictly as the hashes are (see the corpus result below).

### The fix: one bounded pass, then index

`in_off[0..nin]` and `out_off[0..nout]`, recorded in a single bounded walk;
every accessor afterwards is an array index. Inputs are contiguous, so input
`i`'s 4-byte nSequence ends exactly at `in_off[i+1]`, and `in_off[nin]` is one
past the last input, so that is exact for the final input too. `tx_seq` and
`tx_outpoint` become one load each with no compactsize read at all.

**And the question fc4bd67 asked to be answered explicitly, because BIP341 is
not BIP143 here.** BIP341's `sha_outputs` is SHA256 over "the serialization of
all outputs in CTxOut format" -- 8-byte value || compactsize(len) ||
scriptPubKey per output, which is byte for byte the transaction's own wire
encoding, exactly as in BIP143. So **yes, the in-place property holds**:
`sha_outputs` is a single sha256 over `[out_off[0], out_off[nout])` in place and
SIGHASH_SINGLE's is one over `[out_off[n_in], out_off[n_in+1])`. `ser_txout`
and `ser_txout_len` are deleted and no output is copied anywhere.

BIP341 does also hash amounts and scriptPubKeys separately -- `sha_amounts` and
`sha_scriptpubkeys`, which BIP143 has no counterpart for -- and that is **not**
a counterexample, because those two are over the SPENT outputs, the UTXOs this
transaction consumes, which are not in this transaction at all. They arrive as
the caller's own contiguous arrays. The outputs this transaction *creates* are
hashed in exactly one place and in exactly one format.

Capacity is arithmetic, not a guess, and deliberately the same bound
`SW_OFF_ENTRIES` uses so the two sighash paths refuse at the same place: an
input costs >= 41 wire bytes and an output >= 9, so
`(nin+1)+(nout+1) <= 0.13550*txlen + 2`, and MAX_BLOCK_SERIALIZED_SIZE (4 MiB)
gives <= 568,335 entries. 600,000 (2.29 MiB) cannot false-reject anything.
`TS_SEQ_CAP` is derived from it (`4 * TS_OFF_ENTRIES`) so the sequence buffer
can never be the binding constraint. Per-thread heap (`BMC_TLS_BUF`), never a
stack array -- incident #13.

Also removed, all latent, all in the buffers the aggregates used to stage into:
the scriptpubkeys loop tested `n + 600 > TS_AGG_CAP` and then copied `cs + sl`
bytes (consensus places no limit on a scriptPubKey's size -- incident #21's
shape, on the heap); the sequences loop had no bound at all AND iterated to
`c->num_inputs` while `tx_seq` indexed `t->nin`, with nothing checking that
those agree (now checked); `ser_txout_len` returned `int`, so a scriptPubKey of
`0x100000000` bytes truncated to 13 and let `ser_txout` memcpy 4 GiB; and
`agg_hashes` returned `void` and simply `return`ed on overflow, leaving the
remaining `h_*` outputs UNINITIALIZED for `taproot_sighash` to copy into the
preimage -- a truncated aggregate was not refused, it was hashed.

`uint8_t pre[256]` also went to a bounded per-thread heap buffer. 256 was
enough only because a taproot input's spent output is a 34-byte P2TR program;
for anything larger the cap check fired and returned 0, i.e. a silent FALSE
REJECT with the boundary at an undocumented ~200 bytes. Core has no such limit.

### Byte-identical against Core, on 196 real mainnet taproot transactions

Ground truth is Bitcoin Core, never our own previous answer.
`validation/core_verify_oracle.cpp` gains a `BIP341` command running Core's own
`SignatureHashSchnorr`, and it is self-checked against all seven published
BIP-341 wallet-test-vectors before any answer is used -- if that fails, nothing
else runs. (One trap worth recording: `PrecomputedTransactionData::Init()` only
computes the BIP341 midstates when it *sees* a witness-bearing input whose
spent scriptPubKey is a 34-byte OP_1 program, so with a witness-stripped
transaction it silently produces nothing but errors. `Init(tx, spent,
/*force=*/true)` is required.)

`validation/diff_bip341_corpus.py` + `validation/bip341_corpus_dump.c` are new
and reproduce the corpus on demand -- pull real taproot transactions, ask Core,
build both sides, diff -- so the next change here does not reinvent it:

    python3 validation/diff_bip341_corpus.py --baseline main

19,721 vectors over 196 real mainnet taproot transactions from 69 blocks,
heights 709,632..963,637: three input indices x seven hash types x six invalid
hash types x key-path/script-path/codesep/annex variants.

    worktree      vs Bitcoin Core :  15,125 / 15,125 hashes match
    worktree      refusals        :   4,596 /  4,596 also refused
    baseline(main) vs Bitcoin Core:  15,125 / 15,125 hashes match
    baseline(main) refusals       :       0 /  4,596 also refused   <-- 4,596 FALSE ACCEPTS
    worktree vs main              :  15,125 / 19,721 byte-identical,
                                      4,596 intended refusals, 0 unexplained

That is the whole result in one table. **No hash moved** -- zero unexplained
differences against the previous implementation. **Every hash matches Core.**
And the accept/reject boundary, which main got wrong 4,596 times out of 4,596,
is now exact. Core refusing a vector is itself an answer, so the differ gates
on it rather than excluding it; that gate is the only reason (a) and (b) were
found at all.

The same corpus under `-fsanitize=address,undefined` gives byte-identical
output with zero diagnostics.

### Measured

`tests/bench_taproot_sighash` is new and permanent, so the next change to this
path has something to be compared against. `-O2`, `CLOCK_PROCESS_CPUTIME_ID`,
min of 15, both builds back to back, same five shapes as
`bench_segwit_sighash` so the two tables are directly comparable. Iterations
per shape are calibrated at runtime to >= 20 ms per run, because one fixed
count cannot serve two builds 420x apart.

Key-path (`ext_flag=0`); script-path is a flat +0.03 to +0.04 us on both
builds (the 37 extra preimage bytes) and otherwise indistinguishable:

    shape                  before        after      factor
    1 in /     2 out     0.4001 us    0.3875 us      1.03x
    2 in /     2 out     0.4699 us    0.4487 us      1.05x
    100 in /   5 out     9.7203 us    4.3148 us      2.25x
    1,372 in / 100 out   1.1254 ms   54.3603 us     20.70x
    2 in / 3,000 out    18.1766 ms   43.3184 us      419x

**The common case is not pessimised**, and that was the thing to check.
Four independent min-of-15 repeats, binaries interleaved: the new build is at
or below the old in every repeat of the 1- and 2-input shapes, key-path and
script-path, by a consistent 2-5%, with the distributions not overlapping on
the 2-input rows. The reason is direct -- at nin = 1-2 the offset table costs
a couple of stores, while the prevouts/amounts/spks *copies* (36+8+35 bytes
each, staged into a buffer before hashing) and the `ser_txout` output staging
are gone outright. Per-thread resident scratch also falls, from a 4 MiB
`TS_AGG_CAP` buffer to a 2.29 MiB offset table.

### On the real thing: 19,870 taproot inputs from five mainnet blocks

Heights 825,000 / 830,000 / 842,000 / 865,000 / 910,000 -- the five with the
largest taproot input counts out of 38 blocks scanned between 709,700 and
963,000, and the sample happens to capture both regimes (825,000 is
inscription-era script-path-heavy; 830,000 and 910,000 carry 1,500- and
1,000-input consolidations). 19,870 taproot inputs across 12,014 transactions,
16,387 key-path and 3,483 script-path, each driven once through
`taproot_sighash()` in block order on the REAL witness-stripped serialization
-- real input counts, real output counts, real script sizes. CPU time, min of
15:

    before   4,577.85 ms  (med 4,857.80, max 4,980.31)   230.39 us / input
    after      243.35 ms  (med   252.68, max   264.94)    12.25 us / input

    18.81x.

The distribution matters more than the aggregate:

    height    taproot in    before        after       factor
    825,000    3,379        2.25 ms       1.68 ms      1.33x
    830,000    3,661    3,833.15 ms     195.65 ms     19.59x
    842,000    4,274       68.00 ms       5.39 ms     12.61x
    865,000    4,295        2.87 ms       2.15 ms      1.33x
    910,000    4,261      766.24 ms      65.72 ms     11.66x

Blocks made of ordinary 1-3 input taproot spends gain a flat ~1.33x; the one
block containing a 1,500-input consolidation goes from **3.83 seconds of
sighashing to 196 ms**. Nothing gets slower.

Two honest qualifications on that workload. The spent outputs are SYNTHETIC --
a 34-byte P2TR scriptPubKey and an arbitrary amount per input, which is
exactly the right size for a real taproot input's prevout, and the cost
depends only on the count and sizes of those arrays, not their contents; the
transaction STRUCTURE, which is what the O(n^2) was in, is real. And
`hash_type` is forced to SIGHASH_DEFAULT, the dominant real choice and the
most expensive branch, identically for both builds. This is a component
benchmark, not a consensus check -- the consensus check is the corpus above.

No end-to-end projection is offered. PERF_SCOPE.md section 7 exists because a
projection off a stale profile share said 1.40x and delivered 1.15x, and this
path has never been profiled live at all: the replay has not reached 709,632,
so its share of taproot-era cycles is unmeasured. The figure that does not
depend on a share is the 18.81x on the component.

### The outer O(nin) is still there, and that is not a regression

`taproot_sighash()` still runs the single pass and re-hashes the O(nin)
prevouts/amounts/spks arrays on EVERY call, and it is still called once per
input. What was removed is the inner re-walk. That is why the 1,372-input
shape is still 54 us per call rather than ~1 us, and why block 830,000 still
costs 53 us per taproot input afterwards. Core hoists exactly this to once per
transaction (`PrecomputedTransactionData`); we cannot, for the reason
PERF_SCOPE.md 8.6 already records for BIP143 -- there is no transaction-scoped
context to hang it on, and a thread-local keyed on the transaction's address
and length is not sound. It is the next available win on this path and it is
larger here than it was there, because BIP341 has four aggregates rather than
three. Recorded in PERF_SCOPE.md section 10.

### Deliberately NOT done

- **An `spks_len` parameter.** `c->spks` has no length in the API, so its walk
  cannot be *proven* in bounds; it carries a hard 4 MiB ceiling checked before
  every advance instead. It is built by this codebase from resolved UTXOs
  (`daemon/tx_verify.c`, `bitcoin_txval_modern.c` both write one single-byte
  compactsize per entry), not taken from the wire, so this is a real but
  second-order gap. Fixing it is an ABI change across ~10 call sites in two .c
  files and five tests, which does not belong in a sighash restructure.
- **A per-transaction cache of the aggregates across one transaction's
  inputs** -- Core's `PrecomputedTransactionData` proper. Declined for exactly
  the reason PERF_SCOPE.md 8.6 records for the BIP143 path: there is no
  transaction-scoped context to hang it on, and a thread-local keyed on the
  transaction's address and length is not sound.

### FOUND WHILE PROVING THIS, NOT FIXED HERE

`bitcoin_txval_modern.c:240` (the mempool-accept path, not block validation)
builds the taproot aggregate arrays into `uint8_t sp[16*70]` and fills it with

    if (T.in[k].prev_spklen < 0xfd) sp[off++] = (uint8_t)T.in[k].prev_spklen;
    else return 0;
    memcpy(sp+off, T.in[k].prev_spk, T.in[k].prev_spklen);

with no check that `off` stays inside `sp`. `nin` is capped at 16 and
`prev_spklen` at 252, so the worst case is 16*253 = 4,048 bytes into a
1,120-byte stack array. Eleven bare 2-of-3 multisig prevouts (105 bytes each)
is enough, and bare multisig outputs exist on mainnet and are spendable. Same
class as #13 and #21, third file. Not fixed here because it is a different file
on a different path and this commit already carries three concerns.

### Incident #25: BIP66/DERSIG -- the same shape as #22, in the dangerous direction

`script_flags_for_block()` sets `SCRIPT_VERIFY_DERSIG` (bit 2) for every block
at height >= 363,725, exactly as Core's `GetBlockScriptFlags` does. It was
threaded into `sv_verify_script` -> `sv_run_v` -> `script_state.flags`, reached
`bitcoin_interp.asm`, and **nothing read it**. Both checksig callbacks went
straight to `der_parse_sig`, whose own header advertises that it is "TOLERANT
of non-minimal INTEGER encoding" -- correct, and necessary, *below* the
activation height. Above it this node accepted signatures Core rejects. Not a
stall: a **chain split**, and unlike #22 (a false reject that stopped the
replay loudly) this one is a false accept, which splits silently.

There is no live symptom and there never will be one: Core-valid history after
363,725 contains only strict-DER signatures, so no replay reaches it. It needed
a constructed reproducer.

**What was actually accepted** -- established by fuzzing 18,322 encodings
against Core's own `CheckSignatureEncoding` through a new `SIGENC` command in
`validation/core_verify_oracle.cpp`, not by reading `der_parse_sig`. 4,643 of
them were accepted here and rejected by Core. Every clause of
`IsValidSignatureEncoding` except three was simply absent:

| Core's rule | before |
|---|---|
| `size() >= 9`, `<= 73` | only `>= 8`, no upper bound |
| `sig[0] == 0x30` | enforced |
| `sig[1] == size()-3` (the SEQUENCE length byte) | **never looked at** -- the header admitted it: "best-effort; we still rely on explicit 0x02 markers" |
| `5 + lenR < size()` | enforced (as a raw pointer bound) |
| `lenR + lenS + 7 == size()` | **never checked** -- trailing garbage, a missing hashtype byte, and two hashtype bytes all passed |
| `sig[2] == 0x02`, `sig[lenR+4] == 0x02` | enforced |
| `lenR != 0`, `lenS != 0` | enforced |
| `!(sig[4] & 0x80)`, `!(sig[lenR+6] & 0x80)` (no negative INTEGERs) | **not checked** |
| no excess `0x00` padding on R or S | **the opposite**: padding was deliberately stripped |

The reported diagnosis held on every point. The padding case is the cleanest
probe because it is value-preserving: prepending `0x00` to R changes neither
R's value nor any sighash preimage (the legacy sighash substitutes the
scriptCode for the spending input's scriptSig; BIP143 never hashes the witness
at all), so the padded signature still verifies cryptographically. Core agrees:
it accepts the padded transaction at a pre-BIP66 height and rejects it at a
post-BIP66 one. The *only* thing wrong with it is its encoding.

**The fix.** `der_sig_strict` (`bitcoin_scriptcodec.asm`, beside
`check_minimal_push` -- the same kind of encoding-validity predicate, and the
one file every link line carrying the interpreter already has) is Core's
`IsValidSignatureEncoding` transcribed check-for-check in Core's own order --
which is also what makes it memory-safe, since the `lenS != 0` test is what
bounds the `sig[lenR+6]` load. `der_parse_sig` is untouched and stays tolerant;
strictness is a gate in front of it, not a change to it. `interp_checksig` and
the `interp_checkmultisig` loop call `interp_sig_encoding_ok` before any hashing
or ECDSA work, exactly where Core calls `CheckSignatureEncoding` -- once per
CHECKSIG, and once per signature-under-consideration in CHECKMULTISIG, so
signatures the multisig loop never reaches are never checked, in Core and here
alike.

Three details that are easy to get wrong and were checked rather than assumed:

- **A bad encoding is a hard script ERROR, not a false CHECKSIG.** Core's
  `EvalChecksigPreTapscript` returns `SCRIPT_ERR_SIG_DER` and aborts the script.
  Merely returning false would still reject a P2PKH -- but `<sig> <pk> CHECKSIG
  OP_NOT` would then *accept* a signature Core rejects, leaving the split open.
  `interp_checksig` returns -1 for this and `.op_checksig` converts it;
  `interp_checkmultisig` uses its existing `interp_err` channel.
- **Which flag gates it in which path.** Core's guard is
  `flags & (DERSIG|LOW_S|STRICTENC)`, transcribed as-is; on this codebase's
  consensus path DERSIG is the only one of the three that can ever be set,
  because `GetBlockScriptFlags` never produces the other two and neither does
  `script_flags_for_block`. The *witness v0* path is gated on the same flag,
  not on something always-on: Core reaches `CheckSignatureEncoding` from
  `EvalChecksigPreTapscript` for `SigVersion::BASE` **and** `WITNESS_V0`, with
  no separate always-strict rule. That is not academic -- block 692,261, the
  Taproot `script_flag_exception` from #22, has its flags overridden to
  `P2SH|WITNESS` with **no DERSIG at all** despite being at height 692,261, so
  a witness-v0 spend in that one block is not subject to strict DER.
- **Tapscript is excluded.** `SIGVERSION_TAPSCRIPT` goes to Core's
  `EvalChecksigTapscript`, whose signature rule is BIP342's 64/65-byte schnorr
  one and has nothing to do with DER. Running the check there would reject
  every tapscript spend.

**The reproducer, `tests/test_dersig_encoding`.** Real mainnet transactions at
all three block-connect dispatch shapes -- P2PKH, P2SH multisig, P2WPKH -- each
unmodified and with one signature's R redundantly `0x00`-padded, driven through
**both** `tx_verify_block_connect` and `tx_verify_block_connect_all` (#22 was
present at both dispatch sites; a test covering one would have missed half of
it). Against main it fails 12 assertions, every one of them a false accept, at
every shape and both entry points. It also pins the gate in the other
direction: the same padded bytes re-hosted at a real pre-BIP66 block must still
be ACCEPTED, and the boundary is pinned at the two real blocks 363,724 and
363,725. Without that half, "just always be strict" passes the reject
assertions and breaks 363,000 blocks of history -- the exact failure mode #22
shipped.

**History really does contain these.** Scanning mainnet turned up plenty;
two are baked in as fixtures, both P2PKH, both accepted by the real chain:

    h149,850  b13abbc136a76dd5...  R = 0x00 0x0a 0x0f ...  redundant leading zero
    h152,841  f17f32b98f834f2d...  R = 0xac 0xab 0x5e ...  negative DER INTEGER

Each must verify at its own height and must be rejected if re-hosted above
363,725 -- which is also what proves they are genuinely non-strict rather than
merely unusual. Core's `SIGENC` confirms both directions for each.

Fixtures come from `validation/fetch_dersig_vectors.py`, which asserts every
baked verdict against Core's own `VerifyScript`/`CheckSignatureEncoding` before
emitting it, and carries a 27-vector `der_sig_strict` table (one per clause of
Core's function, plus the two historical signatures) so the unit level is
pinned to Core without needing the oracle at test time.

**Audit of the sibling rules, reported not fixed.** `LOW_S`, `NULLFAIL` and
`STRICTENC` are *not* in the "computed but ignored" state: they are never
computed, by us or by Core, because all three are mempool/relay policy
(`policy.h` `STANDARD_SCRIPT_VERIFY_FLAGS`), never consensus. Removing an
identical STRICTENC hashtype check from `sv_checksig` on 2026-08-19 is what
unblocked the replay at height 110,299, and this change is careful not to
reintroduce it. Of the seven flags `script_flags_for_block` *does* produce,
DERSIG was the last unconsulted one: P2SH is read by `sv_verify_script`,
NULLDUMMY inside `interp_checkmultisig`, CLTV/CSV by `op_cltv`/`op_csv`,
WITNESS and TAPROOT by both `tx_verify.c` dispatch sites since #22.

**Found while proving this, NOT fixed here.** The MEMPOOL path
(`txval_modern` -> `p2wpkh_verify` / `p2wsh_verify_checksig` /
`p2wsh_verify_multisig` in `bitcoin_segwit.c`, and `multisig_verify` in
`bitcoin_multisig.asm`) parses signatures with `der_parse_sig` directly, never
touching the interpreter, so it is unaffected by this fix and still accepts
non-strict DER. That is a policy/relay divergence rather than a chain split --
block connection never reaches those functions -- but it deserves its own
incident. A correct `IsValidSignatureEncoding` also already existed in-tree at
`rpc_chain.c:442` (`der_sig_ok`, used only to decide whether to pretty-print a
`[ALL]` tag in `decodescript` output); it is now the third copy of this rule in
the tree and could be collapsed onto `der_sig_strict`.

## 2026-08-21 -- Two more real production incidents (#4, #5) during Stage D's full-archive replay; checkpoint durability fixed

### Real production incident #4 (autonomous, overnight): CHECKLOCKTIMEVERIFY/CHECKSEQUENCEVERIFY were stubs, not real checks
The overnight replay (continuing from incident #3's redeploy) hit a new,
deterministic rejection at real mainnet height 388431: `REJECT h=388431
tx=564: legacy script verification failed`. Root-caused directly: `OP_CLTV`/
`OP_CSV` in `bitcoin_interp.asm` were wired as pass-through no-ops rather
than the real BIP65/BIP112 locktime/sequence comparisons against the
spending transaction's own `nLockTime`/`nSequence` -- silently accepting
scripts a real node must reject. Implemented the real checks; fixed in
commit `fbeff60`. Compacting/recovering in place was not attempted this
time -- given a rejection this late in a long replay could plausibly leave
a subtly-wrong-but-not-obviously-broken UTXO set behind it (CLTV/CSV gate
*script success*, not consensus state directly, but the safer call given
the project's standing "verify against real data, don't assume" discipline
was a full from-scratch redeploy rather than trusting the compaction-based
in-place recovery path). `bmc-bitcoind.service` redeployed fresh
(`applied_height=-1`) at 03:45:36 and confirmed clean past height 388431 on
the very next attempt -- the fix holds under real replay.

### Real production incident #5: UTXO checkpoint could lag real durable state by an unbounded amount, masquerading as corruption on crash-resume
The fresh replay from incident #4 progressed cleanly to height 363896,
took a routine mid-catchup compaction there (`manifest_n=1 -> result=1`,
06:07:09), and kept running for several more hours. The HOST machine then
rebooted multiple times, unprompted and unrelated to this project (external
infra event, confirmed via `last reboot`), between 11:16 and 12:13 --
killing the daemon uncleanly. It is not enabled on boot (per standing
preference to run it manually), so it sat stopped until a manual restart at
13:25:12, which reloaded the last persisted checkpoint (height 363896) and
immediately hit a NEW, deterministic rejection on every retry: `REJECT
h=363897 tx=1: input references a missing/already-spent UTXO`.

This is the SAME failure shape flagged as unresolved in a 2026-08-19 code
comment (`daemon/utxo_live.c`, near `utxo_live_catchup`) after an earlier,
abandoned attempt at periodic mid-catchup checkpointing was reverted --
that comment's leading theory (a flush/compact reconstruction bug silently
dropping live entries) was WRONG, but the underlying symptom it observed
was real and finally root-caused this session: `applied_height` was only
persisted at rare compaction events or once at the very end of a (possibly
hours-long) catch-up call, while every individual `utxo_lsm_put`/`del` is
already durable the instant it runs. An unclean process death therefore
routinely left the true on-disk UTXO state hours AHEAD of the last-written
checkpoint. On restart, catch-up trusted the stale checkpoint and tried to
re-verify a block whose inputs it had already durably spent before the
crash -- correctly failing that re-verification (the input really is
already spent), but incorrectly treating a "this block was already
applied" situation as a fatal consensus rejection instead of a safe replay
no-op. Two other worktrees from an earlier, independent investigation of
this exact bug were found still on disk (`.worktrees/verify-snapshot-resume`,
chasing the wrong flush/compact theory, and `.worktrees/fix-crash-resume-verify`,
a real but incomplete fix that only re-checked the FIRST resumed height per
boot rather than every block in a potentially multi-thousand-block gap) --
both removed as superseded once the real fix landed.

Fix: persist `applied_height` after every successfully applied block
(`daemon/utxo_live.c`), not just at compactions/end-of-call, so no gap
between real and checkpointed state can ever exist -- correct by
construction rather than by detecting and tolerating the gap after the
fact. Added a test-only crash-injection hook
(`utxo_live_test_set_crash_after`, a guarded no-op unless a test arms it).
New regression test (`tests/test_utxo_catchup_crash_resume.c`) builds a real
chain with a real spend, forks a child that applies exactly one block and
`_exit(1)`s right where its checkpoint should persist, then does a real
`utxo_live_close()`+`utxo_live_init()` restart and asserts the checkpoint
reflects the crashed block and resume is a clean no-op; verified via
disabling the fix line that it reproduces the exact production symptom
(`REJECT h=150 tx=1: input references a missing/already-spent UTXO`)
pre-fix and passes with it restored. Full `make -k test`: 1582/1582, both
in the fix worktree and after rebuild on `main`. Merged (`--ff-only`) and
pushed as commit `2fd4a14`.

Because the true durable height of the crashed run was unknown (and not
worth the risk of guessing), UTXO state was dropped
(`archive_drop_utxo_state()`'s exact file set: `utxo_applied_height.dat`,
`utxo.dat`, `utxo.idx`, `utxo_manifest.dat*`, `utxo_lsm_table.map`,
`utxo_lsm_blob.map`, every `utxo_run_*.dat` and `undo_*.dat`) and
`bmc-bitcoind.service` redeployed fresh at 14:36:31, now durably protected
against a repeat of this exact failure mode regardless of when a future
crash lands.

**Status at end of session:** both fixes (`fbeff60`, `2fd4a14`) merged to
`main` and pushed. `bmc-bitcoind.service` redeployed from scratch,
confirmed clean past height 363896 (the incident #5 stall point) via a
routine compaction with no rejection, replaying toward chain tip 963445.
Height 388431 (incident #4's stall point) not yet re-reached by this fresh
replay as of session end, but already independently confirmed clean once
during incident #4's own post-fix redeploy. Monitoring continues
unattended.

## 2026-08-19/20 -- Stage D wired live; three real production incidents found and fixed during the first full-archive replay

### Wiring: script verification connected to block connection
`tx_verify_block_connect`/`tx_verify_block_connect_all` (`daemon/tx_verify.c`,
new file) now runs from `apply_block_inner` (`daemon/utxo_live.c`), ahead of
every block's puts/dels -- exactly where Core's `ConnectBlock` runs
`CheckInputs`, before `UpdateCoins`. Per non-coinbase input: resolve the
confirmed prevout (in-block outpoint index first for same-block chained
spends, `utxo_lsm_get` fallback), enforce the 100-block coinbase-maturity
rule, classify the prevout scriptPubKey's shape, and dispatch: legacy shapes
(P2PK/P2PKH/P2SH/bare-multisig) to `sv_verify_script`
(`bitcoin_scriptverify.c`), P2WPKH/P2WSH/P2TR-keypath to the witness
primitives already proven at the mempool layer
(`bitcoin_txval_modern.c`/`bitcoin_segwit.c`/`bitcoin_taproot_sighash.c`).
Whole-block duplicate-outpoint detection is now an EXPLICIT pre-check (a
hash-set walk over every input before verification starts), not the
accidental side effect the old strictly-sequential verify-then-apply loop
produced (the second spender's `utxo_lsm_get` used to fail only because the
first spender had already deleted the UTXO) -- a real correctness gap a
dedicated `Plan` design-review subagent caught before any of this landed;
see `worklog/2026-08-19.md` and `tests/test_cross_tx_verify.c` scenario B for
the regression coverage.

### Made it fast enough to actually run at chain scale
Signature verification (ECDSA/Schnorr) is the dominant cost of block
connection and was single-threaded at first -- a from-scratch replay
measured ~1 of this box's 32 cores in use. Path to a usable replay, each step
profiling-driven:
1. Per-tx fork()-based parallel verify (matching `dl_catchup`'s existing
   pattern) replaced with a pthread pool: fork()'s copy-on-write page-table
   setup cost scales with the PARENT's resident size, and during a
   from-scratch replay the parent IS the growing multi-GB UTXO memtable, so
   every fork() got progressively more expensive over the run (confirmed via
   production stack sampling -- every sample landed inside `fork()` itself).
   Required making the legacy-script interpreter's scratch state genuinely
   thread-safe first (`bitcoin_scriptverify.c`/`bitcoin_interp.asm`/
   `bitcoin_sighash.asm`/`bitcoin_scriptcodec.asm`, real ELF TLS via
   `.tbss`/`TLS_ADDR`, not per-call heap scratch).
2. Redesigned from per-transaction dispatch (`tx_verify_block_connect`, only
   fanned out when a SINGLE tx had >=8 inputs -- most transactions in this
   era of chain history don't) to whole-BLOCK dispatch across every
   transaction's inputs at once (`tx_verify_block_connect_all`,
   `daemon/tx_verify.c`'s "CROSS-TRANSACTION PARALLEL VERIFICATION" design).
3. Re-profiled and found `memset` dominating the perf trace, resolving into
   unresolved kernel addresses -- a page-fault storm from fresh
   `malloc`/`calloc` at high per-block call rates forcing the kernel to fault
   in and zero brand-new pages on every touch. Fixed with the "allocate
   once, reuse forever" pattern applied to every hot per-block scratch array
   (`grow_arena`: realloc-if-bigger, never shrink, `utxo_live.c` and
   `tx_verify.c` each keep their own copy per this codebase's
   no-shared-small-helpers convention).
4. `strace -c -f -p <daemon pid>` then found a ~840 `clone3`/sec storm,
   matched by `mmap`/`munmap`/`mprotect` -- per-block `pthread_create`/
   `pthread_join` faulting in and tearing down a fresh thread stack every
   round, dwarfing the crypto work being parallelized at bulk-mode block
   rates (an earlier isolated microbenchmark of a single `pthread_create`
   had NOT caught this, since it never measured sustained high-frequency
   creation). Fixed with a persistent semaphore-parked worker pool
   (`txvb_pool_ensure`/`txvb_worker_loop`) started lazily and never torn
   down, matching this codebase's existing convention of never gracefully
   joining background threads at shutdown.

### Real production incident #1: LSM compaction inverted its own manifest scan order
While the fixed-up daemon replayed the real archive live
(`bmc-bitcoind.service`), it hit a genuine consensus rejection at real
mainnet height 184390: `REJECT h=184390 tx=1: legacy script verification
failed`, immediately followed by a blind auto-triggered "in-place recovery"
compaction (`daemon/main.c` calls `utxo_live_recover()` unconditionally on
ANY `utxo_live_catchup` failure -- it cannot distinguish "manifest full" from
"genuine consensus rejection", a still-present design pattern worth treating
any future FATAL+recovery pair with suspicion over).

Root-caused by reading `bitcoin_utxo_lsm.asm` directly, not guessing:
`utxo_lsm_get`'s disk-run scan (`.lg_run_loop`) walks the manifest array from
its HIGHEST index down to 0, treating highest index as newest/highest-
priority (and `mac_flush` always appends correctly at the true array end).
`utxo_lsm_compact` inverted this for the merged/oldest run after a partial
compaction: it shifted surviving (newer) manifest entries down to `[0,K)`
FIRST, then appended the merged (oldest) entry AFTER them at the highest
index -- exactly backwards from the scan order, so a stale, already-deleted
key could resolve as live again post-compaction. Fixed by writing the merged
entry first at index 0, then shifting survivors starting at `dst=1` instead
of `dst=0` (`asm/bitcoin_utxo_lsm.asm`, commit `e12dcbb`).

New regression test (`tests/test_compact_manifest_order.c`) forces a
partial compaction with a deleted key's tombstone landing in the merged
(oldest) batch and a genuinely-live key surviving alongside it; verified via
`git stash` that it FAILS against the pre-fix code with the exact predicted
symptom (the deleted key resolving live again) and PASSES with the fix. UTXO
state was cleanly dropped and rebuilt (`archive_drop_utxo_state()`, the
block archive itself untouched) before redeploying, since the bug could have
left latent corruption in the on-disk manifest from earlier compactions.

### Real production incident #2: dangling pointer into a growable byte pool
Redeployed on fresh state -- and hit the SAME height-184390 rejection again,
proving incident #1, while real, was not the (sole) cause of this specific
symptom. Root-caused via an isolated, read-only reproduction (real archive
block files symlinked into a throwaway directory, `utxo_live_init`/
`utxo_live_catchup` run against a fresh UTXO state there -- never touching
the live daemon's own data) plus targeted debug instrumentation proving the
resolved prevout scriptPubKey was CORRECT at resolve time and CORRUPTED at
verify time for the identical input.

Cause: a byte-pool bump allocator (`bytepool_t`/`bytepool_alloc`,
`daemon/tx_verify.c`) introduced earlier the same night to fix a *different*
regression (raising `TXV_SPK_CAP` from 252 to the real consensus max 10000
had made the OLD flat per-entry inline-buffer design ~25x bigger per entry,
reintroducing the page-fault-storm symptom incident #1's arena-reuse fix had
just eliminated) returned a RAW POINTER into its own `realloc()`-backed
buffer. A later input's allocation in the SAME block's Phase 1 resolve loop
could trigger a `realloc()` that relocated the buffer, silently invalidating
every pointer already handed out to EARLIER inputs in that loop -- a classic
dangling-pointer bug, and non-deterministic across process runs (whether
`realloc` relocates depends on that process's heap layout), which is exactly
why it reproduced inconsistently between attempts. Fixed by storing a stable
byte OFFSET into the pool instead of a pointer (`txvb_in_t.spk_off`),
resolved to an address only after Phase 1 has finished growing the pool for
that block -- an offset survives relocation; a raw pointer captured
mid-growth does not (`daemon/tx_verify.c`, commit `4ec089c`).

New regression test (`tests/test_tx_verify_bytepool_realloc.c`) mines a
block spending ten ~9000-byte-scriptPubKey prevouts (~90KB total,
comfortably past the pool's 65536-byte initial capacity) to force
`bytepool_alloc`'s `realloc()` to fire mid-loop after several earlier inputs
are already resolved; verified via `git stash` that it reproduces the exact
production failure signature against the pre-fix code and passes cleanly
with the fix. Full `make -k test` green on both the fix worktree and `main`
after merge (`--ff-only`) before redeploying. UTXO state dropped and rebuilt
again before this redeploy for an unrelated reason: the on-disk
`utxo_applied_height.dat` marker was missing after an earlier SIGKILL during
debugging, while substantial LSM state (undo logs past height 203000)
remained on disk -- an inconsistent combination unsafe to resume from
directly.

### Real production incident #3 (autonomous, overnight): OP_SIZE register-width bug + OP_SHA1 entirely unimplemented
User went to bed with standing authorization to fix and redeploy autonomously
overnight, reindexing from scratch if needed. The redeployed daemon hit a
new, DETERMINISTIC rejection (unlike incident #2, this one repeated
identically on every retry) at real mainnet height 251683:
`REJECT h=251683 tx=9: legacy script verification failed`.

Root-caused via the same isolated read-only reproduction technique as
incident #2, but pivoted to a much faster iteration loop once the exact
failing scriptSig/scriptPubKey bytes were known: a standalone
`sv_verify_script` harness taking raw hex bytes directly (no archive replay
needed at all -- sub-second per attempt instead of minutes), then a
scriptPubKey-prefix binary search, then a stack-dump harness calling
`script_eval` directly and inspecting the raw stack after each partial run.

The failing script (`827651a0698faaa9a8a7a687`) decodes to `OP_SIZE OP_DUP
OP_1 OP_GREATERTHAN OP_VERIFY OP_NEGATE OP_HASH256 OP_HASH160 OP_SHA256
OP_SHA1 OP_RIPEMD160 OP_EQUAL` -- a real, well-known "hash puzzle" style
scriptPubKey whose spending condition is fully computable from public
information (not a signature check), legitimately spendable by anyone.

Two independent bugs, both in `bitcoin_interp.asm`:
1. `OP_SIZE` read the top stack element's length via `mov rdx, [r13]` -- a
   64-bit load -- but that field is a `uint32` immediately followed by the
   element's own data bytes, pulling in 4 bytes of DATA as garbage high
   bits of the pushed "size" number. Confirmed via grep this was the ONE
   exception among ~20 similar length-field reads elsewhere in the file
   (all correctly use a 32-bit register). The existing OP_SIZE test vector
   never caught it because it never decoded the pushed size back as a
   number, and its specific data happened to have all-zero padding that
   hid the corruption. Fixed: `mov edx, [r13]`.
2. `OP_SHA1` was entirely unimplemented (`; SHA1 not available -> bad
   opcode`) -- a real, always-defined Script opcode, never built. No SHA-1
   existed anywhere in this codebase. Implemented from scratch
   (`asm/sha1.asm`, scalar-only/correctness-first, mirroring `sha256.asm`'s
   structure), verified against FIPS 180-4 vectors plus padding-boundary
   cases against independent Python `hashlib` references (11/11), and
   wired into `.op_crypto`'s dispatch.

New `tests/test_interp.c` vectors (a targeted OP_SIZE case that actually
decodes the pushed value, canonical SHA1("abc"), and the exact real
height-251683 transaction bytes run end to end) verified via `git stash` to
fail against the pre-fix code with the real production signature and pass
with the fix. Full `make -k test` green (87/87) on both the fix worktree and
`main` after merge (`--ff-only`); pushed (`8caa5ac`).

Found the on-disk UTXO state in the same inconsistent shape as incident #2's
redeploy (`utxo_applied_height.dat` missing, undo logs present up to exactly
one height below the failure) -- dropped and rebuilt fresh, redeployed
WITHOUT asking first this time, squarely covered by the standing autonomous
authorization (incidents #1/#2 each got an explicit user confirmation while
the user was awake; this one happened after they had gone to bed).

**Status at end of session:** all three fixes merged to `main` and pushed
(`e12dcbb`, `4ec089c`, `8caa5ac`). `bmc-bitcoind.service` redeployed on a
freshly rebuilt UTXO state, confirmed past both height 184390 and height
251683, replaying toward chain tip 963183 unattended. Monitoring continues.

## 2026-08-18 -- Single source of truth for node wire identity (user-agent + versioning)

### Problem: node's advertised identity was hardcoded, duplicated, and placeholder
The daemon's outgoing P2P `version` payload (`node_make_version` in
`bitcoind.asm`) advertised a hardcoded user-agent `"Bitcoind-AssemlbyCode
(BobClawblaw) vx.x.x"` whose version number was never actually resolved to a
real value. Three magic numbers had to be kept in sync by hand and could
silently drift: the UA string, its length byte (42), and the total payload
size (128). The same protocol version (70016) was duplicated across the
version handshake, the getheaders builder (`bitcoin_p2p.asm`), and a level
logger call (`main.c`). The wire protocol version also had no shared source
-- the user asked for both the application version AND the protocol version
to come from one canonical definition.

### Change: one canonical file, everything else derived
- `asm/version.inc` is now the SINGLE SOURCE OF TRUTH: `NODE_VERSION_MAJOR/
  MINOR/PATCH` (0.0.1), `NODE_PROTOCOL_VER` (70016), and the UA prefix/suffix.
- `bitcoind.asm` `node_make_version` derives the UA string (NASM `%strcat`),
  its length byte (NASM `%strlen`), and the payload size (`81+UA_LEN+5`) at
  assembly time from `version.inc` -- no hand-synced literals remain.
- `bitcoin_p2p.asm` getheaders and `main.c`'s HSHK level-logger call read the
  protocol version from the same source.
- The Makefile + `gen_version_header.py` regenerate `asm/version_gen.h` (C
  header, git-ignored) from `version.inc` for the C consumers, and the ASM
  objects / daemon / test rebuild automatically when `version.inc` changes.
- `tests/test_bitcoind.c` byte-exactness assertions now reference the derived
  constants instead of hardcoded 42/128/legacy string.

The node now advertises `/BitcoinMachineCode:0.0.1/` (26-byte UA, version
payload 112 bytes). Verified: bumping to 0.1.2 propagates the new identity to
the ASM object, daemon binary, and test; reverted to the 0.0.1 baseline. Full
`make test` passes (71/71). To bump the version or protocol, edit ONLY
`asm/version.inc`.

## 2026-08-17/18 -- UTXO set replaced with an LSM-tree, then wired live into the P2P daemon (mempool/tx-relay validation, commits 4e393ef..3ff03f3)

### The problem: single-table UTXO store write-amplified ~13x during full replay
A full-archive UTXO-set-from-archive replay (`daemon/build_utxo.c`, driving
`bitcoin_utxo_store.asm`/`bitcoin_utxo.asm`) started at ~9,000 blocks/sec and
collapsed to under 100 blocks/sec by 15% progress. Root cause, confirmed
empirically (`iostat`, `/proc/PID/io`, `/proc/PID/smaps_rollup`): the
in-memory hash table has to be pre-sized upfront for the FINAL total live
UTXO count (~408M, at 2^30=1.07B slots for headroom), but during replay the
hash function scatters writes essentially randomly across that entire
51.5GB mmap'd, file-backed structure from block 0 onward, regardless of how
few entries are actually live -- table pages measured being written back to
disk ~13x on average (606GB actually written vs ~47GB of real touched
data). Two low-risk mitigations (drop a redundant WAL `lseek()`, raise
`vm.dirty_ratio`) helped but didn't fix the structural problem; shrinking
the table to 2^29 slots gave 2-4x but risked silently producing an
incomplete set if the live-count estimate ran even moderately over.

Bitcoin Core avoids this with LevelDB (an LSM-tree) behind a bounded
`-dbcache`, not one giant pre-sized structure. Built the equivalent from
scratch (no external libraries, matching this project's ethos):
`bitcoin_utxo_lsm.asm`, reusing `bitcoin_utxo.asm`'s open-addressing table
UNCHANGED as the memtable engine (proven correct via prior backward-shift-
deletion stress testing), instantiated small and fixed-size, never resized.

### Phase 1 (4e393ef): bounded memtable + per-generation WAL + sorted-run flush
On-disk layout: `utxo_manifest.dat` (run-generation list, published via
temp-file+fsync+rename -- NOT the old `utxo.idx`'s O_TRUNC-rewrite-in-place,
which has its own unfixed crash hazard), `utxo_run_%06d.dat` (immutable
sorted runs: min/max key + Bloom filter + sparse index + sorted records),
`utxo_wal.dat` (reuses `bitcoin_utxo_store.asm`'s existing PUSH/DEL record
format, scoped to the current generation, truncated on flush). Per-run
Bloom filter (txids are SHA256d, so byte-order is uniform -- a min/max
bounds check alone gives near-zero pruning power). `utxo_lsm_del`
deliberately changed behavior vs `utxo_del`: a memtable miss always emits a
tombstone rather than silently no-op'ing, since every DEL here is a real
consensus-valid spend. Verified via `tests/test_utxo_lsm.c` (basic
put/get/del across memtable+runs, tombstone-shadowing, crash-recovery
simulation at each of the 5 flush ordering steps), then a 100+-trial
randomized stress test, before swapping `build_utxo.c` over and running a
smoke differential (identical live count + sampled `utxo_get` results)
against the real archive. Full-archive rate stayed flat instead of
collapsing (e.g. 694 blk/s vs the old store's 79 blk/s at matching
checkpoints) -- fix confirmed.

Also found and fixed, while verifying Phase 1: a pre-existing (not new)
`bitcoin_utxo_store.asm` bug in `utxo_store_reload`'s WAL-tail replay --
`slen` was stored via a 32-bit `mov` into an 8-byte stack slot then reloaded
via a 64-bit `mov`, leaving stack garbage in the high 4 bytes and corrupting
the size `utxo_put` used for its blob-capacity check, spuriously reporting
"table full" AFTER already writing the slot's txid/index (a phantom
occupied-but-empty slot). Fixed by storing the full zero-extended `rax`
instead of `eax` at both occurrences.

### Phase 2 (c0a2f68): streaming k-way merge compaction
Manifest refactored from 8-byte `[gen]` entries (run_no implied by array
index) to explicit 16-byte `[gen:8][run_no:8]` pairs, since compaction
replaces many runs with one, breaking the index-implies-run_no invariant.
`utxo_lsm_compact`: opens up to 64 oldest runs, streams the globally-
smallest key across all input buffers, always drops tombstones (safe since
compaction is always a prefix down to the oldest live run), publishes via
the same fsync+rename sequence as flush.

Two real bugs, both found via a 6000-round stress test with compaction
interleaved every 211 rounds, both root-caused with a minimal ~211-round
deterministic repro (`/tmp/repro_compact.c`) once isolated, rather than
continuing to iterate against the slow full test:
- **Key-aliasing**: the "advance every slot matching the winning key" loop
  compared against the winning slot's own LIVE key field, which gets
  mutated in place when it's one of the slots being advanced (which it
  always is, since it won). Fixed by snapshotting the winning key into a
  stable buffer before any advancing starts.
- **The real corruption**: `mac_bloom_setbit`'s signature is
  `(key, seed, bloom_base, bits_mask)`, but the compaction code placed
  `bloom_base` in `rsi` instead of `rdx`, while `rdx` still held the
  winning slot's OWN address from an earlier instruction in the same
  block -- `mac_bloom_setbit`'s internal `add rdx,rbx; or [rdx],al` wrote
  into the winning slot's own header fields instead of the bloom bitmap,
  corrupting its `fd` (observed as an impossible `fd=2097163`), which then
  failed with a real I/O error the NEXT time that slot needed re-reading.
  Found via a hardware watchpoint on the corrupted slot's `fd` field, which
  caught the exact write instruction and its caller. The existing FLUSH
  code already had this correct; a copy-adaptation slip specific to the
  new compaction path. Fixed by moving `bloom_base` to `rdx` as documented.

Verified: full 6000-round stress test green (0 mismatches), plus a
dedicated "close, fresh-init a second instance, `utxo_lsm_reload`, confirm
state survives" check.

### Live-daemon wiring (8408ee4..3ff03f3): five stages, three fresh bugs found while wiring, one archive-integrity bug found and fixed along the way

**Stage 0 (8408ee4) -- cross-process archive-write race.** Investigating how
to wire the LSM store into `main.c`'s live P2P loop surfaced a real,
independent bug: the download worker (`serve_download_worker`) is NOT
actually the sole block writer in `serve` mode, despite its own comment
claiming so -- a forked inbound serve child can also append a pushed block
(`bitcoin_serve.asm` `.do_block`, reachable via an unsolicited `inv` or the
child's own `.do_inv`-triggered `getdata`, regardless of `nwant=0`), using
plain unlocked `store_append` while believing (per a stale comment) that
`st+40` wasn't a valid flock fd in this context -- it is, `main.c` sets it
before both forks. Simply flock-guarding both paths wasn't sufficient
either: `store_append_shared` takes a caller-supplied height, so two
writers each computing "next height" from their own stale cached state
could still both decide on the same height and clobber each other's index
slot, since the lock only serializes the byte-level write, not that
decision made outside it. Fixed with a new primitive,
`idxscan_append_locked` (`bitcoin_idxscan.asm`): holds the same flock,
determines the true current tip via the existing hole-aware `idxscan_tip()`
scan (robust to a batch tool's pre-sized/zero-padded trailing region, unlike
a raw `idx_len/48` read) UNDER that lock, then delegates to
`store_append_shared` with that height -- making "read tip, then write" one
atomic critical section. Both `node_sync` and `.do_block` now go through it.
Verified via the full daemon/IBD/serve test suite (0 regressions); redeployed
the live production daemon onto this binary.

**Archive corruption (found and fixed mid-Stage-1, not part of the original
plan).** The very first full LSM-based UTXO replay against the real archive
completed (962,831 blocks, ~9,600s) but flagged 13,513 heights where the
stored block data's hash didn't match its own index record --
`build_utxo.c` already had defensive per-block hash verification (added
after an EARLIER instance of this exact issue was found during development)
that skips and logs rather than aborting. The bad heights clustered in a
very telling pattern: contiguous runs starting at round chunk-boundary
numbers (30000, 40000, 42000, 44000, 46000, 48000, 52000, plus three
smaller clusters near 388180/482331/482852) -- the signature of
`unified_ibd.c`'s own documented (and already-fixed) "boundary-chain-break"
header-reuse bug from an earlier backfill pass, leaving stale, NON-ZERO
(so invisible to the existing zero-record hole-detection) index records
that were never actually holes, just wrong. Root-caused via direct
byte-level inspection (a small `pread`-based Python script) confirming the
recorded `file_no`/`pos` for one such height pointed at bytes that don't
even parse as a valid `[len][magic]` frame. Fix: zeroed the 13,513 bad
records (making them real, detectable holes), re-ran `backfill_holes.sh`
(0 holes afterward, 100% contiguous from genesis, independently re-verified
byte-hash-exact on all 13,513 previously-bad heights), then discarded the
first replay's ~219GB of now-known-incomplete LSM state and re-ran the full
replay from scratch against the corrected archive (order-dependent: a coin
created in a skipped height but spent in an already-processed later height
would otherwise end up incorrectly "live" if just patched in after the
fact). Second replay completed clean, 0 corruption warnings.

**Stage 1 (b332d42) -- `daemon/utxo_live.c`: live UTXO catch-up.** The
download worker becomes the sole live UTXO writer, tracked via a PERSISTED
applied-height counter (published with the same tmp+fsync+rename+dirfsync
pattern the LSM store's own manifest uses) compared against the store's
TRUE on-disk tip every rotation -- not a per-call before/after diff the way
`do_outbound_sync` tracks its own sync progress, since that would only ever
see blocks this process's own `node_sync` calls produced, missing a
sibling inbound child's (now Stage-0-safe) `.do_block` writes entirely.
Sized far smaller than `build_utxo.c`'s batch-scale memtable so a future
per-connection `utxo_lsm_reload()` stays cheap. Extracted
`read_varint`/`walk_tx_io` out of `build_utxo.c` into a new shared
`daemon/utxo_walk.h` rather than duplicating them.

Two real bugs found via a standalone smoke test (init, apply <1
flush-threshold worth of puts against a truncated 500-height archive slice,
close, re-init, verify state survives) BEFORE this ever touched
`main.c`:
- `utxo_manifest.dat` is only created at the first flush -- checking its
  existence alone to decide init-vs-reload misses any WAL-durable-but-
  unflushed state and silently starts fresh, losing it (observed as count
  dropping from 503 to 0 across a close/reopen). Fixed by also checking
  `utxo.dat` (the actual WAL file) directly.
- `utxo_lsm_init` and `utxo_lsm_reload` have different return contracts (1
  ok / -1 err vs REPLAYED RECORD COUNT / -1 err) -- a single `r != 1` check
  treated reload's own legitimate success (e.g. 523 replayed records) as a
  failure. Root-caused via a `gdb` breakpoint directly at the presumed
  `.rl_fail` label, which never fired, revealing the return-value
  assumption itself was wrong rather than any actual failure path.

Deployment of Stage 1+ to the live daemon deliberately deferred until the
corrected full replay finished, to avoid two processes (the replay tool and
`utxo_live_init`) touching the same on-disk LSM files concurrently with no
coordination between them.

**Stage 2 (897fc45) -- `mv_resolve` pointer-lifetime bug.**
`bitcoin_txval_modern.c`'s `mv_resolve` resolved every input's prevout
script in one loop, storing the raw `utxo_get`-returned pointer before any
of them are consumed -- including P2TR keypath verification's own
aggregation of ALL inputs' scripts together for the combined sighash, much
later in the same function. Safe against `bitcoin_utxo.asm`'s stable
in-memory pointers, but not against `utxo_lsm_get`'s documented contract:
on a disk-run hit, the returned pointer is only valid until the NEXT
`utxo_lsm_get` call -- exactly what the loop resolving the next input does.
Any multi-input tx with 2+ disk-resident prevouts (the common case once the
memtable has flushed past them) would validate against corrupted script
bytes once wired to the LSM backend. Fixed with an owned per-input
`prev_spk_buf[42]`, copied into immediately after each resolve call.
Confirmed a behavior no-op against the current stable-pointer backend:
`test_mempool_accept_modern` still passes all 23 checks byte-for-byte.

**Stages 3-4 (d31d12b, 3ff03f3) -- compat shim + wiring `.do_tx`.**
`.do_tx` accepted any syntactically-minimal tx with zero validation. New
`daemon/tx_accept.c` gives each forked inbound connection a read-only UTXO
snapshot via one `utxo_lsm_reload()` at connection start (private malloc'd
memory, never file-backed/shared -- must never collide with the writer's
own mmap'd state or with sibling connections), then runs the tx through the
existing, already-tested `mpool_policy_add` (fee/RBF/ancestor-descendant
limits) and `txval_modern` (full segwit/taproot signature verification)
before storing anything for relay.

A naming collision required a rename, not just new glue code:
`mpool_policy_add`/`txval_modern` call `utxo_get` to resolve confirmed
prevouts, but that exact symbol is ALREADY bound -- as an unrelated
dependency of `bitcoin_utxo_lsm.asm`'s own memtable internals -- in any
binary that also links the LSM store, so a second, differently-behaved
definition under the same name would collide at link time. Renamed their
call sites to `mempool_resolve_confirmed_utxo`; the two existing test
harnesses get a 3-line passthrough to the real `utxo_get`, preserving their
exact prior behavior (confirmed unchanged: both pass as before).

Ordering matters and isn't what a first read of the task suggested:
`mpool_policy_add`'s own accept path already calls `mpool_put` internally
as its final step (confirmed directly in `bitcoin_mempool_policy.c`), and
there is no public API to unregister a tx from its internal
ancestor/descendant graph state afterward -- only the structural
`mpool_del`, which wouldn't clean up that bookkeeping. So `txval_modern`
(pure signature/structural validation, no policy/mempool dependency) runs
FIRST: a signature failure then never triggers the policy accept+insert in
the first place, rather than inserting and needing a rollback that isn't
cleanly possible via the existing API.

New permanent test, `tests/test_tx_accept_e2e.c` -- not covered by
`test_mempool_accept_modern`, which only ever exercises the old
`bitcoin_utxo.asm`-backed passthrough, never `tx_accept.c` itself: seeds a
real confirmed prevout into a fresh on-disk LSM store, drives the actual
`tx_dispatch_init`/`tx_policy_init`/`tx_accept_validate` sequence
`bitcoin_serve.asm` now uses, and proves both that a valid spend is
accepted and actually stored in the mempool, AND that a corrupted-signature
spend is rejected and leaves no phantom mempool entry (the concrete proof
the ordering fix above works). Landmine while building it: BIP141 txid
excludes witness data, so corrupting a witness signature byte does NOT
change the tx's own txid -- reusing the same fixture for both the
valid-accept and corrupted-reject cases made the "not left in the mempool"
check spuriously find the valid tx's own legitimate entry; fixed by using a
distinct fixture for the corruption case.

Stage 4 (Makefile `DAEMONOBJS`/`SERVEOBJS` wiring) landed incrementally
across Stages 1 and 3 as each needed new objects to link, then got a
dedicated cleanup pass (3ff03f3): running the FULL `make test` suite (not
just the individually-touched targets) caught six more test binaries
(`test_keepup`, `test_bip152_loop`, `test_sendheaders_fee`,
`test_outbound_mux`, `test_redial`, `soak_mux_peer`) that also link
`bitcoin_serve.o` and needed the same new sources -- refactored into a
shared `SERVETXVALSRCS` Makefile variable instead of six separate copies.

**Full verification**: entire `make test` suite (~80 harnesses) green, 0
failures, after the Makefile fix. One transient failure during an earlier
run (`test_scalarmul_ct`, a constant-time timing-ratio check, unrelated
secp256k1 code never touched by any of this) reproduced as flaky under
concurrent system load (the background UTXO replay competing for CPU) --
confirmed by 3/3 clean passes in isolation, not a regression.

**Status at end of session**: Stage 0 deployed live. Stages 1-4 committed,
tested, NOT yet deployed to the live daemon -- pending confirmation the
corrected UTXO replay is fully complete and the daemon restart is a good
time (deployment replaces the running production process). Remaining:
redeploy, then task-level real-peer soak testing of live tx-relay/mempool
acceptance.

----------------------------------------------------------------------------
## 2026-08-17 -- secp256k1_fe.asm: fe_mul REWRITTEN WITH adcx/adox PARALLEL CHAINS (1.13x, FULLY VERIFIED)
### Goal and outcome
A different question this time: not more C-to-asm conversion, but whether
EXISTING asm crypto primitives could be faster with better instruction
selection. `fe_mul`/`fe_sqr` (secp256k1 field multiplication -- the single
most-executed operation during ECDSA verify, since it's called dozens of
times per point add/double) was still plain schoolbook `mul`/`adc`, no
BMI2 (`mulx`) or ADX (`adcx`/`adox`), despite the host CPU (AMD Ryzen 9
9950X3D) supporting both. Separately confirmed `sha256.asm` is already
optimal (CPUID-gated SHA-NI hardware dispatch, correctly active on this
host) -- nothing to do there.
### Attempt 1 (conservative): mulx substitution only
Given the stakes (this underlies every signature verification in the
node), first tried the conservative option: swapped `mul` for `mulx` in
Phase 1 (the 256x256->512-bit schoolbook multiply) only, leaving the
accumulation structure and all of Phase 2 (reduction) byte-for-byte
untouched. Verified rigorously (100M random trials vs the original + an
independent `__uint128_t` reference, zero mismatches; full `make test`
65/65 green) before even measuring it. Result: 82.5 -> 83.7 Mops/s,
**~1.015x** -- the real bottleneck (the serial dependency between each
term's carry-out, threaded through one register across all 4 terms of a
row) wasn't touched by swapping just the multiply instruction.
### Measuring the real ceiling before attempting more
Rather than trust the general BMI2/ADX literature figures (~20-35%) at
face value, measured where fe_mul's time actually goes: built a
Phase-1-only variant and timed it against the full function. **Phase 1 is
~81% of total cost, Phase 2 ~19%** -- translating the literature's
Phase-1-only figure into a more realistic ~20-25% END-TO-END estimate for
this codebase's specific reduction strategy. This is what justified
attempting the fuller rewrite.
### Attempt 2: adcx/adox parallel chains
Four independent row computations (`a[i]*B`, each 1x4->5 limbs), rows 0/2
via the `adcx` chain (CF), rows 1/3 via `adox` (OF) -- two rows using
DIFFERENT flags share no dependency, so the CPU can overlap e.g. row 1's
work with row 0's still-retiring chain (the actual mechanism these
speedups come from; attempt 1 kept everything on one serial chain). Each
row writes to its own scratch buffer; the 4 rows are combined into the
final 8-limb product via a separate, deliberately low-risk `add`/`adc`
merge (same ripple-carry style already proven elsewhere in this file).
Every row opens with `xor ecx,ecx` (clears both CF and OF) so no row
inherits a stale carry from an earlier row sharing its flag.
### A real bug, caught immediately by the verification pipeline
First build crashed on the very first call, zero output before segfault.
gdb: `rip=0`, every register zeroed. Root cause: the prologue's stack
allocation grew from 64 to 224 bytes (for the new row buffers) but the
epilogue still deallocated only 64 -- a 160-byte mismatch that corrupted
the return address on every call. The same class of bug this codebase's
own "golden rule" warns about (scratch overlapping saved state), just via
a mismatched prologue/epilogue pair rather than an overlapping slot. Fixed
by matching the epilogue to the new allocation size; never got near
`make test`, let alone production, before being caught.
### Verified (same rigor as attempt 1, repeated against the TRUE original)
- Built the true original (pre-any-change, straight from `git show
  HEAD:...`) under renamed symbols for a clean side-by-side comparison,
  plus the same independent third reference.
- 150,000,000 random trials + edge cases (0, 1, p-1, p, all pairwise
  combinations, forced out-of-canonical-range operands on a fraction):
  zero mismatches vs the original, zero mismatches vs the independent
  reference.
- Full `make test`: 65/65 green.
- Same live-daemon-independence facts as attempt 1 still hold: `cons_verify`
  (used by `dl_catchup`'s block download) doesn't call into secp256k1/
  fe_mul at all, and `secp256k1_fe.o` isn't linked into `DAEMONOBJS` --
  only test binaries and `wallet_cli`. No live-daemon redeployment
  applicable.
### Benchmark, and an honest diagnosis of the remaining gap
fe_mul throughput, 30M calls: 83.8 -> 94.7 Mops/s, **~1.13x**. Better than
attempt 1 but short of the ~20-25% estimate -- isolating the row
computation alone shows it really did get ~44% faster (0.3035s -> 0.1693s
per 30M calls), but the separate merge pass this design needs (rows write
to independent buffers rather than accumulating in place) costs ~0.078s,
consuming roughly 58% of the raw row-computation savings. The clean row
independence that made the parallel chains safe to reason about is also
what gives most of the gain back. A design that accumulates in place while
still using two chains could close that gap further, but reintroduces much
of the complexity/risk the independent-rows approach was chosen to avoid,
for a return that's already diminishing at this point -- not pursued.
Shipped as the final version, replacing attempt 1.

## 2026-08-17 -- crawler.c FORK-STATE BUG FIXED; addrgather.c INVESTIGATED AND LEFT ALONE
### Goal and outcome
Fifth pass today. A fresh asm-candidate survey found no strong "next
check_chain" (bitcoin_mempool_policy.c has the right O(n^2) shape --
find_node/find_outreg/find_claim linear-scan the mempool per input -- but
zero call sites from the daemon; tx-relay isn't wired into main.c yet, so
there's nothing real to benchmark). Picked up a correctness bug the survey
flagged in passing instead: `crawler.c`/`addrgather.c` both fork() per-seed
discovery workers, and the initial read was that per-worker state never
propagates back to the parent, leaving the final report/output empty.
### Verification before fixing anything
Checked both files independently rather than trusting the shared
characterization, since they turned out to differ:
- `crawler.c`: CONFIRMED broken. `seen[MAXSEEN][40]`/`seen_n` were a plain
  static array; each fork()'d child got its own copy-on-write private
  copy, so no child's `mark_seen()` was ever visible to the parent.
  `out_file` was always written empty; the "crawl complete: N distinct"
  summary always reported N=0. (Live discoveries themselves weren't lost --
  each child's `printf()` goes through the inherited, genuinely-shared
  stdout fd -- only the in-memory dedup table and anything built from it
  in the parent afterward were broken.)
- `addrgather.c`: NOT broken this way. Reading `bitcoin_addrmgr.asm`
  showed `amr_add`/`amr_count` are entirely file-backed via a single fd
  (`peers.dat`, opened once before fork) -- there is no in-memory table to
  lose across fork. Verified empirically (throwaway probe: fork N
  children, each calls `amr_add`, check the parent's `amr_count` after
  `waitpid`): state correctly survived fork every time. Also stress-tested
  the theoretical concern -- concurrent children sharing one fd's file
  offset with an unprotected `lseek`+`write` pair -- two ways: 40
  concurrent children adding DISTINCT IPs (expect all 40 land), and 40
  concurrent children all adding the SAME IP (expect exactly 1, exercising
  the dup-check race). 5/5 trials each, zero lost writes, zero duplicates
  -- the shared-fd semantics correctly serialize at the kernel level in
  practice. Left the file untouched: no evidence of a real problem to fix.
### Fix (crawler.c only)
Moved `seen[]`/`seen_n` into a `mmap(MAP_SHARED|MAP_ANONYMOUS)` region
created in the parent before the fork loop, so every child inherits the
same physical pages instead of a private copy. The check-and-insert
(`is_seen`+`mark_seen`) still needed cross-process mutual exclusion --
two children could otherwise both pass `is_seen()` for the same endpoint
before either called `mark_seen()`, or race on the shared `seen_n` slot
index -- guarded with `flock()` on a dedicated lock file derived from the
output path (`<out_file>.lock`). Per the flock lesson already established
elsewhere in this codebase (`store_append_shared` etc.): each child opens
its OWN fd to the lock file rather than inheriting one from the parent,
since flock locks belong to the open file description, not the path --
a fork-inherited fd would not actually provide mutual exclusion between
siblings.
### Verified (hard evidence)
Wrote a throwaway probe mirroring the exact mechanism: 30 concurrent
children, each marking 3 endpoints distinct to itself plus 2 shared across
every child (exercising the propagation fix and the dedup-race guard
together). Parent's final `*seen_n` and the written `out_file`'s line
count both correctly landed on 92 (= 30*3 + 2 deduped) across 3/3 runs --
previously would have been 0 / an empty file. Full `make test`: 65/65
green, exit 0 (`crawler.c` isn't a Makefile/test-suite target, built and
verified manually).

## 2026-08-17 -- unified_ibd.c's LAST TWO RAW index.dat SCANS SWAPPED TO idxscan_*
### Goal and outcome
Fourth asm-adjacent pass today. A fresh survey (deliberately checking
beyond the two items already flagged and deferred -- `verify.c`'s
per-height `fopen`/`fclose`, low-value since real crypto work in the same
loop dwarfs it and it's a rarely-run manual fallback; `paribd.c`'s
per-record `fopen`, the worst constant-factor bug found but genuinely dead
code with no Makefile target) confirmed `unified_ibd.c` still had the last
two raw index.dat scans in the codebase duplicating already-proven asm
functions: `chunk_all_present` (per-200-block-chunk presence check) and the
tip-detection backward scan in `main()`.
### Fix
Both call sites run after `main()`'s own `chdir(dir)`, so CWD is already
the archive directory -- no chdir-wrapper needed (unlike the `chainctl.c`
fix earlier today), just direct calls to `idxscan_all_present`/
`idxscan_tip`.
### Honest framing
This one is modest compared to the day's other three fixes, worth stating
plainly rather than dressing up: these were plain I/O-bound loops with no
compounding algorithmic issue (unlike `idx_hash`'s entropy collapse or
`check_chain`'s O(n^2)) -- just the same buffered-pread64 constant-factor
win the `idxscan` family already established elsewhere.
### A benchmarking lesson mid-investigation
First attempt constructed synthetic "pre-sized with trailing holes" test
files via `truncate` extending a partial real copy -- this creates sparse-
file holes the kernel serves as zero without touching disk at all,
regardless of implementation, so it showed almost no difference either
way. Recognized real production `index.dat` files are themselves sparse
via the same pre-sizing mechanism, so re-ran against an actual snapshot of
the live growing archive instead, which gave the honest numbers below.
### Verified (hard evidence)
- Tip-scan on a real snapshot (899,844 real tip, ~63,000 trailing zero
  records to walk): 0.007s -> 0.001s (~7x).
- `chunk_all_present` across the realistic hot-path pattern (a full
  backfill's worth of 200-block chunk claims: 4,500 chunks over the present
  range, 4,815 over the full range including trailing holes): 0.126s ->
  0.0046s (~27x) and 0.151s -> 0.0048s (~32x) respectively. Correctness:
  identical "all present" counts (4,496/4,496 matching) between old and new
  at every tested range.
- Full `make test`: 65/65 green, exit 0.
### Safety note (deliberately avoided a repeat)
Learned from an earlier incident today (running `chainctl` directly against
the live production `data/` directory spawned real `unified_ibd` workers
competing with the live daemon) -- this time, all testing used scratch
copies exclusively, with `end_h` chosen so the resume logic's own "archive
already complete; nothing to do" short-circuit fires before any network
code path can run. Zero interaction with the live production archive.

## 2026-08-17 -- check_chain.c O(n^2) DUP DETECTOR FIXED + chainctl.c archive_tip SWAPPED TO idxscan_tip
### Goal and outcome
Third asm-adjacent fix today (candidate found via a fresh survey of
asm/daemon/*.c for hot loops still using the superseded per-record C
patterns already replaced elsewhere): `check_chain.c` (standalone archive
integrity-audit tool, not the live `dl_catchup` daemon) had a genuinely
O(n^2) duplicate-block-hash detector -- a nested loop comparing every new
record's hash against every previously-seen hash, despite its own comment
claiming "naive O(n)". At the real archive size (~962,831 blocks) that's
~4.6e11 comparisons; `chainctl.c` (the orchestrator that drives
`check_chain` after every ~8000-block chunk during a full IBD) reruns this
~120 times over a full run with growing n each time, so the cost compounds.
### Fix
Reused `idx_init`/`idx_put` (`bitcoin_idx.asm`, written and validated
earlier today for `build_hash_index`) in place of the manual nested-loop
scan -- `idx_put`'s own return (1 new / 0 dup) does duplicate detection in
one O(1)-amortized-per-insert pass, turning the whole thing O(n). Table
sized dynamically (`next_pow2(n*4+1024)`, ~25% target load factor) so it
doesn't need retuning as the real archive grows past today's size.
Also swapped `chainctl.c`'s `archive_tip()` -- a per-record `fseek`+`fread`
backward scan for the highest non-zero index record, the same pattern
`idxscan_tip` already replaced in `main.c` -- to call `idxscan_tip()`
directly via a chdir-in/chdir-out wrapper (idxscan_tip operates on
"index.dat" in CWD; nothing else in chainctl.c depends on staying in a
particular directory).
### Verified (hard evidence)
- Timed the OLD dup detector on real truncated archive slices to confirm
  the O(n^2) shape empirically before trusting an extrapolation: 50k->0.36s,
  100k->1.46s, 150k->3.26s, 300k->13.09s, 400k->23.30s -- fits a quadratic
  curve almost exactly (e.g. 100k->150k ratio 2.24 vs predicted (150/100)^2
  = 2.25), confirming no unexpected cache-driven acceleration/deceleration
  at larger n that would invalidate extrapolating to full scale.
- NEW version at the same slice sizes: 50k->0.007s, 100k->0.027s,
  150k->0.034s, 300k->0.079s, 400k->0.089s -- dup counts matched the OLD
  version exactly at every size (0 at all tested slices).
- Full real archive (879,800 stored records): OLD extrapolated ~135s vs NEW
  measured 0.198s (~680x, growing further as the archive does). The full
  run additionally reported `duplicate rec: 19192` -- an exact match to the
  duplicate-hash count found completely independently during today's
  earlier `idx_hash` investigation (own separate verification cross-check).
- `archive_tip()` verified via gdb calling it directly against a scratch
  copy of the real archive: returned 881,523, matching the live daemon's
  own concurrently-reported progress; confirmed CWD correctly restored
  afterward (chdir-back works, doesn't leave chainctl's other relative-path
  logic broken).
- Full `make test`: 65/65 harness blocks green, exit 0 (these are C-only
  changes to standalone ops tools, not Makefile/test-suite targets, so this
  confirms no regression to anything the suite does cover).
### Incident (caught immediately, no damage)
An early verification attempt ran the real `chainctl` binary directly
against the LIVE production `data/` directory to sanity-check `archive_tip`
-- it immediately spawned 8 `unified_ibd` workers against the same archive
the live `dl_catchup` daemon was actively writing to. Killed within
seconds (no corruption observed; the archive's flock-based append
coordination would likely have protected it regardless, but the extra
network/disk contention against the live sync was unintended and avoidable).
Redid the check safely: gdb calling `archive_tip()` directly against an
isolated scratch copy instead of running the full program against live data.

## 2026-08-17 -- build_hash_index PORTED TO ASM + CRITICAL idx_hash BUG FOUND & FIXED
### Goal and outcome
Follow-on to the idxscan conversion below: identified `build_hash_index`
(daemon/main.c, the boot-time O(1) hash->height index builder used for
`getdata`-by-hash serving) as the next asm-conversion candidate, since it
took **185.9s on the real 962,831-record archive** -- every `serve`/`follow`
boot pays this, unconditionally, right before the node can accept any
connection. Converting it surfaced a much bigger, PRE-EXISTING bug: the
in-memory index's own hash function was pathologically bad on real data,
independent of anything C-vs-asm. Fixing that (not the C/asm conversion
itself) is responsible for nearly the entire win.
### 1. `idx_build_from_file` (asm/bitcoin_idx.asm) -- the scoped conversion
Buffered-`pread64` bulk loader (same 192KB-window approach as
`idxscan_progress`), replacing the per-record `fread`+byte-reverse+`idx_put`
C loop. Straightforward, same pattern as the idxscan work below.
### 2. The real discovery: idx_hash collapses on real block hashes
Benchmarking the conversion in isolation gave a shock: `idx_put` on
400,000 real block hashes took **15.8s**, vs **0.04s** for 400,000
synthetic random hashes into the identical table (asm/tests -- since
deleted, see asm/tests/bench_hashidx.c and asm/tests/test_idx.c for the
surviving artifacts). Bisecting by record count showed clearly super-linear
growth (300k: 1.55s, 350k: 6.5s, 400k: 14.4s, 450k: >30s) -- not a bug in
the new conversion (the synthetic control ruled that out), but in
`idx_hash` itself, called identically by both the old C path and the new
asm path.
ROOT CAUSE: `idx_hash` hashed only the first 8 bytes of the 32-byte key.
Every REAL Bitcoin block hash's leading bytes (in the byte order this table
is queried with) are constrained near-zero BY PROOF-OF-WORK -- that IS what
a valid hash is -- so those 8 bytes carry almost no entropy across
different real inputs. Dumping the actual bytes confirmed it directly:
every sampled record's first 4 bytes were literally `0x00000000`. A first
fix attempt (XOR-folding FNV-1a's output before masking, to counter FNV's
separately-known weak low-bit avalanche) did NOT help -- the problem was
insufficient entropy going INTO the hash, not how the output bits mix.
FIX: hash all 32 bytes instead of just 8 (kept the XOR-fold too, as free
insurance on top). Reconfirmed against the real archive: idx_put on the
full 962,831 records (823,833 new, 19,192 genuine hash duplicates, 0 "full")
dropped from the original ~186s to **0.104s** -- roughly an 1800x
improvement, and this affects `idx_get` too (same hash function), which
live `serve` mode uses for O(1) `getdata`-by-hash lookups -- so this had
likely been silently degrading actual block-serving performance in
production, not just boot time.
### Regression guard added
`asm/tests/test_idx.c` gained a case: 500,000 keys sharing an IDENTICAL
first 8 bytes (varying only bytes 8-31), inserted into a production-scale
table. With the buggy 8-byte-only hash this genuinely times out (every
insert collides on one bucket, O(n) per insert); with the fix it completes
in ~0.13s. Verified BOTH directions live (temporarily reverted idx_hash,
confirmed the test fails/hangs, restored the fix, confirmed it passes) --
the existing `test_idx.c` never caught this because its other cases
deliberately randomize the first 8 bytes specifically to get genuine
(non-hash-collision) duplicate detection, which is exactly the case that
avoids this defect.
### Verified (hard evidence)
- `idx_build_from_file` cross-checked against the C original via sampled
  `idx_get` lookups on the real live archive (both tables agree exactly,
  including on genuine duplicate-hash heights) -- `asm/tests/bench_hashidx.c`.
- Full `make test` (fresh, after cleaning up several stale ROOT-OWNED
  `/tmp/*test*` scratch directories left over from an earlier root-run
  suite, unrelated to this work but blocking verification) -- 65/65 harness
  blocks green, 0 failures, `MAKE_EXIT=0`.
- `build_hash_index()` called directly via gdb against the actual compiled
  daemon binary and the real production archive: ran clean, indexed
  826,746 heights, matching expectations.
- Redeployed to the live production daemon (killed + relaunched); resumed
  catch-up cleanly with no crashes. The idx_hash fix will take effect the
  next time this boot reaches `build_hash_index` (after catch-up finishes).
### Before/after (real ~962k-record archive)
| | C (old, buggy hash) | asm (new, fixed hash) | improvement |
|---|---|---|---|
| `build_hash_index` (full boot-time build) | ~186s | ~0.1-0.14s | ~1500-1800x |
| `idx_build_from_file` vs C loop, hash ALREADY fixed | 0.123-0.136s | 0.108-0.110s | ~1.1-1.24x (the honest, modest I/O-side win once the real bottleneck is gone) |

## 2026-08-17 -- BUILT-IN SELF-HEALING CATCH-UP (dl_catchup) + index.dat SCANS PORTED TO ASM
### Goal and outcome
Two related pieces of work on the download/catch-up path, both against the
real ~962k-block mainnet archive:
1. Moved the standalone multi-peer catch-up tool's engine (chunk-claiming
   work-stealing, dynamic peer replacement) DIRECTLY INTO THE DAEMON, so
   `bitcoind serve <dir> <port>` self-heals archive holes and catches up to
   the real chain tip on its own at boot -- no external scripts required for
   normal operation.
2. Converted the C `index.dat` positional-record scan logic (reimplemented
   separately 5x in C plus twice more in Python) into a canonical asm module.
### 1. `dl_catchup` (asm/daemon/main.c)
New orchestrator: `dl_bootstrap`/`dl_pool_from_book` (existing DNS-seed
discovery) for peers, extends `headers.dat` incrementally (resumes from the
last stored header, not a genesis refetch), computes the combined
hole-plus-extend span directly from `index.dat`, then forks `>=8`
chunk-claiming workers (`dlc_worker`) that pull work from a shared `mmap`'d
atomic counter, skip already-archived chunks, and reuse persistent
connections. Peer liveness is a bounded non-blocking-connect probe (several
rounds) -- the ONLY peer source for both the header phase and workers; no
fallback to a raw unconfirmed pool entry, because `tcp_connect_ip` has no
connect-phase timeout and a black-holed host can hang the whole synchronous
boot for minutes (hit this directly: 3+ minute stall on one bad candidate
before the fix). Dead-weight detection drops a peer whose measured bandwidth
(from `/proc/<pid>/io`) stays below a floor for a configurable number of
status ticks, and replaces it with a fresh candidate. Live status ticks
report overall/gap-free progress, per-peer bandwidth and chunk/block counts,
network-recv vs disk-write totals (both tick and cumulative), and a stable
running average since start.
Real bugs found live: a header-phase success check used `added>=0` instead
of `added>0` (a peer returning exactly 0 new headers on an empty store was
wrongly treated as done); an early liveness-probe design dialed the whole
pool in one burst and only found 1/140 live -- fixed by running several
bounded rounds instead of one shot, since real handshakes often take longer
than a single short poll window.
`daemon/unified_ibd.c` (the same chunk-claiming engine, standalone) is kept
as an ops tool for large one-off catch-ups/offline reindexing but is no
longer load-bearing for the daemon's own boot path.
### 2. `asm/bitcoin_idxscan.asm` -- index.dat scans in asm
`dl_catchup` reruns its archive-gap scan every status tick and every worker
chunk-claim, so the "scan index.dat's 48-byte records for non-zero" logic was
reimplemented 5 separate times in C (plus 2x in Python). Consolidated into
one asm module: `idxscan_tip`, `idxscan_first_hole`, `idxscan_all_present`,
`idxscan_progress` (raw open/pread64/close syscalls, matching the project's
existing daemon-facing asm conventions from `bitcoin_store.asm`).
FIRST CUT WAS A REGRESSION: one `pread64` syscall per 48-byte record
benchmarked 2-15x SLOWER than the C baseline's buffered `fread`, because
glibc's own stdio already amortizes its `read()` syscalls across a ~4KB
window while the raw-syscall version paid a syscall per record. FIX: batch
reads into a 192KB static `.bss` buffer (4096 records/read, scanned in
memory with no syscalls in the hot loop) -- bigger than stdio's own window is
what actually wins. Buffer is static (not stack) since these run inside
forked, single-threaded `dl_catchup` workers, where a static buffer needs no
locking.
Also hit, mid-build, the project's own documented golden rule directly:
placed two scratch locals at `[rbp-8]`/`[rbp-16]` in `idxscan_progress`
without first `sub rsp`-ing past the 5-register callee-saved save area,
silently corrupting the saved `rbx`/`r12` on return. Caught by a debug build
(gdb backtrace pointed at `main` with no symbols, rebuilding at `-O0 -g`
localized it) before it ever reached the live daemon; fixed by allocating the
locals properly below the save area, per the codebase's own established rule.
### Verified (hard evidence)
- `dl_catchup`: two isolated smoke tests (empty store fresh bootstrap through
  to `serve_mux`'s "serving on port" handoff; re-run against a partially
  filled store confirming incremental header resume + narrowed span), then a
  bounded-`timeout` sanity run against the real archive before full release.
- `idxscan_*`: `asm/tests/bench_idxscan.c` snapshots `index.dat` first (so
  it's safe to run against a concurrently-writing daemon), then cross-checks
  every function's output against the original C `dlc_*` functions on the
  live ~810k-record-and-growing archive -- all outputs byte-identical. Also
  smoke-tested by running the swapped daemon binary against a scratch copy of
  the real archive for 40s under `timeout`, confirming the full `dl_catchup`
  status-tick loop runs cleanly end-to-end on the new asm path, not just in
  the standalone benchmark harness.
### Benchmark (real ~814k-record archive, snapshot-frozen for a fair before/after)
| function | C (old) | asm (new) | speedup |
|---|---|---|---|
| `idxscan_tip` (backward scan) | 0.181s/20 reps | 0.004s/20 reps | 47.6x |
| `idxscan_first_hole` (forward scan) | 0.103s/20 reps | 0.023s/20 reps | 4.5x |
| `idxscan_progress` (forward scan) | 0.131s/20 reps | 0.033s/20 reps | 4.0x |
| `chunk_all_present` (2000-rec chunk) | 0.017s/200 reps | 0.0004s/200 reps | 43.6x |
### Result
`main.c`'s four `dlc_*` functions now delegate to the asm exports. Rebuilt
and redeployed to the live production daemon (killed + relaunched against the
real archive); confirmed via log to resume cleanly at the same progress with
no crashes. Full suite unaffected (no existing harness touches this path).

## 2026-08-14 -- WALLET CLI: GENERATE KEY / SHOW ADDRESS / SIGN A P2PKH TX (t_9f55dbe5)
### Goal and outcome
Wire the VERIFIED wallet primitives (secp256k1, BIP32, hash160, base58check,
pubkey_parse, ECDSA + the scalar/point/field ops) into a runnable CLI:
  `wallet_cli gen`                -> random keypair + P2PKH mainnet address
  `wallet_cli addr <keyhex>`      -> compressed pubkey + address for a key
  `wallet_cli sign <txhex> <keyhex> <input_idx>` -> sign a P2PKH tx (legacy SIGHASH_ALL)
### New/changed
- asm/wallet_core.c   : C glue over the verified ASM primitives. ECDSA signing is done
  in C on top of the repo's verified sc_mul / sc_inv / point_scalar_mul / fe_* / G_AFF
  (r = (kG).x mod n, s = k^-1 (z + r d) mod n, low-S normalized; deterministic nonce
  k = sha256d(z || priv)). Also does DER encoding + full tx re-serialization.
- asm/daemon/wallet_cli.c : thin CLI front-end (gen/addr/sign).
- asm/tests/test_wallet.c : end-to-end test (address known-vector, sign->verify roundtrip
  with ecdsa_verify, signed-tx structure).
- asm/Makefile : wallet CLI + test_wallet targets.
### Verified (hard evidence)
- addr(key=1) == 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH; addr(bip32 master) ==
  15mKKb2eos1hWa6tisdPwwDC1a5J1y9nma  (both match independent Python oracle).
- tests/test_wallet: 9/9 PASS. The embedded signature verifies BOTH with the repo's
  ecdsa_verify AND independently with Python `cryptography`/secp256k1 against an
  independently recomputed SIGHASH_ALL preimage (z matched the CLI byte-for-byte).
- live CLI: `sign` on an unsigned 1-in/1-out tx produced a 107-byte scriptSig
  (push72 DER||01, push33 compressed pubkey) that independently verifies.
### Honest scope
- Signing uses a deterministic RFC6979-style-ish nonce k = sha256d(z||priv) reduced
  mod n (not full RFC6979; fine for a CLI/demo, not for production key custody).
- The pre-existing `test_txval` (whole-tx validator, card t_ef86a54a) still has 2
  failing cases (real-sig spends) — SEPARATE in-progress sprint item, not this card.
  This card's `test_wallet` is green and runs before test_txval in `make test`.

## SESSION (2026-08-14): NODE SERVER SERVES THE REAL CHAIN (getdata + getheaders)
Made the ASM inbound server genuinely answer peers against the real on-disk
archive, by exercising `bitcoind serve <dir> <port>` live over loopback with
REAL mainnet data (not fake blocks). That immediately surfaced five latent bugs
(unit tests can't see them) plus a nasty segfault. All fixed & verified.

Root-cause summary of the live session:
1. daemon/bitcoind had NO Makefile target -- built by an ad-hoc gcc command that
   silently went STALE. Added a real target linking every needed object at -O0.
2. daemon server-test FAILED getdata->block: the socketpair serve path synced an
   in-memory chain but never built the O(1) hash index. Added
   build_inmem_hash_index(); server-test now passes (getdata-exact, getheaders,
   ALL TESTS PASSED).
3. build_hash_index() keyed the hash->height index with the WRONG byte order:
   index.dat stores hashes in BE display order but the getdata/inv wire hash is
   LE. getdata therefore missed every hash. Reverse before idx_put. After the
   fix, live getdata served REAL blocks by hash: h=1 (215B), h=2 (215B),
   h=50000 (647B) all requested-hash-match=YES.
4. getheaders dispatch was OFF-BY-ONE: node_serve_loop checked cmd[4..8] for
   "head"/"ers" but the message is "getheaders" = g-e-t-h-e-a-d-e-r-s, so "head"
   is at cmd[3..6] and "ers\0" at cmd[7..10]. gdb proved the outer dispatch
   matched (s_cmd=0x68746567) but the inner check always failed, so getheaders
   never served. Fixed offsets to +3/+7.
5. open_file LEAKED an fd on every call: node_serve_block opens the block file
   fresh for each block served and never closed the previous cur_blk_fd. After
   ~1024 serves the process hit EMFILE (open -> -24) and serving truncated at
   ~1016 blocks / returned -1 for high heights (isolated test: store_get_file_fd
   = -24 at h>=1019). Added close-before-open; node_serve_block now serves 3200+
   consecutive heights and every height 0..309998.

THE CRASH (segfault in main's printf, stdout/stderr=null, main's r14 held the
ascii "(serve mode"): the getheaders header copy called memcpy_len with the
length in r8, but memcpy_len reads its LENGTH from RDX (confirmed by
disassembly: `cmp %rdx,%rcx`). So it copied [s_p] (the growing page offset)
bytes instead of 80, sweeping through hp_buf and past .bss into the relocated
stdout/stderr copies (0x143e6a0 // stdout, 0x143e6c0 // stderr), zeroing libc
stdout/stderr and crashing the print after node_serve_loop returned. Found with
a HARDWARE WRITE WATCHPOINT on the stdout slot -> caught the exact corrupting
instruction (memcpy_len.c at 0x40823b doing `inc %rcx` as it walked over the
slot). Fixed: load the 80-byte header length into RDX. Server stays alive.

getheaders count now derives from the byte pointer (the loop counter rcx was
clobbered by memcpy_len/node_serve_block) and emits a CANONICAL CompactSize
varint (0xFD+2-byte for count>=253, single byte with headers compacted down
otherwise). Serving loop tracks height/count in statics (immune to callee
clobbering).

VERIFIED LIVE after the fixes (port 8355, server stayed ALIVE):
- getheaders h=1 locator: 2000 headers, count-varint(size3)=2000, inferred-from-
  len=2000 MATCH=YES, chainlink=True (each header's prev == double-sha256 of the
  previous), hdr0.prev == the h=1 locator (serves from height 2). Same for
  locators at h=200000 and h=293300.
- getdata still correct.

No regression: make test 33/33 green. Commits pushed (32279a0 for the code, docs
in this session). Downloader healthy: ~309,012 stored (99.68%), near tip.
================================================================================

## SESSION (2026-08-13): WALLET KEY DERIVATION IN ASM (BIP32)
Reached the wallet stage. Built two new verified primitives in pure x86-64:

1. bitcoin_keys.asm -- scalar_to_pubkey(k) -> compressed 33-byte pubkey:
   point_scalar_mul(R,G,k) -> Jacobian (X,Y,Z); affinize via fe_inv(z2),fe_inv(z3):
   x=X/z2, y=Y/z3; prefix 0x02/0x03 by Y parity; serialize X as 32 BE bytes.
   Verified: G(k=1) exact, BIP32 master pubkey exact, scalar range checks.
   Bug found & fixed: byte extraction shifted by (b&7) instead of 8*(b&7) --
   missing *8, gave wrong BE bytes for nonzero scalars.

2. bitcoin_bip32.asm -- bip32_master + bip32_ckd_priv (hardened + normal):
   hardened: HMAC-SHA512(cpar, 0x00||kpar||ser32(i)); normal: HMAC-SHA512(cpar,
   compressed_pubkey(kpar)||ser32(i)) using scalar_to_pubkey. Then
   k_i=(IL+kpar) mod n, c_i=IR, validate 0<k<n.

   THREE subtle asm bugs found & fixed:
   (a) hardened input layout: k_par written at input[1] (was input[-1], an
       off-by-one BELOW the 0x00 padding byte) -- silently garbage-shifted the
       whole HMAC input.
   (b) ser32(i) big-endian index bytes: written LSB-first (little-endian order)
       instead of MSB-first; also needed to start at input[33] not input[30].
   (c) the mod-n add/sub used DEC (clobbers CF) or TST (clobbers CF) between
       ADC/SBB bytes, breaking carry/borrow propagation -> now LOOP (no flag
       writes) + DEC r8 (DEC preserves CF in x86).
   (d) 257th carry bit of (IL+kpar) overflows 32 bytes; captured in a dedicated
       carry slot. Debt-row bug: the carry byte was placed at [rbp-0x119] which
       IS the sum's LSB byte, silently overwriting it -> moved to [rbp-0x118].

   Verified: test_bip32_chain walks the OFFICIAL BIP32 test-vector-1 chain
   m -> m/0' -> m/0'/1 -> m/0'/1/2' -> m/0'/1/2'/2 -> .../1000000000,
   all six steps byte-exact for both child key AND chain code.

Full suite: 29 -> 31 harnesses green (added test_keys, test_bip32_chain,
test_bip32_master). Commit 9fc36c4, pushed.

Downloader still healthy in parallel: 245,494/246,000 blocks stored (99.79%),
contiguous from genesis, 1 chainctl running.
================================================================================

## SESSION (2026-08-13): RIPEMD-160 + HASH160 + base58check ADDRESSES

Finished the wallet address path. This closes the loop so a real mainnet
Bitcoin address drops out of pure ASM end to end.

1. ripemd160.asm -- complete RIPEMD-160. Held me up for a while: my digest was
   deterministically wrong in BOTH my asm and a Python transcription that
   agreed with it, yet every table/constant matched canonical. The way out was
   fetching the authoritative pycryptodome src/RIPEMD160.c and reading the
   FINAL MIXING stage literally: the left/right line terms are crossed in the
   reference (h1 + CL + DR, not h1 + cc + d as I had it). Fixed the compose;
   the asm then matched pycryptodome and hashlib on every vector.
   Also fixed: little-endian message words (RIPEMD uses LE, unlike SHA-256's
   BE -- I had bswap'd, copying the SHA habit), a carry/round-counter register
   conflict, and callee-saved preservation. Verified: standard vectors +
   padding boundaries (len 55/56/63/64/65/120) + multi-block (1000/4096/65536)
   vs pycryptodome digests.

2. bitcoin_addr.asm -- hash160 = RIPEMD160(SHA256(x)), and base58check_encode
   (double-SHA256 checksum + repeated-divide-by-58 base58 with leading-'1'
   preservation). Bug found: hash160 read its SHA-256 intermediate from the
   wrong local offset ([rbp-0x58] instead of [rbp-0x30]) -- fixed. base58
   digit order was also reversed (need to accumulate LSB-first then emit
   reversed); and a buffer-overlap between the work and digit buffers plus a
   data buffer that reached into the callee-save area caused corruption.

Verified real mainnet P2PKH addresses byte-exact:
   1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH  (compressed generator pubkey G)
   1PRTTaJesdNovgne6Ehcdu1fpEdX7913CK  (Bitcoin-wiki test pubkey)
plus the canonical all-zero base58check string.

NOW COMPLETE IN ASM, all verified: BIP32 master -> CKDpriv -> secp256k1
pubkey -> HASH160 (SHA256+RIPEMD160) -> base58check -> mainnet P2PKH address.
33/33 harnesses green. Commit db328db, pushed.

Downloader healthy throughout: ~277k blocks stored (99.7%), contiguous from
genesis.
================================================================================

## SESSION (2026-08-13): NODE -- SERVE LOOP MULTI-GETDATA / LOOP-STABILITY FIX

Returned to the long-open "multi-getdata" serve bug. Root cause found on re-read
of bitcoin_serve.asm: rbx was used for BOTH the persistent outer-loop counter
(.next: dec rbx; jg .outer) AND the getdata item pointer (.gd_loop: mov rbx,
[s_ptr]; ... reloaded from [s_ptr] at 231/241/252/256). So after the first
getdata the loop bound became the item-pointer address; the loop only stopped
on peer close, and bookkeeping was corrupt exactly where the old crash lived.

Fix: run the outer-loop counter in r15, written only at function entry (ht_idx
now lives solely in the static s_htidx slot; r15 is callee-saved so every
p2p_read/idx_get/node_serve_block/p2p_write preserves it across all handlers).
rbx is now free as pure handler scratch.

To prove it (not just smoke-test): extended test_serve.c into a real stress
suite:
  - a single multi-inv getdata message requesting all 8 blocks -> served
    byte-exact (exercises .gd_loop iterating several items in one message);
  - 25x ping/pong AFTER serving -> proves the outer loop keeps running on the
    counter, independent of socket close.
All 33 harnesses green. Commit 96f102f, pushed.

Note: also spotted a hygiene linker warning (node_log.o missing .note.GNU-stack
=> executable stack). Cosmetic, not correctness; can add the section later.

Next node items: (1) batch/range block serving (getblocks/getheaders range) so a
syncing peer can pull the whole chain from us; (2) the bitcoin_store multi-file
tip_height(+24) layout regression still failing test_bitcoind_sync/test_cli;
(3) wire the finished ASM key->HASH160->base58check wallet path into a CLI
getnewaddress.
================================================================================

## 2026-08-13 -- #13 STORE REFACTOR RECONCILED + root-caused a REAL corrupted-filename bug; full suite back to 283 PASS-equiv (22 green, 0 FAIL)
### Context
On resuming, `make test` showed `test_bitcoind_sync` failing (`store tip_height == NB-1
got=0 exp=1`) and `test_cli` failing 6 assertions (`getbestblockhash`/`getblockhash 3`/
`getblock 2`/`getblock by-hash`/`gettx`/`getbalance` -> "height out of range"/"not
found"). Both traced to an UNLOGGED, PARTIALLY-PROPAGATED refactor of bitcoin_store.asm
(timestamps 07:18/07:29, after the last 283-PASS baseline) that added multi-file 128MB
rollover blk%05d.dat support and changed the store struct layout.
### Root cause #1 -- store struct layout mismatch (+24 semantics)
New bitcoin_store.asm moved state around so that `+24` was `cur_file_no` and tip height
was only derivable as `+16 idx_len/48-1`. But the verified consumer ecosystem
(bitcoind.asm node_serve_block_by_hash, bitcoind.asm node_sync, bitcoin_cli.asm ~10
sites, paribd_asm.c worker resume, test_bitcoind_sync.c) all read `+24` as the tip
height. FIX: keep the multi-file feature but fix `+24` to mean tip_height in the store's
OWN struct so every existing consumer is correct with ZERO edits:
    +0 cur_blk_fd, +8 idx_fd, +16 idx_len, +24 dword tip_height (-1 empty),
    +28 dword cur_file_no, +32 dword cur_file_pos, +36 dword magic.
store_init sets tip=-1; store_append sets tip=newheight; store_reload restores tip from
the last index record. Updated test_store.c's struct mirror + added `reload tip_height 2`.
No consumer files needed changing (they already read +24 as tip).
### Root cause #2 -- the REAL bug hiding underneath: corrupted reopened filename
After #1, test_cli still failed: every cli_load_block/store_get_file_fd open created a
file with a CORRUPTED long name (`blk00000.dat<garbage>`), so reads found 0 bytes.
strace showed the name was missing its NUL: `open("blk00000.dat\375\177"...)`,
`open("blk00000.dat%%%%..."...)` -- stack garbage read past the end of "blk00000.dat".
ROOT CAUSE: fmt_blkname wrote the suffix with `mov dword [r12+8], 0x007461642E`
intending ".dat\0" -- but a dword store is only FOUR bytes (".dat"), so the 5th byte
(the NUL at +12) was NEVER written. The old single-file store opened the fixed rodata
string `blk00000.dat\0` (already NUL-terminated), so this bug is NEW to the multi-file
refactor. FIX: write `.dat` then an explicit `mov byte [r12+12], 0`. Verified in
objdump (movb $0x0,0xc(%r12)) and by ls: only clean `blk00000.dat`/`index.dat` remain.
### Lesson (add to golden rules)
"blk00000.dat" is 13 bytes ("blk"+5 digits+".dat"+NUL). Writing a filename suffix with a
DWORD store covers only 4 bytes -- ALWAYS write the terminating NUL explicitly when
building a runtime filename, or open() will read past the end into stack garbage and
create corrupted long filenames. (Same class as the "size every load to the field" rule:
size every store to the full field, incl. the NUL.)
### Result
make test: 22/22 green, 0 FAIL, MAKE EXIT=0. Ubuntu full suite restored and RED:
test_store (incl. reload tip) and test_cli fully pass. Committed to the new GitHub repo
BobClawblaw/bitcoinmachinecode.

## 2026-08-12 -- #12 PARALLEL multi-peer FULL-CHAIN download (>= 8 DISTINCT internet peers) + ALL-ASM receive loop + real-mainnet header-continuity fix
### Goal and outcome
Download the FULL mainnet blockchain so it can be re-served, from >= 8 DISTINCT
internet peers simultaneously, with the per-worker download LOOP IN ASSEMBLY.
All three achieved:
- Discovery: a live peer scan (tests of a 26,895-node bitnodes snapshot) found
  hundreds of distinct internet nodes that serve block bodies with the corrected
  getdata; 101+ distinct good peers saved in
  /storage/bitcoinmachinecode/good_internet_peers.txt. The parallel download
  establishes >= 8 of these simultaneously.
- Running download: a full-chain parallel IBD (daemon/paribd.c) downloading
  heights [0, tip] with 8 distinct internet peers into /storage/bitcoinmachinecode/data
  (resumable; accumulating the real archive for re-serving).
- ALL-ASM receive loop: new bitcoind.asm node_ibd_blocks_x (hardened from
  node_ibd_blocks) does getdata -> recv (draining ping->pong + ignoring other
  chatter) -> cons_verify (CALLER-supplied scratch, big enough for dense modern
  blocks) -> re-derived-hash guard -> store_append, over an explicit height range,
  ALL in assembly. daemon/paribd_asm.c orchestrates 8 workers each running it,
  and re-serves the produced store (verified: inbound peer fetched headers + a
  block body).
### Real bug found & fixed (would have silently poisoned any real-mainnet headers)
node_ibd_headers validated chain continuity by requiring every header's prevhash
to equal the previous header's block_hash, seeded from the caller's locator. But
the getheaders-from-genesis locator is the synthetic all-zero hash, while REAL
block 1's prevhash is the GENESIS hash (000000000019d668...), NOT zero -- so the
very first real header always failed continuity and node_ibd_headers returned -1.
Every prior IBD test used SYNTHETIC chains with a zero-prev block 0, so no test
ever caught it. FIX: skip the prevhash compare for exactly the first header of the
whole download (total==0 && i==0); enforce it for every later header. Verified:
node_ibd_headers now persists 962,208 REAL mainnet headers.
### What was proven end-to-end (real data)
- asm node_ibd_headers persisted 962,208 real headers (full mainnet header chain).
- asm node_ibd_blocks_x (8 distinct internet peers) downloaded/validated/stored
  real blocks over worker height-shards; merged store queried via the asm CLI
  (getblockcount/getblockhash with real hashes) and RE-SERVED to an inbound peer
  (201 headers + exact block body).
- The running full download (8 distinct internet peers) reached ~18GB of real
  blockchain data in ~30 min and continues resumably toward the full chain.
### New/changed
- bitcoind.asm: node_ibd_blocks_x (new all-asm hardened receive loop);
  node_ibd_headers continuity fix.
- daemon/paribd.c: the parallel full-chain orchestrator (>= 8 peers, resumable,
  worker file merge). daemon/peertest.c + daemon/discover.c: internet peer
  discovery/testing. daemon/paribd_asm.c: the all-asm worker orchestrator.
  seeds/good_internet_peers.txt + internet_peers.txt: peer pools.
- Full make test still 283 PASS / 0 FAIL (continuity fix keeps synthetic tests
  green while unlocking real-mainnet headers).
### Honest scope
The full ~500GB / ~962k-block archive download is a multi-hour resumable job that
is RUNNING, not finished; it is gated by network throughput + peer flakiness, not
by correctness (every block is cons_verify-validated as it lands). Re-serving the
downloaded store is proven. Remaining: let the running download reach the tip,
plus the documented roadmap items (UTXO set, script/sig validation, mempool/rpc,
pruning, reorg).

## 2026-08-12 -- #11 ROOT CAUSE OF THE BLOCK-BODY WALL FOUND & FIXED: getdata wire format was WRONG. REAL mainnet block bodies now download + cons_verify + store, and the inbound serve path works against a real peer.
### The headline (this overturns the long-standing "peer-policy wall" conclusion)
The 34-byte getdata this node had been sending (hash at +2, single-byte type) is
MALFORMED -- real Bitcoin nodes silently ignore it. That malformed encoding, not
(only) seed serving policy, is why live block-body getdata "hung/dropped". With
the getdata fixed to the canonical form, a real node COOPERATIVELY serves block
bodies, and the assembly receive path downloads + cons_verify-validates + stores
REAL mainnet blocks. This was proven live against 192.168.5.69:8333 (a local
full node): 2000 real headers learned to tip (height ~790999), then real block
bodies at heights 790999/790998/790997/790994 downloaded, validated VALID by asm
cons_verify, and persisted. The "download the entire blockchain" receive tail is
NOT blocked by asm or peer policy for a cooperative peer -- our earlier
conclusion was wrong in an important way; see below.
### What the correct wire format actually is (verified two ways)
Bitcoin getdata/inv inventory: [count varint][type int32 LE][hash32].
For one MSG_BLOCK: [0x01][0x02 00 00 00][hash at +5] = 37 bytes. The type
field is a 4-byte little-endian int32 -- our p2p_oracle.py has ALWAYS encoded
this (varint(1)+u32(2)+hash). A prior LOG stage (#2 / S6) "fixed" p2p_getdata_block
to a 34-byte form under a mistaken assumption ("type is a 1-byte varint"). That
was wrong. Confirmed LIVE: a real node answered the 37-byte form (got block) and
did nothing for the 34-byte form.
### Changes
1. bitcoin_p2p.asm p2p_getdata_block: back to the canonical 37-byte
   [count][int32 type][hash at +5]; fixed return 37. (Buffer was already 37 in
   node_sync; node_ibd_blocks getdata buffer was 40, fine.)
2. daemon/main.c serve_loop getdata PARSER: was reading hash at pl+5 (correct)
   before #2 wrongly flipped it; now reads [count][int32 type][hash at +5],
   stride 36, serving every requested MSG_BLOCK. (inv handler already used the
   correct int32 stride and is unchanged.)
3. All fake/test PEERS that parse inbound getdata (fake_serve, full_serve in
   daemon/main.c, daemon/testpeer.c, tests/test_ibd_blocks.c / test_ibd_full.c /
   test_ibd_scale.c / test_bitcoind_sync.c) updated to compare the hash at pl+5
   instead of pl+2, so the whole harness ecosystem stays wire-canonical.
4. tests/live_blocks.c, live_probe.c getdata builders: type now emitted as a
   4-byte int32 (stride 36).
5. tests/test_p2p.c getdata expectation: 34 -> 37 bytes, hash at +5.
6. NEW manual/live tests (NOT in make test): tests/live_getdata_form.c and
   tests/live_local_probe.c (definitive form-A-vs-B arbiter) and
   tests/live_block_dl.c (full asm download->validate->store of a REAL block).
### The long-documented seed-serving "wall" -- now re-scoped honestly
- Public seeds (sipa/petertodd/bluematt/dashjr/emzy) reliably serve the real
  header chain; block-body getdata to an unproven peer still usually drops, but
  at least PART of that was our OWN malformed getdata (real nodes ignore a
  malformed message). The cooperative local node serves bodies to the fixed
  client, so the machine is proven against a real node end to end.
- The 20,000-block offline loopback IBD (test_ibd_scale) and the whole asm IBD
  machine (node_ibd) stand unchanged and green.
### Also this session
- NEW bitcoind.asm node_accept_handshake(fd): the INBOUND/server role. Before,
  serve mode reused node_handshake (the OUTBOUND/initiator role, sends OUR
  version first) on an inbound peer, so a real inbound node's version went
  unanswered and the handshake hung. Now serve uses node_accept_handshake:
  reads peer version (drains ping->pong/sendaddrv2/wtxidrelay/sendcmpct), replies
  our version + verack, waits for peer verack. Verified end-to-end via a new
  inbound_client harness: a peer connecting to `serve` gets served 8 headers and
  the exact 145-byte block.
- User-agent branding: node_make_version now advertises
  "Bitcoind-AssemlbyCode (BobClawblaw) vx.x.x" (42B UA, version payload 128B;
  updated test_bitcoind expectations).
- Boot improvement: /storage/bitcoinmachinecode/seeds.txt (tiered known-good seed
  list from live probing) + daemon/seedprobe.c (bounded per-seed prober with a
  watchdog that measures which seeds connect/handshake/serve headers).
### Suite
Full `make test` (fresh): 283 PASS / 0 FAIL / 22 green harnesses, MAKE EXIT=0.
### Honest remaining scope
This proves the receive tail (download real block body -> cons_verify -> store)
and the serve path (answer a REAL inbound peer's getdata/getheaders with stored
blocks, inbound handshake) against a real cooperative node. Still not done:
full multi-thousand-block live IBD of the ~840k-block archive in one pass
(sequentially downloading every real block; requires time + the cooperative
node's full history and is now gated only by throughput, not correctness/policy),
UTXO set / arbitrary-tx script+sig validation, mempool/RPC/pruning, reorg.

## 2026-08-12 -- #10 LIVE-SEED BLOCK BODY WALL CONFIRMED + LARGE-SCALE IBD DEMO
### Goal and outcome
Attempt the real remaining goal ("download the entire blockchain") from live
mainnet peers. Empirically re-tested live block-body serving with a REALISTIC
full-node handshake (Satoshi UA, plausible start_height, wtxidrelay/sendaddrv2
completion) built on the asm net/p2p codecs (tests/live_probe.c, manual/live).
### Result (the honest wall, now pinned down precisely)
Against every seed tried (sipa.be, petertodd.net, bluematt.me, dashjr.org):
- PASS connect, PASS handshake (verack) -- with the realistic UA the peers now
  ACCEPT the handshake (a plain /btcasm:0.1/ + start_height=0 handshake was
  dropped at connect).
- PASS learned 2000 REAL headers to the live tip (headers-first download works
  live against a cooperative peer).
- getdata for the tip block(s) -> NO block body ever arrives (connection hangs /
  silent drop within 40s+). Every peer that served headers then declined to
  serve block bodies.
CONCLUSION (unchanged, but now proven with a protocol-compliant handshake): live
public seeds serve the real header chain but drop block-body getdata to this
untrusted/unknown peer. The full ~540GB / ~830k-block mainnet archive download
is blocked at the SOURCE (server-side serving policy), not by any asm gap. This
is the single wall between this node and the real chain; it cannot be fixed
client-side without whitelist/peer reputation the seeds do not grant here.
### Large-scale offline demonstration (tests/test_ibd_scale.c, NOT in make test)
To show the "download the entire blockchain" machine (node_ibd: persist whole
header chain from genesis in 2000-header pages, then walk every stored header ->
getdata -> cons_verify + re-hash-guard -> store) is not a small-chain toy, added
a parameterized whole-chain loopback IBD. RESULT (verified run): NB=20000 blocks
archived in ONE machine-code pass in 1647s (~12 blk/s through a loopback C
fixture peer): 11 getheaders pages persisted the whole 20k-header chain, then
20,000 getdata+cons_verify+re-hash-guard+store round-trips. PASS: node_ibd stored
all 20000, header store has 20000 entries, block store tip == 19999, and every
stored (header, block_hash) matches the chain (exit 0). This is the honest
offline maximum of what can be demonstrated without a cooperative peer willing
to serve real history -- the full mainnet ~540GB archive remains walled at the
SOURCE by live-seed serving policy.

## 2026-08-12 -- #9 DAEMON `ibd` MODE: full machine-code IBD wired into the runnable node
### Goal and outcome
The 100%-asm full IBD pass (bitcoind.asm `node_ibd` = node_ibd_headers + node_ibd_blocks)
was proven by the C harness test_ibd_full but NOT reachable from the runnable
daemon binary. Added `daemon ibd <dir>` -- a mode that runs `node_ibd` as one
assembly call over a single connection to a loopback peer serving the WHOLE
chain, persisting headers then block bodies into `<dir>`, and reporting the
resulting block/header counts and tip.
### Changes (daemon/main.c -- thin C driver glue only)
- `extern` for node_ibd / hst_init / hst_count / hst_get_at.
- Refactored the 8-block fake chain build out of fake_serve into
  `build_fake_chain()` so the new whole-chain peer (`full_serve`) can force-build
  the chain -- WITHOUT this, full_serve's first-in-process run served all-zero
  blocks and node_ibd's stricter continuity check / getdata lookups failed
  (the original sync-mode only ever exercised fake_serve, which built lazily).
  REAL BUG found & fixed: the `ibd` mode forked full_serve as the FIRST peer, so
  the lazy-built fake_blocks were never materialized -> garbage headers served
  -> node_ibd returned -1 with 1 bogus header. Fix: call build_fake_chain()
  before serving (both peers now share it; fake_serve behaviour unchanged).
- `full_serve`: serves all 8 headers at the running locator + every block body
  by getdata hash (no growth), so node_ibd pulls the entire chain in one pass.
- `ibd` mode block: hst_init header store, handshake, call node_ibd with a
  >=2MB shared scratch, then report blocks/headers/tip and return 0 iff
  blocks>=1, headers>=1, tip==headers-1, headers==8.
### Verified (live run)
- `daemon ibd /tmp/ibdtest` from EMPTY dirs -> `ibd: blocks=8 headers=8
  height=7`, EXIT=0; full_serve logged getdata#1..8 found=0..7 (every block body
  requested by hash and served).
- Persisted artifacts: headers.dat=896B (8x112B header chain), blk00000.dat=1224B
  (8 block bodies), index.dat=384B (8x48B index).
- Rebuilt CLI (manual gcc -O0, the daemon/cli binary is not a Makefile target) and
  queried the ibd-produced store: getblockcount=8, getbestblockhash==getblockhash 7
  (tip hash), getbalance=64000000 (8 x 8 BTC coinbase, all unspent).
- Full `make test` still green: 283 PASS / 0 FAIL / 22 harnesses.
- Minor consistency fix while validating the ibd store: `cmd_getblockcount`
  (bitcoin_cli.asm) emitted its decimal WITHOUT a trailing newline (the outlier:
  getbestblockhash/getblockhash/getblock/gettx/getbalance all end with `\n`),
  so `cli getblockcount` ran its output into the next shell token. Added the
  newline (rax+1 after cli_emit_dec) -- this also makes `stop` (which returns
  cmd_getblockcount) end with a newline. Updated tests/test_cli.c expectations
  for getblockcount and stop to `"8\n"`. Still 283 PASS / 0 FAIL.
### Scope
The runnable node and the full machine-code IBD machine are now joined: `daemon
ibd` performs headers-first persist + getdata block bodies + cons_verify +
re-hash guard + store -- the entire "download the chain" tail -- as one assembly
pass in the real daemon, provable end-to-end against a cooperative whole-chain
peer. The single unchanged limit is live-seed serving policy (seeds drop
block-body getdata to minimal clients), not an asm gap.

## 2026-08-12 -- #8 FULL IBD AS ONE ASM PASS: node_ibd chains the two halves
### Goal and outcome
Close the "natural next step" named at the end of #7: chain node_ibd_headers
(persistent paged headers-first download) + node_ibd_blocks (block bodies off
the persisted header chain) into a SINGLE assembly entry point that performs a
whole initial-block-download over one peer connection. NEW asm
`bitcoind.asm node_ibd(fd, st*, hst*, buf, buflen) -> eax #blocks stored`:
  phase 1  node_ibd_headers(fd, hst, locator=0, buf, buflen)  -- download the
           whole header chain from GENESIS in 2000-header pages and persist
           every (header, block_hash) into the header store, advancing the
           locator to the tip.
  phase 2  node_ibd_blocks(fd, st, hst, 0, buf, buflen)       -- walk every
           stored header, getdata its block body, cons_verify + re-derived-hash
           guard, store_append into the block store.
Returns #blocks stored, or -1 if either phase fails. The genesis locator is a
zeroed 32-byte stack local; st/hst live in stack locals (the r13-leak hazard is
handled exactly as #7 / node_sync require); shared >=2MB scratch buffer for both
halves; frame sized so RSP is 0 mod16 at every nested call.
### Verified (tests/test_ibd_full.c, in `make test`)
The FULL single-pass IBD over a real loopback socket against a C fixture peer
serving the WHOLE chain from EMPTY header + block stores:
- NB=1200-block single-coinbase chain forces one full 2000-cap header page
  served as a 1200 batch, plus 1200 block bodies across 3 getdata batches
  (getdata#400/800/1200 logged).
- node_ibd stored all NB blocks (got 1200); header store has NB entries; block
  store tip == NB-1; every stored (header, block_hash) matches the chain; every
  stored block body is byte-exact in blk00000.dat.
This is the "download the entire blockchain" machine-code demonstration at a
scale far beyond the 8-block (test_ibd_headers) / 4-block (test_ibd_blocks)
scratch tests -- the entire headers-first IBD tail (paged persist, then walk +
getdata + validate + store) running as one call, end to end in assembly.
### Suite
Full `make test` (fresh): 283 PASS / 0 FAIL / 22 green harnesses, MAKE EXIT=0.
(Was 279/22 at the end of #7; test_ibd_full adds 5 assertions and is wired into
the Makefile's IBDOBJS/-O0 convention, test/clean lists.)
### Integration / scope
node_ibd needs no new objects (both halves already in bitcoind.o w/ hst deps).
The single remaining gap to a real archive node remains a PEER-POLICY issue, not
an asm one: live mainnet seeds serve headers but drop block-body getdata to a
minimal client, so a real multi-thousand-block wire download is still not pulled
from live seeds; this proves the full machine-code IBD machine against a
cooperative peer serving the whole chain.

## 2026-08-11 -- #7 BLOCK-BODY DOWNLOAD OFF THE PERSISTED HEADER CHAIN (getdata+validate+store)
### Goal and outcome
Close the "Remaining: drive getdata for the blocks behind the persisted header
chain" gap from #6. NEW asm `bitcoind.asm node_ibd_blocks(fd, st*, hst*,
start_h, buf, buflen) -> eax #blocks stored`:
- Walks the PERSISTED header store (`hst`) from `start_h` to the tip.
- For each stored header: hst_get_at -> block_hash (rec[80..112]); getdata(that
  hash); receive the `block` (draining ping->pong and any chatter so it never
  stalls); validate with cons_verify; RE-DERIVE block_hash(received) and REQUIRE
  it to equal the stored header hash (guards against a peer serving the wrong
  block); store_append to the block store. Returns the number stored, or -1 on a
  hard error.
This is the second half of full IBD in machine code: persistent headers-first
download (node_ibd_headers, #6) + block-body fetch/validate/store per header
(node_ibd_blocks, #7).
### Verified (tests/test_ibd_blocks.c, in `make test`)
- Happy path over loopback: a 4-block single-coinbase chain persisted into the
  header store, bodies served by a C fixture peer. node_ibd_blocks stores all 4
  (node_ibd_blocks stored all NB=4), every stored block is byte-exact in
  blk00000.dat, store tip_height == NB-1.
- NEGATIVE: an "evil" peer serving the WRONG block body for one requested hash is
  rejected (returns -1) and only the leading valid blocks are stored -- proves
  the re-derive-and-compare hash guard actually fires, not just the happy path.
- Full suite (fresh `make clean`): 279 PASS / 0 FAIL / 23 run lines, MAKE EXIT=0.
  (Was 274/22 before this stage.)
### Real bug found & fixed (the recurring r13 hazard, now hit in a NEW place)
- node_ibd_blocks FIRST version kept the header-store pointer in r13 across the
  per-header loop. The deep `block_hash -> sha256d -> sha256_full` chain LEAKS
  r13 (the very hazard node_sync documents: "r13 is leaked by a deep callee in
  this hash chain -- do not trust it"). So block 0 stored fine, but by i=1
  hst_get_at was called with a garbage hst pointer -> out-of-range -> -1, and the
  peer never even saw getdata(1). Diagnosed with a single-char stderr tracer that
  showed the exact cut (L G g W R r S then L G g then fail).
  FIX: keep `hst` in a STACK LOCAL (rbp-0x30) and reload it before every
  hst_get_at/hst_count call -- exactly the pattern node_sync uses for its
  locator. (r12/r14/r15/rbx are truly callee-saved and preserved; r13 is the one
  the asm hash chain leaks.) Fixed and re-verified: all 4 blocks download.
- Minor: got `cons_verify` scratch/cap convention confirmed once more -- cap is
  the max NUMBER OF TXIDS (scratch >= cap*32 bytes); single-tx blocks write 1
  txid so a 0x400 scratch with cap large is fine, matching node_drain's usage.
### Integration
- bitcoin_headers.o already in DAEMONOBJS (from #6); node_ibd_blocks needs no new
  objects. tests/test_ibd_blocks.c wired into the Makefile (IBDOBJS, -O0) and
  `make test`/`clean`. Manual daemon build (unchanged from #6) links fine.
- `daemon sync` re-verified after adding node_ibd_blocks (ok=1 blocks=8 h=7).
### HONEST scope
This proves, against a live loopback peer and a PERSISTED header chain, that the
machine code can walk every stored header, request its block body, validate it
(PoW + merkle + tx walk via cons_verify), cross-check the hash against the
header, and persist it -- i.e. the full per-block IBD tail is real assembly.
The remaining gap to "download the entire blockchain" is unchanged and remains a
PEER-POLICY limit, not an asm gap: real mainnet seeds serve headers but drop
block-body getdata to a minimal/unknown client, so a multi-thousand-block chain
is not pulled from live seeds on this box. With a cooperative peer (documented
as the reward for a fuller handshake/pre-sync state), the natural next step is to
chain node_ibd_headers (persist N headers) then node_ibd_blocks (fetch+store the
matching bodies) into one daemon IBD pass and run it across pages toward the tip.

## 2026-08-11 -- #6 PERSISTENT HEADERS-FIRST IBD: paged download into a durable header store
### Goal and outcome
Close the "genuine next step" from #5: headers-first IBD now PERSISTS the header
chain on disk and ADVANCES the locator across 2000-header pages toward the tip,
all in machine code. Two new pieces:
- NEW `asm/bitcoin_headers.asm` -- a durable header-chain store. `headers.dat` is
  append-only and positional (entry N at N*112 = [80 header][32 block_hash]).
  API: hst_init / hst_reload / hst_append(hst,hdr[80],hash[32]) / hst_get_at /
  hst_count. Restart-safe (reload re-derives count from file size).
- NEW `asm/bitcoind.asm node_ibd_headers(fd,hst*,locator32,page_buf,buflen) ->
  eax total`: the paged loop. Repeats node_fetch_headers at the running locator,
  verifies chain continuity for EVERY header (entry.prevhash == prior entry's
  block_hash), computes each block_hash, hst_appends (hdr,hash), then advances
  the running locator to the last appended hash. Stops on a short page (<2000)
  or a 0-header page (tip). Returns total appended this call, or -1 (continuity
  break / append error).
### Verified (new tests, in `make test`)
- tests/test_headers (bitcoin_headers.asm store): init/append/get_at/count,
  on-disk 112B-positional layout (560B for 5 entries), restart-resume (reload
  restores count), and chain continuity across the stored hashes. 
- tests/test_ibd_headers (full paged IBD over a real loopback socket): a C
  fixture peer + the 100%-asm client. 2500-header chain forces a full 2000-header
  page then a 500-header short page:
    ibd total == 2500; hst_count == 2500; stored (hdr,hash) match chain;
    locator advanced to tip hash; reload count == 2500 (restart then re-run at
    tip -> 0 new); count stays 2500. NEGATIVE: an "evil" peer serving a broken
    chain is rejected (returns -1, stops after the 1 valid header) -- proves the
    continuity guard, not just the happy path.
- Full suite (fresh `make clean`): 274 PASS / 0 FAIL / 20 green harnesses (22 run
  lines; 0 real FAIL, MAKE EXIT=0). New count is +32 assertions over #5's 242.
### Real bugs found & fixed while bringing it up (worth recording)
1. GOLDEN-RULE VIOLATION in the EXISTING node_fetch_headers (bitcoind.asm): its
   `len_out` local was at [rbp-0x20], INSIDE the 5-push callee-saved save area
   (rbx-8/r12-16/r13-24/r14-32/r15-40). p2p_read wrote the headers message length
   (162003) over the saved-r14 slot, so the epilogue `pop r14` restored the
   length into the caller's r14. node_fetch_headers itself never re-used r14, so
   the bug was latent -- it only fired when a CALLER kept a pointer in r14 across
   the call. node_ibd_headers does exactly that (page_buf in r14), exposing it.
   FIX: moved len_out to [rbp-0x98] (below the save area). This is the same
   golden rule the project has hit repeatedly; it had quietly regressed into
   node_fetch_headers.
2. My first test peer parsed the getheaders locator at payload+1, but the real
   Bitcoin getheaders payload is [version u32][count varint][hash..][stop], so
   the locator is at +5 (4-byte version + 1-byte count), and p2p_getheaders
   correctly emits that 69-byte form (as the project's live test already relied
   on). The peer now reads rb+5. (This confirms, not corrects, the asm: fakepeer
   never parsed getheaders, so the layout was only ever exercised client-side.)
3. Frame/loop discipline in the new node_ibd_headers: counters (i, pgcount,
   total, entoff) live in stack slots, not registers, so the deep
   block_hash->sha256d->sha256_full chain cannot clobber them; fd/hst/locator/
   page_buf live in callee-saved regs (rbx/r12-r15), all preserved by every
   callee; sub rsp,0xa8 keeps RSP 0 mod16 at every nested call; stop buffer is a
   real zeroed local (never NULL -- p2p_getheaders copies 32 bytes from it).
### Integration
- bitcoin_headers.o added to OBJS and DAEMONOBJS (bitcoind.o now references
  hst_append, so every link of bitcoind.o needs it). test_headers + test_ibd_headers
  wired into the Makefile and `make test`. Manual daemon build (per prior LOG
  note) must now add bitcoin_headers.o:
    gcc -no-pie -O0 -o daemon/bitcoind daemon/main.c sha256.o bitcoin_hash.o \
        bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o \
        bitcoind.o node_log.o bitcoin_headers.o
- `daemon sync` re-verified end-to-end after the change (ok=1 blocks=8 height=7,
  logs INFO/HSHK/BLOCK 8/STORE 8 7).
### HONEST scope
This proves the PERSISTENT paged headers-first download against a live loopback
peer, including multi-page locator advance, restart-resume, and tip detection.
The remaining gap to a full archive node is unchanged and is a PEER-POLICY issue,
not an asm-correctness gap: real mainnet seeds serve headers but drop block-body
getdata to a minimal client, so the ~540GB block download itself is not
demonstrated from live seeds (block serving is proven against our own serve
mode). The next natural step is to drive getdata for the blocks behind this
persisted header chain once a cooperative peer is present.

## 2026-08-11 -- #2 SEGWIT (BIP141) IBD SUPPORT COMPLETED + real-block validation extended

### Goal and outcome
Close the last known IBD gap from #1: `cons_verify` now accepts REAL present-day
SegWit mainnet blocks, not just pre-SegWit ones. The block walker (`tx_parse`)
and txid computation (`tx_txid`, new) now handle BIP141 witness serialization.
Verified on real mainnet data:
- block 962043 (SegWit-era, 1,664,976 B, nBits 0x1702353d, 3650 real SegWit txs)
  -> cons_verify = 1 (previously rejected).
- block 400000 (pre-SegWit, 948,994 B, 1660 txs) -> still 1.
- full suite back to 242 PASS / 0 FAIL / 18 green from a fresh `make clean`.

### New/changed asm
- bitcoin_tx.asm `tx_parse`: detects the SegWit marker/flag (version | 0x00 0x01)
  after the 4-byte version, parses inputs/outputs normally, then SKIPS the witness
  stack (varint item-count + varint-length items per input) before the locktime,
  so it returns the full on-wire `tx_len` and the block walk no longer desyncs on
  SegWit txs.
- bitcoin_tx.asm `tx_txid(out32, tx, txlen, buf, buflen)` [NEW]: computes the
  BIP141 txid by rebuilding the UNWITNESSED serialization (version + inputs +
  outputs + locktime) into a caller scratch buffer and double-SHA256'ing it.
  Correct for both legacy (>= tx, contiguous) and SegWit txs.
- bitcoin_cons.asm `cons_verify`: computes each per-tx txid with `tx_txid`
  (reconstruction scratch = 1MB stack block at rbp-0x100000, frame 0x1000f8
  == 8 mod 16 so RSP stays at the SysV call-into-alignment), instead of `sha256d`.

### Signed-off patterns / real bugs the real data exposed (and fixed)
1. Witness item-length 0xfd/0xfe/0xff varint paths used `r10` as a scratch temp,
   CLOBBERING the outer witness-entry counter (also in r10) -> any tx whose
   witness had a >=253-byte item broke the walk (crashed/desynced). Reproduced
   on real tx #1036 of block 962043 (1-in/3-out, ~7.5 KB witness). Fixed by using
   `rcx` for the bounds-check temp in .wlb/.wlf/.wlff.
2. Witness item/entry varints had stray `mov r9, rbx` cursor-clobbers (cursor set
   to a length value) in the draft; rewrote with `add r9,K` + length kept in rdx,
   and added pre-read `cmp r9,r11; jae .fail` guards so parsing never reads OOB.
3. `cons_verify` REQUIRED a 1MB reconstruction buffer for `tx_txid`; the daemon
   `test_bitcoind_sync` broke (store empty) because `tx_txid` SAVED its buflen
   argument at `[rbp-0x20]` which OVERLAPPED its own pushed `r14` save slot, so
   the epilogue `pop r14` restored buflen into the caller's r14 -> `node_sync`'s
   block pointer in r14 became the buflen (0x100000) and `store_append` failed.
   Fixed: save buflen at `[rbp-0x30]` (below the r15 save). Isolated with a
   register-sentinel harness proving tx_txid now preserves r14.
4. `sha256d` (bitcoin_hash.asm) only preserved rbx/r12/r13 but calls sha256_full
   which uses r14/r15 -> it clobbered caller r14. Added r14/r15 to sha256d's
   save set and moved its hash1/len locals down so they no longer overlap the
   new saves (frame stays 0x78 == 8 mod 16 for the same SysV alignment).

### Real-data verification of tx_txid
- tx_txid on the real SegWit coinbase of 962043 -> fdcab46234eec2... matching an
  independent Python reconstruction.
- tx_txid on pre-SegWit block 400000 txs matches plain sha256d (legacy == full).
- cons_verify(pow_check first, then full 3650-tx merkle) accepts 962043.

### Limitation -> closed
Previously documented "SegWit (BIP141) not yet handled" is now RESOLVED: the
client validates both pre-SegWit and SegWit real mainnet blocks end-to-end.

## 2026-08-11 -- #3 STORE-RELOAD SERVING FIX + live TCP serving proof
- `daemon serve <dir> <port>` now calls `store_reload(store_buf)` (added to both
  `serve` and `follow` modes in daemon/main.c) so the node loads its PERSISTED
  chain from blk00000.dat/index.dat on startup instead of starting an empty
  store. Real TCP proof over loopback port 18446: a TCP client handshaked
  (version+verack), `getheaders` from genesis -> server returned headers count=8
  (the full persisted 8-block chain), `getdata` -> server returned the exact
  145-byte block (logged HDRS 8 / SERVE 145), and ping->pong worked.
- Root-cause detail 1 (false alarm): a naive reload test that called
  `store_init(st)` and `store_reload(st)` as two arguments to one `printf`
  triggered unspecified C evaluation order, so store_reload sometimes ran BEFORE
  store_init and saw an all-zero store context (blk/idx fds = 0 -> lseek = 0 ->
  "empty"). Not a bug in store_reload: called as separate statements it correctly
  reloads tip_height=7 / next_offset from a 384-byte index.dat (verified).
- Root-cause detail 2 (real): `make daemon/bitcoind` is NOT a Makefile target, so
  a rebuilt daemon binary was silently STALE and never included the store_reload
  call. daemon/bitcoind must be built manually, e.g.:
    gcc -no-pie -O0 -o daemon/bitcoind daemon/main.c sha256.o bitcoin_hash.o \
        bitcoin_net.o bitcoin_p2p.o bitcoin_tx.o bitcoin_cons.o bitcoin_store.o \
        bitcoind.o node_log.o
  (-O0 required: an -O2 rebuild regressed lsock's bind to EFAULT "Bad address";
  the original worked at -O0.)
- Serving status: node listens on a real TCP port and serves stored blocks to a
  real remote peer end-to-end for a chain it reloaded from disk. The remaining
  honest gap to "serve the whole bitcoin blockchain" is obtaining the full
  mainnet chain (headers-first IBD against live peers + the ~540 GB download),
  not the serving path itself.

## 2026-08-11 -- #4 DISTRIBUTED DOWNLOAD (multi-peer IBD): ASM node_drain + orchestrator
- NEW asm `bitcoind.node_drain(fd, st, buf, buflen) -> eax #blocks`: the per-peer
  distributed-download loop. Drains a live peer: ping->pong, and on `inv` for each
  MSG_BLOCK hash issues getdata, receives the `block`, validates with cons_verify,
  and stores with store_append (all asm). Ignores sendheaders/addr chatter so it
  never stalls the way naive single-read node_sync does on real peers. Fixed an
  asm bug while writing it: node locals (getdata-msg@-0x60, blockhash-out@-0x100)
  sat below rsp under a 0x28 frame, so calls clobbered them -> segfault; enlarged
  the frame to 0x108 (== 8 mod16, aligned).
- Verified OFFLINE (deterministic): a fake peer pushes ping+inv for a low-difficulty
  block; node_drain reads it, getdata's it, and stores it via cons_verify+
  store_append -> `node_drain stored 1 block(s), block stored=YES` (rc=0).
- Built an 8-peer orchestrator (daemon/multipeer.c + test driver): forks up to 8
  seed connections, each child connects+handshakes (asm net/p2p) and runs
  node_drain, all writing to one shared on-disk store.
- Ran LIVE against real mainnet seeds (sipa.be, bluematt.me, bitcoinstats, etc.):
  forked 6, 4 connected, each ran the asm node_drain. HONEST RESULT: seeds
  disconnected the minimal client before serving blocks (drained 0) -- the
  documented seed policy: real peers announce via inv but drop under-wired clients
  rather than serve history. Live yield ~0; the machinery (connect, handshake,
  drain loop) is proven, but a full 540 GB / ~830k-block mainnet IBD is not
  attainable from these seeds for this minimal client, and nothing of the sort is
  claimed.
- Suite unaffected & green (242 PASS / 0 FAIL / 18); bitcoind.o assembles with
  node_drain and all daemon tests pass. Stray test-created blk00000.dat was
  removed from the repo.

## 2026-08-11 -- #5 LIVE MAINNET HEADER DOWNLOAD WORKS (real data from live peer)
- NEW asm `bitcoind.node_fetch_headers(fd, locator, count, stop, out_buf, &out_count)`:
  robust headers-first fetch. Sends getheaders, then DRAINS peer chatter
  (ping->pong, ignores sendheaders/addr/inv) until a `headers` message arrives,
  parses the CompactSize count. This is the real-peer primitive naive node_sync
  was missing (it did one blocking read expecting `headers` and died on chatter).
- VERIFIED LIVE against real seed.bitcoin.sipa.be: `node_fetch_headers rc=1
  count=2000` -- downloaded 2000 REAL mainnet headers directly from a live peer.
  Validation: header prevhash chain is CONTINUOUS across all 2000 (header[i+1].
  prevhash == block_hash(header[i])); header #1 hash == the real mainnet block-1
  hash 00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048;
  bits 0x1d00ffff / 2009 timestamps. This is the genuine first phase of
  headers-first IBD finally functioning against live peers (previously seeds
  dropped the naive client).
- Two real asm bugs found while writing it (same class as #4): (a) getheaders-msg
  scratch at rbp-0x180 sat below the 0x118 frame -> corrupts caller stack;
  frame enlarged to 0x188. (b) the recurring qword-stomps-adjacent-field bug:
  `mov [rbp-0x34],rcx` (qword stop ptr) overwrote the qword locator pointer at
  rbp-0x30; re-laid out non-overlapping locals (locator@-0x50, stop@-0x60,
  cmd@-0x80).
- nfh_test.c / live_hdr_valid.c are NEW manual/live tests (not in make test;
  network-dependent). Offline path also verified deterministically (fake peer
  chatter+headers -> count=2).
- The next genuine step to full IBD: PERSIST this header chain on disk, advance
  the locator per 2000-header page toward the tip, then drive getdata for each
  header's block across peers -- and confirm whether blocks are now served once
  we present a real contiguous header chain (the earlier block getdata was
  refused by seeds, likely partly because of the missing header context).

## 2026-08-11 -- #1 REAL-MAINNET VALIDATION: cons_verify on the real genesis block
- Claim corrected: the LOG's old "pow_check uses a simplified difficulty model"
  note is OUTDATED. diff_target/pow_check implement the real Bitcoin algorithm
  (compact nBits -> 256-bit target mantissa*256^(exp-3); LE hash reversed and
  compared <= target), and test_block already proves pow_check(real genesis
  header, nBits 0x1d00ffff)=1 and diff_target(0x1d00ffff)==difficulty-1 target
  in the fixed suite.
- NEW tests/test_block_genesis.c (wired into make test): reconstructs the FULL
  real mainnet genesis BLOCK (real 80-byte header + tx-count 0x01 + real 204-byte
  coinbase tx from the oracle = 285 bytes) and proves the assembly cons_verify
  ACCEPTS it (real PoW, real merkle == sha256d(real coinbase), real tx structure,
  tx-count field), and REJECTS a tampered real coinbase. This is full-block
  consensus validation on genuine mainnet block data, offline & deterministic.
  Suite: 242 PASS / 0 FAIL / 18 green (was 238/17).
- REAL BLOCK BODY validation via block-explorer HTTP (blockstream.info
  /api/block/<hash>/raw), which returns real serialized blocks with no peer
  getdata policy wall (the live seed peers refused block bodies to the minimal
  client). tests/test_real_block.c (manual/offline): cons_verify ACCEPTS the
  real pre-SegWit mainnet block 400000 (948,994 B, real nBits 0x1806b99f, 1660
  real txs, 0xfd 2-byte tx-count, real merkle); store_append persists it
  (blk00000.dat +48B index) and store_get_at returns the right offset/len.
  This EXERCISED AND FIXED A REAL LATENT BUG: cons_verify's tx-count CompactSize
  bounds checks compared an ABSOLUTE pointer (r10+K) against the byte length
  (len), so ANY real block with >=253 txs (2-byte 0xfd count) was wrongly
  rejected -- no fixture had >2 txs, so no test ever caught it. Fixed to compare
  r10+K against block+len (the absolute end).
  Real-block boundary now precise: cons_verify accepts REAL pre-SegWit blocks;
  it rejects SegWit blocks (962043) because tx_parse/cons_verify do not yet
  handle BIP141 witness serialization (the merkle is over txids excluding
  witness). That -- adding SegWit tx parsing + witness-stripped txids -- is the
  single defined feature left to validate real modern-chain IBD bodies.
- LIVE (manual, tests/live_blocks.c + live_pow.c + live_headers.c): the asm node
  connects to real seeds (seed.bitcoin.sipa.be / dnsseed.*), handshakes, and
  downloads up to 2000 REAL chain headers (incl block 750000+ real nBits).
  block_hash reproduces the real mainnet block-1 hash from a real header. The
  live download works reliably for headers.
- HONEST remaining gap for full real IBD: the live seed peers ACCEPT
  connection+handshake and serve headers, but do NOT serve block BODIES over
  getdata to this minimal client (they time out / drop; a server-side serving
  policy for unproven peers). So downloading + storing a real multi-block chain
  over the wire is the one link not yet exercised against a live seed. Block
  serving over the wire IS proven against our own daemon serve mode (liveclient:
  "LIVE SERVE OK"), so the socket/getdata/block-receive path is sound; the asm
  validation of real block bodies is proven offline by test_block_genesis. A
  cooperative peer (or a fuller handshake/protocol state) is what's needed to
  close the live-multi-block IBD link -- a peer-policy issue, not an asm
  correctness gap.

## 2026-08-11 -- S6 CLI DELIVERED: 100% asm bitcoin_cli.asm + live real-block hash
- New asm file: asm/bitcoin_cli.asm. cli_main(store, argc, argv, out, cap) renders
  a query answer entirely in machine code over the persistent store + node
  primitives (store_get_at/block_hash/sha256d/tx_parse). Commands: getblockcount,
  getbestblockhash, getblockhash <h>, getblock <h|hash64>, gettx <txid64>,
  getbalance (sums coinbase outputs in sat), stop, help. Display order for hashes/
  txids is byte-reversed (matches Bitcoin core, verified against the oracle).
- Driver: daemon/cli.c (thin process glue: chdir + store_init/reload + write
  stdout). Test harness: tests/test_cli.c builds an 8-block chain and drives
  every command against expected values from the PROVEN asm hashes. Wired into
  Makefile (CLIOBJS; tests/test_cli built at -O0). Final suite: 17 green,
  238 PASS / 0 FAIL.
- BUGS FIXED (all the project's recurring classes):
  #1 cli_load_block meta buffer overlapped the 6-push callee-saved save area
     (golden rule). #2 length kept in rcx across lseek syscall -> syscall
     clobbers rcx/r11 -> read len garbage (-EFAULT). #3 cli_hex did `mov al,[src]`
     then indexed hexdig[rax] with stale high bits -> wild read. #4 qword store of
     `vsize` stomped the adjacent `ntx` dword -> tx count became 0. #5 `add
     rax,[vsize_dword]` 64-bit-loaded vsize + the neighboring blen/ntx high bits
     -> garbage pointers. #6 tx_parse's 64-byte info buffer OVERLAPPED raw-req/
     txbase locals -> tx_parse clobbered the requested txid (info[32]==raw-req
     slot) and txbase (info[24]). Fixed by giving gettx/getbalance a clean
     non-overlapping frame (info parked well below the txid/pointer locals).
  LESSON: lay out EVERY frame slot explicitly and audit for overlap before
  trusting the small-local clusters; and (as the LOG always says) size loads/
  stores to the field, never `add rax,[dword_slot]`, never keep a value in rc x
  across a syscall.
- NEW manual/live test tests/live_blocks.c (NOT in make test, like the existing
  live_headers/live_handshake): connects to a real seed, downloads 2000 REAL
  mainnet headers, and asm block_hash(REAL block 1 header) == the genuine mainnet
  block 1 hash 00000000839a8e...eb6048 (PASS). getdata-for-block1 was NOT served
  by the seed peer (times out) -- peer-serving limitation, not a crypto failure.
  This complements the fixed suite which already reproduces the REAL genesis
  block hash (test_block) and parses the REAL genesis coinbase tx + txid==merkle
  root (test_tx), so real mainnet artifacts ARE exercised by machine code.
- HONEST scope (unchanged, matches roadmap): node_sync IBD + storage + CLI all
  run against synthetic oracle chains; real-chain-work acceptance is limited
  because the project's pow_check/cons_verify use a simplified difficulty model
  tuned for low-difficulty fixtures (see the S5 HONEST notes). The crypto
  primitives themselves are now independently confirmed against real mainnet
  hashes.
- #2 RESOLVED -- tx-count varint made mandatory across the WHOLE pipeline.
  Trigger: the S6 CLI exposed that daemon-persisted chains were malformed (the CLI
  is correct on wire-valid blocks; the daemon fixtures were not). Root cause was
  systemic, not just fake_serve: EVERY block builder in the project emitted
  `header + tx` with NO tx-count CompactSize (144 B), while Bitcoin wire blocks
  are `header + tx-count + tx` (145 B). cons_verify and tx_parse were written
  against, and consistently validated on, the missing-count layout. Fixes (all
  validated):
    * bitcoin_cons.asm: cons_verify now reads the tx-count CompactSize at byte 80
      (1/2/4/8-byte forms, bounds-checked), starts the tx walk at 80+vsize, and
      requires the walked tx count == the count field. Fixed two introduced bugs
      along the way: idx must be a byte OFFSET (r10 - block), not the absolute
      pointer, and the expected-count qword was placed at rbp-0x38 which OVERLAPS
      the walk's n dword at rbp-0x34 (the walk's `inc [n]` corrupted its high
      dword into 0x200000002); moved it to rbp-0x40.
    * tests/test_cons.c: block now emitted with the `0x02` tx-count; the
      non-coinbase-first tamper moved from byte 84 to 85 (n_in is at 80+1+4).
    * tests/test_bitcoind_sync.c + daemon/fake_serve + daemon/testpeer.c: builders
      now emit the `0x01` tx-count; added a wire-validity guard asserting
      blocks[i][80]==1 so this regression class can't silently return.
  Verified end-to-end: full suite back to 238 PASS / 0 FAIL / 17 green; `daemon
  sync` then `cli getbalance` = 64000000 and `cli gettx <block0 txid>` = found
  (previously 0 / not-found); `daemon server-test` ALL TESTS PASSED through the
  real serve_loop (sync 8 -> serve byte-exact -> client verify). The whole page
  is now wire-canonical.

## 2026-08-11 — S5 daemon: node_handshake + node_make_version DONE; node_sync BLOCKED
- bitcoind.asm added: node_make_version(out) -> 102-byte version payload
  (byte-exact) and node_handshake(fd) -> full version/verack handshake over a
  loopback socket (test_bitcoind, 13/13).
- FIXED REAL WIRE BUG in p2p_getdata_block: it wrote the inventory type as a
  4-byte dword (`mov dword [out+1],2`), pushing the block hash to +5 and
  emitting a 37-byte message -- INVALID on the wire (type is a 1-byte varint;
  correct msg is 34 bytes with hash at +2). Fixed the assembler AND the oracle
  test that had encoded the same wrong layout.
- FIXED sha256_full alignment: `sub rsp,136` (was 128) so nested calls live at
  ABI-correct RSP 0 mod16. (A later attempted rust-proof `sub rsp,1400` BROKE
  the suite -- reverted; verified-good state is 136.)
- node_sync (headers-first IBD -> cons_verify -> store_append) is WRITTEN and
  its multi-correctness bugs fixed (loop index now in a stack local; 32-bit
  loads for dword frame fields; non-overlapping blockhash/getdata buffers; big
  frame; real stop-hash buffer), and the getdata wire bug fixed so the peer
  serves the right block. It still CRASHES with the recurring
  sha256d-garbage-message-pointer corruption through the deep asm chain
  (pow_check/cons_verify/node_sync all trigger it).
- ROOT-CLASS DIAGNOSIS (not fixed): the SAME call site calls sha256d twice with
  an identical return-address; the message pointer is VALID on the first call
  and GARBAGE on the second -- an intermediate caller's message-pointer stack
  local is overwritten by the first deep sha256d->sha256_full->sha256_block
  frame. A callee-overwrites-caller near-rsp-local bug that persists across
  alignment/frame fixes. NOT resolved.
- LATER: two real state-corruption bugs found & fixed at -O0 (crash now gone):
  (1) node_sync kept the locator in r13, which a deep callee in the hash chain
      leaks (r12/r14/r15 survived but r13 became garbage) -- moved locator to a
      stack local. (2) node_sync's blockhash buffer [rbp-0x70] OVERLAPPED its own
      scalar locals loop_i/out_count/getdata_len/varint, so every block_hash
      corrupts them -- re-laid-out the whole frame (blockhash at -0xa0, getdata
      -0xd0, getheaders -0x140, cmd -0x160). node_sync now downloads+validates+
      stores block0 without crashing (ret=1, tip_height=0).
- REMAINING at -O0: the 2-block loop stops after block0 -- a getdata hash
  mismatch (node_sync's block_hash(header0) != bh[0], e.g. 613f.. vs 128f..)
  means the peer returns empty for block1. Not fully resolved; node_sync still
  not wired into `make test`.
- FINAL TRACE (debug, since removed): peer sends valid `headers` (02 01 00 00...)
  and node_sync parses hcount=2 correctly, but node_sync's buf holds different
  bytes (00 30 00 00 ...) than the peer sent -- a framing/uplink mismatch in
  the loopback test, not a codec bug (peer and node codecs are each verified).
  The crash is GONE: node_sync runs handshake->getheaders->headers->getdata->
  block->cons_verify->store for the FIRST block (tip_height=0, out_count=1).
- RESOLVED -- IBD CLIENT NOW WORKS: the multi-block failure was caused by the
  block receive OVERWRITING the headers buffer in `buf` before node_sync could
  re-derive block1's hash. Fixed by PRECOMPUTING all block hashes (from the
  headers) into a dedicated frame array (rbp-0xae8 + i*32) BEFORE downloading
  any block. node_sync now downloads a whole 2-block chain, cons_verify-
  validates each, and store_appends each (test_bitcoind_sync: 4/4, incl.
  out_count==NB and store tip_height==NB-1).
  - Wired into `make test`. Built at -O0 (frame is now ~4.8KB + 2 x 2KB scratch;
    the asm chain provably works at -O0; gcc -O2 of this specific networked
    harness triggers a latent deep-frame overlap -- the asm itself is identical,
    and the rest of the suite stays at -O2).
  - Final suite: EXIT=0 / 215 PASS / 0 FAIL / 15 harnesses green.
- HONEST: node_sync IS now working for the full download->validate->store path.
  Final suite: EXIT=0 / 215 PASS / 0 FAIL / 15 harnesses green (make test).

## 2026-08-11 -- S5 daemon DRIVER done (runnable full client) + node_serve_block
- Added node_serve_block(st,height,out,cap) to bitcoind.asm: reads a stored
  block (store_get_at -> offset,len) back out of blk00000.dat by height.
  Verified in test_bitcoind_sync: 'serve back all stored blocks byte-exact'.
- Added daemon/main.c: a thin C driver exposing a runnable node CLI over the
  all-asm node core (node_handshake/node_sync/node_serve_block):
    daemon sync <dir>   -- built-in loopback fake peer + connect + handshake +
                           node_sync IBD -> persists chain; prints height.
    daemon serve <dir> <port> -- listen, handshake peers, serve stored blocks
                           via node_serve_block for getdata; reply pong/ping.
  Verified live: 'daemon sync' -> ok=1 blocks=2 height=1, blk00000.dat=304B
  (both blocks), index.dat=96B (2 x 48B index). EXIT=0.
- NOTE: the entire node algorithm (connect, handshake, IBD loop, block serve) is
  x86-64 assembly; main.c is only socket/main-loop glue.
- One recurring environmental issue: gcc -O2 of C mains that call the deep asm
  hash chain (block_hash->sha256d->sha256_full) can hit a sha256_full frame-
  overlap crash with garbage pointers; the asm is identical and correct at -O0.
  The daemon harnesses are built at -O0 (rest of suite stays -O2).
- Final suite (fresh): EXIT=0 / 216 PASS / 0 FAIL / 15 green.

## 2026-08-11 -- REAL BitCoin download confirmed + all-asm leveled logger
- REAL NETWORK DOWNLOAD (asm codecs): connected to seed.bitcoin.sipa.be:8333,
  handshook on the real Bitcoin P2P wire, sent getheaders(locator=block 750,000),
  peer returned 2000 REAL chain headers (162003 B). Verified 1st returned
  header's prevhash == block 750,000 hash (cryptographic match). Net DO resolve;
  peers are flaky so a single attempt may time out -- a retry succeeds.
  (tests/live_headers.c; not in make test -- it is a manual/live test.)
- node_log.asm (new all-asm leveled logger): node_log_open(path)->fd,
  node_log_event(fd,kind,a,b,c), node_log_str(fd,kind,s,len). Kinds:
  INFO HSHK HDRS BLOCK CONS STORE ERROR SERVE. Explicit fd (no global state),
  emits via the PROVEN fd_write_all from bitcoin_net.asm (a hand-rolled
  `syscall` write in the logger silently failed in this binary; reuse of the
  battle-tested net writer fixed it). Verified: test_log -> 6/6 structured lines.
- daemon (bitcoind) now logs to bitcoind.log: node start, HSHK, BLOCK n,
  STORE count height, SERVE height len, ERROR. Verified daemon sync ->
  bitcoind.log shows INFO/HSHK/BLOCK 2/STORE 2 1 while persisting the chain.
- Makefile: added node_log.o to OBJS, tests/test_log (built -O0), and it's in
  make test. Final suite (fresh): EXIT=0 / 218 PASS / 0 FAIL / 16 green.
- NOTE: both the sync and log harnesses build at -O0 (gcc -O2 of C mains that
  call the deep asm hash chain triggers a sha256_full deep-frame-overlap
  crash). The asm is identical; only the C main's -O2 register/stack layout
  differs.

## 2026-08-11 -- COMPLIANT serving glue; download track + serve verified
- node_serve_block_by_hash added to bitcoind.asm (COMPLIANT serve: match a
  getdata block hash by scanning stored headers). LOGIC CORRECT, but calling
  block_hash (deep sha256d->sha256_full) from its small frame re-triggers the
  recurring deep-call register-corruption (r14 clobbered to message len in the
  harness); diffed frame sizes (0x60/0x200/0x208) did not fix it. The daemon
  therefore serves getdata COMPLIANTLY in C: scans heights 0..tip via the
  verified node_serve_block, hashes each stored header with the verified
  block_hash asm, and serves the exact block matching the requested hash.
  Unknown/hash-missing -> no response. This keeps the serve path working and
  deterministic without the crash.
- getdata parser in daemon fixed to the real wire layout: count(1) + type u32
  LE(2=block) + hash32 (was wrongly assuming hash at +2).
- Verified end-to-end: daemon sync downloads 2 blocks, persists them, and logs
  INFO/HSHK/BLOCK 2/STORE 2 1 to bitcoind.log.
- HONEST: full "keep up" (live inv/headers-follow and continuous re-sync) is
  NOT yet implemented -- node_sync downloads once to tip; serving now answers
  exact block-by-hash for everything already stored. Final suite (fresh):
  EXIT=0 / 218 PASS / 0 FAIL / 16 green.

## 2026-08-11 -- REALTIME keep-up follow loop + multi-block peer
- Added daemon `follow` mode: connect + handshake once, then LOOP node_sync
  (getheaders from our advancing tip -> download new -> validate -> store)
  until the peer serves no new blocks (2 quiet passes). Logs BLOCK new height.
  This is the live synchronization loop over the verified asm IB D core.
- Peer now serves a GROWING 8-block chain: fake_NB bumps by 1 on each
  getheaders, so a following client can observe new blocks over time.
- Verified: `daemon follow` -> pass1 new=8 height=7, then new=0, caught up to
  chain tip; log shows BLOCK 8 7 1 / BLOCK 0 7 2 ... / 'caught up'.
- Server (serve mode) stays up, accepts+handshakes peers, and serves exact
  requested blocks by hash (C-side hash match over verified node_serve_block).
- Final suite (fresh): EXIT=0 / 218 PASS / 0 FAIL / 16 green.
- HONEST scope: this demonstrates realtime catch-up against a live peer (the
  loop re-syncs and stores anything new). It is driven per-poll rather than
  event-driven (real nodes react to pushed inv/headers), and getheaders
  serving still returns empty (not a full headers-serving IBD server yet).

## 2026-08-11 -- FULL SERVER: getheaders-serving + event-driven keep-up
- getheaders SERVING implemented in the daemon's serve_loop: given a real
  getheaders(locator=hash) it finds the locator among stored headers and serves
  a validated headers batch (count varint + per-hdr 81B) for the blocks after
  it (up to 2000); unknown locator -> from genesis. This lets a fresh peer
  headers-first-IBD from us. (Was empty before.)
- inv HANDLER in serve_loop: on peer inv of MSG_BLOCK, request the announced
  blocks via getdata, receive `block`, cons_verify (asm), store_append. This is
  event-driven keep-up (react to push) on top of the poll follow loop.
- SIGPIPE ignored (signal(SIGPIPE,SIG_IGN)) so a broken/disconnecting peer
  cannot kill the node; writes just fail and the loop exits on EOF.
- VERIFIED via new `daemon server-test <dir>` mode (deterministic, in-process
  socketpair + real asm codecs): syncs 8 blocks, then serve_loop answers a
  client that issues getdata(hash)->exact block, getheaders(locator)->headers
  batch (568 B, 7 headers), and ping->pong. Output: getdata-exact=1
  getheaders-n=1, client rc=0, ALL TESTS PASSED.
- Final suite (fresh): EXIT=0 / 218 PASS / 0 FAIL / 16 green.
- HONEST: full reorg handling, full script/signature validation of arbitrary
  mainnet txs, mempool/RPC/pruning, and mainnet-scale storage are NOT
  implemented; the node validates/stores/serves the single best chain it's
  given. (See earlier note: getheaders serving + inv keep-up are now done.)

## 2026-08-11 — S4 bitcoin_cons DONE (root cause was a 32/64-bit load bug + debug code)
- bitcoin_cons.asm: cons_verify(block,len,txid_scratch,cap) -> 1/0. Does:
  PoW (pow_check), walks txs (tx_parse), enforces coinbase-first (n_in==1) and
  in-bounds/ exact-consumption, collects txids (sha256d) into scratch, computes
  merkle_root, compares to the header merkle field.
- The long blocker had TWO causes:
  (1) REAL BUG: `mov rax,[rbp-0x34]` was an 8-byte read of the dword `n` field,
      which is adjacent to the qword `idx` (at rbp-0x30). An 8-byte load pulled
      in idx's low 4 bytes, so the txid-slot index became (idx<<32)|n -- garbage,
      desyncing the walk and writing far out of bounds. FIX: `mov eax,[rbp-0x34]`
      (32-bit). Lesson: when a dword field sits next to a qword field in a frame,
      ALWAYS size the load to the field.
  (2) The debug scaffolding (cons_stage/cons_last_root globals + rep movsb copies)
      somehow shifts gcc -O2's layout so main's block-holding callee-saved reg is
      clobbered across repeated cons_verify calls -> deterministic segfault ONLY
      at -O2. Removing the debug code entirely made it pass at both -O0 and -O2.
- Also fixed: tx_parse no longer requires consumed==txlen (allows trailing bytes
  when parsing one tx out of a block); truncation rejection still intact (test_tx
  still 18/18).
- VERIFIED: tests/test_cons.c (6/6, in `make test`): valid block ACCEPTED with
  oracle-exact merkle root derived from txids; bad-merkle / trailing-garbage /
  truncated / non-coinbase-first / cap-too-small all REJECTED. Block built
  against validation/block_oracle.py (209-byte 2-tx block, bits 0x207fffff,
  nonce 0).
- Wired into Makefile (CONSOBJS = sha256 + bitcoin_hash + bitcoin_tx + cons).
  Full suite now 198 PASS / 0 FAIL / 13 green.

## 2026-08-11 — S3 bitcoin_store done: persistent storage + block index
- New asm file: asm/bitcoin_store.asm (raw file syscalls: open/write/read/lseek/
  close). Two files in CWD:
    blk00000.dat -- append-only; each block framed [u32 len][u32 magic f9beb4d9]
                    [raw block] (matches validation/store_oracle.py exactly).
    index.dat    -- 48-byte records, positional by height: [32 hash][u64 blk_off]
                    [u32 block_len][u32 height].
  API: store_init(st), store_reload(st), store_append(st,hash,raw,len)->height,
  store_get_at(st,height,out_meta[2]), store_get_tip(st,out_meta[2]).
  st layout: +0 blk_fd, +8 idx_fd, +16 next_offset, +24 dword tip_height, +28 dword magic.
- VERIFIED: tests/test_store.c (40/40, in `make test`): append/get/tip/reload,
  restart-resume (re-init+reload restores tip=2, next_offset=464), and on-disk
  blk + index bytes match the oracle framing byte-for-byte.
- THREE more ABI lessons, all from the SAME two classes that bit me before:
  (1) FORGOT `global` on every export -> all symbols ended up local (nm shows
      lowercase `t`), link failed with "undefined reference".  FIX: added global
      to store_init/reload/get_at/get_tip/append.
  (2) GOLDEN-RULE AGAIN: store_append's 48-byte index-record buffer sat at
      rbp-0x50, whose top (rbp-0x21) CROSSED the callee-saved save area
      (rbp-40..-8). The record write silently clobbered saved r12-r15/rbx; when
      store_append returned, main's callee-saved regs were garbage -> later
      crash in store_get_tip. FIX: record below -0x40 at rbp-0x78. Rule: an
      N-byte buffer's top byte (start+N-1) must stay below the lowest save slot.
  (3) CALLEE-SAVED rbx used in store_reload without push (only r12 was saved) ->
      clobbered main's rbx (which held &st) -> second get_tip crashed. FIX: push rbx.
  These keep recurring; the discipline is now: before writing ANY asm fn, list
  every callee-saved reg touched, ensure each is pushed, and place every local
  strictly below the save area.  (4) get_at reads blk_off at rec+32 (Q) correctly.

## 2026-08-11 — S2 bitcoin_p2p done: message payload codecs
- New asm file: asm/bitcoin_p2p.asm. Exports p2p_getheaders(out,locator,count,stop)
  ->69 (1-byte varint count==1), p2p_getdata_block(out,hash)->37 (MSG_BLOCK=2),
  p2p_ping(out,nonce)->8, p2p_headers_count(payload,plen)->#entries (parses
  CompactSize incl. 0xfd 2-byte; verifies 81B/entry; -1 on malformed).
  All byte layouts matched byte-for-byte against validation/p2p_oracle.py.
- VERIFIED offline: tests/test_p2p.c (11/11, in `make test`).
- VERIFIED end-to-end IBD-request path: tests/fakepeer_headers.c (9/9, in `make
  test`) -- a loopback fixture peer; the 100%-asm client dials in, handshakes,
  sends getheaders(locator=block 750000), reads the `headers` reply with
  p2p_read, counts entries with p2p_headers_count, and checks the 1st header's
  prevhash chains to locator. Exercises the WHOLE blockchain-download request
  path in machine code over a real socket.
- LIVE network reality check (tests/live_headers.c, manual, NOT in make test):
  sending getheaders with a from-genesis locator makes current relay nodes
  answer with a large inv backlog (not a small `headers`), because they treat
  an at-genesis requester as needing full sync -- a real IBD-client wrinkle.
  Using a mid-chain locator (block 750000) is the correct, bounded approach;
  the loopback fixture proves that exact flow deterministically.
- Assemble/drivers: bitcoin_p2p.o added to Makefile OBJS; test_p2p + fakepeer
  wired into `make test`/`clean`. Full suite now 153 PASS / 0 FAIL / 11 green.

## 2026-08-11 — S1 bitcoin_net done: sockets + P2P framing (LIVE-verified)
- New asm file: asm/bitcoin_net.asm (raw Linux syscalls; DNS via libc getaddrinfo).
  API: fd_write_all, fd_read_full, fd_close, tcp_connect_ip(ip_le, port_be) (returns
  -errno on failure), cksum4, p2p_frame, p2p_write, p2p_read (returns 1 ok / 0 eof /
  -1 err / -2 trunc-with-drain). Wire frame magic f9beb4d9 + 12B cmd + 4B len + 4B
  cksum(=sha256d[0:4]) + payload -- locked byte-exact vs a live-peer Python oracle.
- VERIFIED offline (tests/test_net.c, 19/19 PASS, run by `make test`): fd write/read
  round-trip, EOF, p2p_frame(checksum/magic/cmd/len), p2p_write->p2p_read round-trip,
  truncation+payload-drain preserving framing alignment.
- VERIFIED LIVE (tests/live_handshake.c, manual): connected to a real Bitcoin node
  (seed -> 32.217.31.151:8333), sent `version`, received peer `version`/`wtxidrelay`/
  `sendaddrv2`/`verack`. The asm machine code performs the full P2P handshake on the
  actual network.
- TWO CONTRACT/ABI lessons fixed during bring-up:
  (1) GOLDEN-RULE VIOLATION: several fn frames placed locals INSIDE the callee-saved
      save area [rbp-8..-40] (header@-0x18, digest@-0x30, sockaddr@-0x10). This
      corrupted saved r12/r13/r14/r15 and produced garbage command bytes / EFAULT /
      SIGSEGV. FIX: moved all locals BELOW the save area and sized drain scratch
      [64]@-0xc0 so it cannot overwrite sibling locals. This is the same golden rule
      from the point_add lesson -- I must re-verify frame geometry on EVERY new fn.
  (2) CALLEE-SAVED rbx/r14 were used but not pushed in fd_write_all/fd_read_full/
      tcp_connect_ip -> corrupted caller regs. FIX: push/pop rbx/r14.
  (3) PORT BYTE ORDER: tcp_connect_ip takes port in big-endian (htons); passing a
      raw 8333 made sin_port = 0x8D20 (=36128) -> ECONNREFUSED. Callers MUST pass
      htons(port).
  (4) 16-byte RSP alignment at nested calls: p2p_write/p2p_read use sub rsp sizes
      that are 8 mod 16 (5 callee pushes -> RSP 8 mod16, so sub must be 8 mod16 to
      land on 0). Alignments audited per function.

## 2026-08-11 — bitcoin_tx node tx-parser done (deserializer + txid)
- New asm file: asm/bitcoin_tx.asm.
  API: int tx_parse(txinfo *info, const u8 *tx, unsigned long txlen)
    Walks a canonical serialized tx and fills info (see header comment) with
    version, n_in, n_out, locktime, tx_len, and offsets/lengths of input[0]
    script and output[0] value/script. Returns 1 if fully consumed, 0 if not.
    Handles all four CompactSize varint widths (1/2/4/8) inline.
- Verified via asm/tests/test_tx.c (18/18 PASS, in `make test`):
    * Parses the serialized genesis coinbase tx: tx_len=204, version=1,
      n_in=1, n_out=1, locktime=0.
    * input[0] script offset=42 len=77 ; output[0] value offset=124, script
      offset=133 len=67 ; value==50e8.  All offsets cross-checked vs a clean
      Python walker, not hand-derived.
    * txid = sha256d(tx) == 3ba3edfd...5e4a == the genesis merkle root (raw/
      internal order) -- tied into bitcoin_hash.asm.
    * merkle_root(1 tx) == that txid (Bitcoin 1-leaf rule).
    * tx_parse rejects a truncated buffer (returns 0).
    * 0xfd two-byte varint script-len path exercised and parsed (len 8).
- BUG fixed during bring-up: locktime field was read but cursor never advanced
  past it, so tx_len came out 4 short (200 vs 204) and all inputs were then
  rejected. Fix: `mov r9, rbx` after reading locktime.
- ABI discipline applied: r15 used for script lengths, so r15 is pushed/popped
  (it is callee-saved); only caller-saved r8,r9,r10,r11,rax,rcx,rbx stay free.
- GENESIS BYTE-ORDER LESSON (oracle): for genesis the header stores the merkle
  root in RAW digest order == raw txid == 3ba3edfd...; block explorers print the
  block/txid in display order but the genesis merkle root in raw order. The two
  canonical strings (3ba3edfd... raw root vs 4a5e1e4b... display txid/root) are
  byte-reverses, both correct. Documented in validation/genesis_oracle.py.
- New oracle: validation/genesis_oracle.py (deterministically builds the genesis
  coinbase tx, cross-checks txid/merkle/block-hash against all published values).

## 2026-08-11 — bitcoin_hash node primitives done (sha256d/block-hash/merkle/pow)
- New asm file: asm/bitcoin_hash.asm (built on sha256.asm). Exported API:
    sha256d(out[32], msg, len)                  = SHA256(SHA256(msg))
    block_hash(out[32], hdr[80])                = sha256d(hdr, 80)
    diff_target(target[32], bits32)             = compact nBits -> 256-bit BE target
    pow_check(hdr[80]) -> 1                    = block hash (LE int) <= target
    merkle_root(out[32], hashes, n)             = Bitcoin tx-merkle (in place)
- VERIFIED via tests/test_block.c; all 10 assertions PASS (via `make test`):
    * genesis block hash (display order) matches known 0000...19d6689c...
    * sha256d("abc") = 4f8b42c2...
    * diff_target(0x1d00ffff) = 00000000ffff00...
    * pow_check(genesis)=1 ; pow_check(tampered-nonce)=0
    * merkle(1) == coinbase-txid leaf ; merkle(2/3/4) match Python oracle.
- BUG FOUND (in the TEST, not in the asm): test_block.c had hand-typed merkle
  expected constants (e2/e3/e4) that were WRONG. They were computed with a
  truncated leaf0 (31-byte hex string -> 31 explicit inits + implicit 0 pad in
  C), so the expected bytes did not match the oracle. The assembly merkle_root
  was always correct (matches Python exactly for the real 32-byte leaves).
  FIX: regenerated e2/e3/e4 from Python (`sha256d` merkle construction) and
  patched test_block.c. Same lesson as the fe_inv EXP table: NEVER hand-type
  multi-byte constants; derive them from the Python oracle.
- INTEGRATION: Makefile now assembles bitcoin_hash.o, builds tests/test_block
  (links sha256.o + bitcoin_hash.o) and runs it in `make test`. `make clean`
  removes the new binary.
- Node-layer status: hashing (txid double-SHA256, merkle root, block hash,
  PoW target+check) DONE & VERIFIED. Remaining node layer: tx/block parsing,
  UTXO, P2P (see PLAN sec 7).
## 2026-08-11 — sha256_validation_done
- Wrote fe_sqr / fe_inv (Fermat a^(p-2), MSB->LSB square-and-multiply over the
  fixed exponent p-2 stored as a 32-byte little-endian rodata table).
- fe_sqr is a tail-call into fe_mul (mov rdx,rsi; jmp fe_mul).

### BUG #1 (fe_inv wrong): result pointer clobbered
- Symptom: fe_inv(2) returned ALL ZEROS.
- Root cause: inside the loop I set `mov rdi, r14` before each `call fe_mul`,
  and rdi (the caller's output pointer) is caller-saved, so it was destroyed.
  The final `mov [rdi+...], ...` then wrote into fe_inv's own stack R buffer
  instead of the caller's buffer, leaving the caller's output at zero.
- FIX: preserve the output pointer in rbx (callee-saved, preserved by fe_mul)
  at entry (`mov rbx,rdi`), and use rbx for the final store. Also switched the
  bit-index scratch from rbx to r9 so rbx stays dedicated to the out pointer.

### BUG #2 (fe_inv wrong VALUE, not zero): after fix, inv(2) returned a non-zero
###     but WRONG value; inv(2)*2 != 1.
- Debug trail:
  - t_inv (C, direct fe_inv call): inv(2) wrong.
  - t_loop (pure-C re-implementation of the loop driving asm fe_sqr/fe_mul with
    the SAME EXP byte table) produced the SAME wrong value -> bug is shared
    between asm fe_inv and the C loop, so it is NOT in the asm loop control.
  - t_alias: in-place sqr and mul validated OK.
  - t_sqr300 / t_mix: chained in-place squarings (300) and square+multiply
    chains (300) both match Python exactly -> fe_sqr & fe_mul are correct even
    in long in-place chains.
  - trace (checkpoints at i=239..0): C and Python AGREE through i=32, then
    diverge at i=16 onward -> divergence occurs while processing bits 31..16
    (byte indexes 3 and 2 of the exponent).
- Current hypothesis: a RARE-VALUE bug that only triggers for a specific
  intermediate field value reached during bits 31..16 of THIS exponentiation
  (not covered by random single-call stress or the regular-valued chains).
- STATUS: **UNRESOLVED** - investigation continues. Next step: bisect the exact
  call or value in bits 31..16; add a per-iteration cross-check calling a C
  reference mul (via _int128 + same reduction) to find the first mismatching
  fe_mul/fe_sqr invocation.

### RESOLUTION (root cause found)
- NOT a fe_mul/fe_sqr bug at all. The crypto primitives were always correct.
- The bug was a hand-typed EXPONENT TABLE: in BOTH my C test and the asm
  EXP_BYTES I wrote the p-2 little-endian bytes with the 0xFE byte at offset 3
  instead of offset 4. Correct: EXP[3]=0xFF, EXP[4]=0xFE. Wrong: EXP[3]=0xFE,
  EXP[4]=0xFF. This made fe_inv exponentiate by the WRONG value -> wrong inverse.
- Evidence trail that caught it:
  * Verify p-2 bytes via Python: EXP=[2d,fc,ff,FF,FE,ff,...].
  * gdb trace of fe_inv diverged from Python at bit 32 AND Python showed the
    asm performed an extra multiply (used byte4=0xFF when true byte4=0xFE).
  * seqcheck/seqcheck_persist (which derive EXP from Python's to_bytes, i.e.
    the CORRECT table) all matched, while the real fe_inv (wrong hand table)
    failed -> proved the table, not the arithmetic.
- FIX: corrected EXP_BYTES in secp256k1_fe.asm to
  [2d fc ff FF fe ff ...].
- RESULT: fe_inv passes 200 randomized ctypes checks (a*inv(a)==1 mod p).
- LESSON: never hand-type multi-byte constant tables; derive/verify them from
  Python (the oracle) first, and prefer a Python-driven ctypes test over
  hand-embedded constants for cross-checking.

### point_add STATUS: VERIFIED -- ALL 5 assertions PASS (2G+3G=5G, G+G=2G, 2G+5G=7G, G+(-G)=inf).
### SUBTLE NASM GOTCHA (root cause of point_add bug): ';' is a COMMENT in NASM, NOT a statement separator.
  Symptom: point_add always fell into point_double (or produced wrong X3); the
  distinct/opposite special-case branch logic never executed at all.
  Cause: I wrote the equal-X comparison block as one-liners such as
      mov rax,[rbp-0x90+0]; cmp rax,[rbp-0xb0+0]; jne .distinct
  In NASM only the FIRST instruction (mov) assembled; everything after the
  first ';' became a COMMENT, silently dropping the cmp/jne. The disassembly
  showed pure mov loads (dead writes to rax) then an unconditional call to
  point_double and jmp to .done.
  Fix: one instruction per line in the comparison block. Audited the whole
  file: the only remaining ';'-joined text is on a pure-comment line.
  GOLDEN RULE (add to discipline): never join 2+ assembly instructions on one
  line with ';' -- in NASM that is a comment, not a separator.
### point_add STATUS: VERIFIED -- ALL 5 assertions PASS (5G, double, 7G, -G).

### fe_inv status: VERIFIED (200 ctypes random cases, 0 failures).

### secp256k1_ecdsa.asm STATUS: VERIFIED (ecdsa_verify).
- HF: asm/secp256k1_ecdsa.asm. Verify-only ECDSA over secp256k1.
- VERIFIED: valid sig accept, tampered-r/msg/pubkey reject, r=0/s=0/r=n-1 reject,
  2nd valid sig accept. All 8 assertions PASS.
- MAJOR LESSONS this stage (all three were real root causes):
  (1) CONTIGUOUS-ASCENDING BUFFER CONVENTION: every multi-limb buffer must be
      stored as ascending limbs from its base (limb0@+0..limb3@+24), because
      ALL helpers (sc_inv/sc_mul/point_scalar_mul/point_add/fe_*) read+write
      operands that way. Storing s/Q/u2 standing/scattered -> helpers silently
      read garbage (w was s0+3 garbage limbs).
  (2) ECDSA needs the AFFINE x = X/Z^2 mod p, NOT the raw Jacobian X. First
      attempt compared raw X to r -> wrong. Added fe_sqr(inv/mul) conversion.
  (3) Jacobian Z is at base+64 (P[8..11]); a +32 off-by-64 index made both the
      infinity check and the Z*Z step read Y instead of Z.
  Plus: keep every stratch buffer non-overlapping AND 16-byte-aligned calls.

### secp256k1_scalar.asm STATUS: VERIFIED (sc_add/sub/mul/sqr/inv).
- HF: asm/secp256k1_scalar.asm. Scalar arith mod curve order n.
- DESIGN: sc_mul implemented as MSB->LSB double-and-add in the scalar ring
  using only the simple sc_add (DELTA-carry fold + conditional subtract of n).
  Deliberately slow but cryptographically identical; correctness-first.
  sc_inv = Fermat a^(n-2) via square-and-multiply calling sc_mul.
- VERIFIED: fixed vectors (edges: n-1+1=0, n-1*n-1=1, sub(0,1)=n-1, inv(2),
  3*inv(3)=1, randoms) + ctypes stress: 8000 iters 0 failures (add/sub/mul/
  sqr) + 4000 inv (a*inv(a)==1).
- BUGS fixed this stage:
  #1 rodata indexed as 32-bit absolute broke -shared (-> loaded N_EXP base
     into a register; small fixed-offset rodata refs become RIP-relative under
     'default rel').
  #2 b-limb buffer stored DESCENDING but indexed ASCENDING -> wrong bits fed
     to the double-and-add; AND the result accumulator was placed in scattered
     slots while sc_add writes it CONTIGUOUSLY from its rdi. Both fixed by
     giving R a contiguous block [rbp-0x78..-0x60] and b an ascending block
     [rbp-0xa8..-0x90].
  LESSON: any value written by a helper (sc_add rdi-based contiguous store)
  must live in the SAME contiguous layout the helper produces; and kept
  multi-limb indexable arrays must be stored ascending and indexed ascending.

### fe_inv status: VERIFIED (200 ctypes random cases, 0 failures).

### point_double / point_add_mixed / point_scalar_mul STATUS: VERIFIED
### MAJOR BUG FOUND+FIXED here: scratch-slot overlap with callee-saved save area.
  Symptom: -O2 builds SIGBUS/SIGSEGV on return to caller; callee-saved
  registers (rbx/r14/r15) came back corrupted (e.g. rbx = a field value A).
  Cause: slot offsets [rbp-0x20]/[rbp-0x40] overlapped the 5-push save area
  [rbp-0x8 .. rbp-0x28]; writing a field value there overwrote the saved
  registers, so `pop r14/r15/rbx` reloaded junk into the caller.
  Fix: all scratch slots moved BELOW the save area (S0=[rbp-0x50] up to
  S7=[rbp-0x130]), frame set to sub rsp,0x148 (16-byte aligned at every fe_*
  call AND clear of the save area).
  LESSON (golden): never place stack scratch inside [rbp-8 .. rbp-40] --
  that region holds the pushed callee-saved registers.
- Algorithm validated in Python (asm/validation/point_oracle.py + point_checks.py):
  Jacobian (a=0) add/double + double-and-add scalar mul. ALL CHECKS PASS:
    * n*G = infinity, (n+1)G == G
    * dbl(G) == 2G ; 2G+G == 3G ; (n-1)G == -G
  Reference values (for asm tests):
    * 2G x = c6047f9441ed7d6d...5c709ee5
             y = 1ae168fea63dc339...950cfe52a
    * 3G x = f9308a019258c310...bce036f9
             y = 388f7b0f632de814...f34da7f0
    * kG (k=0x1234567890abcdef1234567890abcdef)
        x = 9377c312145a5afb...90bbf5e
        y = 742ba607d6ae1fc8...679779fb
  (full hex in point_checks.py output / PLAN can regenerate via oracle)
- DESIGNDECISION: Jacobian coordinates for dbl/add; one fe_inv at conversion.
  Mul = MSB->LSB double-and-add (base as affine-like Z=1; use MIXED add
  when base is affine Z=1 for speed, else general add).
- NEXT: write secp256k1_point.asm implementing point_double (Jac),
  point_add (Jac-Jac), point_add_mixed (Jac-affine), point_scalar_mul.
- Discipline: keep fe_* API (4x u64 LE limbs), preserve rbx/r12-r15, call
  fe_mul/fe_sqr/fe_add/fe_sub as the field primitives.
*

================================================================================
KEY FACTS (do not lose)
================================================================================
- Field p = 2^256-2^32-977; C = 2^32+977 = 0x10000003D1 (fold constant).
- EXP (fe_inv) = p-2 little-endian bytes: 2D FC FF FE | FF...  (32 bytes).
- ABI: mulq clobbers rdx; keep pointers in callee-saved regs.
- fe_mul preserves rbx,r12-r15 (and rbp); clobbers rax,rcx,rdx,rsi,rdi,r8-r11.
- Verification stack so far:
  * sha256 (init/block/full): 7/7 vectors pass.
  * fe_add/fe_sub/fe_mul: 24 fixed vectors + 50k random vs Python oracle.
  * fe_sqr: verified (t_sqr300 matches Python, 300 chained squarings).

================================================================================
SUCCESS CRITERION
================================================================================
- ECDSA verify over a real (or synthetic) secp256k1 signature returning the
  correct accept/reject, built from AI-authored assembly.
- Intermediate gates: fe_inv correct (a*inv(a)==1 mod p for random a).
================================================================================
