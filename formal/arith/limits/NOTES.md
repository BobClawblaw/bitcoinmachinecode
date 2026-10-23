# limits: size, weight, sigops, vsize and CompactSize against Core v31.1

`./run.sh` runs the whole group: 58 checks, 0 failures, about 42 s. It
builds the real objects into `.build/` (`build.sh`: nasm and gcc, never
`make` in asm/), cuts the product C into `gen/` (`gen.sh`, via
`lib/extract.py`), and runs each check once through runlib's `_lim`
(`systemd-run --user --scope -q -p MemoryMax=8G -p MemorySwapMax=0 -- nice
-n15`), one solver process at a time.

Tools: CBMC 6.11.0 with CaDiCaL, NASM 2.16.01, gcc 13.3.0.

To reproduce one check by hand, from this directory after `./gen.sh`, run
`$FORMAL_TOOLS/cbmc/usr/bin/cbmc <harness> <flags>`, with the flags shown
on that check's `run.sh` line.

Locks L4 (`../locks/l4_hdrtime.c`) proves the nVersion floors (BIP34/66/65,
including CON-5's int32 read) for every header; they are not repeated here.

## Check kinds

- **proof**: CBMC must report VERIFICATION SUCCESSFUL.
- **reach**: run with `-DREACH`. Witnesses for each interesting outcome must
  fail, which shows the assumptions are satisfiable.
- **mutant**: one `sed` on a scratch copy of the cut product code, or one
  replace on a scratch copy of an asm file. It counts as caught only when a
  property assertion fails. An unwinding-assertion failure or a build failure
  does not count.
- **known-divergence**: a property is expected to fail, and does. Each one is
  explained below, together with why it is not a finding.
- **diff**: a differential test of a real assembled object against a C port
  of Core.

## Results

| ID | bmc code (real) | claim | method / bound | result | time |
|---|---|---|---|---|---|
| CS-utxo_walk, CS-block_witness, CS-tx_verify, CS-mempool_policy | `daemon/utxo_walk.h` utxo_walk_read_varint, `daemon/block_witness.c` rd_varint, `daemon/tx_verify.c` txv_rd_cs, `bitcoin_mempool_policy.c` rd_varint | Accept/reject, value and width equal Core's `ReadCompactSize(range_check=true)`: canonical encoding and MAX_SIZE 0x02000000. | CBMC on every byte string of 0..9 bytes. No reader reads more than 9 bytes. Each reader runs twice, with independent bytes past `end`, which proves it never reads past `end`. Complete. | PROVED | 0.1 s each |
| CS-segwit, CS-signet_block | `bitcoin_segwit.c` read_cs, `daemon/signet_block.c` rd_cs | Equal to `ReadCompactSize(range_check=false)`: canonical, no MAX_SIZE. | same | PROVED (`-DNO_RANGE`); the full Core rule FAILS (known) | 0.1 s |
| CS-txval_modern, CS-tx_accept, CS-blk_submit | `bitcoin_txval_modern.c` rd_cs, `daemon/tx_accept.c` txacc_varint, `daemon/blk_submit.c` bsub_varint | Superset: whatever Core accepts, the reader accepts with Core's value and width. | same | PROVED (`-DSUPERSET`); the full rule FAILS (known) | 0.1 s |
| TXP | `bitcoin_tx.asm` tx_parse (the asm tx splitter) | Equal to Core's transaction deserializer, accept/reject and length, on canonical encodings. Accepts non-canonical CompactSize, which Core rejects. | diff of the real object, 1M random txs per mode. Every CompactSize field is drawn from canonical, wider, > MAX_SIZE and 9-byte forms, with trailing bytes and truncation | 0 unexpected divergences. 104,981 of 1M accepted non-canonical cases (known) | 0.5 s |
| W | `daemon/utxo_live.c` Phase 0.10 (bad-blk-length) and the post-0.25 weight block (bad-blk-weight), run in order | Accept / reject / decode-failure equals CheckBlock (`vtx.size()*4`, `stripped*4`) and ContextualCheckBlock (`3*stripped + total`). | CBMC. ntx ≤ 3, or ntx·4 > 4,000,000 (rejected before the loop). val_read_tx is stubbed (free stripped sizes, free decode bit). `-DNONEMPTY` | BOUNDED-OK | 0.5 s |
| W-empty | `bitcoin_cons.asm` cons_verify | An empty block (ntx = 0) is refused before Phase 0.10. Positive control: a one-coinbase block is accepted. | concrete run of the real objects | OK | 0.03 s |
| S-ledger | `utxo_live.c` Phase 4.6 | bmc's one running check (`sum cost > 80,000`) rejects exactly what Core's two checks reject together: CheckBlock `legacy·4 > 80,000` and ConnectBlock's running `GetTransactionSigOpCost`. | CBMC. ≤4 txs. Per-tx legacy L < 2^24, extra E < 2^30, coinbase E = 0. bmc's export modelled as 4L + E | BOUNDED-OK | 0.2 s |
| S-lastpush | `tx_verify.c` txv_sgc_last_push | The P2SH subscript (or the empty one on a 0 return) equals Core's `GetSigOpCount(scriptSig)` vData, byte for byte. | CBMC, every scriptSig ≤ 9 bytes | BOUNDED-OK | 12 s |
| S-witness | `tx_verify.c` txv_witness_sigops | Equals Core WitnessSigOps when the witness stack is non-empty, or the program is not 20-byte v0. | CBMC, complete over versions 0..16, program lengths 2..40, stacks ≤ 3 | PROVED; the empty-stack case FAILS (known) | 0.06 s |
| S-count | `bitcoin_sigops.asm` script_sigops_ex, tx_legacy_sigops | Equal to `CScript::GetSigOpCount(fAccurate)` and GetLegacySigOpCount. | diff of the real object: every script ≤ 2 bytes in both modes (131,586), 2M random scripts, 250k random txs | 0 divergences | 2.4 s |
| V | `bitcoin_mempool_policy.c` weight/vsize lines and the bytespersigop block | Entry vsize equals `GetVirtualTransactionSize(weight, sigop_cost, bps)` = `(max(w, cost·bps) + 3) / 4`, and weight = `3·nonwit + total`. | CBMC. txlen < 2^32, cost < 2^32. bps fixed per run: 1, 20, 100000 | PROVED per bps; bps = 0 FAILS (known) | 0.1–2 s |

Mutants caught (CBMC's first failing property, verbatim in the run output):

- **CompactSize, one per reader:**
  - utxo_walk: `v < 0xfc`
  - block_witness: MAX_SIZE check removed
  - tx_verify: `v < 0xffff`
  - mempool_policy: `minimum = 0xfc`
  - segwit: `min = 0xffff`
  - signet_block: `0xfc` minimum
  - txval_modern, tx_accept: `f < 0xfc` for the 1-byte form
  - blk_submit: `p+6 > end` on the 5-byte form
- **TXP:** `movzx r15, word` → `byte` for the 3-byte scriptSig length. 38,077
  divergences.
- **W:** `2*stripped` in the weight rule; `stripped*3` in the length rule.
- **S-ledger:** limit 80004.
- **S-lastpush:** OP_N yields a 1-byte subscript.
- **S-witness:** `proglen == 33`.
- **S-count:** multisig default `20` → `19`. 115,776 script divergences.
- **V:** `(adj_w + 2) / 4`.

## Known divergences (not findings), and why

1. **Lenient CompactSize readers.** These readers are segwit and
   signet_block (no MAX_SIZE), txval_modern, tx_accept and blk_submit (no
   canonical check, no MAX_SIZE), plus asm tx_parse (no canonical check).
   Each one only re-walks bytes that a canonical reader on the same path
   also reads. I established this by reading the code; it is not proved.
   - **Blocks.** apply_block_inner's Phase 0.10 runs val_read_tx, which reads
     every field with utxo_walk_read_varint (proved FULL), on every
     transaction before anything is accepted. A failed decode is filed as
     MUTATED (Core: deserialization failure). blk_submit runs cons_verify
     and then the same apply path.
   - **Mempool.** tx_accept_validate runs txval_modern and then
     mpool_policy_add, whose parse_tx reads every field with the canonical
     rd_varint (proved FULL).
   - **Consequence.** If a future path calls tx_parse, or one of the lenient
     readers, without the canonical re-read, it would accept a
     non-canonical encoding that Core refuses.
2. **P2WPKH with an empty witness stack.** txv_witness_sigops returns 0
   (`!wit_last`), while Core's WitnessSigOps returns 1. Such an input always
   fails script verification (WITNESS_PROGRAM_WITNESS_EMPTY), so the block
   is invalid either way. The verdict is the same, and at most the reject
   reason could differ.
3. **bytespersigop = 0.** bmc maps 0 to 20; Core's 0 turns the sigop term
   off. bmc's config parser (`node_config.c`, `clamp_int(IV, 1, 100000)`)
   refuses 0, so the daemon never passes it. Core also accepts values above
   100000; bmc refuses them. This is a config difference, and policy only.
4. **Core's separate CheckBlock legacy-sigop check** does not exist in bmc.
   S-ledger proves that the running cost check subsumes it, given bmc's
   export cost_t = 4·legacy_t + extra_t.

## Not covered

- **The parsers' own arithmetic in W and V.** val_read_tx computing Core's
  `GetSerializeSize(TX_NO_WITNESS)`, and the sigop cost tx_accept parks for
  the policy layer (the MPL fix's input), are taken as inputs and not
  re-proved.
- **txv_sigop_cost_tx's witness-program predicate** (size 4..42, version
  byte, `ws[1] + 2 == size`) was checked against Core's IsWitnessProgram by
  reading only. Core does not check `2 ≤ ws[1] ≤ 40` separately; the size
  rule implies it.
- **The bounds in W, S-ledger and S-lastpush** come from loop unrolling. W
  and S-ledger are linear sums, so a larger bound adds nothing new; this is
  an argument, not a proof.
