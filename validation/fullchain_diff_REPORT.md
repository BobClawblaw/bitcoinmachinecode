# Full-Chain Differential vs Bitcoin Core — Report

Task t_fd5dc8f4 · generated 2026-08-16 15:34 UTC · branch `wt/fullchain-diff`

## Verdict: ZERO DIVERGENCES across the ENTIRE active chain (962,749 blocks)

This closes the gap flagged in the worklog post-mortem: the sampled
differential gate (t_a6b10dab, 8,935 blocks / 8,000 txs) passed 0-divergence,
but 'consensus done' required a hash-for-hash differential over the WHOLE
~962k-block chain. That full-chain proof is delivered here.

## Surfaces (compared against live Bitcoin Core, unpruned, tip 962,748)

| Surface | Meaning | Result |
|---------|---------|--------|
| A accept | ASM `cons_verify` accepts every active-chain block | 962,749 / 962,749 |
| B hash   | ASM `block_hash` == Core's authoritative per-height hash | 962,749 / 962,749 |
| D pow    | ASM `pow_check` accepts every header | 962,749 / 962,749 |
| E txcount| wire varint tx-count decodes identically in ASM & Python | 962,749 / 962,749 |
| CHAIN    | on-disk `prev` of block h == Core hash of block h-1 | 962,748 / 962,748 |
| coverage | every active-chain height matched an on-disk ASM record | 0 missing |

`divergences: 0` · `EXIT 0`. Reference read is a full offline scan of Core's
809 GB blk*.dat files (no reorg risk); B-surface anchors each height to
Core's authoritative `getblockhash`.

## Fixes made this run (validation/fullchain_diff.py)

1. **De-obfuscation (`_xor_deobf`) was returning garbage.** The numpy pack
   `raw.reshape(n_words,8).astype(np.uint64)` left each element a widowed
   byte instead of packing uint64 words, so de-obfuscation produced
   `f9edffc0` where Core's real magic is `f9beb4d9`, and block counting found
   0 valid blocks. Replaced with a position-aligned byte-wise XOR
   `plain[pos] = raw[pos] ^ key[pos % 8]`, proven byte-for-byte correct by
   decoding genesis + blocks 1-3 to their known hashes.

2. **Pipe-buffer deadlock.** `stream_pass` wrote each block frame to the
   shim without `flush()`. Small frames sat in Python's 8 KB buffered writer
   while `readline()` blocked -> all workers stuck in `anon_pipe_read`,
   machine 95% idle mid-run, no progress. Fixed with `shim.stdin.flush()`
   after every frame.

3. **Calibrate-off format crash.** `calibrate=%d % (args.calibrate or 'off')`
   passed a string to `%d`; only triggered on a full (non-pilot) run. Fixed to `%s`.

4. **False 'chain' divergences: physical file order != active-chain order.**
   Core's blk*.dat files retain reorg'd/orphaned blocks, so the assumption
   'file position == height' breaks (visible as spurious prev-link breaks
   near heights 169-196, where replaced blocks sit out of order). Rewrote
   `verify_surfaces` to be **hash-keyed and Core-anchored**: index every
   ASM record by block hash, then for each active-chain height compare the
   ASM record for Core's `getblockhash` height. This surfaced 100% correct
   hashes with 0 spurious divergences.

5. **Benign tail-padding flagged as a divergence.** Core pads the final
   blk file after the last block, so the walk hit a non-magic tail; treated
   as normal end-of-stream (frame integrity is independently validated by
   the count phase and by every hash matching Core).

## Method

- Reference: full offline scan of `/storage/bitcoin/data/blocks` (5706 blk
  files, ~809 GB), each frame `<len:4 LE><block>`, XOR-deobfuscated against
  `xor.dat`.
- ASM side: new batch `asm/tests/fullchain_shim` (same `cons_verify` /
  `block_hash` / `pow_check` asm objects as `consensus_shim`) streams frames
  in len-prefixed framing, one verdict line per block out.
- 32 workers, one streaming pass; then Core-anchored hash-keyed verify.
- Wall clock ~20 min (stream 1070 s + verify).

## Deliverables

- `validation/fullchain_diff_report.json` (machine-readable)
- `validation/fullchain_diff_report.txt` (human-readable)
- `asm/tests/fullchain_shim.c` + `asm/Makefile` rule (batch shim)
- `validation/fullchain_diff.py` (tool, with the 5 fixes)
