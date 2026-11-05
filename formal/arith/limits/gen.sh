#!/usr/bin/env bash
# Cut the product code the limits harnesses verify into limits/gen/ (verbatim).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
wt=$(cd "$here/../../.." && pwd)
x="python3 $here/../lib/extract.py"
a=$wt/asm
g=$here/gen
mkdir -p "$g"
# ---- CompactSize readers ----
{ $x "$a/daemon/utxo_walk.h" lines '^#define UTXO_WALK_CS_MAX_SIZE ' '^#define UTXO_WALK_CS_MAX_SIZE '
  $x "$a/daemon/utxo_walk.h" func utxo_walk_read_varint; } > "$g/cs_utxo_walk.inc"
{ $x "$a/daemon/block_witness.c" lines '^#define BW_CS_MAX_SIZE ' '^#define BW_CS_MAX_SIZE '
  $x "$a/daemon/block_witness.c" func rd_varint; } > "$g/cs_block_witness.inc"
{ $x "$a/daemon/tx_verify.c" lines '^#define TXV_CS_MAX_SIZE ' '^#define TXV_CS_MAX_SIZE '
  $x "$a/daemon/tx_verify.c" func txv_rd_cs; } > "$g/cs_tx_verify.inc"
$x "$a/bitcoin_segwit.c" func read_cs > "$g/cs_segwit.inc"
{ $x "$a/bitcoin_mempool_policy.c" lines '^#define MPOL_CS_MAX_SIZE ' '^#define MPOL_CS_MAX_SIZE '
  $x "$a/bitcoin_mempool_policy.c" func rd_varint; } > "$g/cs_mempool_policy.inc"
$x "$a/bitcoin_txval_modern.c" func rd_cs > "$g/cs_txval_modern.inc"
$x "$a/daemon/tx_accept.c" func txacc_varint > "$g/cs_tx_accept.inc"
$x "$a/daemon/signet_block.c" func rd_cs > "$g/cs_signet_block.inc"
$x "$a/daemon/blk_submit.c" func bsub_varint > "$g/cs_blk_submit.inc"
# ---- block size / weight (utxo_live.c Phase 0.10 and Phase 0.27) ----
ul=$a/daemon/utxo_live.c
$x "$ul" block 'const u64 MAX_BLOCK_WEIGHT = 4000000ULL;'   > "$g/w_phase010.inc"
$x "$ul" block 'u64 weight = 3ULL \* stripped \+ blocklen;'  > "$g/w_phase027.inc"
# the empty-block early return in front of both (CheckBlock's vtx.empty())
$x "$ul" lines 'if \(ntx == 0\) return 1;   /\* matches the old loop' 'hit by real chain data\) empty-block behavior' > "$g/w_ntx0.inc"
# ---- sigops (utxo_live.c Phase 4.6; tx_verify.c helpers) ----
$x "$ul" block 'const u64\* tx_sigops = \(const u64\*\)txvb_last_tx_sigops' > "$g/s_phase46.inc"
$x "$a/daemon/tx_verify.c" func txv_sgc_last_push   > "$g/s_last_push.inc"
$x "$a/daemon/tx_verify.c" func txv_witness_sigops  > "$g/s_witness_sigops.inc"
# ---- sigop-adjusted vsize (bitcoin_mempool_policy.c) ----
mp=$a/bitcoin_mempool_policy.c
$x "$mp" lines '^    m->weight = m->nonwit_len \* 3 \+ txlen;' '^    m->vsize  = \(m->weight \+ 3\) / 4;' > "$g/v_weight.inc"
$x "$mp" lines '\{ uint64_t sigops_x = mpol_pending_sigops;' '^      \} \}$' > "$g/v_adjusted.inc"
$x "$mp" func mpool_policy_set_bytespersigop > "$g/v_set_bps.inc"
