# C-to-assembly conversion candidates — scoped 2026-09-04

Ten `.c` files ranked by expected payoff if converted to hand-authored NASM.
Ranking is by position on the **profiled connect/IBD path**, not by file size.

Read `PERF_SCOPE.md` first. Everything below is anchored to its measurements;
where a candidate rests on an unmeasured assumption, this document says so
rather than implying a number it does not have.

**Deployment rule carries over from `PERF_SCOPE.md`:** every candidate that
touches the live verify or storage path is scoped now and landed later, not
built into the running daemon on the strength of this document.

---

## The ordering constraint, stated first

`PERF_SCOPE.md` §14.3: *"parallelising the taproot pass comes before any
further `fe_mul` work. A 1.15x on 54% of one core is worth far less than
moving that work onto 32."*

§14.8 built that (branch `taproot-parallel`), but §14.8's own "Not verified"
section records that **end-to-end replay throughput was never measured** and
that **the re-profile §14.3 asks for is not done**. Candidates 3-6 below are
all sized against a profile that predates it.

**Re-profile before spending effort on candidates 3-6.**

---

## 1. `asm/bitcoin_scriptverify.c` (392 lines) — top priority

`MAX_STACK * ELEM_SIZE` = 1000 x 528 = **528,000 bytes**, and the file
`memset`s all of it *per script verification*:

| site | operation | when |
|---|---|---|
| `bitcoin_scriptverify.c:348` | `memset(main_e, 0, 528000)` | every `verify_script` call |
| `bitcoin_scriptverify.c:357` | `memcpy(copy_e, main_e, 528000)` | every input with `SV_P2SH` set |
| `bitcoin_scriptverify.c:378` | `memcpy(main_e, copy_e, 528000)` | every actual P2SH redeem |

That is ~1.5 MB of memory traffic per legacy P2SH input, to service a stack
that is realistically fewer than ten elements deep.

**This appears to close an open question in `PERF_SCOPE.md`.** §11.2 item 3
and §12.8 item 2 both still read *"Attribute the 6.9% in
`memmove`/`memset`/`copy_bytes` -- source unknown without a call-graph
profile."* §11's own table gives:

    __memmove_avx512    3.82%
    __memset_avx512     1.78%
    copy_bytes.cb_loop  1.31%
    -------------------------
                        6.91%

The arithmetic matches. This is the likely source, and it is a hypothesis a
single call-graph `perf record` can confirm or kill.

**Stated honestly: the first win here is algorithmic, not assembly.** Clearing
only the live `sp` slots, and making the P2SH snapshot lazy, is cheaper in C
than any rewrite and should be measured on its own before an `.asm` port is
justified. The assembly case is separate and real -- a native stack machine
whose 528-byte element descriptor folds into registers -- but it should be
argued against a baseline that has already had the free win taken out of it.

## 2. `asm/bitcoin_witness_v0.c` (215 lines)

The same `ELEM_SIZE` / `MAX_STACK` stack and the same 528 KB TLS clear
(`bitcoin_witness_v0.c:180`), on the witness path rather than the legacy one.
It was split out of candidate 1 on 2026-08-22 and shares its stack helpers
and `sv_ctx`. **Convert the pair or neither** -- splitting them would leave
two stack representations to keep in consensus agreement.

## 3. `asm/daemon/utxo_live.c` (2,702 lines) — extract, do not convert

`PERF_SCOPE.md` §14.8 names the UTXO apply as *"the next ceiling"* once the
taproot pass parallelises.

Most of this file is orchestration, WAL handling and crash recovery, none of
which belongs in assembly. Extract the per-input/per-output kernels instead:

| symbol | line | what it is |
|---|---|---|
| `live_on_input` | `:589` | per-input UTXO spend |
| `live_on_output` | `:633` | per-output UTXO create |
| `outpoint_hash` | `:760` | 36-byte outpoint hash |
| `bidx_insert` / `bidx_get` | `:811` / `:830` | in-block output index |
| `bspent_claim` | `:859` | in-block duplicate-spend guard |
| `val_read_tx` | `:1206` | transaction parse |
| `walk_block_txs` | `:1733` | block walk |

Open-addressed hashing over 36-byte keys, and a wire-format parser, are both
shapes assembly is genuinely good at.

## 4. `asm/bitcoin_taproot_sighash.c` (1,166 lines)

`PERF_SCOPE.md` §10.4 is an explicit, still-open, still-un-landed lever: the
BIP341 SigMsg serializer re-hashes the O(nin) prevouts / amounts /
scriptPubKeys arrays **on every call, once per input**. Only the inner re-walk
was removed in the 2026-08-22 single-pass work.

Measured consequences, from §10.4: block 830,000 costs **53 us per taproot
input**; the 1,372-input shape costs **74.6 ms per transaction**.

§10.4 also prescribes the fix: thread a real per-transaction context down from
`taproot_verify_input()`, rather than keying a cache on an address. That is an
ABI change, which makes it the natural moment to move the serializer to
assembly rather than a second occasion to touch the same code.

## 5. `asm/bitcoin_segwit.c` (632 lines)

The BIP143 half of candidate 4's shape. Smaller prize -- §8.6 priced the
equivalent transaction-scoped cache at ~2x on the rarest shape and ~0 on the
common one -- but it is only 632 lines and every primitive underneath it
(`sha256_full`, `ecdsa_verify`, `pubkey_parse`, `der_parse_sig`) is already
assembly.

## 6. `asm/daemon/tx_verify.c` (1,721 lines)

The per-input flatten and dispatch layer: `tapagg_build` (`:390`-`:445`) and
the arena `memcpy` at `:318`.

§14.2 identified the `TXV_SHAPE_P2TR` skip in both worker loops as the single
largest structural gap to Core -- every taproot input verified in a sequential
loop after the threads join. §14.8 removed the shared-scratch race that forced
it. **Any work here follows that, it does not precede it.**

## 7. `asm/utxo_lsm_mm.c` (378 lines)

`lsm_run_lookup_mm` is **2.13% of the main thread** (§14.1 table).

`bloom_h` (`:278`) is a byte-at-a-time FNV over the 36-byte key, run three
times per run per lookup; `cmp_key` (`:291`) drives a binary search over
mmapped records. Small, self-contained, and it carries no consensus surface --
a wrong answer here is a cache miss, not a wrong verdict.

## 8. `asm/block_filter.c` (247 lines)

Per *line*, the weakest C in the tree on a path that runs once per block:

* `bf_siphash` (`:50`) assembles each 8-byte message word with an **inner
  byte loop** (`:59`), and does the same for the tail (`:63`).
* `bw_bit` / `bw_bits` (`:77`, `:84`) write the Golomb-Rice stream **one bit
  at a time**.
* The element array is `qsort`ed **twice** (`:198`, `:208`), with an indirect
  comparison call per compare (`bf_cmp_u64`, `:113`).

`bitcoin_cmpct.asm` already has `siphash24_uint256`; per this file's own
comment at `:36` it is fixed to 32-byte messages, which is the only reason
`bf_siphash` exists. Generalising the assembly one to arbitrary lengths
subsumes most of this candidate.

## 9. `asm/bitcoin_mempool_policy.c` (1,866 lines) — profile first

Not on the IBD path, so it appears nowhere in `PERF_SCOPE.md`. It is listed
because it is the hot path for the *other* workload -- sustained relay and
mempool admission -- and **nothing in this tree has ever profiled that**.

Do not start here on the strength of this entry. Run `perf record` against a
relay-saturated daemon first; the entry is a prompt to measure, not a claim.

## 10. `asm/bitcoin_aes.c` (174 lines) — the toolchain warm-up

Byte-oriented AES-256 with no T-tables, by its own header comment. AES-NI is
20-40x on this shape, the file is 174 lines, and a FIPS-197 Appendix C.3
known-answer test already exists (`tests/test_aes.c`).

It is a **cold path** -- wallet at-rest encryption behind a passphrase -- so
the throughput win is worth approximately nothing end to end. It is on the
list because it is the lowest-risk possible exercise of the conversion
process: self-contained, consensus-free, and already covered by a
known-answer vector.

---

## Deliberately excluded, with reasons

Four files look like obvious assembly targets and are not. In each case the
file's own header already argues the case, and the argument is correct:

| file | why not |
|---|---|
| `crypto_chacha20.c` (93) | BIP324 calls it once per network packet, where the socket dominates by orders of magnitude. `bitcoin_muhash.asm` already has the specialised version MuHash needs; widening a verified primitive for a caller that cannot benefit is a net loss. |
| `crypto_poly1305.c` (214) | Same path, same reasoning. The constant-time verify is also easier to keep honest in C. |
| `crypto_fe_sqrt.c` (87) | A handful of roots per BIP324 handshake. Auditability against libsecp256k1's chain is worth more than throughput here. |
| `bitcoin_sha3.c` (63) | Tor v3 onion-address checksums only. Nothing else in the tree uses SHA3, and Bitcoin itself uses none. |

`bip340_sign.c` (121) and `bip32_ckdpub.c` (266) are similarly cold -- wallet
signing and descriptor derivation, both interactive -- and are excluded for
the same reason, not because their crypto is uninteresting.
