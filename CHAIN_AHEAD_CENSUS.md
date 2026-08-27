# Census: the un-replayed chain vs the verifier's limits

> **Status 2026-08-27 (historical document).** The premise below — a chain
> "ahead" of the verifier — is closed: the node replayed the whole chain to
> the live tip and its UTXO set is proven byte-identical to Core's (MuHash).
> The one hard wall flagged here (`TXV_MAX_WIT_ITEMS`) was raised before the
> replay reached it; every shape below has since validated on real chain data.
> Kept as the record of how the walls were found before they were hit.

Written 2026-08-22, while the Stage D replay sat at height 498,786. Purpose:
after a run of "first occurrence in history" consensus bugs (incidents
#10–#15 in `LOG.md`), stop discovering walls one at a time. This samples the
chain **ahead** of the replay (499,000 → ~869,000, the Core oracle's tip) via
`getblock … 2`, classifies every input's script/witness shape, and
cross-references the maxima against the verifier's actual caps — so the walls
are known before the replay reaches them.

This is deliberately **not** a set of hand-written synthetic vectors. Tonight
proved those share the author's blind spots (the P2WPKH-scriptCode and
NULLDUMMY bugs passed synthetic tests because the generator made the same
mistake as the verifier). The real chain is the independent adversary; this
just consults it early.

## Method / honesty

257 blocks sampled: stride 1,500 across 499k–869k, plus every 250th block
through the taproot-activation window 709k–712k. First-occurrence heights and
running maxima recorded. **Gaps:** a rare shape between stride points can be
missed (especially a one-off exotic tapscript); input/output **maxima are
lower bounds** (a larger consolidation tx may sit between samples). Shapes
were classified from scriptSig + witness only (exact for all witness spends).

## Measured maxima vs our caps

| measured | value | our cap | status |
|---|---|---|---|
| witness items / input | **21** | `TXV_MAX_WIT_ITEMS` = 8 | **EXCEEDS — the one hard wall** |
| tapscript leaf size | 371,967 B (inscription) | `script_eval` walks in place; `MAX_SCRIPT_SIZE` exempt for tapscript | OK |
| tapscript op count | 10,000 | `MAX_OPS`=201 **exempt** for tapscript | OK |
| control-block depth | 21 (705 B) | `TAPROOT_CONTROL_MAX_NODES` = 128 | OK |
| P2WSH multisig n | 11 (6-of-11) | CHECKMULTISIG ≤ 20 | OK |
| witnessScript size | 887 B | `TXV_SPK_CAP` = 10000 | OK |
| tx inputs | 1,372 | `TXV_MAX_INPUTS` = 20000 | OK (sampled) |
| block inputs | 10,200 | 20000 | OK (sampled) |

## Predicted walls, by height

| first-height | shape / limit | our gap | verdict | evidence txid |
|---|---|---|---|---|
| **~551,500** | witness stack > 8 items (max 21) | `TXV_MAX_WIT_ITEMS=8` | **WILL REJECT** — fix in flight on `wit-items`; cap → MAX_STACK, not 21 | cf33e9d272219d23ff0b… |
| ~532,000 | P2WSH with OP_CODESEPARATOR | general-P2WSH (#12) present | handled, UNTESTED | 23b098958df5086d8f49… |
| 517,000+ | P2WSH HTLC: CLTV+CSV+IF+HASH160/SHA256 | present via `script_eval` | handled, UNTESTED (first real CLTV/CSV/hashlock *inside a witness script*) | 4022cbaecf465bde2176… |
| 730k / 788.5k / 815.5k | sighash 0x81 / 0x83 / 0x82 (ACP, SINGLE\|ACP, NONE\|ACP) | BIP143 htype masking present | handled, UNTESTED (SINGLE\|ACP is the ancient corner) | 229614… / 11ace7… / 9ea2fe… |
| **~775,000** | P2TR **script-path** (tapscript), incl. 363 KB inscriptions | dispatched; ops/size exempt; walked in place | handled, UNTESTED at scale — no fixture > 10 KB tapscript or a real inscription | 4cc72b13218183d4a6b1… |
| 806.5k / 824.5k / 826k | tapscript CSV / CLTV / **CHECKSIGADD** | interp has OP_CHECKSIGADD + tapscript rules | handled, UNTESTED (first real CHECKSIGADD, tapscript CLTV/CSV) | e5dd… / 38806… / 7152875897af592bdd36… |

## Taproot era (709,632+)

Key-path common from ~713,500 (incl. ~11k non-default-sighash spends by
713.5k). Script-path from ~775,000 and immediately heavy (one sampled block
had 44,933 script-path inputs — inscriptions). Only leaf version 0xc0 seen
(no future leaf versions yet). Control-block depth maxes at 21 (≪ 128). The
tapscript opcodes that appear — OP_IF (ubiquitous), CHECKSIGADD, CLTV, CSV,
HASH160 — all have code paths and **none has a real-chain fixture**. The
single biggest untested risk is a real inscription-scale tapscript spend
end-to-end.

## What this means (the strategic answer)

1. **One hard wall remains** before ~869k: the witness-item cap, already
   being fixed. Nothing else in the sampled range rejects outright — the
   #11–#14 fixes plus the tapscript size/op exemptions cover the shape
   diversity. After `wit-items` lands, the replay should run *much* further.
2. **The remaining risk is coverage, not code:** ~15 distinct "handled but
   never run on real data" shapes. The high-value move is one differential
   test that pulls the evidence txids above from the oracle and runs each
   through `tx_verify_block_connect_all` — turning "should work" into
   "verified," so a latent bug surfaces in a test, not at block 826,000.
   Groups: (a) P2WSH HTLC / CODESEP / CLTV / CSV; (b) sighash
   0x81/0x82/0x83; (c) tapscript incl. one inscription and one CHECKSIGADD.
3. **Design-worthy, not urgent:** `tap_leaf_hash`'s 4 MB buffer caps a
   tapscript leaf at 4 MB; a > 4 MB leaf would fail — none seen, and block
   weight makes it near-impossible, but note it.

## Outcome (appended 2026-08-22 evening, replay past 576,000)

Recorded against the predictions above, including where the census was
wrong. The original text is left unedited — its value is as a record of
what the method did and did not catch.

| prediction | outcome |
|---|---|
| witness stack > 8 items, "the one hard wall" | **CORRECT, and it was even earlier than predicted.** It rejected at **498,787** (a 17-item P2SH-P2WSH), not ~551,500 — the stride-1,500 sampling had simply missed the first occurrence, exactly the gap the Method section warned about. Fixed as incident #15 (`d1a2259`), cap → 1004. |
| P2WSH CODESEP / HTLC / sighash 0x81/0x82/0x83 | Fixtures now exist and pass (`tests/test_segwit_coverage.c`) — the "turn should-work into verified" move from item 2 was done. |
| tapscript CSV / CLTV / CHECKSIGADD, "handled, UNTESTED" | **The census's assessment was WRONG in the dangerous direction.** These were not handled: `OP_CHECKSIGVERIFY` was routed to `.bad_opcode` under SIGVERSION_TAPSCRIPT, so HTLC-style leaves could never execute, and the script-eval context was zeroed so tapscript CLTV/CSV were silently gated off. Incident #16 (`4dc5941`). Found by pulling the 806500 evidence txid and actually running it — i.e. by item 2, not by the classification. |
| ">10 KB tapscript / real inscription" untested at scale | **CLOSED, and the census's own maximum was 10x too small.** Fixtures now exist and pass (`tests/test_tapscript_scale.c`): a **3,938,182-byte** leaf at height **774628** — below the 775,000 this table calls the first script-path height, and within 1.5% of the ~3,999,000 MAX_BLOCK_WEIGHT allows at all, so nothing on the chain can be materially larger — plus the 371,967 B leaf at 779500, the 42,594 B leaf at 775000 (this row's evidence txid, full txid `4cc72b13218183d4a6b13e79ef3e0a73c7987688dd0334866a8398b03e514057`), a 21-node control block at 850000 and a 12-item script-path witness at 860500. Nothing on the size path broke. Chasing *why* it did not break is what found incident #18. |
| `tap_leaf_hash` 4 MB leaf cap | **CLOSED, and it is provably unreachable, not merely unseen.** The asm bounds `slen` at `TAP_PREIMG_CAP-70` = **4,194,234**; MAX_BLOCK_WEIGHT = 4,000,000 caps any leaf a valid block can carry near **3,999,000**, so ~195 KB of headroom can never be consumed. Measured too: `tests/test_tapscript_scale.c` sweeps `tap_leaf_hash` at 0 / 1 / 252 / 253 / 65,535 / 65,536 / 371,967 / 3,938,182 / 3,999,000 / 4,194,234 bytes against independently-computed BIP341 hashes, and confirms 4,194,235 fails cleanly (returns 0, writes nothing). |
| *(not predicted)* BIP342 initial-stack element-size limit | **A bug the census could not have found, because the shape does not exist on the chain.** `taproot_verify_input` applied no `MAX_SCRIPT_ELEMENT_SIZE` check to the tapscript initial stack, and `stack_push` bounds only the stack depth — so a >524-byte initial-stack item overran a 528,000-byte heap buffer by up to ~3.4 MB, and a 521-byte one was a silent consensus false-accept. 47,578 sampled real script-path inputs (68 blocks, 775k–869k) max out at a **79-byte** initial-stack item and contain **no OP_SUCCESSx leaf**, so no amount of chain sampling would have surfaced it. Incident #18. |
| *(not predicted)* **output** scriptPubKey size vs the BIP143 CTxOut buffer | **A wall this document had every means to predict and did not, because it only ever classified INPUTS.** `sw_ser_txout` serialized a CTxOut into `uint8_t tmp[600]` on the stack with no bound; consensus limits an output's scriptPubKey not at all. A sparse sweep (481,824..950,000, step 5,000) says the chain's maximum output scriptPubKey is **105 bytes**, which is exactly the kind of reassurance this table has been wrong about twice already. Dense sampling of the reachable shape — a segwit-v0 input in a transaction with a >589-byte output — finds it in **1 of 464** blocks over 900,000..946,400 and **7 of 920** over 940,000..963,000, first located at height **927,500** (a P2WPKH spend with a 2,019-byte `OP_RETURN`). The replay will hit it. Incident #21. |

**The lesson.** Conclusion 2 above — "the remaining risk is coverage, not
code" — was the wrong call, and it was wrong because the census classified
shapes by whether a code path *existed*, not by whether it *worked*. A
dispatch table entry that routes a valid opcode to `.bad_opcode` looks
identical, from the outside, to a correct implementation. The census was
still worth writing: it named the right region and the right evidence
txids, and running one of those txids is what found the bug hours before
the replay would have hit it. But "handled" in the table above should be
read as "has a code path", never as "verified" — only a fixture that fails
on the old code and passes on the new can say that.

**A second lesson (added with the last two rows).** The census's method — ask
the chain what shapes exist, compare against our caps — is sound for finding
walls the replay will hit, and it found them. But it is structurally blind to
a whole class of bug: a shape that is *consensus-valid and therefore mineable*
yet has simply never been mined. Incident #18's oversized tapscript stack item
is exactly that. No sampling density would have produced it; only reading the
path against Core's `ExecuteWitnessScript` line by line did, and only Core
itself (a new `TAPVERIFY` command in `validation/core_verify_oracle.cpp`)
could then say which way the vector was supposed to go. "What has the chain
done" and "what may the chain do" are different questions, and this document
only ever asked the first.

**A third lesson (incident #21).** Two blind spots, and the second is the
uncomfortable one. First, this census classified **inputs** — script shape,
witness depth, leaf size — and never once measured an **output**'s
scriptPubKey, even though a BIP143 sighash serializes every output of the
spending transaction. Whole fields go unexamined when the classifier is
written around the code you happen to be worried about. Second, and worse: the
sparse answer to "how big do output scripts get" was **105 bytes**, and it was
wrong by a factor of nineteen. It was not wrong the way #18 was wrong (a shape
that has never been mined); the shape is *on the chain*, in ~1% of recent
blocks, and a stride-5,000 sweep walked straight past it. A census result is a
statement about its sampling interval. When the number it produces is the
reason not to fix something, re-sample at the density the conclusion needs
before believing it.

**Final note 2026-08-25.** The chain this census surveyed has now been fully
replayed and rebuilt through the live tip, and the resulting set proven
byte-identical to Core's by MuHash (`README.md`). The census's record above —
what it predicted, what it missed and why — stands unedited as a document
about sampling, which was always its real subject.
