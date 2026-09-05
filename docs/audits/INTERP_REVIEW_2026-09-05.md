# SCRIPT INTERPRETER REVIEW — in-session code review of the interpreter slice

**Review date:** 2026-09-05 (UTC)
**Tree state:** `main` @ `efd9735` (clean working tree). Reviewed via scaffold branch `review/interp` @ `6815e2c`: the root commit plus `asm/bitcoin_interp.asm`, `asm/bitcoin_script.asm`, `asm/bitcoin_sigops.asm`, `asm/bitcoin_script_flags.asm` exactly as on `main` (4,581 lines, byte-identical, verified). The scaffold is **not for merging** — it carries nothing else.
**Reviewer:** Claude Code `/code-review` (in-session mode), run as eight parallel finder angles, de-duplicated, then one adversarial verifier per candidate. Verification traced callers outside the four-file slice, which is why several findings anchor in `bitcoin_scriptverify.c`, `bitcoin_taproot_verify.asm`, `bitcoin_witness_v0.c` and `bitcoin_taproot_sighash.c`.
**Method:** line-level reading against Bitcoin Core's `interpreter.cpp` / `script.cpp` semantics; each candidate independently re-derived from the source with a concrete failure input before it was kept.
**Counts:** 36 candidates → 22 after de-duplication → **17 kept** (14 CONFIRMED, 3 PLAUSIBLE, per the review's own verifier) → **5 refuted**.

**Severity scale:** CRITICAL / HIGH / MEDIUM / LOW / INFO — assigned here by the project, not by the review tool.
**Status (as written, 2026-09-05 morning):** every finding below was OPEN and UNREPRODUCED. **See §7 for closure by ID** -- 12 of 17 closed the same day, each reproduced with a test watched to fail first. The review's verifier is not the same thing as a failing test here. This tree has already shown that findings from careful reviewers can be already-fixed, understated, or come with a fix that introduces a bug; each one is to be reproduced with a test that is watched to FAIL before any code moves, per `docs/ENGINEERING_RULES.md`.

---

## 1. Headline

**Two live consensus false-accepts in the interpreter, one latent, and three denial-of-service shapes reachable by a valid block.** All in a slice that has been through three external audits.

| # | What | Reach | Finding |
|---|---|---|---|
| 1 | Every net-growing stack op discards the "stack full" return at exactly 1,000 elements, so a script Core rejects with `STACK_SIZE` is accepted | any block, any sigversion | **IR-1 (CRITICAL)** |
| 2 | `der_parse_sig`'s S-bound includes the hashtype byte — one byte looser than Core's lax parser | pre-BIP66 blocks only (`assumevalid=0`, alternate history) | **IR-2 (HIGH)** |
| 3 | The asm twin of `taproot_verify_input` drops the interpreter's deferred `hard_fail`, and under-allocates its ctx frame | latent: the daemon links the C twin; the differential guarding the asm twin has no `OP_CHECKSIG` leaf and cannot see it | **IR-3 (HIGH)** |
| 4 | fExec rescans the whole condition stack per opcode; tapscript has no size/op-count cap | ~15–40 min per block from one valid input | **IR-4 (HIGH)** |
| 5 | Segwit/taproot sighash re-parses the transaction and recomputes the aggregate hashes on every signature | ~8.5 GB of SHA-256 per block from one valid 4 MWU tx | **IR-5 (HIGH)** |
| 6 | `OP_ROLL` moves whole 524-byte records; tapscript is unbounded | ~445 GB of memmove per block from one valid input | **IR-6 (HIGH)** |

**IR-1 is adjacent to SCR-1** (the 2026-09-03 audit's per-stack `MAX_STACK_SIZE` finding). SCR-1's fix added the post-op check at `bitcoin_interp.asm:2409`; IR-1 is that the ops themselves drop the push *before* that check runs, so the check sees 1,000 and passes. **IR-4 is adjacent to SCR-2** (the unbounded `vfexec` buffer): the buffer is now bounded at 5 MiB, and the cost of scanning it is what IR-4 is about.

### Finding counts

| Severity | Count | IDs |
|---|---|---|
| CRITICAL | 1 | IR-1 |
| HIGH | 5 | IR-2, IR-3, IR-4, IR-5, IR-6 |
| MEDIUM | 4 | IR-7, IR-8, IR-9, IR-10 |
| LOW | 6 | IR-11 … IR-16 |
| INFO | 1 | IR-17 |
| **Total kept** | **17** | |
| Refuted | 5 | §5 |

---

## 2. Findings

| ID | Severity | Location | Title | Class |
|---|---|---|---|---|
| IR-1 | CRITICAL | `asm/bitcoin_interp.asm:1265` (and 1016, 1025, 1041, 1050, 1059, 1075, 1084, 1227, 1295, 1374, 1473, 1484, 1495) | Net-growing stack ops ignore the 0 return of `stack_dup_index`/`stack_push`; at exactly 1,000 elements the op is a silent no-op and the post-op check at 2409 passes | consensus false accept |
| IR-2 | HIGH | `asm/bitcoin_script.asm:220`; callers `bitcoin_scriptverify.c:228`, `bitcoin_checksig.asm:142`, `bitcoin_witness_v0.c:74` | `der_parse_sig` bounds S against the full push length including the trailing hashtype byte; Core pops the hashtype first, so its bound is one byte tighter | consensus false accept (pre-BIP66) |
| IR-3 | HIGH | `asm/bitcoin_taproot_verify.asm:485` (frame at `weight_left@88, size 96`, `L_CTX 0x178`) | asm twin never reads `taproot_checksig_ctx.hard_fail` after `script_eval`; reserves 96 bytes for a 104-byte ctx so `hard_fail`/`hard_err` land in the dead `err` slot | consensus false accept (latent) |
| IR-4 | HIGH | `asm/bitcoin_interp.asm:477`; `asm/bitcoin_scriptcodec.asm:808-819` | fExec recomputed per opcode by `vfexec_all_true`, a linear scan with no cached first-false; no `MAX_SCRIPT_SIZE` or 201-op cap under `SIGVERSION_TAPSCRIPT` → O(N²) vs Core's O(1) `ConditionStack` | DoS by valid block |
| IR-5 | HIGH | `asm/bitcoin_witness_v0.c:77`; `asm/bitcoin_bip143.asm:380, 411-511`; `asm/bitcoin_taproot_sighash.c:432-449` | Witness-v0 and taproot checksig callbacks re-parse the tx and recompute `hashPrevouts`/`hashSequence`/`hashOutputs` (and `ts_agg_hashes`) on every signature; no `PrecomputedTransactionData` equivalent | DoS by valid block |
| IR-6 | HIGH | `asm/bitcoin_interp.asm:1357`; `asm/bitcoin_scriptcodec.asm:891-916` (`stack_erase_index`, `elem_move`) | `OP_ROLL` shifts every record above the index with a per-record `rep movsb` of len+4 bytes (524 B at max) where Core moves a 24-byte vector header; tapscript unbounded | DoS by valid block |
| IR-7 | MEDIUM | `asm/bitcoin_scriptverify.c:348, 357, 378`; asm twin `bitcoin_scriptverify_drv.asm:239-243, 268, 330` | 528,000-byte memset per legacy input; 528,000-byte memcpy for every input whenever `SV_P2SH` is set (all post-BIP16 inputs, not only P2SH spends); 528,000-byte restore for P2SH spends | efficiency |
| IR-8 | MEDIUM | `asm/bitcoin_interp.asm:2044`, dispatch at 712, skip at 586-593 | Core's pre-fExec arm `OP_CODESEPARATOR && BASE && CONST_SCRIPTCODE → SCRIPT_ERR_OP_CODESEPARATOR` is absent; the error (254) is never emitted; flag consulted only at FindAndDelete sites | policy divergence |
| IR-9 | MEDIUM | `asm/bitcoin_taproot_sighash.c:1137` (and asm twin `:67/462`); `asm/daemon/tx_verify.c:604-616` | `taproot_verify_input` has no flags parameter and hard-codes `CLTV\|CSV`; `TXV_SHAPE_P2TR` dispatch does not forward `flags` (WV0/LEGACY arms do), so `TXV_MEMPOOL_POLICY_FLAGS` never reach a tapscript leaf; `MINIMALDATA` and `DISCOURAGE_OP_SUCCESS` dead for mempool tapscript, though `tx_verify.c:922` documents `interp.asm:457` as the enforcement site | policy divergence |
| IR-10 | MEDIUM | `asm/bitcoin_script.asm:468, 472-475`; file-private `parse_varint` at 367 vs `.walk` at 451/463 | `verify_p2pkh` walks scriptSig push lengths with no bound against the scriptSig or tx end and assumes direct single-byte pushes; its `parse_varint` clobbers `cl` while `.walk` counts inputs in `rcx` | memory-unsafety (latent: linked by test/wallet targets only, no daemon caller) |
| IR-11 | LOW | `der_parse_sig`, `verify_p2pkh`, `tx_legacy_sigops` | 8-mod-16 stack frames (latent; already tracked in `docs/ABI_STACK_ALIGNMENT.md`) | ABI |
| IR-12 | LOW | `asm/bitcoin_interp.asm:2538` | `is_opsuccess_c` copies all 64 bits of `rdi` for an `int` argument; fix `mov eax, edi` | correctness (latent) |
| IR-13 | LOW | `asm/bitcoin_interp.asm:2752` | LOW_S arm reports `HIGH_S` for S ≥ N where Core does not; unobservable while LOW_S is always paired with NULLFAIL | error-code parity |
| IR-14 | LOW | `asm/bitcoin_verify.c:254` | parity oracle's STRICTENC hashtype rule is wrong; never exercised | test oracle |
| IR-15 | LOW | `sv_checksig` | redundant per-(sig,key) FindAndDelete | efficiency |
| IR-16 | LOW | `asm/bitcoin_interp.asm` opcode dispatch | 73-entry linear dispatch chain | efficiency |
| IR-17 | INFO | `asm/bitcoin_sigops.asm` header | `[accurate]` header comment is inverted | documentation |

---

## 3. Detail — CRITICAL and HIGH

### IR-1 — stack-growing ops discard "stack full" (CRITICAL, consensus false accept)

**Sites:** `OP_DUP` 1265, `OP_OVER` 1295, `OP_IFDUP` 1227, `OP_PICK` 1374, `OP_2DUP` 1016/1025, `OP_3DUP` 1041/1050/1059, `OP_2OVER` 1075/1084, `OP_TUCK` 1473/1484/1495.

`stack_dup_index` / `stack_push` return 0 when the stack is at `MAX_STACK_SIZE`. None of the listed sites test that return. At exactly 1,000 elements the op silently does nothing (or, for the multi-push ops, part of something), then the post-op check at 2409 — `cmp rax, MAX_STACK_SIZE / ja` — sees 1,000, which is not greater than 1,000, and passes. Core pushes to 1,001 and fails with `SCRIPT_ERR_STACK_SIZE`.

**Failure input:** `scriptSig = 1000 × OP_1` (push-only, legal; `sv_run` fills to exactly 1,000 and carries `st.sp` into the scriptPubKey run), `scriptPubKey = OP_DUP`. Core: block invalid. Here: script ends with top = 0x01 → `SCRIPT_ERR_OK` → **accepted**. Same on witness v0 (`drv.asm:207 ja`) and tapscript (`taproot_sighash.c:1081` admits a 1,000-item initial witness). `OP_2DUP` at 999 leaves `… A B A`; `OP_TUCK` at 1,000 leaves `x2 x1` — wrong stack contents as well as wrong verdict.

**Test first:** the input above, expect `STACK_SIZE`, watch it return `OK`. Then every site.

**Fix shape:** each site tests the return and fails with `SCRIPT_ERR_STACK_SIZE`. Equivalently, make the push helpers fail the script instead of returning 0 — but audit every caller that relies on the 0 return first (the sigops and codec paths may).

### IR-2 — `der_parse_sig` S-bound one byte loose (HIGH, consensus false accept, pre-BIP66)

`der_parse_sig` bounds the S INTEGER against the full push length (`lea r8,[r12+r13]; cmp rax,r8; ja .fail`). Every consensus caller passes `siglen` **including** the trailing hashtype byte. Core pops the hashtype before `ecdsa_signature_parse_der_lax`, so its `slen > inputlen - pos` bound is one byte tighter.

**Failure input:** pre-BIP66 legacy CHECKSIG. Signer grinds `k` until S's low byte is `0x01` and pushes the 70-byte `30 44 02 20 R[32] 02 20 S[32]` with **no** separate hashtype byte. Here S ends exactly at the push end (`ja` accepts equality), `sv_checksig` reads `ht = sig[69] = 0x01`, the SIGHASH_ALL digest matches, verify is TRUE → block accepted. Core: lax parse over 69 bytes, `slen 32 > 31` remaining → parse fails → block rejected.

**Reach:** mainnet below 363,725 with `assumevalid=0`, or any alternate pre-DERSIG history. Masked above the DERSIG height by `der_sig_strict`'s `sig[1] == size-3` check. This is exactly the range the never-run full-verification IBD benchmark (`FEATURE_GAPS.md`, "Confirmed genuinely still open") would exercise.

**Fix shape:** in the callers, pass `siglen - 1`. Not in the parser — other users rely on its trailing-`0x01` detection.

### IR-3 — asm taproot twin drops `hard_fail` (HIGH, consensus false accept, latent)

After `call script_eval / test eax,eax / jz .r_exec / .accept` (485-489) the asm twin of `taproot_verify_input` never reads `taproot_checksig_ctx.hard_fail`. Its frame reserves 96 bytes (`weight_left@88, size 96`, `L_CTX 0x178`) for a ctx whose `sizeof` is 104, so the callback's `hard_fail`/`hard_err` writes (`taproot_sighash.c:772/807`) land in the dead `err` slot at `[rbp-0x118]`. The interpreter's deferred-hard-fail contract for `SIGVERSION_TAPSCRIPT` is silently dropped.

**Failure input:** tapscript leaf `<64-byte invalid sig> <32-byte xonly pk> OP_CHECKSIG OP_NOT` (or `OP_0 OP_0 OP_CHECKSIG` with a truthy tail). The callback sets `hard_fail = 1` and returns 0/1; the interpreter pushes bool (`TS_FLAGS` has no NULLFAIL); `script_eval` returns 1; the asm twin goes to `.accept`. The C twin (`taproot_sighash.c:1161`) and Core reject with `SCHNORR_SIG` / `TAPSCRIPT_EMPTY_PUBKEY`.

**Reach today:** none from the daemon — it and `bitcoin_tapagg.asm` call the C twin. Only `tests/test_taproot_verify_diff` and `verify_p2sh_shim` link the asm one, and that differential has no `OP_CHECKSIG` leaf, so it cannot catch this. It becomes a live consensus false accept the moment the asm twin is promoted.

**Fix shape:** read `hard_fail` after `script_eval` as the C twin does; size the frame for `sizeof(taproot_checksig_ctx)`; add an `OP_CHECKSIG` leaf with an invalid signature to `test_taproot_verify_diff` so the differential can see this class at all.

### IR-4 — O(N²) fExec under tapscript (HIGH, DoS by valid block)

fExec is recomputed before every opcode by `call vfexec_all_true` (477), a byte-at-a-time linear scan of the whole condition stack (`bitcoin_scriptcodec.asm:808-819`) with no cached first-false position. Under `SIGVERSION_TAPSCRIPT` neither `MAX_SCRIPT_SIZE` (412-415) nor the 201-op count (501-502) applies. Core's `ConditionStack` is O(1).

**Failure input (consensus-valid):** taproot script-path spend whose leaf is `OP_1 OP_IF` × ~1.33M, `OP_ENDIF` × ~1.33M, `OP_1` — ~4 MB witness, no sigops. Every opcode scans an all-true condition stack up to 1.33M deep: ~2.7×10¹² loads, roughly 15–40 minutes on one core. Core validates the block in milliseconds. One such input per block, every block. The only bound is the 5 MiB `VFEXEC_MAX` buffer, which is never reached.

**Fix shape:** Core's `ConditionStack` — a counter plus the position of the first false; `all_true` is a compare.

### IR-5 — sighash recomputed per signature (HIGH, DoS by valid block)

The witness-v0 and taproot checksig callbacks reached from `interp_checksig` (`call qword [r12+96]`, 2921) re-parse the transaction and recompute the BIP143/BIP341 aggregate hashes on every signature check: `segwit_v0_sighash` → `swtx_parse_asm` (`bip143.asm:380`) then `hashPrevouts`/`hashSequence`/`hashOutputs` (411-511); `taproot_sighash` → `ts_agg_hashes` (`taproot_sighash.c:432-449`). No `PrecomputedTransactionData` equivalent exists in `sv_ctx` or the block verifier.

**Failure input (consensus-valid):** one ~4 MWU transaction with ~14,600 P2WPKH inputs (under the 80,000 sigop budget). Each `OP_CHECKSIG` re-parses the ~2.2 MB stripped tx and sha256d's `36·nin + 4·nin` bytes plus all outputs: ~8.5 GB of SHA-256 and ~32 GB of byte parsing per block. Core: ~3 MB. Tens of seconds per block on a non-SHA-NI or single-core node, every block. The legacy path re-serializes per signature too, but so does Core — only segwit/taproot diverge.

**Fix shape:** compute the three aggregate hashes (and the BIP341 set) once per transaction, carry them in `sv_ctx`.

### IR-6 — `OP_ROLL` moves whole records (HIGH, DoS by valid block)

`OP_ROLL` erases via `stack_erase_index` (`scriptcodec.asm:891-916`), which shifts every record above the index with one push/push/push/`call elem_move`/pop/pop/pop per record; `elem_move` copies len+4 bytes by `rep movsb` — 524 B for max-size items. Core moves a 24-byte vector header. Tapscript has no script-size or opcode limit.

**Failure input (consensus-valid):** taproot script-path input with 1,000 × 520-byte witness items (passes `TS_MAX_STACK`/`TS_MAX_ELEM`) and a ~3.4 MB tapscript of repeated `02 E6 03 75` (`<998> OP_ROLL`, ~850K rolls). Each roll moves 998 × 524 B → ~445 GB copied. The review measured ~10.9 s vs 0.47 s for the vector representation per 1M rolls at depth 998 on a fast desktop; proportionally worse on slow nodes; every block. `SWAP`/`ROT`/`2SWAP`/`TUCK` also copy whole records through `elem_tmp` (constant factor only); `NIP`/`2ROT` shift O(1) records.

**Fix shape:** a handle/index array over records so erase/insert/swap move 8-byte slots.

---

## 4. Detail — MEDIUM

**IR-7** — `sv_verify_script` zeroes 528,000 bytes per legacy input (348), copies 528,000 bytes `main_e → copy_e` for every input whenever `SV_P2SH` is set (357: all post-BIP16 inputs, not only P2SH spends), and restores 528,000 bytes for actual P2SH spends (378). No reader touches bytes beyond `[rec+4, rec+4+len)`; the witness drivers run the same interpreter on never-zeroed malloc'd arenas. Block connection (`tx_verify.c:625/1303`, `txv_dispatch.asm:289`) pays ~1.06 MB per legacy input (~30–60 µs, comparable to one ECDSA verify) and ~1.6 MB per P2SH spend; 4,000–8,000 legacy inputs is 4–13 GB of dead traffic. Drop the memset; copy `sp × ELEM_SIZE` plus `sp`, in both the C and the asm driver (`scriptverify_drv.asm:239-243/268/330`).

**IR-8** — Core rejects `OP_CODESEPARATOR` under `SCRIPT_VERIFY_CONST_SCRIPTCODE` for `SIGVERSION_BASE` *before* the fExec gate, so it fires even in unexecuted branches. Here `.op_cs` is reached only via post-fExec dispatch (712), tests neither the flag nor sigversion, and `SCRIPT_ERR_OP_CODESEPARATOR` (254) is never emitted anywhere. Mempool candidate spending legacy P2SH with redeemScript `OP_IF OP_CODESEPARATOR OP_ENDIF <pk> OP_CHECKSIG`: `tx_verify_mempool` ORs bit 16 (`tx_verify.c:948`) into flags and they reach `script_eval`; Core says `non-mandatory-script-verify-flag`, we admit and relay. Policy only — `CONST_SCRIPTCODE` is not a block flag.

**IR-9** — `taproot_verify_input` (C 1137, asm 67/462) hard-codes `st.flags = CLTV|CSV`, and `tx_verify.c:604-616` dispatches `TXV_SHAPE_P2TR` without forwarding `flags` while the WV0/LEGACY arms do. `TXV_MEMPOOL_POLICY_FLAGS` therefore never reach `script_eval` for a tapscript leaf: the `MINIMALDATA` checks (`interp.asm:561, :192`) and the `DISCOURAGE_OP_SUCCESS` arm (`:457-470`, also pre-empted by the unconditional `if (ts_has_op_success(...)) return 1;` at 1078) are dead for mempool tapscript, although `tx_verify.c:922` documents `interp.asm:457` as the enforcement site. Leaf `0x01 0x01 OP_DROP <32B pk> OP_CHECKSIG` (non-minimal push) or any `OP_SUCCESSx` leaf: admitted and relayed; Core rejects. `MINIMALIF` for tapscript is enforced unconditionally (792-803), so block validation is unaffected. **Note:** SCR-9's `TXV_MEMPOOL_POLICY_FLAGS` work (this week) documented interp.asm:457 as the enforcement site without noticing the tapscript arm never receives the flags. That is a defect in that closure.

**IR-10** — `verify_p2pkh` reads the scriptSig's two push-length bytes and jumps by them (`movzx ecx, byte [rdi]` 468; `add rdi, rcx / add rdi, 1 / movzx ecx, byte [rdi]` 472-475) with no bound against the scriptSig length or the tx end (`r14`), and assumes direct single-byte pushes. Its file-private `parse_varint` (a duplicate of `bitcoin_sighash.asm`'s) clobbers `cl` at 367 while `.walk` counts inputs in `rcx` (451/463), so any earlier input with a ≥253-byte scriptSig corrupts the walk. A structurally complete tx with an empty scriptSig on the target input (`tests/gen_txval_vectors.py` vector 5): 468 reads `sequence[0] = 0xff` as the sig length, 472-475 read ~250 bytes past an ~84-byte buffer. Linked only by test/wallet targets; no daemon caller. Latent memory-unsafety in an exported symbol.

---

## 5. Refuted by the verification pass (recorded so they are not re-found)

| Candidate | Note |
|---|---|
| Flag-table drift / `WITNESS_PUBKEYTYPE` | refuted by the verifier; reasoning is in the review transcript, not preserved in its summary |
| `-5` callback return code mis-mapped | same |
| `script_state` layout over-read in production | same |
| `bitcoin_sigops.asm` `wit_last` drift | same |
| A `MINIMALIF`-flag-gated sub-claim of IR-9 | `MINIMALIF` is enforced unconditionally for tapscript (`taproot_sighash.c:792-803`); the sub-claim was wrong, the parent finding stands |

These are listed so that a future pass does not re-raise them without new evidence. A refutation by the verifier is not proof of absence either.

---

## 6. How to act on this

**Order.** IR-1 first: it is reachable from any block, and its test is a two-line script. Then IR-2 and IR-3 (consensus, narrower reach). Then IR-4, IR-5, IR-6 as one "valid-block DoS" pass — they share the fix pattern of doing per-transaction or per-stack work once instead of per-opcode. IR-9 next, since it is a defect in a closure made this week. The rest as capacity allows.

**Discipline, per finding.** Write the failure input as a test. Watch it FAIL against `main`. Fix. Watch it pass. Revert the fix and watch it fail again before committing — this tree has shipped six tests that passed against the bug they were written for. Every new test into the gate; every consensus-touching commit through `/code-review` or `/ultrareview` on a branch before it lands on `main`, which is the flow this review demonstrated and the flow the last week's consensus commits skipped.

**Close by ID.** When a finding closes, its commit message names it (`IR-1`), so `comm` against this file's ID list re-derives what is open. Narrative status tracking has already dropped a finding once (STO-10).

**Don't trust this document more than the code.** Three of the 2026-09-03 audit's premises were false and four of its suggested fixes would have introduced bugs. Expect the same rate here.

---

## 7. Closure log

Every closure below was reproduced with a test that was watched to FAIL against
the unfixed object before the fix went in, then watched to pass, and the test is
in the gate. Commits name the finding ID so `comm` against this file re-derives
what is open.

| ID | Status | Commit | Proof |
|---|---|---|---|
| IR-1 | **CLOSED** | `9952a1c` | 14 of 14 growing-op vectors accepted at the cap before; `STACK_SIZE` after. **17 sites, not 14** -- the review missed `OP_2ROT`'s two pushes and `OP_PICK`'s second path; the net-zero ops got the check too, since a refused push there is silent corruption |
| IR-2 | **CLOSED** | `406a1b6` | a genuinely valid 70-byte DER with S ending in 0x01 and no hashtype byte verified on both twins, legacy and witness v0, before; rejected after; the 71-byte control still verifies. **Eleven caller sites, not three** -- `bitcoin_segwit.c` ×3, `bitcoin_checksig.asm` ×2, `bitcoin_multisig.asm`, the parity oracle and `verify_p2pkh`; callers that relied on the parser's optional-hashtype detection now read `sig[siglen-1]` themselves, as Core does |
| IR-3 | **CLOSED** | `9df5e95` | `rc 0 vs 1` on the invalid-signature leaf before; both twins reject with the same reason after; the empty-signature control still accepts. **The empty-pubkey vector the review listed is not an IR-3 vector** -- the interpreter refuses it itself (SCR-3) before `hard_fail` is ever read; kept as a control |
| IR-4 | **CLOSED** | `71b6de1` | 250,000-deep nested IF: **16,684 ms → 6.3 ms**. Core's `ConditionStack` (cached first-false position); the byte buffer stays as the SCR-2 backstop |
| IR-7 | **CLOSED** | `1138aed` | proven dead rather than asserted: the arena was filled with `0xAA` instead of zero and 16 suites through `sv_verify_script` stayed green; then the memset went and the copies narrowed to `sp × ELEM_SIZE`, in C and the asm driver identically |
| IR-8 | **CLOSED** | `fe3fb99` | unexecuted-branch and executed `OP_CODESEPARATOR` both admitted to the standard mempool before; refused after; witness v0 with the same flag still accepts (the sigversion gate); an IF/ENDIF without `0xab` accepts everywhere |
| IR-9 | **CLOSED** | `3fcdbe8` | non-minimal-push and `OP_SUCCESSx` leaves admitted to the standard mempool before; refused after, consensus and `-acceptnonstdtxn` unchanged. New `taproot_verify_input_flags`; the 12-argument symbol stays as a zero-flags wrapper so the asm callers' stack frames remain valid. Only `MINIMALDATA` and `DISCOURAGE_OP_SUCCESS` pass through |
| IR-10 | **CLOSED** | `a7c16c7` | empty-scriptSig tx flush against a `PROT_NONE` page: killed by signal 11 before, returns 0 after; a signed 3-input tx with a 253-byte scriptSig on input 0 fails to reach input 2 before, verifies after. `parse_varint` saves `rcx` itself |
| IR-12 | **CLOSED** | `b7455a8` | `mov eax, edi` |
| IR-13 | **CLOSED** | `b7455a8` | `S == N` reported `HIGH_S` (27) before, `NULLFAIL` (32) after -- Core's lax parser overflows `S >= N` to a zero signature; the `N/2+1 → HIGH_S` and `N/2 → low` controls hold |
| IR-14 | **CLOSED** | `b7455a8` | oracle now Core's `CheckSignatureEncoding`; the parity test still agrees with the code under test |
| IR-17 | **CLOSED** | `b7455a8` | header corrected after confirming `script_sigops_accurate` is the one that sets `accurate = true` |
| IR-11 | tracked elsewhere | -- | all three functions already sit in `docs/ABI_STACK_ALIGNMENT.md`'s NEEDS-ENTRY-0 table (rows 156, 157, 170); not re-fixed here |
| IR-15 | **accepted** | -- | the FindAndDelete in `sv_checksig` is required for plain `OP_CHECKSIG` (Core does it in the opcode handler) and is a no-op over an already-stripped slice inside `CHECKMULTISIG` (`bitcoin_interp.asm:3324-3336` strips every signature once, BASE only, as Core does). Removing the redundancy needs a "called from multisig" flag through the checksig callback ABI, for at most 20×20 scans per multisig. Correct; not worth the surface |
| IR-16 | deferred | -- | a jump table is a dispatch-loop rewrite; the 73-compare chain costs on the order of 100 ns per opcode worst case and no valid-block shape makes it dominant. Its own change |
| IR-5 | **OPEN** | -- | design scoped: the aggregate hashes are per-transaction but `sv_ctx` is built per input, so the cache must be a per-thread memo scoped by an explicit per-tx session that the block-connect and mempool entry points open -- an implicit (pointer, length) key could hit a stale entry from a different transaction at the same address, which is a false reject of a valid block. Touches `bitcoin_bip143.asm`'s aggregate section and `ts_agg_hashes` |
| IR-6 | **OPEN** | -- | design scoped: a handle/index array over records so erase/insert/swap move 8-byte slots is a change to the stack representation every opcode touches; it wants the differential harnesses extended first |

**12 of 17 closed; 2 accepted or tracked; 1 deferred; 2 open (both scoped).**

## 8. Found while closing

- **A fresh clone cannot pass `make test`.** The `link-check` prerequisite resolves "who defines symbol X" with `nm` over `*.o` files that exist; in a fresh checkout the asm objects do not exist yet and it does not assemble them itself, so every rule with an asm `.o` prerequisite looks unsatisfied and the gate aborts before running a test (observed twice, in two scratch worktrees, one with the daemon pre-built). The gate is only green on a warm tree. `scripts/makefile_link_audit.py`; its own lane.
- **The gate log had no `MAKE_EXIT` line** because `make -j8 test` was launched bare; `scripts/gate_log_audit.py` rightly refuses to call that a finished run. Launch with `; echo MAKE_EXIT=$?` appended. The "crash report" it also flagged is `test_rpc_signer`'s deliberate *device wedged* child, present in every gate log.
- **Two vectors in this closure were green for the wrong reason before they were caught**: the first IR-3 empty-pubkey control was rejected for control-block parity (a hard-coded `0xc0` where the tweak had odd parity), and IR-10's existing vector-5 case passed only because the bytes past the buffer happened to be mapped. `expect()` in `test_taproot_verify_diff` now fails a rejection for the wrong reason, and every taproot fixture derives its parity bit from the tweak.
- **`pkill -f` / `pgrep -f` matches the shell issuing it.** Cost one killed session mid-cleanup. Match by pid and `/proc/<pid>/cwd`.
- **An unquoted heredoc executed this document's code spans as shell** on the first attempt to write this section (every backtick span became a command substitution). Harmless in effect, caught by the noise it made, and the reason the section was rewritten through a quoted heredoc. Text that contains backticks is never passed through an unquoted heredoc.
