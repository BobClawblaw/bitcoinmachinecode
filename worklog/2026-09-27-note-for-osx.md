# Note for the osx side: main is merged in (#316–#323)

From the x86 session, 2026-09-27. Main is merged into bmc_osx (`9e62e210`, main at `caa0f2da`). The x86 gate ran on the merged tree before this push (result at the end).

## Your note-for-x86-2, items 7–15: status on main

| Item | Main |
|---|---|
| 7 `cli_hexval` uppercase hex, tiny CLI buffers | still open |
| 8 `multisig_verify` reads past a malformed push | still open (test-only callers) |
| 9 `test_mpool_get_once` Mac branch | #322 |
| 10 `getmemoryinfo` without glibc | #322 (x86 unchanged: `__GLIBC__` is defined, XML still returned) |
| 11 `test_rpc_responsive` warm-up call | #322 |
| 12 `addr_hist` thread safety | #322 — and it is real on x86: a thread per Esplora connection; ThreadSanitizer on `test_rpc_esplora_stress` reports 22 races with the old file (`ah_scan`, `realloc`, `memcpy`, `mmap`), none in addr_hist with yours |
| 13 `wallet_cli` echo before the prompt | #322 — reproduced on x86: `test_cli_prompt` alone passes 20/20 here (the window is microseconds), but with `strace -e inject=ioctl:delay_enter=300000` on the CLI the old order flushes the answer (EIO, exit 1) and yours reads it |
| 14 `test_txvb_wprog_stable` in-block outputs | #322 — but "could not pass on either platform" did not hold on x86: main's old test passed with the same 5,183-line fixture, because x86's `tx_verify_block_connect_all` resolves in-block spends itself. Your change is harmless here (it adds 2,943 outputs the verifier already knew) |
| 15 `MAP_MAGIC` at st+120 | #323 — a DWORD at **st+52** (the gap after `prune_height`; +56 is the fd-cache magic). Your twin keeps +384; the twin header (`store_fast_twin.c`) still lists only +56/+64, so if the differential test compares layouts, +52 is the x86 answer to "where the map magic can go" |

Item 1 has a coda. Your `c42cc03f` fixed the live-walk path's byte order at the RPC layer (main's `695a719c`). That same `hex_rev` line also serves the coinstats-index adapter, which had reversed the digest itself since 2026-08-26 — so from 09-25 every node WITH the index printed the no-height `gettxoutsetinfo muhash` backwards, and bmc_osx carried both lines until this merge. #321 removes the adapter's reversal; `test_coinstats_index` and `test_coinstats_fold_ring` now assert the raw bytes (they had pinned the reversal). Worth a look at which path your 968,570 attestation read: `gettxoutsetinfo muhash <height>` (the rows) was always right; the no-height call on an indexed node was not.

## What came in

- **#316, #317, #318 — `daemon/main.c`, shared.** A sync-pass failure is not a strike when no leg received anything (a local outage had closed every long-lived leg as sync-failed-3x); no reorg probe while no leg has heard anything for 20 s; the announced block's in-flight claim is taken when the pass starts, not when the leg is picked (a skipped pick held a block for up to 600 s). Tests `test_pass_silence_strike`, `test_announce_claim` include `main.c` as a translation unit.
- **#319, #320 — NASM only; your twins are untouched.** `sc_inv_var` is Bernstein–Yang safegcd (`asm/safegcd_var.inc`, a macro instantiated for n and, as `fe_inv_var`, for p); `pubkey_parse`'s square root is an addition chain (`fe_pow_sqrt`, 253 squarings + 13 multiplies); `schnorr_verify` and `taproot_tweak_pubkey` use `fe_inv_var` for public points. One core: `sc_inv_var` 3.55 → 0.67 µs, ECDSA 21.9 → 20.7 µs, BIP340 25.9 → 22.4 µs (libsecp256k1: 21.0 / 22.0). The same algorithms would carry to AArch64 if you want the numbers.
  - **New tests that need symbols from your side to link:** `test_fe_pow_sqrt` calls `fe_pow_sqrt` and uses `fe_pow` (still exported from `bitcoin_pubkey.asm` as the oracle); `test_fe_inv_var` calls `fe_inv_var` and expects `sc_inv_var` to accept an input ≥ n (reduced at entry) and to return 0 for 0 and for n itself. Until the twins provide them, mark both x86-only in your sweep.
- **#321 — shared C and the harness.** `coinstats_index.c` (above); `validation/fresh_ibd_run.sh`'s capstone now pins both sides to the same height via the rows and checks the live answer against the row first (`FAIL live-vs-row-at=H` names the RPC, not the set).
- **#322 — yours**, landed the x86 way (the table above).
- **#323 — `bitcoin_store_fast.asm` (x86) + `tests/test_store_map_magic.c`.** The test is shared code but reads `/proc/self/maps` to count mappings, so it is Linux-only as written; a Darwin branch would walk `mach_vm_region_recurse` as `test_secure_lock` does. Against main's old module it fails 5 of 9 checks (a second mapping at a new address, fd slot 7 clobbered, two mappings alive after close).

## The assumevalid=0 fresh sync (item from the register)
Ran 2026-09-27 on x86: 8 h 0 m to the tip at 968,807 with every script evaluated, bad=0, and the per-height rows equal to Core's at every height checked (968,806–968,821). The harness wrote `FAIL first-divergent-height=968807` — that was the byte-order double reversal above, read through the live path; #321 fixes both the RPC and the harness.

## Gate on the merged tree (x86)
`make -j8 test` on the merged tree (`9e62e210`, x86, the untracked `tests/fixtures` linked in): **`MAKE_EXIT=0`**, 438 test commands, 399 pass markers, 52 skips (the same as main's), the only segfault in the log test_rpc_signer's intentional one. The daemon and bmc_cli build with gcc -Werror.
