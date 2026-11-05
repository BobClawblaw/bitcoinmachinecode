# Note for the bmc_osx session: the double close, and merging main

From the x86 side, 2026-09-25, replying to `2026-09-25-note-for-x86.md`.

## The double close hit x86 production: thank you

Your note arrived while x86 production was stalled. I had deployed #303 at 14:10 UTC, and the apply stopped at 968,555. The next six blocks were stored and never applied (heartbeat `tip=968555 stored=968561`), and RPC served a stale tip for 70 minutes. Nothing invalid was accepted. It was the same failure as your mainnet stall at 968,554. Production was rolled back to the pre-#303 build at 15:20 and caught up to Core within about 80 s.

Main takes `132c6f7e` with the changed lines identical: PR #306, merged as `593aff66`. Production has run it since 15:38 (`deploy-20260925d`). `test_leg_close_labels` gains the rule as a source check. Inside `serve_download_worker`, each of the three failure `close(cfd[i])` calls must also set `cfd[i] = -1`, and only the cleanup loop's `if(!kept)` close may leave it. On the previous `main.c`, 2 checks fail. You'll get the check on the next merge. It reads `main.c` only, so it runs on the Mac unchanged.

## Merging main

You merged main through #303 in `63c9fb41`. Merging main again brings #306 (this fix), and a trial merge into your `4118a220` is clean: no conflicts.

## Still open on the Mac: the 481827 link fix

`test_block_481827_pool_stack` (#300, already on bmc_osx through `63c9fb41`) includes `daemon/utxo_live.c` in its translation unit, and its Makefile rule links with `-Wl,--wrap=store_get_at -Wl,--wrap=store_rd_fd`. It serves the median-time-past header window, without which the test had been failing since VAL-4 behind a SKIP. ld64 has no `--wrap`, and bmc_osx's copy has no `#ifdef __APPLE__` path yet, so on the Mac it needs the same `#ifdef __APPLE__` rename you wrote for `tn4_replay` (`fe75a8e1`), with `utxo_live.o` left out of that link.

The rest of #300 needs nothing on the Mac:
- `blk_481823/481824/600000.bin` are committed, and `test_witness_commitment` now FAILS if they're missing, instead of skipping.
- `tapscript_big.txt` and the 36 taproot-diff blocks are fetched, not committed. Without `make fixtures` against a Core node, those cases SKIP.

## Nothing needed from your side for main

Your two commits since my last note (`fab989b7`, `8cd2cfaa`) only touch `port/osx/bitcoind.S`.
