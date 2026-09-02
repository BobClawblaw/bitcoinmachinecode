# TODO — arm-port state after the 2026-09-01 session

Started at `0919aee` with GLV in flight and a broken parity harness. Everything
below is landed on `arm-port` and pushed; details in `worklog/2026-09-01.md`.

## Done this session
- [x] 1. `point_scalar_mul_glv` fixed (disjoint frame map; the draft's TAB[8]
      overlapped AUXX/ZR/AI/DGE/S_*). 4b1903f
- [x] 2. GLV landed + wired (MODULES, DAEMONOBJS, test rules). 5ff7c60 aee718a
- [x] 3. ecdsa_verify GLV dispatch like x86 + frozen pre-4.2 verifier ported
      (ecdsa_verify_ref.S). 5a80781
- [x] 4. script_op_len exported. b24ba0f
- [x] 5. parity_sweep.sh replaced parity_all.sh; two native rounds over all 358
      asm/tests sources (round 2: 256 pass / 12 bench-ok / 21 fail / 6
      build-fail / 11 skip); SEVEN port bugs found and fixed: byte-swapped
      undo/serve ASCII immediates (x6 sites), idx wire-order lag (f80d09e),
      node_serve_block fd-in-x1-across-svc, missing violation reporting +
      p2p_read -3, daemon HARDENFLAGS. c23dd35 2d09a54 9ed5ceb 77072df
      369bc2a 17561e6 2561264 272c999 27e280c

## Open (next sessions)
- [x] The CHECKSIG cluster: der_parse_sig's 8-byte hashtype store + interp_checksig's
      zero-extended w0 -1 return (BIP66 bypass) -- fixed; every script/segwit/sighash
      test passes (see worklog 2026-09-01).
- [x] test_keepup: the serve loop's block dispatch constant was byte-rotated
      ("oloc" vs "bloc") -- fixed; ALL PASS.
- [x] Post-merge functional fails (archive_trim, mempool_persist_wiring,
      node_config, rpc_whitelist, txospender_index): the sweep harness now runs
      from asm/ (the x86 layout) so tt_src() resolves; the special builds derive
      from build_daemon.sh's lists every sweep -- ALL PASS.
- [ ] test_utxo_wal_buffer: the ONLY genuine fail -- re-port the x86's buffered
      WAL (mac_wr_log 1 MB wal_buf; fd in a CALLEE-SAVED register, and give the
      fork/compact paths a story for the shared buffer). It checks crash-suffix
      semantics only buffering provides.
- [ ] env-only (documented, no action): bench_checkblock/bench_hashidx/
      bench_idxscan/bench_taproot_block need production data files;
      test_net_timeouts needs >600s.
- [ ] Optional hardening: port the x86 auditor's SAVE-AREA-ALIAS check; the two
      untouched perf ports (buffered WAL above + mac_flush's 1 MB record writer).
