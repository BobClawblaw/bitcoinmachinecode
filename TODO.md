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

## Open (next sessions, evidence in the worklog)
- [ ] verify_p2pkh/der_parse_sig/be_to_limbs port into bitcoin_script.S
      (~133 instrs; blocks test_p2pkh, test_send, test_txval,
      test_wrpc_{send,sign}, test_e2e_sighash).
- [ ] Interpreter/store segfaults: test_dersig_encoding (stack_push copy loop,
      len=0xffffffff via the toalt path), test_interp_legacy_spend (done+44),
      test_archive_truncate_nonmonotonic (main+528: some asm callee clobbers
      main's x22; store_get_at audited clean), test_taproot_parity,
      test_utxo_lsm, test_utxo_setinfo, test_multisig_opcount. Systematic tool
      needed: AArch64 port of scripts/abi_callee_saved_audit.py (the x86 one is
      NASM-specific; my objdump heuristic is not sound enough to gate fixes).
- [ ] Serve getaddr replies nothing (test_addrv2_serve); keepup does not serve
      a pushed block (test_keepup). Likely one shared root post-serve-fixes.
- [ ] signet chain flags: test_chainparams (4 fails), test_script_flags
      (signet h=1 flags=0x20801 missing bits).
- [ ] daemon-lifecycle tests (test_rpc_server/test_rpc_transport) with the
      scratch ./daemon symlink now provided; test_node_config "0 of 0
      documented keys" — input resolution from the scratch cwd.
- [ ] 6. IBD smoke (ibd_lsm/ibd_par) against the 2026-08-31 leveled compaction
      + defer_publish/unlink; record heights/compaction numbers.
- [ ] env-only (documented, no action): bench_checkblock/bench_hashidx/
      bench_idxscan/bench_taproot_block need production data files;
      test_net_timeouts needs >600s.
