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
- [x] verify_p2pkh/der_parse_sig/be_to_limbs port into bitcoin_script.S --
      test_p2pkh/txval/send/wrpc_send/wrpc_sign/e2e_sighash all PASS
      (daeb44a; bring-up caught the s-marker strip-invariant and the varint
      cursor-in-x1 return contract).
- [x] serve getaddr: now calls serve_getaddr over the v2 book (7b22e29);
      test_addrv2_serve PASSES. Sweep harness: wallet_cli/bitcoin_rpcd/
      bitcoin_cli special builds + scratch daemon/ real dir + the
      relative-symlink fix (all overlay targets absolute now).
- [ ] Interpreter/store segfaults: test_dersig_encoding (stack_push copy loop,
      len=0xffffffff via the toalt path), test_interp_legacy_spend (done+44),
      test_archive_truncate_nonmonotonic (main+528: some asm callee clobbers
      main's x22; store_get_at audited clean), test_taproot_parity,
      test_utxo_lsm, test_utxo_setinfo, test_multisig_opcount. Systematic tool
      needed: AArch64 port of scripts/abi_callee_saved_audit.py (the x86 one is
      NASM-specific; my objdump heuristic is not sound enough to gate fixes).
      NOTE: test_utxo_lsm/utxo_setinfo now also have a REAL state to check
      against (post-backfill production LSM, live=241230455).
- [ ] test_keepup: pushed block not served byte-exact (the .do_block chain
      gate or the serve-side store read; gdb multi-inferior capture pending).
- [x] signet chain flags: 4-way sfc_chain dispatch restored (f2877e2);
      test_chainparams + test_script_flags PASS.
- [x] daemon-lifecycle tests: bitcoin_rpcd + bitcoin_cli now special-built;
      test_rpc_server + test_rpc_transport PASS.
- [x] 6. IBD smoke done (fa4f769 8238256): resume-at-tip vs the LAN oracle,
      3 real blocks applied, persistence MATCH; tx_walk segwit fix.
- [x] 7. LSM backfill DONE (late 2026-09-01): ibd_backfill tool shipped
      (offline re-apply of archived windows; Makefile rule ibd_backfill).
      Production run over 965009..965017: added=94801 spent=67995 bad=0,
      flush runs 8->17, PERSISTENCE MATCH; h965009 coinbase spot-check exact
      (val=546 h=965009 cb=1 slen=23). Along the way fixed TWO ibd_lsm
      defects: outputs were keyed by WTXID (now witness-stripped txid_of,
      merkle-validated) and tx_out/tx_in missed the BIP144 marker/flag (all
      segwit vouts read as garbage "vout 0", all segwit spends skipped).
      Window extended past the hole to 965017 because the wtxid-keyed run
      also missed its own intra-window spends. Residue documented in the
      worklog: 13992 wtxid junk entries (unspendable, cleanup out of scope),
      missing=2667 pre-existing pre-tip LSM holes, +42 recount artifact.
- [ ] env-only (documented, no action): bench_checkblock/bench_hashidx/
      bench_idxscan/bench_taproot_block need production data files;
      test_net_timeouts needs >600s.
