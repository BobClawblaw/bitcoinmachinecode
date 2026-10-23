# formal/parsers/proofs.sh -- the proof table run.sh sources. One line per
# proof and per mutant; the README's property table is keyed on these names.

# ---------------------------------------------------------------- P2P: inv / getdata
proof  P-INV        inv_bounds.c "$D/serve_invbounds.c" "--unwind 10"
mutant M-INV-canon  inv_bounds.c "$D/serve_invbounds.c" 's/(o == 3 \&\& c < 0xfd)/(o == 3 \&\& c < 0xfc)/' "canonical" "--unwind 10"
mutant M-INV-cap    inv_bounds.c "$D/serve_invbounds.c" 's/if (c > INV_MAX_SZ) return -1;/if (c > INV_MAX_SZ + 1) return -1;/' "MAX_INV_SZ" "--unwind 10"
mutant M-INV-fit    inv_bounds.c "$D/serve_invbounds.c" 's|if ((unsigned long long)(plen - o) / INV_ENTRY < c) return 0;|if ((unsigned long long)(plen - o + INV_ENTRY) / INV_ENTRY < c) return 0;|' "vector fits" "--unwind 10"

# ---------------------------------------------------------------- P2P: getheaders / getblocks locator
proof  P-LOC        locator.c "$D/serve_invbounds.c" "--unwind 104"
mutant M-LOC-max    locator.c "$D/serve_invbounds.c" 's/if (n > 101) return 0;/if (n > 102) return 0;/' "MAX_LOCATOR_SZ" "--unwind 104"
mutant M-LOC-fit    locator.c "$D/serve_invbounds.c" 's/if (plen < p + n \* 32u + 32u) return 0;/if (plen < p + n * 32u) return 0;/' "inside the payload" "--unwind 104"
diverge X-LOC-canon  locator.c "$D/serve_invbounds.c" "CORE: accepted locator count is canonical" "--unwind 104"

# ---------------------------------------------------------------- P2P: BIP324 v2 transport
proof  P-V2         v2xport.c "$A/crypto_bip324_transport.c" "-DFP_FEEDS=3 -DFP_CHUNK=40 -DFP_EXPORT=1200 --unwind 130 --unwindset advance.3:12"

# ---------------------------------------------------------------- block / tx witness (peer blocks, compact reconstructions)
proof  P-BWTX       bw.c "$D/block_witness.c" "-DFP_N=24 --unwind 26"
proof  P-BWBLK      bw.c "$D/block_witness.c" "-DFP_BLOCK -DFP_N=48 -DFP_NTX=3 --unwind 50"
mutant M-BW-canon   bw.c "$D/block_witness.c" 's/if (\*v < 0xfdULL) return 0;  /if (*v < 0x10ULL) return 0;  /' "exactly what Core" "-DFP_N=24 --unwind 26"
mutant M-BW-superfl bw.c "$D/block_witness.c" 's/if (!\*has_witness) return 0;/(void)0;/' "exactly what Core" "-DFP_N=24 --unwind 26"
mutant M-BW-commit  bw.c "$D/block_witness.c" 's/if (v >= 38 \&\& p\[0\]==0x6a/if (v >= 6 \&\& p[0]==0x6a/' "commitment inside" "-DFP_N=24 --unwind 26"
mutant M-BW-scratch bw.c "$D/block_witness.c" 's/if (scratch_cap < ntx \* 32)/if (scratch_cap < ntx * 16)/' "" "-DFP_BLOCK -DFP_N=48 -DFP_NTX=3 --unwind 50"

# ---------------------------------------------------------------- P2P: addr / addrv2
# @noconv: bmc_addr_group's 64->32-bit fold and the (unsigned) time() cast are
# intentional narrowings; the clock is bounded to 2001..2100 by the stub
proof  P-ADDR1      addr.c "$D/addr_ingest.c" "@noconv -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
proof  P-ADDRV2     addr.c "$D/addr_ingest.c" "@noconv -DFP_V2 -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
mutant M-ADDR1-max  addr.c "$D/addr_ingest.c" 's/if(cnt > 1000){ AI_VIOL(q); return 0; }               \/\* Core: MAX_ADDR_TO_SEND/if(cnt > 1001){ AI_VIOL(q); return 0; }               \/* Core: MAX_ADDR_TO_SEND/' "count over 1000" "@noconv -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
mutant M-ADDR1-fit  addr.c "$D/addr_ingest.c" 's/if(base+k\*30+30>plen) break;/if(base+k*30+29>plen) break;/' "" "@noconv -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
mutanth M-ADDRV2-len addr.c "$D/addr_ingest.c" "$D/netaddr.c" 's/if (o + al + 2 > len) return -1;/if (o + al > len) return -1;/' "" "@noconv -DFP_V2 -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
diverge X-ADDR1-core  addr.c "$D/addr_ingest.c" "CORE: addresses taken only from a payload Core deserializes" "@noconv -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
diverge X-ADDRV2-core addr.c "$D/addr_ingest.c" "CORE: addresses taken only from a payload Core deserializes" "@noconv -DFP_V2 -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"

# ---------------------------------------------------------------- disk: mempool.dat
proof  P-MPD        mpd.c "$D/mempool_persist.c" "@nouov -DFP_FSZ=64 --unwind 66"
mutant M-MPD-over   mpd.c "$D/mempool_persist.c" 's/if (tl == 0 || pos + tl + 16 > (u64)fsz)/if (tl == 0 || pos + tl + 8 > (u64)fsz)/' "trailing bytes inside" "@nouov -DFP_FSZ=64 --unwind 66"
mutant M-MPD-leak   mpd.c "$D/mempool_persist.c" 's/free(buf); MPD_ERR("truncated delta map"); return -1;/MPD_ERR("truncated delta map"); return -1;/' "memory-leak" "@nouov -DFP_FSZ=64 --unwind 66"
mutant M-MPD-key    mpd.c "$D/mempool_persist.c" 's/if (!kl || klen != 8 || 8 + (u64)kl + klen > (u64)fsz)/if (!kl || klen != 8 || 8 + klen > (u64)fsz)/' "pointer outside object bounds" "@nouov -DFP_FSZ=64 --unwind 66"
diverge X-MPD-delta mpd.c "$D/mempool_persist.c" "arithmetic overflow on unsigned *" "-DFP_FSZ=64 --unwind 66"

# ---------------------------------------------------------------- disk: mempool departure journal
proof  P-MPJ        mpj.c "$D/mempool_journal.c" "@nouov --unwind 6"
mutant M-MPJ-cap    mpj.c "$D/mempool_journal.c" 's|filecap > ((uint64_t)sb.st_size - MPJ_HDR_BYTES) / MPJ_REC_BYTES|filecap > ((uint64_t)sb.st_size) / MPJ_REC_BYTES|' "capacity fits" "@nouov --unwind 6"
mutant M-MPJ-wrap   mpj.c "$D/mempool_journal.c" 's/if (seq == 1) break;                   \/\* unsigned: do not wrap below 1 \*\//(void)0;/' "unwinding assertion" "@nouov --unwind 6"
diverge X-MPJ-stats mpj.c "$D/mempool_journal.c" "unwinding assertion loop 0" "@nouov -DFP_STATS --unwindset mpj_stats.0:6 --unwind 6"

# ---------------------------------------------------------------- RPC: JSON body
proof  P-JSON       json.c "$A/rpc_json.c" "-DFP_N=6 --unwind 8"
proofm P-JSONDEPTH  json.c "$A/rpc_json.c" 's/#define RJ_MAX_DEPTH 512/#define RJ_MAX_DEPTH 2/' "-DFP_N=6 -DFP_DEPTH --unwind 8"
mutant M-JSON-depth json.c "$A/rpc_json.c" 's/#define RJ_MAX_DEPTH 512/#define RJ_MAX_DEPTH 2/;s/++c->depth > RJ_MAX_DEPTH/++c->depth > RJ_MAX_DEPTH + 1/' "nesting within" "-DFP_N=6 -DFP_DEPTH --unwind 8"
mutant M-JSON-leak  json.c "$A/rpc_json.c" 's/if (c->err) { xfree(key); rj_free(o); return NULL; }/if (c->err) { xfree(key); return NULL; }/' "memory-leak" "-DFP_N=6 --unwind 8"
mutant M-JSON-ctl   json.c "$A/rpc_json.c" 's/if (c->end - c->p < 5) { c->err = 1; break; }/if (c->end - c->p < 4) { c->err = 1; break; }/' "dereference failure" "-DFP_N=6 --unwind 8"

# ---------------------------------------------------------------- disk: undo runs (rev*.dat + undo.idx)
proof  P-UNDO       undo.c "$D/undo_log.c" "--unwind 8"
mutanth M-UNDO-whole undo.c "$D/undo_log.c" "$D/undo_store.h" 's/if (len - off < (size_t)UNDO_REC_HDR + slen){ more = 1; break; }/(void)0;/' "" "--unwind 8"
mutanth M-UNDO-slen  undo.c "$D/undo_log.c" "$D/undo_store.h" 's/if (slen > UNDO_REC_MAXSCRIPT){ bad = 1; break; }/(void)0;/' "slen" "--unwind 8"

# ---------------------------------------------------------------- disk: UTXO LSM manifest
proof  P-LSMMAN     lsm.c "$D/lsm_manifest.c" "@nouov -DFP_FSZ=68 --unwind 6"
mutant M-LSM-cap    lsm.c "$D/lsm_manifest.c" 's/if (n > lst->manifest_cap){ free(ents); return -1; }/(void)0;/' "" "@nouov -DFP_FSZ=68 --unwind 6"
mutant M-LSM-max    lsm.c "$D/lsm_manifest.c" 's/if (\*n > (1u << 20)){ fclose(f); return -1; }/(void)0;/' "fread" "@nouov -DFP_FSZ=68 --unwind 6"
diverge X-LSM-gen   lsm.c "$D/lsm_manifest.c" "CORE: next_gen/next_run_no exceed every entry" "@nouov -DFP_FSZ=68 --unwind 6"

# ---------------------------------------------------------------- disk: txindex / txospender run files
proof  P-IRS        irs.c "$D/index_runs.c" "@nouov --unwind 10"
mutant M-IRS-hdr    irs.c "$D/index_runs.c" 's/sb.st_size < IRS_HDR/sb.st_size < 8/' "dereference failure" "@nouov --unwind 10"
diverge X-IRS-wrap  irs.c "$D/index_runs.c" "CORE: sparse table inside the mapping" "@nouov --unwind 10"

# ---------------------------------------------------------------- disk + P2P: fork tree
proof  P-HDRTREE    hdrtree.c "$D/hdr_tree.c" "-DFP_FSZ=200 --unwind 82"
mutant M-HDRTREE-rs hdrtree.c "$D/hdr_tree.c" 's/if (n <= g_cap) return 1;/if (n <= g_cap + 1) return 1;/' "" "-DFP_FSZ=200 --unwind 82"

# ---------------------------------------------------------------- P2P: BIP152 compact blocks
# MODEL CHANGE (stated in the README): CR_MAX_TX lowered from 20000 to 16 in a
# scratch copy, so the per-block arrays and the loops over ntx are within
# the unwinding bound; every check in the code is written against the macro.
CMPCT_M='s/#define CR_MAX_TX 20000/#define CR_MAX_TX 16/'
proofm P-CMPCT      cmpct.c "$D/cmpct_recv.c" "$CMPCT_M" "-DFP_N=104 --unwind 24"
proofm P-BTXN       cmpct.c "$D/cmpct_recv.c" "$CMPCT_M" "-DFP_BLOCKTXN -DFP_N=104 --unwind 24"
