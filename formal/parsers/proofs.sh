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
# OPEN: every phase of this harness exceeded the 8 GB cap, down to one 24-byte
# feed in the application state with the cipher stubbed and secure_zero's
# asm barrier removed; kept, not run. X-V2-type is confirmed concretely
# (confirm/c_v2.c) on the real transport with the real cipher.
#OPEN proof  P-V2-SNIFF   v2xport.c "$A/crypto_bip324_transport.c" "-DFP_START=0 -DFP_FEEDS=1 -DFP_CHUNK=20 -DFP_EXPORT=8 --unwind 66 --unwindset advance.3:4,advance.0:2"
#OPEN proof  P-V2-GARB    v2xport.c "$A/crypto_bip324_transport.c" "-DFP_START=2 -DFP_FEEDS=1 -DFP_CHUNK=24 -DFP_EXPORT=8 --unwind 66 --unwindset advance.3:4,advance.0:10"
#OPEN proof  P-V2-APP     v2xport.c "$A/crypto_bip324_transport.c" "-DFP_START=4 -DFP_FEEDS=2 -DFP_CHUNK=24 -DFP_EXPORT=1200 --unwind 66 --unwindset advance.3:4,advance.0:2"
#OPEN mutant M-V2-garb    v2xport.c "$A/crypto_bip324_transport.c" 's/if (i > BIP324_MAX_GARBAGE_LEN) return 0;/if (i > BIP324_MAX_GARBAGE_LEN + 1) return 0;/' "garbage beyond" "-DFP_GARB -DFP_START=0 -DFP_CHUNK=4 -DFP_EXPORT=8 --unwind 66 --unwindset advance.3:6,advance.0:4120"
#OPEN proof  P-V2-GBOUND  v2xport.c "$A/crypto_bip324_transport.c" "-DFP_GARB -DFP_START=0 -DFP_CHUNK=4 -DFP_EXPORT=8 --unwind 66 --unwindset advance.3:6,advance.0:4120"
#OPEN mutant M-V2-short   v2xport.c "$A/crypto_bip324_transport.c" 's/if (t->pending_len < 13){ free(plain); return 0; }/if (t->pending_len < 2){ free(plain); return 0; }/' "" "-DFP_START=4 -DFP_FEEDS=2 -DFP_CHUNK=24 -DFP_EXPORT=1200 --unwind 66 --unwindset advance.3:4,advance.0:2"
#OPEN diverge X-V2-type   v2xport.c "$A/crypto_bip324_transport.c" "CORE:" "-DFP_START=4 -DFP_FEEDS=2 -DFP_CHUNK=24 -DFP_EXPORT=1200 --unwind 66 --unwindset advance.3:4,advance.0:2"

# ---------------------------------------------------------------- block / tx witness (peer blocks, compact reconstructions)
# P-BWTX takes ~15 min. Its mutants target one ASSERTION each, so they check
# only that property (--property) to fail fast.
proof  P-BWTX       bw.c "$D/block_witness.c" "@relwaive -DFP_N=66 --unwind 9 --unwindset bw_walk_tx.0:2,c_vin.0:2,bw_walk_tx.3:2,core_tx_ok.1:2,bw_walk_tx.1:8,c_vout.0:8,bw_walk_tx.2:70,core_tx_ok.0:70"
mutant M-BW-canon   bw.c "$D/block_witness.c" 's/if (\*v < 0xfdULL) return 0;  /if (*v < 0x02ULL) return 0;  /' "exactly what Core" "--property main.assertion.1 -DFP_N=66 --unwind 9 --unwindset bw_walk_tx.0:2,c_vin.0:2,bw_walk_tx.3:2,core_tx_ok.1:2,bw_walk_tx.1:8,c_vout.0:8,bw_walk_tx.2:70,core_tx_ok.0:70"
mutant M-BW-superfl bw.c "$D/block_witness.c" 's/if (!\*has_witness) return 0;/(void)0;/' "exactly what Core" "--property main.assertion.1 -DFP_N=66 --unwind 9 --unwindset bw_walk_tx.0:2,c_vin.0:2,bw_walk_tx.3:2,core_tx_ok.1:2,bw_walk_tx.1:8,c_vout.0:8,bw_walk_tx.2:70,core_tx_ok.0:70"
mutant M-BW-commit  bw.c "$D/block_witness.c" 's/if (v >= 38 \&\& p\[0\]==0x6a/if (v >= 6 \&\& p[0]==0x6a/' "commitment inside" "--property main.assertion.2 -DFP_N=66 --unwind 9 --unwindset bw_walk_tx.0:2,c_vin.0:2,bw_walk_tx.3:2,core_tx_ok.1:2,bw_walk_tx.1:8,c_vout.0:8,bw_walk_tx.2:70,core_tx_ok.0:70"

# ---------------------------------------------------------------- P2P: addr / addrv2
# @noconv: bmc_addr_group's 64->32-bit fold and the (unsigned) time() cast are
# intentional narrowings; the clock is bounded to 2001..2100 by the stub
proof  P-ADDR1      addr.c "$D/addr_ingest.c" "@noconv -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
proof  P-ADDRV2     addr.c "$D/addr_ingest.c" "@noconv -DFP_V2 -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
mutant M-ADDRV2-max addr.c "$D/addr_ingest.c" 's/if(cnt > 1000){ AI_VIOL(q); return 0; }               \/\* Core: MAX_ADDR_TO_SEND/if(cnt > 1001){ AI_VIOL(q); return 0; }               \/* Core: MAX_ADDR_TO_SEND/' "count over 1000" "@noconv -DFP_V2 -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
mutant M-ADDR1-fit  addr.c "$D/addr_ingest.c" 's/if(base+k\*30+30>plen) break;/(void)0;/;s/(pl\[0\]==0xfe?5:9))/(pl[0]==0xfe?5:10))/' "" "@noconv -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
mutanth M-ADDRV2-len addr.c "$D/addr_ingest.c" "$D/netaddr.c" 's/if (o + al + 2 > len) return -1;/if (o + al > len) return -1;/' "" "@noconv -DFP_V2 -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
diverge X-ADDR1-core  addr.c "$D/addr_ingest.c" "CORE: addresses taken only from a payload Core deserializes" "@noconv -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"
diverge X-ADDRV2-core addr.c "$D/addr_ingest.c" "CORE: addresses taken only from a payload Core deserializes" "@noconv -DFP_V2 -DFP_N=64 --unwind 10 --unwindset memcmp.0:17"

# ---------------------------------------------------------------- disk: mempool.dat
# @noconv: the time and fee-delta fields are int64 stored as u64 (Core's
# format); the casts back are intended. The obfuscated form is proved on files
# of <= 26 bytes (key, count, delta map): the XOR loop over a longer file
# exceeds the memory cap; v1 is proved on <= 52 bytes (two transactions).
proof  P-MPD        mpd.c "$D/mempool_persist.c" "@nouov @noconv -DFP_FSZ=52 --unwind 10 --unwindset mempool_dump_read.7:2,mempool_dump_read.14:4 --slice-formula"
proof  P-MPDV2      mpd.c "$D/mempool_persist.c" "@nouov @noconv -DFP_V2 -DFP_FSZ=26 --unwind 10 --unwindset mempool_dump_read.7:20,mempool_dump_read.14:2 --slice-formula"
mutant M-MPD-over   mpd.c "$D/mempool_persist.c" 's/if (tl == 0 || pos + tl + 16 > (u64)fsz)/if (tl == 0 || pos + tl + 8 > (u64)fsz)/' "trailing bytes inside" "@nouov @noconv -DFP_FSZ=52 --unwind 10 --unwindset mempool_dump_read.7:2,mempool_dump_read.14:4 --slice-formula"
mutant M-MPD-leak   mpd.c "$D/mempool_persist.c" 's/free(buf); MPD_ERR("truncated delta map"); return -1;/MPD_ERR("truncated delta map"); return -1;/' "memory-leak" "@nouov @noconv -DFP_FSZ=52 --unwind 10 --unwindset mempool_dump_read.7:2,mempool_dump_read.14:4 --slice-formula"
mutant M-MPD-key    mpd.c "$D/mempool_persist.c" 's/if (!kl || klen != 8 || 8 + (u64)kl + klen > (u64)fsz)/if (!kl || klen != 8 || 8 + klen > (u64)fsz)/' "memcpy source region readable" "@nouov @noconv -DFP_V2 -DFP_FSZ=26 --unwind 10 --unwindset mempool_dump_read.7:20,mempool_dump_read.14:2 --slice-formula"
diverge X-MPD-delta mpd.c "$D/mempool_persist.c" "arithmetic overflow on unsigned *" "@noconv -DFP_FSZ=44 --unwind 10 --unwindset mempool_dump_read.7:2,mempool_dump_read.14:4 --slice-formula"

# ---------------------------------------------------------------- disk: mempool departure journal
# @noconv: the time fields are int64 stored as u64 (the record format)
proof  P-MPJ        mpj.c "$D/mempool_journal.c" "@nouov @noconv --unwind 9 --unwindset pread.0:65,mpj_recent.0:4,mpj_lookup.0:4,memcmp.0:33"
mutant M-MPJ-cap    mpj.c "$D/mempool_journal.c" 's|filecap > ((uint64_t)sb.st_size - MPJ_HDR_BYTES) / MPJ_REC_BYTES|filecap > ((uint64_t)sb.st_size) / MPJ_REC_BYTES|' "mapping no longer than the file" "@nouov @noconv --unwind 9 --unwindset pread.0:65,mpj_recent.0:4,mpj_lookup.0:4,memcmp.0:33"
mutant M-MPJ-wrap   mpj.c "$D/mempool_journal.c" 's/if (seq == 1) break;                   \/\* unsigned: do not wrap below 1 \*\//(void)0;/' "unwinding assertion" "@nouov @noconv --unwind 9 --unwindset pread.0:65,mpj_recent.0:4,mpj_lookup.0:4,memcmp.0:33"
diverge X-MPJ-stats mpj.c "$D/mempool_journal.c" "unwinding assertion loop 0" "@nouov -DFP_STATS --unwindset mpj_stats.0:4,pread.0:65,mpj_recent.0:4,mpj_lookup.0:4 --unwind 9"

# ---------------------------------------------------------------- RPC: JSON body
# OPEN: symbolic execution of the recursive descent did not finish inside
# 300-900 s even at a 3-byte body, unwind 3, no arena; kept, not run.
# MODEL CHANGE: the per-request arena's first chunk (RJ_ARENA_CHUNK, 256 KiB)
# lowered to 64 bytes in a scratch copy, so chunk chaining is reached and the
# arrays stay inside the memory cap. P-JSONDEPTH also lowers RJ_MAX_DEPTH to 2.
RJ_M='s/#define RJ_ARENA_CHUNK (256u << 10)/#define RJ_ARENA_CHUNK 64u/'
#OPEN proofm P-JSON       json.c "$A/rpc_json.c" "$RJ_M" "@noconv -DFP_STUB_PRINTF -DFP_N=4 --unwind 5"
#OPEN proofm P-JSONDEPTH  json.c "$A/rpc_json.c" "$RJ_M;s/#define RJ_MAX_DEPTH 512/#define RJ_MAX_DEPTH 2/" "@noconv -DFP_STUB_PRINTF -DFP_N=4 -DFP_DEPTH --unwind 5"
#OPEN mutant M-JSON-depth json.c "$A/rpc_json.c" "$RJ_M;s/#define RJ_MAX_DEPTH 512/#define RJ_MAX_DEPTH 2/;s/++c->depth > RJ_MAX_DEPTH/++c->depth > RJ_MAX_DEPTH + 1/" "nesting within" "@noconv -DFP_STUB_PRINTF -DFP_N=4 -DFP_DEPTH --unwind 5"
#OPEN mutant M-JSON-leak  json.c "$A/rpc_json.c" "$RJ_M;s/if (c->err) { xfree(key); rj_free(o); return NULL; }/if (c->err) { xfree(key); return NULL; }/" "memory-leak" "@noconv -DFP_STUB_PRINTF -DFP_N=4 --unwind 5"
#OPEN mutant M-JSON-ctl   json.c "$A/rpc_json.c" "$RJ_M;s/if (c->end - c->p < 5) { c->err = 1; break; }/if (c->end - c->p < 4) { c->err = 1; break; }/" "dereference failure" "@noconv -DFP_STUB_PRINTF -DFP_N=6 --unwind 7"

# ---------------------------------------------------------------- disk: undo runs (rev*.dat + undo.idx)
# OPEN: none of these closed inside the 8 GB cap and 600 s, even reduced to
# one reader per run, a 110-byte rev file, unwind 4 and (as a model change)
# a 64-byte initial read buffer instead of 1 MiB. Kept for the record, not run.
#OPEN proof  P-UNDO       undo.c "$D/undo_log.c" "--arrays-uf-always -DFP_MODE=0 --unwind 8 --unwindset strcmp.0:14"
#OPEN proof  P-UNDOLOAD   undo.c "$D/undo_log.c" "--arrays-uf-always -DFP_MODE=1 --unwind 8 --unwindset strcmp.0:14"
#OPEN proof  P-UNDOREPLAY undo.c "$D/undo_log.c" "--arrays-uf-always -DFP_MODE=2 --unwind 8 --unwindset strcmp.0:14"
#OPEN mutanth M-UNDO-whole undo.c "$D/undo_log.c" "$D/undo_store.h" 's/if (len - off < (size_t)UNDO_REC_HDR + slen){ more = 1; break; }/(void)0;/' "" "--arrays-uf-always -DFP_MODE=2 --unwind 8 --unwindset strcmp.0:14"
#OPEN mutanth M-UNDO-slen  undo.c "$D/undo_log.c" "$D/undo_store.h" 's/if (slen > UNDO_REC_MAXSCRIPT){ bad = 1; break; }/(void)0;/' "slen" "--arrays-uf-always -DFP_MODE=0 --unwind 8 --unwindset strcmp.0:14"

# ---------------------------------------------------------------- disk: UTXO LSM manifest
proof  P-LSMMAN     lsm.c "$D/lsm_manifest.c" "@nouov -DFP_FSZ=68 --unwind 6"
mutant M-LSM-cap    lsm.c "$D/lsm_manifest.c" 's/if (n > lst->manifest_cap){ free(ents); return -1; }/(void)0;/' "" "@nouov -DFP_FSZ=68 --unwind 6"
mutant M-LSM-max    lsm.c "$D/lsm_manifest.c" 's/if (\*n > (1u << 20)){ fclose(f); return -1; }/(void)0;/' "fread" "@nouov -DFP_FSZ=68 --unwind 6"
diverge X-LSM-gen   lsm.c "$D/lsm_manifest.c" "CORE: next_gen/next_run_no exceed every entry" "@nouov -DFP_FSZ=68 --unwind 6"

# ---------------------------------------------------------------- disk: txindex / txospender run files
proof  P-IRS        irs.c "$D/index_runs.c" "@nouov --unwind 10 --unwindset strcpy.0:13,vsnprintf.0:40,vsnprintf.1:40"
mutant M-IRS-hdr    irs.c "$D/index_runs.c" 's/sb.st_size < IRS_HDR/sb.st_size < 8/' "dereference failure" "@nouov --unwind 10 --unwindset strcpy.0:13,vsnprintf.0:40,vsnprintf.1:40"
diverge X-IRS-wrap  irs.c "$D/index_runs.c" "CORE: sparse table inside the mapping" "@nouov --unwind 10 --unwindset strcpy.0:13,vsnprintf.0:40,vsnprintf.1:40"

# ---------------------------------------------------------------- disk + P2P: fork tree
# OPEN: over the 8 GB cap even at one record and unwind 4 (the 256-entry
# realloc'd table of 92-byte entries); kept for the record, not run.
#OPEN proof  P-HDRTREE    hdrtree.c "$D/hdr_tree.c" "-DFP_STUB_PRINTF -DFP_FSZ=100 --unwind 4 --unwindset memcmp.0:33,block_hash.0:33,main.0:81"
#OPEN mutant M-HDRTREE-rs hdrtree.c "$D/hdr_tree.c" 's/if (n <= g_cap) return 1;/if (n <= g_cap + 1) return 1;/' "" "-DFP_STUB_PRINTF -DFP_FSZ=100 --unwind 4 --unwindset memcmp.0:33,block_hash.0:33,main.0:81"

# ---------------------------------------------------------------- P2P: BIP152 compact blocks
# OPEN: over the 8 GB cap even with the model change below and a 100-byte
# payload (the minimum is 90: header + nonce); kept, not run.
# MODEL CHANGE (stated in the README): CR_MAX_TX 20000 -> 4, HT_BITS 21 -> 4,
# HT_MIN_BITS 12 -> 2 and the 4 MiB prefilled-copy buffer -> 256 bytes, in a
# scratch copy, so the per-block arrays and the loops over ntx are within
# the unwinding bound; every check in the code is written against the macro.
CMPCT_M='s/#define CR_MAX_TX 20000/#define CR_MAX_TX 4/;s/#define HT_BITS 21 /#define HT_BITS 4 /;s/#define HT_MIN_BITS 12 /#define HT_MIN_BITS 2 /;s/unsigned char pre\[4 << 20\];/unsigned char pre[256];/'
#OPEN proofm P-CMPCT      cmpct.c "$D/cmpct_recv.c" "$CMPCT_M" "-DFP_STUB_PRINTF -DFP_N=100 --unwind 10 --unwindset main.0:33,block_hash.0:33,sha256_full.0:33,tx_wtxid.0:33,ht_build.2:9"
#OPEN proofm P-BTXN       cmpct.c "$D/cmpct_recv.c" "$CMPCT_M" "-DFP_STUB_PRINTF -DFP_BLOCKTXN -DFP_N=100 --unwind 10 --unwindset main.0:33,block_hash.0:33,sha256_full.0:33,tx_wtxid.0:33,ht_build.2:9"

# ---------------------------------------------------------------- RPC: HTTP request line, pre-auth headers
# @noconv: (unsigned char) reads of char bytes are intended
proof  P-HTTP       http.c "$A/rpc_net.c" "@noconv -DFP_N=24 --unwind 26"
mutant M-HTTP-ctl   http.c "$A/rpc_net.c" 's/if ((unsigned char)\*q < 0x20 || (unsigned char)\*q == 0x7f) return 0;/(void)0;/' "no control byte" "@noconv -DFP_N=24 --unwind 26"
# OPEN (P-AUTH and its mutants): over the 8 GB cap even at a 16-byte header
# block; kept, not run.
#OPEN proof  P-AUTH       auth.c "$A/rpc_server.c" "@noconv -DFP_STUB_PRINTF -DFP_N=16 --unwind 18 --slice-formula"
#OPEN mutant M-AUTH-b64   auth.c "$A/rpc_server.c" 's|size_t out_cap = (inlen / 4) \* 3 + 3;|size_t out_cap = (inlen / 4) * 3;|' "" "@noconv -DFP_STUB_PRINTF -DFP_N=16 --unwind 18 --slice-formula"
#OPEN mutant M-AUTH-empty auth.c "$A/rpc_server.c" 's/if (!\*pass) by_pass = 0;/(void)0;/' "empty configured password" "@noconv -DFP_STUB_PRINTF -DFP_N=16 --unwind 18 --slice-formula"

# ---------------------------------------------------------------- disk (-asmap) / P2P addresses: ASMap interpreter
# OPEN: over the 8 GB cap even on a 2-byte bytecode (26 nested size classes
# per JUMP, each bit read a 64-bit divide/modulo by 8); kept, not run.
#OPEN proof  P-ASMAP      asmap.c "$D/asmap.c" "-DFP_N=2 --unwind 18 --slice-formula"
#OPEN mutant M-ASMAP-bit  asmap.c "$D/asmap.c" 's/if (\*bitpos >= nbytes \* 8) return -1;/if (*bitpos > nbytes * 8) return -1;/' "" "-DFP_N=2 --unwind 18 --slice-formula"
#OPEN mutant M-ASMAP-ip   asmap.c "$D/asmap.c" 's/if ((int)(ip_bits_end - ip_bit) < matchlen) break;/(void)0;/' "" "-DFP_N=2 --unwind 18 --slice-formula"

# ---------------------------------------------------------------- P2P: version payload (BIP330 offer), sendtxrcncl
# @noconv: the u32 protocol version is read into an int (a value >= 2^31 is
# negative and so below 70016: refused), and the salt is cut into bytes
proof  P-TXRCN      txrecon.c "$D/txrecon.c" "@noconv -DFP_N=90 --unwind 10"
mutant M-TXRCN-rly  txrecon.c "$D/txrecon.c" 's/    if (o >= len) return 1;/    if (o > len) return 1;/' "" "@noconv -DFP_N=90 --unwind 10"

# ---------------------------------------------------------------- P2P: BIP157 filter serving
# @noconv: the u64 filter offset read from disk is passed to pread as a long
# (a value >= 2^63 is negative: pread fails, the request is refused), and
# CompactSizes are cut into bytes.
# MODEL CHANGE: CF_MAX_FILTER (the 1 MiB static filter and reply buffers)
# lowered to 64 bytes in a scratch copy; every bound in the code is written
# against the macro. With the real size CBMC exceeds the 8 GB cap.
CF_M='s/#define CF_MAX_FILTER   (1u << 20)/#define CF_MAX_FILTER   64u/'
proofm P-CF0        cfilters.c "$D/serve_cfilters.c" "$CF_M" "-DFP_KIND=0 @noconv -DFP_STUB_PRINTF --unwind 9 --unwindset memcmp.0:9,strcmp.0:14,cf_hash_fd.0:33"
proofm P-CF1        cfilters.c "$D/serve_cfilters.c" "$CF_M" "-DFP_KIND=1 @noconv -DFP_STUB_PRINTF --unwind 9 --unwindset memcmp.0:9,strcmp.0:14,cf_hash_fd.0:33"
proofm P-CF2        cfilters.c "$D/serve_cfilters.c" "$CF_M" "-DFP_KIND=2 @noconv -DFP_STUB_PRINTF --unwind 9 --unwindset memcmp.0:9,strcmp.0:14,cf_hash_fd.0:33"
mutant M-CF-range   cfilters.c "$D/serve_cfilters.c" "$CF_M;s/if (stop - start + 1 > lim){/if (stop - start + 1 > lim + 5000){/" "MAX_GETCFILTERS_SIZE applied" "-DFP_KIND=0 @noconv -DFP_STUB_PRINTF --unwind 9 --unwindset memcmp.0:9,strcmp.0:14,cf_hash_fd.0:33"
mutant M-CF-cap     cfilters.c "$D/serve_cfilters.c" "$CF_M;s/if (len > cap) return 0;/(void)0;/" "" "-DFP_KIND=0 @noconv -DFP_STUB_PRINTF --unwind 9 --unwindset memcmp.0:9,strcmp.0:14,cf_hash_fd.0:33"

# ---------------------------------------------------------------- REST (unauthenticated with rest=1): getutxos body
# OPEN: symbolic execution did not finish in 15 min (the reply is built with
# rpc_json.c, whose own harness is OPEN for the same reason); kept, not run.
#OPEN proof  P-REST       rest.c "$A/rest.c" "-DFP_STUB_PRINTF @noconv -DFP_P=4 -DFP_B=38 --unwind 40"
#OPEN mutant M-REST-fit   rest.c "$A/rest.c" 's/if (rawlen < p + (long)cnt \* 36){/if (rawlen < p + (long)cnt * 35){/' "" "-DFP_STUB_PRINTF @noconv -DFP_P=4 -DFP_B=38 --unwind 40"
#OPEN mutant M-REST-cs    rest.c "$A/rest.c" 's/if (cnt == 253){ if (rawlen < p + 2)/if (cnt == 253){ if (rawlen < p + 1)/' "" "-DFP_STUB_PRINTF @noconv -DFP_P=4 -DFP_B=38 --unwind 40"

# ---------------------------------------------------------------- config file lines
# OPEN (P-CFG, M-CFG-hcap: classify / host:port / addlist): over the 8 GB cap
# at 8-byte lines; only the hex reader (P-CFGHEX) is run.
#OPEN proof  P-CFG        cfg.c "$D/node_config.c" "-DFP_STUB_PRINTF -DFP_N=8 --unwind 10 --unwindset cfg_addlist.0:34"
proof  P-CFGHEX     cfg.c "$D/node_config.c" "-DFP_STUB_PRINTF -DFP_HEX --unwind 72"
#OPEN mutant M-CFG-hcap   cfg.c "$D/node_config.c" 's/if(!hl || hl >= hcap) return 0;/if(!hl || hl > hcap) return 0;/' "" "-DFP_STUB_PRINTF -DFP_N=8 --unwind 10 --unwindset cfg_addlist.0:34"
mutant M-CFG-hex    cfg.c "$D/node_config.c" 's/if(n==0 || n>64) return 0;/if(n==0 || n>66) return 0;/' "1..64 hex digits" "-DFP_STUB_PRINTF -DFP_HEX --unwind 72"
