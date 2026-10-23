# formal/parsers: bounded model checking of the untrusted-input parsers

CBMC proofs of memory safety and absence of undefined behaviour, plus
documented postconditions and Core-equivalence checks, for the C code in
`asm/` that parses bytes from the network or from disk. Code under
verification: the security integration branch `integ/2026-10-23-sec-all`
(b841251b). Core reference: Bitcoin Core v31.1.

Tools: CBMC 6.11.0 (`$FORMAL_TOOLS/cbmc/usr/bin/cbmc`, `FORMAL_TOOLS`
defaults to `$HOME/.local/opt/formal`), gcc for the concrete confirmations.

## Reproduce

    formal/parsers/run.sh            # every proof, cover run, mutant and divergence
    formal/parsers/run.sh 'P-INV|LOC'  # a subset (bash regex on the entry names)
    formal/parsers/confirm/run.sh    # the concrete reproductions of the findings

`run.sh` exits 0 only if every proof verifies, every cover goal is reached,
every mutant is caught and every divergence still reproduces. Each CBMC
process runs under `flock` (one at a time) inside
`systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0`, niced, with a
timeout, and only while `free -g` reports at least 25 GB available.

Every check flag is on for every entry (`--bounds-check --pointer-check
--signed-overflow-check --unsigned-overflow-check --pointer-overflow-check
--conversion-check --div-by-zero-check --memory-leak-check
--float-overflow-check --nan-check --unwinding-assertions`), except where an
entry's tokens say otherwise:

* `@nouov` drops `--unsigned-overflow-check` (wrap-around is defined C; the
  harness then asserts the consequence that matters explicitly).
* `@noconv` drops `--conversion-check` where the code narrows on purpose
  (byte extraction, a u64 field read back as int64); proofs.sh says why.
* `@relwaive` (P-BWTX only): `bw_walk_tx` bounds-checks by forming a pointer
  past its object (`p + 36 > end`), undefined by the letter of C11 6.5.6p8 but
  never dereferenced; the entry passes when the only failed properties are
  those eight "pointer arithmetic/relation: pointer outside object bounds in
  p + k" relations (block_witness.c lines 33, 36, 39, 63, 69, 75, 114).

Entry kinds (see `proofs.sh`): `proof` (must verify; its cover run must reach
every goal: the vacuity check), `proofm` (a proof over a scratch copy with a
stated model change), `mutant`/`mutanth` (a scratch copy of the source or a
header with one injected defect: CBMC must fail, on the named property),
`diverge` (Core's rule asserted under `-DFP_CORE_STRICT` on the unmodified
code: CBMC must report it violated; each is a finding, confirmed concretely
in `confirm/`).

## Method

Each harness (`harness/*.c`) `#include`s the product source, so its static
functions are visible, and calls the parser on a buffer of nondeterministic
content and nondeterministic length up to a bound N. Input buffers are
tail-aligned in a constant-size object (`nd_tail`): any read past the input's
end leaves the object and is caught, while the object's size stays concrete
for the solver. Only environmental functions are stubbed (I/O, the clock,
crypto primitives and NASM routines with a stated contract); each stub checks
the spans it is handed. Unwinding assertions are on everywhere, so an
insufficient bound is reported, never hidden.

## Results

Times are from the full `run.sh` of 2026-10-23 (proof + cover seconds;
total 3370 s, 56 min wall, on the shared box under the 8 GB cap; M-MPJ-wrap
was then revised, the earlier one being an equivalent mutant, and caught in
188 s). `confirm/run.sh` takes about 40 s.
"BOUNDED-OK" = verified for every input up to the bound, with unwinding
assertions; "PROVED" = no bound on the input length.

| ID | Function (file) | Claim | Bound | Result | Time | Mutation that made it fail |
|---|---|---|---|---|---|---|
| P-INV | serve_inv_bounds (daemon/serve_invbounds.c) | memory safe; accepted count canonical, <= MAX_INV_SZ 50000, off + 36*count <= plen | any length | PROVED | 0+0 s | canonical bound 0xfd->0xfc; cap +1; fit check off by one entry (M-INV-*) |
| P-LOC | serve_locator_from (same) | memory safe; n <= 101, locator + stop hash inside the payload, <= 102 index lookups | any length | PROVED | 2+1 s | 101->102; stop hash dropped from the length check (M-LOC-*) |
| X-LOC-canon | same | Core: count canonical | any length | VIOLATED (F1) | 2 s | - |
| P-BWTX | bw_walk_tx (daemon/block_witness.c) | memory safe; accepts exactly what Core's UnserializeTransaction accepts (both directions, outside the zero-input domain); commitment and witness item inside the tx | tx <= 66 bytes | BOUNDED-OK (8 waived past-the-end relations) | 713+80 s | canonical 0xfd->0x02; superfluous-witness check removed; commitment size 38->6 (M-BW-*) |
| P-ADDR1 | addr_ingest_msg_vg + bmc_addr_decode_v1 (daemon/addr_ingest.c, netaddr.c) | memory safe; added <= 1000 and <= limit; book gets well-formed addresses; count > 1000 is a violation | payload <= 64 | BOUNDED-OK | 13+11 s | record bound removed with a wrong base (M-ADDR1-fit) |
| P-ADDRV2 | same, addrv2 + bmc_addr_decode_v2 | same | payload <= 64 | BOUNDED-OK | 243+14 s | cap 1000->1001 (M-ADDRV2-max); length check without the port (M-ADDRV2-len) |
| X-ADDR1-core, X-ADDRV2-core | same | Core: addresses only from a payload Core deserializes | payload <= 64 | VIOLATED (F2) | 17 s, 359 s | - |
| P-MPD | mempool_dump_read v1 (daemon/mempool_persist.c) | memory safe, no leak, file closed; each tx + 16 bytes inside the file in order; records <= size/17; result = sink calls | file <= 52 | BOUNDED-OK | 2+1 s | trailing 16->8; a leak on an error path (M-MPD-*) |
| P-MPDV2 | same, v2 (XOR key) | same | file <= 26 | BOUNDED-OK | 10+6 s | key length check without its prefix (M-MPD-key) |
| X-MPD-delta | same | the delta-map bound does not wrap | file <= 44 | VIOLATED (F6) | 2 s | - |
| P-MPJ | mpj_open/append/recent/lookup (daemon/mempool_journal.c) | memory safe; capacity fits the mapping; walks bounded by capacity whatever next_seq the file holds | file <= 368 (2 slots) | BOUNDED-OK | 89+174 s | capacity bound without the header (M-MPJ-cap); next_seq <= 1 guard removed (M-MPJ-wrap) |
| X-MPJ-stats | mpj_stats | the walk is bounded by capacity | same | VIOLATED (F5) | 69 s | - |
| P-LSMMAN | lsm_manifest_read_file, _persisted_live_file (daemon/lsm_manifest.c) | memory safe, no leak; entries <= capacity; count capped before the allocation | file <= 68 | BOUNDED-OK | 6+4 s | capacity check removed; 2^20 cap removed (M-LSM-*) |
| X-LSM-gen | advance_counters | next_gen/next_run_no exceed every entry | same | VIOLATED (F7) | 4 s | - |
| P-IRS | irs_open_run (daemon/index_runs.c) | memory safe; no mapping kept on refusal | file <= 2^40 | PROVED (no input loop) | 1+1 s | header size 48->8 (M-IRS-hdr) |
| X-IRS-wrap | same | records and sparse table inside the mapping | same | VIOLATED (F4) | 14 s | - |
| P-HTTP | http_request_parse (rpc_net.c) | memory safe; method/path/body inside; no control byte in the request line | request <= 24 | BOUNDED-OK | 5+2 s | control-byte check removed (M-HTTP-ctl) |
| P-TXRCN | txrecon_build_offer / version_relays_txs, txrecon_parse (daemon/txrecon.c) | memory safe; an offer only from a version payload whose user agent and start_height fit | payload <= 90 | BOUNDED-OK | 0+0 s | fRelay read at o == len (M-TXRCN-rly) |
| P-CF0/1/2 | serve_cfilters, getcfilters / getcfheaders / getcfcheckpt (daemon/serve_cfilters.c) | memory safe with any index content; range caps 1000/2000 applied before any read; reads only inside the range; replies well formed | request <= 40, index <= 2 filters; CF_MAX_FILTER 1 MiB -> 64 (model change) | BOUNDED-OK | 11+10, 1+1, 1+0 s | range cap +5000 (M-CF-range); filter length check removed (M-CF-cap) |
| P-CFGHEX | nodecfg_hex32_be (daemon/node_config.c) | memory safe; accepts 1..64 hex digits only | string <= 70 | BOUNDED-OK | 315+20 s | 64->66 (M-CFG-hex) |

Vacuity: every proof's cover run reached all its goals (listed in each
harness: e.g. two entries accepted, a 3-byte CompactSize accepted, a witness
tx accepted, a commitment found, two records loaded).


## Findings (each confirmed on the compiled code by `confirm/run.sh`)

Severity is for this node's exposure; none is a memory-safety defect in a
network parser. Core references are v31.1 (`serialize.h` ReadCompactSize
throws "non-canonical ReadCompactSize()" / "size too large"; an exception
while deserializing a P2P message is caught in `net_processing.cpp:5283` and
the whole message is dropped, unscored).

**F1 X-LOC-canon (Low, P2P, unauthenticated).** `serve_locator_from`
(daemon/serve_invbounds.c) accepts a non-canonical locator count. Input:
getheaders `80110100 fd0100 <32-byte known hash> <32 zero bytes>`. Observed:
returns 1 and serves from the hash's height (`from=101`). Expected (Core): the
message does not deserialize and is dropped. A fingerprint and a protocol
divergence; no memory effect (the count is still capped at 101 and checked
against the length).

**F2 X-ADDR1-core / X-ADDRV2-core (Low, P2P).** `addr_ingest_msg_vg` takes
addresses from payloads Core drops whole. Confirmed inputs (each yields
`added=1, viol=0`; Core takes nothing):
(a) addr count `ff 01000000 01000000` (2^32+1): the NASM counter
`p2p_addr_count` (bitcoin_addrmgr.asm `.ff`) reads only 4 of the 8 count bytes,
so the count is 1; Core: "size too large".
(b) addr count `fd 0100` (non-canonical 1).
(c) addrv2 count 2 with one record present: bmc stops at the end of the
payload and keeps the record; Core: end of data.
(d) addrv2 whose second record is network 1 (IPv4) with length 5: bmc skips
it as "unknown" (netaddr.c:244) and keeps the first; Core:
`SetNetFromBIP155Network` throws "BIP155 IPv4 address with length 5" for a
KNOWN network id with the wrong size (only unknown ids are skipped).
The per-response (256) and per-netgroup quotas still bound what one message
can add.

**F3 X-V2-type (Informational, P2P).** A BIP324 long-form message type
holding a control byte (`01 'ping'`) or a byte above 0x7f (`'pi' ff 'ng'`)
is delivered as that type (crypto_bip324_transport.c, the `id == 0` branch).
Core's `V2Transport::GetMessageType` returns no type for either (and for a
non-NUL byte after the first NUL) and drops the message. Downstream no
handler matches such a name, so the effect today is nil. Confirmed with two
real endpoints after a real handshake (confirm/c_v2.c).

**F4 X-IRS-wrap (Low-Medium, disk -> RPC).** `irs_open_run`
(daemon/index_runs.c:41) checks `so + ns*sparse > size` and
`48 + n*rec != so` in 64-bit arithmetic that wraps. Input: a 68-byte
`txindex.r000000000-000000010.dat` with magic `BMCTXIDX`, n=1,
sparse_off=68, nsparse=2^60. Observed: accepted, `nsparse=2^60`
(16 * 2^60 wraps to 0). Expected: refused as a torn build (the header
"describes more than the file holds"). Consequence by reading the reader:
`txi_lookup_locked` (rpc_chain.c:2367) binary-searches `sp + mid*16` with
`mid` near 2^59, a read ~2^63 bytes past the mapping: the process serving
getrawtransaction/the index dies. The same holds for `n` (n + 2^62 passes the
`n*20` equation). Needs write access to the datadir (or corruption).

**F5 X-MPJ-stats (Low-Medium, disk -> RPC).** `mpj_stats`
(daemon/mempool_journal.c:241) does not guard `next_seq == 0`, unlike
`mpj_recent` and `mpj_lookup`: with a journal header whose next_seq is 0,
`written = next - 1 = 2^64-1` and the loop walks `seq` from 2^64-1 down to 1.
Input: create a 2-slot journal, zero bytes 24..31, reopen. Observed:
`bmcgetmempooljournal` (rpc_node.c:3596) never returns (the driver stops it
after 3 s; a bounded walk takes microseconds). `mpj_open` adopts next_seq
from the file unchecked.

**F6 X-MPD-delta (Informational, disk).** `mempool_dump_read`
(daemon/mempool_persist.c:200) checks `pos + nd*40 > fsz` in wrapping
arithmetic: a v1 mempool.dat with count 0 and delta-map count
`ff 6766666666666606` (0x0666666666666667; *40 wraps to 24) is reported as a
valid dump (returns 0) where Core's ReadCompactSize throws "size too large".
Nothing is read past the buffer (the map is skipped, not read); only the
verdict is wrong.

**F7 X-LSM-gen (Informational, disk).** `advance_counters`
(daemon/lsm_manifest.c:35) computes `g + 1` for each manifest entry: an entry
with gen 2^64-1 wraps to 0 and leaves `next_gen` unchanged (7 in the driver),
so a later run can be given a generation no newer than an existing one. Needs
a corrupt manifest.


## Assumptions and trusted base

* **Stubbed environment** (each stub checks the spans it is handed):
  open/close/pread/pwrite/fstat/stat/ftruncate/mmap/munmap and the stdio file
  calls over one or two in-memory files of nondeterministic content
  (`harness/fileio.h` and per-harness stubs); `time()` (2001..2100);
  `getenv` (NULL); the address book (`ab2_open`/`ab2_add_from`); the asmap
  (inactive); `serve_height_of_hash`, `idx_get` (any answer); `p2p_write`.
* **NASM routines with a stated contract**: `tx_parse` (returns 0, or 1
  with a length `1 <= tl <= cap`, reading only `p[0..cap)`); `block_hash`,
  `sha256d`, `merkle_root`, `siphash24_uint256` as free functions of readable
  inputs; `p2p_addr_count` is re-modelled in C instruction by instruction
  (harness/addr.c) -- that model is trusted, and its 4-byte read of the 9-byte
  form is confirmed on the real object (F2a).
* **C library models**: CBMC 6.11's own, plus `memchr` and `strncasecmp`
  written to the C standard in harness/nd.h (CBMC has no model for them);
  `FP_STUB_PRINTF` harnesses replace the printf family by a stub writing an
  empty string (only logged text is lost).
* **Model changes (scratch copies, `proofm`)**: P-CF0..2 lower
  CF_MAX_FILTER from 1 MiB to 64 bytes (the 1 MiB static buffers exceed the
  cap); P-JSONDEPTH (OPEN) and P-CMPCT (OPEN) list theirs in proofs.sh.
* **Bounds**: every result holds for inputs up to the bound in the table and
  for the unwinding bound given in proofs.sh; unwinding assertions are on, so
  no path is cut silently. Only P-INV, P-LOC and P-IRS are unbounded in the
  input length (no loop depends on it beyond the code's own caps).
* **Waived**: the eight past-the-end pointer relations of P-BWTX (above).


## Not covered

* **NASM, out of scope for CBMC** (not covered): `tx_parse`
  (bitcoin_tx.asm, the transaction decoder every path relies on), the v1
  message framing and checksum (`p2p_read`, bitcoin_net.asm), the version /
  verack / headers / inv / getdata dispatch and the headers-message walk
  (bitcoin_p2p.asm, bitcoind.asm, bitcoin_serve.asm; the inv/getdata and
  locator bounds they call ARE covered, P-INV/P-LOC), `p2p_addr_count`
  (bitcoin_addrmgr.asm; modelled, F2a), the compact-block serve side
  (bitcoin_cmpct.asm), mempool admission (bitcoin_mempool.asm), the script
  interpreter (bitcoin_interp.asm), the block store and UTXO-LSM readers
  (bitcoin_store*.asm, bitcoin_utxo_lsm.asm).
* **C, attempted and OPEN** (harness kept, entry commented `#OPEN` in
  proofs.sh with the reason): the BIP324 transport state machine (every phase
  over the 8 GB cap, even one 24-byte feed with the cipher stubbed); BIP152
  compact-block receive (over the cap with CR_MAX_TX 4, a 16-entry short-id
  table and a 100-byte payload, the minimum being 90); the JSON-RPC body
  parser `rj_parse` and the REST getutxos route built on it (symbolic
  execution did not finish in 15 min even at a 3-byte body); the pre-auth
  header / Basic-credential path `auth_ok` (over the cap at 16 bytes); the
  ASMap interpreter (over the cap at a 2-byte map); the undo-store readers
  (over the cap with the real 1 MiB buffer, over 600 s with it lowered to 64
  bytes); the fork-tree loader `hdrtree_open`; the config line classifier and
  host:port splitter; `block_check_witness_commitment` at block level (its tx
  walker is P-BWTX).
* **Not attempted**: `serve_block_ctx_ok` / `hdr_accept_check` (a fixed
  80-byte header; the arithmetic is the pow-rules batch's), socks5 / i2psam /
  torcontrol replies, banlist / anchors / peers2.dat loaders, rest.c routes
  other than getutxos, the wallet and descriptor parsers.

