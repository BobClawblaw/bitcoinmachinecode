# AUDIT RESPONSE — 2026-08-30

Response to `SECURITY_AUDIT_2026-08-29.md` (11 findings).

**Disposition: 8 resolved, 1 partially resolved, 1 config-only, 1 structural
and not closeable by patch.** Every fix is on `main`, gated
(255 test binaries, 1,309 assertions, zero failures), and deployed to the live
mainnet node as `bitcoind.deploy-20260830b`. Rollback binary:
`bitcoind.deploy-20260829ap`.

Two things this document does that a status table would not: it states what
each fix was verified *against*, and it records the mistakes made while
fixing — including one that disabled the RPC server in production and one that
leaked a wallet mnemonic. Both are below in full.

---

## Summary

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | HIGH | Weak custom at-rest wallet encryption | **Resolved** — wallet regenerated in the strong container |
| 2 | HIGH | Plaintext passphrase beside the wallet | **Resolved** — root-owned file outside the datadir |
| 3 | HIGH (structural) | Hand-written consensus assembly | **Not closeable** — see below |
| 4 | MEDIUM | RPC plaintext password; history exposure | **Resolved** (password); history rewrite declined |
| 5a | MEDIUM | Integer overflow in amount parsing | **Resolved** |
| 5b | MEDIUM | Missing consensus `MAX_MONEY` check | **Resolved** — verified against 1,172 real mainnet txs |
| 6 | MEDIUM | P2P framer had no message size limit | **Resolved** |
| 7 | MEDIUM | Misbehaviour scoring never called | **Partially resolved** — one caller; scope limits documented |
| 8 | MEDIUM | ZMQ `tcp://*` bind; poll in the hot loop | **Resolved** — both halves |
| 9 | LOW | Weak ELF/build hardening | **Resolved** |
| 10 | LOW | Filesystem hygiene | **Resolved** — plus three files the audit missed |

---

## FINDING 1 — Weak at-rest wallet encryption — RESOLVED

**What was wrong.** The live wallet was `BMCWAL v2`: PBKDF2-HMAC-SHA512 at
**2,048 iterations**, a custom CTR construction, and a prefix-MAC — with the
same 64 bytes keying both the cipher and the MAC. The tree already contained a
much stronger container (`BMCWENC1`: BytesToKeySHA512AES, 100,000 iterations,
AES-256-CBC, master-key wrap) that `encryptwallet` writes, but it had never
been applied to this wallet.

**How it was fixed.** The wallet was **regenerated**, not migrated. It held no
funds (`getbalance` 0, `txcount` 0), and — see *Incidents* below — its
mnemonic had been exposed during this work, so re-encrypting it would have
wrapped better crypto around a known key. A fresh mnemonic and a fresh
192-bit passphrase were generated from `/dev/urandom` and sealed directly into
the strong container. The old material is archived root-only at
`/etc/bmc/compromised-2026-08-29/` and must be treated as public.

**Two defects found in the migration path while doing this**, both of which
would have bitten any real migration:

1. `wenc_encrypt` unlinked the plaintext store immediately after `rename()`,
   on the strength of `write()` having returned success. Any later failure —
   a corrupt seal, an unreadable file, a passphrase that did not open what was
   just written — would have left the operator with **no wallet at all**. It
   now re-opens the container, unseals it with the same passphrase, compares
   the recovered payload against the input, and only then removes the
   plaintext. On failure the container is discarded and the plaintext store is
   left untouched.
2. An encrypted wallet boots **locked**, as Core's does. Migrating would
   therefore have silently turned the wallet RPCs off at the next restart.
   Boot now auto-unlocks from the configured passphrase source, and stays
   locked when none is set — the correct default.

**How it was tested.** The whole migration was rehearsed on a **copy** of the
real wallet before anything live was touched: the derived seed is byte-identical
across a v2 → `.enc` migration, and a wrong passphrase is rejected. The
generator verifies its own output by re-reading the sealed container from
disk, unlocking it, and confirming both the seed and the first derived address
match before reporting success. It never prints the mnemonic or the
passphrase — only the receive address, which is public by construction.

Live confirmation after deploy:
`[rpc] encrypted wallet adopted and unlocked from the configured passphrase source`

---

## FINDING 2 — Plaintext passphrase beside the wallet — RESOLVED

**What was wrong.** The daemon read the passphrase from `<store>.pass`, a 0600
file next to the wallet. The stated intent was to avoid pairing ciphertext and
key in one *file* — but it put them in one *directory*, under a guessable
name. Any read primitive over the datadir yields both, and so does any backup
of it: the two halves travel together in the tar.

**How it was fixed.** New `walletpassfile=` config key taking an **absolute
path outside the datadir**. The daemon takes the passphrase from
`$BMC_WALLET_PASS` or that file, and no longer reads `<store>.pass` at all.
The file is **refused, with a log line**, if it is world-accessible,
group-writable, or inside the datadir — a passphrase file that is silently
ignored is worse than none, because the operator believes the wallet will
unlock and only discovers otherwise when something needs a key.

Three separate inline copies of the old lookup existed — one in
`daemon/main.c` and two in `rpc_wallet_ops.c`. All now route through
`daemon/wallet_pass.c`, so the boot path and the RPC path cannot disagree
about which secret protects the wallet.

Deployed as `/etc/bmc/wallet.pass`, `root:<service-group>`, mode `0640` — readable by the
service account, writable only by root, outside any datadir backup.
`data/bmcwallet.dat.pass` was removed after byte-comparing the contents.
The CLI keeps `<store>.pass` for development: that is a human at a terminal,
not an unattended service holding a spendable key.

**How it was tested.** `tests/test_wallet_pass` exercises every refusal —
`0644`, `0604`, `0660`, `0666`, a relative path, a path inside the datadir, an
empty file, a missing file — and **pairs each with the mode that must still be
accepted** (`0640`, `0600`), so a check that simply refused everything could
not pass. The real `/etc/bmc/wallet.pass` was then loaded through the daemon's
own code path from the real datadir before the old file was deleted.

---

## FINDING 3 — Hand-written consensus assembly — NOT CLOSEABLE BY PATCH

Accepted as stated. This is a structural property of the project, not a defect
with a fix, and it remains the load-bearing reason the README's "treat as
untrusted" warning is correct.

Nothing in this response reduces it. The audit's recommendations —
continuous oracle differential against a tip-following Core, property-based
differential fuzzing rather than only curated vectors, and a published
machine-readable attestation of divergence at height H — are the right ones
and remain open work.

One data point from this round, offered as evidence rather than reassurance:
the new consensus check (Finding 5b) was validated by replaying **1,172 real
mainnet transactions** through the modified parser rather than by unit tests
alone. That is the shape the audit is asking for, applied to one change.

---

## FINDING 4 — RPC credential model — RESOLVED (password); history declined

**What was fixed.** `rpcuser` and `rpcpassword` were removed from the live
config. The password had been committed to a public repository and must be
treated as compromised; rewriting history would not un-publish it, so the value
is simply gone rather than rotated in place. Authentication is now the cookie
(`<datadir>/.cookie`, 0600, regenerated per start, deleted on shutdown), which
is Core's default and was already implemented and enabled.

Git history rewrite: **declined by the operator**, correctly — the secret is
already public, so rotation is what mattered.

*Added in the addendum:* Core does not merely tolerate the absence of
`rpcuser`/`rpcpassword` — it **prefers** it. `InitRPCAuthentication()` generates
a cookie when `-rpcpassword` is empty, and when it is set it emits a
`LogWarning` calling plaintext credentials "less secure" and recommending
cookie or `rpcauth`. Removing them put this node on Core's default path.

**Verified after deploy:** RPC answers over cookie auth; the removed password
no longer authenticates.

**This fix caused a production outage. See Incident 2 below.** Removing the
credentials tripped a start gate that required `rpcuser` *and* `rpcpassword`,
disabling the entire RPC server. That is now fixed and pinned by a test.

**Not addressed:** the RPC listener remains loopback-only
(`rpcport=8331`, `127.0.0.1`), which was verified during this work — the
audit's concern about exposure does not apply to the current binding. Note
that `port=8332` in the config is the **P2P** port, correctly bound to
`0.0.0.0`; it is not the RPC port.

---

## FINDING 5a — Integer overflow in amount parsing — RESOLVED

**What was wrong.** `crt_amount_to_sat()` accumulated the whole-number part
with no bound, so roughly 19 digits of unauthenticated JSON-RPC input
overflowed a signed 64-bit integer — undefined behaviour, and in practice a
wrap to a negative or arbitrary value that had nonetheless "parsed
successfully".

Measured before the fix: `"9223372036854775807"` returned **−100000000**.

**How it was fixed.** The bound is applied **during** accumulation, not after —
checking the result cannot detect a wrap that has already happened. Values
above `MAX_MONEY` are **rejected**, not saturated: an unrepresentable amount is
a malformed request, not a request for the maximum. Core's `ParseFixedPoint`
does the same.

**How it was tested.** `tests/test_rpc_amount` pins the boundary
(`21000000`, `21000000.00000001`, `INT64_MAX`, `2^64`, all-ones) and asserts
that **no input** produces a negative satoshi count other than the `-1` error
sentinel. The guard was verified by removing the fix and confirming the test
fails on six inputs.

---

## FINDING 5b — Missing consensus `MAX_MONEY` check — RESOLVED

**What was wrong.** The tree had **no money-range check anywhere**. `mv_parse`
summed raw `u64` output values straight off the wire into `out_total` with
neither a per-output bound nor a range check on the running total. This is the
CVE-2010-5139 shape.

**How it was fixed.** Core's `CheckTransaction` rule, in Core's order: reject a
per-output value above `MAX_MONEY`, add, then reject the running total leaving
the range. Core's amounts are signed `int64` and ours are `u64`, so "negative"
and "above `MAX_MONEY`" collapse into one unsigned comparison — a Core-negative
value is ≥ 2^63, far above the cap. Both halves are required: per-output alone
lets many outputs sum past the cap, the total alone lets one output be absurd,
and checking the total **every iteration** is what keeps the `u64` addition
from wrapping at all.

**How it was tested — and why this one got more than a unit test.** A consensus
check that is too *strict* does not produce a bug report, it produces a chain
split: the node rejects a block the rest of the network accepted and stops
following the chain. So this was replayed against real chain data:

> **1,172 real mainnet transactions across 24 blocks, height 1 to tip 964638**
> — spanning pre-BIP16, pre-segwit, the segwit and taproot activations, and the
> witness-stripped region above 481824 — **all still parse, zero rejections.**

Reproducible via `scripts/live_money_range_check.sh`. It cannot reject anything
already in the chain, because Core enforced the same rule when those blocks
were accepted. `tests/test_money_range` pins the boundary exactly, single-output
and split across outputs, plus the original CVE value pair.

The gate then caught a genuine consequence: a test fixture built 60 outputs of
`0x0101010101010101` sat — about 723 million BTC each. Always invalid, never
checked until now. The fixture was corrected (the test is about the structural
`nin`/`nout` cap, not amounts) and the reject still arrives from the resolve
stage as intended. Recorded here because it is evidence the check has teeth.

---

## FINDING 6 — P2P framer had no message size limit — RESOLVED

**What was wrong.** `p2p_read()` acted on the announced length with no upper
bound. Core rejects at exactly this point, and the note beside that check cites
the 2024-07-03 disclosure where its absence let a peer make a node allocate
32 MiB per connection. Here the cost is unbounded **work** rather than memory —
callers cap their own buffers, but the drain loop reads the excess 64 bytes at
a time, so a peer announcing `0xFFFFFFFF` grinds a forked serve child through
~4 GB of socket reads while holding a connection slot.

**How it was fixed.** Reject `announced > 4,000,000`
(Core's `MAX_PROTOCOL_MESSAGE_LENGTH`, the binding one of Core's two limits)
with a **distinct `-3`**, so a caller can score it as misbehaviour rather than
treat it as an ordinary short read.

**How it was tested.** `tests/test_p2p_msgsize` checks two separate things,
because the return code alone would pass even if the drain still ran: the call
rejects with `-3`, **and** it returns without consuming the bytes that follow
the header. It also asserts the refusal is immediate (measured at 0.0 ms
against a peer deliberately left connected), that exactly 4,000,000 is still
**accepted**, and that ordinary frames still round-trip.

---

## FINDING 7 — Misbehaviour scoring never called — PARTIALLY RESOLVED

**What was wrong.** `peer_misbehaving()` existed with a 100-point threshold, a
shared ban list and /32 auto-ban — and **zero call sites**. Machinery that
looked like a defence and did nothing.

**What was fixed.** It now has a real caller: the assembly serve loop reports
an oversized message announcement (the `-3` from Finding 6) and the peer is
scored at the full threshold. No conforming implementation produces one; Core
treats an oversized header as fatal for the connection.

**What is still open, stated plainly:**

- `g_misbehavior` is a **process-local array** and the serve loop runs in a
  forked child, so scores **do not accumulate across connections**. Crossing
  the threshold calls `ctl_ban_add()`, which writes the shared, file-backed ban
  list consulted by both the dial and inbound-accept paths — so a single
  violation does ban the peer for real. But a peer that reconnects between
  offences is not tracked.
- Only **one** violation type is wired. The audit named others — duplicate-inv
  spam, malformed addr/tx/block messages, handshake failures — and those remain
  unwired.

This is documented at the call site rather than left for a reader to discover.

**How it was tested.** `tests/test_serve_violation` drives the **real assembly
serve loop** over a socket and asserts both halves: a malformed announcement
reports with the right reason string, **and** well-formed messages do not — a
hook that fired on every disconnect would ban honest peers and look identical
in a log.

---

## FINDING 8 — ZMQ publisher — RESOLVED (both halves)

**Bind.** `zp_bind()` expanded `*` to `INADDR_ANY`. A ZMQ publisher has **no
authentication** — whoever connects, subscribes — so on a host with a LAN
address, the spelling every tutorial uses quietly publishes all block and
transaction traffic to that LAN: a blast radius the operator inherited rather
than chose. `*` is now **refused** with a message naming the alternatives.
`0.0.0.0` still binds every interface for anyone who means it, so the
capability is intact and only the ambiguous spelling is gone.

**Poll.** `zmqpub_poll()` ran on every pass of the download worker's loop.
It now runs on a **dedicated thread** that blocks in `poll()` and idles at zero
cost; the download loop no longer walks the subscriber list at all.

This second half was done twice. The first attempt merely rate-limited the poll
to 200 ms, which was a mitigation. Checking Core showed why that was the wrong
target: **`zmq_poll` appears nowhere in Core's source.** Core links libzmq,
whose background I/O thread performs every accept, subscription frame and
delivery, so none of it ever touches Core's hot paths. The dedicated thread is
the structural equivalent; the throttle was not.

**The thread is the fix; the race is what it costs.** The servicing thread
accepts subscribers and *compacts* the array when they drop, while the
publishing thread walks that same array and closes subscribers whose send
fails. Unsynchronised, compaction moves entries out from under a walk in
progress and both sides can close the same descriptor — which, once the number
is reused, means writing block data into an unrelated socket. Every read and
write of `subs`/`nsubs` is now under one mutex; the endpoint list is built
before the thread starts and is read-only after.

**How it was tested.** `tests/test_zmq_bind` pairs each refusal with an address
that must still be accepted. `tests/test_zmq_thread` runs 4,000 publishes
against 4 threads connecting and disconnecting throughout, **under
ThreadSanitizer**: zero data races.

TSan's first run found **two real races**, both stop flags declared `volatile`.
`volatile` orders nothing between threads and is not a synchronisation
primitive; it happens to work on x86, which is precisely the kind of thing that
stops being true elsewhere. Both are now `atomic_int`. TSan found no races on
the subscriber array itself, which is the evidence the mutex is placed
correctly.

*(Note for reproduction: TSan aborts with `FATAL: unexpected memory mapping`
under this kernel's ASLR. `setarch -R` gives a clean run.)*

ZMQ is now **enabled and testable** on the live node, loopback only:
`hashblock`+`rawblock` on 28332, `hashtx`+`rawtx` on 28333.

---

## FINDING 9 — ELF/build hardening — RESOLVED

**What was wrong.** `PT_GNU_STACK` was **RWE** — an executable stack — because
**24 of 63 `.asm` files** lacked a `.note.GNU-stack` section, and one such
object is enough to mark the whole program's stack executable. RELRO was
partial (no `BIND_NOW`).

**How it was fixed.** Every `.asm` file now carries the note, and the daemon
links with `-Wl,-z,relro,-z,now`. Verified on the deployed binary:
`GNU_STACK` is `RW`, and the dynamic section carries `BIND_NOW` / `FLAGS_1 NOW`.

**How it was tested.** `tests/test_elf_hardening` parses the ELF program
headers **directly** (no dependency on `readelf` or its output format) and
depends on `daemon/bitcoind`, because both properties regress silently: the
next `.asm` file added without the note re-enables an executable stack, and the
link flag lives in the Makefile, which is not a prerequisite of the binary.

That second point is not hypothetical — **the first attempt at this fix
reported success against a stale binary that had never been relinked.** The
test now depends on the binary specifically so that cannot recur.

---

## FINDING 10 — Filesystem hygiene — RESOLVED

Applied to the live datadir:

| path | before | after |
|---|---|---|
| `data/` | `0755` | `0750` |
| `data/peers2.dat` | `0644` | `0600` |
| `data/peers.dat` | `0664` | `0600` |
| `data/walletscan.dat` | `0644` | `0600` |
| `testnet4-e2e/testnet4/bmcwallet.dat` | `0605` | `0600` |
| `testnet4-e2e/testnet4/bmcwallet.dat.pass` | `0605` | `0600` |

The audit named three files. A sweep found **three more** world-readable
peer-book copies it had not listed — `peers.good`, `peers.dat.pre-port-fix`,
`peers.dat.pre-v2book` — leaking the same peer graph. All now `0600`.

Node verified healthy after the change: peers connected, height advancing.

**Not done, at the operator's direction:** the systemd hardening directives
(`NoNewPrivileges`, `LimitCORE=0`, `ProtectSystem`). Worth noting `LimitCORE=0`
carries more weight than its LOW rating suggests — see Incident 1.

---

## Incidents during remediation

Recorded because they are part of the security state of this system, not
footnotes to it.

### Incident 1 — I leaked the wallet mnemonic

While debugging a crash in the migration probe, I ran `gdb` and its backtrace
printed `wenc_encrypt`'s arguments — **including the wallet mnemonic in
cleartext**, into the session transcript. A 32-byte prefix of the derived seed
and the wallet passphrase were exposed in the same frame.

**Cause:** attaching a debugger to a process holding wallet secrets without
considering that argument values are dumped in a backtrace.

**Impact:** the old wallet and its passphrase are permanently public. The
wallet held no funds and no transactions, so nothing was stealable.

**Remediation:** the wallet was **regenerated** rather than migrated (Finding 1)
— re-encrypting a known key would have been theatre. Old material archived
root-only and marked compromised. The replacement generator never puts the
mnemonic or passphrase into `argv`, the environment, or stdout; it emits only
the derived address.

**Bearing on Finding 9/10:** this is exactly the exposure `LimitCORE=0`
prevents in the crash case. A core dump of the daemon would contain the same
material.

### Incident 2 — the RPC fix disabled the RPC server

Removing `rpcuser`/`rpcpassword` (Finding 4) tripped a start gate in
`serve_start_rpc` that required **both** to be set. The embedded RPC server
therefore never started. The daemon logged one line —
`no rpcuser/rpcpassword in config -- embedded RPC server disabled` — and
carried on serving the P2P network normally.

**Cause of the miss:** I verified cookie authentication against the **running**
daemon, which had been started *with* those credentials present. That proved
authentication worked. It did not prove the server would **start** without
them. Two different claims; I only checked the first.

**Fix:** the server now starts on any usable credential — cookie, `rpcauth`, or
user/password — and refuses only when nothing could authenticate, which would
otherwise be an open port. That is Core's behaviour: the cookie is the default
credential and `rpcuser`/`rpcpassword` are the legacy alternative.
`tests/test_rpc_start_policy` pins the policy, including the exact config that
broke and the refusal that must survive.

**Detection:** by the operator, from the deployed node — not by any test.

### Incident 3 — outbound BIP324 was inert and the node's own log hid it

After deploy, every outbound leg logged `connected over v1`, with **zero**
`advertised v2 but the handshake failed` lines — the signature of a gate that
never fires, rather than one that fails.

**Cause:** every address this node added itself went into the book with a
hardcoded `services=1` (NODE_NETWORK); only gossiped addresses carried real
service bits. The peers actually dialled are ones previously connected to, so
they all read as `services=1`, and the v2 gate returned "no" every time.

Meanwhile the boot line reported *"8341 of 14825 known peers advertise v2"* —
true of the **book**, and irrelevant to the peers dialled. A metric that
counted the wrong population is what made this invisible.

**Fix:** the peer's real service bits, which its `version` message has just
told us, are now written back to the book on a successful handshake. `ab2_add`
refreshes an existing record, so the book self-heals after one contact per
peer.

**Status:** committed (`c2ab554`); outbound v2 will begin appearing as peers
are re-contacted under the new build. Inbound v2 is unaffected and was already
working. **This is the one item in this document whose effect is not yet
observed in production.**

---

## Verification standard used

Every fix in this document has a regression guard that was **checked**, not
assumed. Where a guard was written for a bug, the fix was removed and the guard
confirmed to fail:

- amount bound removed → `test_rpc_amount` fails on six inputs
- `MSG_PEEK` fallback removed → the v1 peer's version message is lost and the
  test fails

Several fixes were verified against **real Bitcoin Core v31.99** or **real
mainnet chain data** rather than against vectors alone:

| what | against |
|---|---|
| BIP324 both directions | Core v31.99, byte-identical session ids |
| BIP324 v1 fallback | Core with `-v2transport=0` |
| money range | 1,172 mainnet txs, height 1 → 964638 |
| ZMQ threading | ThreadSanitizer, 4,000 publishes under churn |
| ELF hardening | the deployed binary's own program headers |
| wallet migration | a copy of the real wallet, seed compared byte-for-byte |

**Gate:** 255 test binaries, 1,309 assertions, zero failures, on `main`.
`prereq-check` clean across 350 rules. `abi-check` clean across 1,194 call
sites.

The gate caught four integration defects that inspection and single-target
builds did not: an ABI stack-alignment violation in a tail call into C, a PIE
relocation that broke four targets, two missing link-list entries, and a
consensus check altering a test fixture's behaviour. Individual target builds
proved nothing about the other targets — that lesson recurred often enough in
this round to be worth stating.

---

## Open items

1. **Finding 3** — structural; needs continuous oracle differential and
   property-based fuzzing, not a patch.
2. **Finding 7** — misbehaviour scores do not survive across connections
   (process-local state in a forked child); only one violation type is wired.
3. **Systemd hardening** — declined this round; `LimitCORE=0` is worth
   revisiting given Incident 1.
4. **Parser recursion-depth counter** — defence in depth, not started.
5. ~~**Incident 3 fix** — committed, effect not yet observed in production.~~
   **Closed 2026-08-30 01:00 UTC** — observed live; see the addendum.
6. **Test wiring survey** — 5 targets are built as prerequisites but never run,
   7 `test_*.c` files have no Makefile rule, 9 have a rule but sit outside the
   gate. Recorded, not triaged; each needs a judgement about whether it is
   deliberately manual.

---

*Response prepared 2026-08-30. Commits `4213dfd..c2ab554` on `main`.
Deployed as `bitcoind.deploy-20260830b`; rollback `bitcoind.deploy-20260829ap`.*
