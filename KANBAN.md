# Bitcoin Machine Code — Kanban Board

The canonical board for this project lives in Hermes kanban: board **`bitcoinmachinecode`**
(live DB at `~/.hermes/kanban/boards/bitcoinmachinecode/kanban.db`).
This file is a human-readable mirror + the workflow contract. **Keep both in sync**:
update this file whenever a card lands or changes status on the board.

Status legend: `todo` · `ready` · `running` · `blocked` · `review` · `done`

## Current sprint — Validation / Wallet bridge

Board state (2026-08-14, auto-synced from the live board):

| Task ID      | Status   | Depends on        | Title                                                    |
|--------------|----------|-------------------|----------------------------------------------------------|
| `t_ef86a54a` | running  | —                 | whole-transaction validator (all inputs, no double-spend, fees, signatures) |
| `t_9f55dbe5` | done     | `t_ef86a54a`      | wallet CLI: generate key, show address, sign a tx        |
| `t_62f9439e` | todo     | `t_9f55dbe5`      | policy + RBF / fee handling                              |
| `t_e1fe0170` | todo     | `t_62f9439e`      | bech32/bech32m (BIP173/350) address codec                |

**Run order is enforced by real dependency links** (parent → child), so each job
auto-starts *after* its parent completes — no manual poking:

`t_ef86a54a (validator)` → `t_9f55dbe5 (wallet CLI)` → `t_62f9439e (policy)` → `t_e1fe0170 (bech32)`

## Node (complete)
| Status | Task |
|--------|------|
| [x] | headers-first IBD + parallel block download + consensus verify |
| [x] | getdata/getheaders/getblocks/inv serving |
| [x] | mempool + tx relay (MSG_TX) |
| [x] | multi-peer (fork per conn) |
| [x] | inv keep-up + inv-announce + reorg/chain-link guard |

## Wallet primitives (complete)
| Status | Task |
|--------|------|
| [x] | sha256/sha512/hmac-sha512, RIPEMD-160 |
| [x] | secp256k1 ecdsa sign+verify, scalar_to_pubkey |
| [x] | BIP32 master+CKDpriv, known-vector verified |
| [x] | hash160 + base58check P2PKH addresses |
| [x] | pubkey decompression |
| [x] | secp256k1 field/scalar/point/ecdsa arith (fe/point/scalar) verified |
| [x] | pubkey_parse: comp/uncomp aff coords + fe_pow sqrt (bitcoin_pubkey.asm) |
| [x] | legacy SIGHASH_ALL preimage builder (bitcoin_sighash.asm) |
| [x] | der_parse_sig + be_to_limbs (bitcoin_script.asm, toward P2PKH) |
| [x] | verify_p2pkh: full signature check (sighash+der+pubkey+ecdsa) |
| [x] | UTXO store: track prevout value/script for validation |

## Backlog / later
- [ ] P2SH / multisig (OP_CHECKMULTISIG) script + hash
- [ ] sighash_all flow tied to a real spend

---

## How we run kanban for this project (conventions — follow these)

1. **One board: `bitcoinmachinecode`.** It's the active board
   (`~/.hermes/kanban/current` points to it). All project work gets a card here.

2. **Every card is created via the board** with a real `id`, a one-line `title`,
   a `body` stating the goal, and `priority` set at creation. Never track work
   only in this markdown — the DB is the source of truth.

3. **Dependencies are REAL links, never prose.**
   - When task B can't start until task A is done, create/link `A → B` with
     `link_tasks` (parent A, child B). Do **not** just write "blocked on t_xxxx"
     in a comment — prose-only blocking caused a real stall on this board
     (2026-08-14) where three jobs sat `blocked` forever with an empty
     `task_links` table.
   - A correctly-linked child auto-promotes `todo → ready` when its parent
     completes, and the dispatcher runs it. No manual unblocking needed.

4. **Lifecycle is driven by status, not comments.** A card moves
   `todo → ready → running → done` (plus `blocked` / `review`). Workers close
   their own card with `kanban_complete`; never leave a finished card `running`.

5. **Blocking = explicit, typed, and attached to a reason.** If a card must
   wait for a human or infra, use `blocked` with a `block_kind` and a concrete
   reason. Don't cite other task IDs as a shorthand for a dependency — link them.

6. **Seed each worker with context.** A worker agent spun up on a card reads
   `PLAN.md` (project plan + verified state), this file, and `LOG.md` (history)
   before touching code. `README FIRST: PLAN.md → KANBAN.md → LOG.md`.

7. **Update this mirror after every terminal transition.** When a card lands,
   bump its row here and record the commit/verification in `LOG.md`.

**Last Updated:** 2026-08-14 (mirrored from live board state + dependency links fixed)
