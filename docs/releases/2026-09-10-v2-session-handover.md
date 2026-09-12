# 2026-09-10 — A BIP324 session travels with its socket across the dial helper's fork

Inventory row 3. Core dials v2 wherever the peer advertises it. Since #163 every leg the background dial helper installed was v1, because the helper child ran the handshake and the cipher state stayed with it; snapshot u had shown what the parent's first bytes did to a v2 peer.

- **The transport exports and imports a completed session** (`bip324_t_export` / `bip324_t_import`): the cipher (two length ciphers, two packet ciphers, the garbage terminators, the session id), the receive state, the undigested receive bytes and a decoded message not yet delivered. Only a session at `BIP324_RECV_APP` is exportable; the garbage buffers and the ephemeral key are spent by then and are not carried.
- **The daemon's per-fd table does the same** (`bmc_v2_export` / `bmc_v2_import`): import rebuilds the connection entry against the fd and installs the read/write hooks, so the next `p2p_write` on it encrypts.
- **The helper carries it.** The child exports after the handshake and writes the bytes after the result struct on the socketpair (64 KB cap; larger, and the dial is reported failed rather than installed broken); the parent reads them in `dh_poll` and imports in `dh_install_leg` before anything is written to the socket. The v1-only gate on helper dials is gone.

`test_v2transport` gained the scenario in the helper's exact shape: a child completes the initiator handshake against the responder, exports, exits; the parent imports on the same fd and carries five encrypted round trips, a 200 KB message and the raw-wire check that the bytes stayed encrypted. On production: helper-dialed legs to v2-advertising peers log "connected over v2" and survive.
