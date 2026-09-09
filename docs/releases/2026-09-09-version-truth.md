# 2026-09-09 — The version message tells the truth

Every `version` this node ever sent carried a fixed timestamp (1700000000, a November-2023 clock), a fixed nonce (0x1122334455667788 -- the field Core uses to detect a connection to itself), port 8333 in both address fields on a node that listens on 8332, and start_height 0 while sitting at 966k. Measured by the operator against `ss` and the conf; proven NOT to be why peers hung up (a Core-shaped client got the same refusals), but wrong on every field, and `test_bitcoind` pinned each wrong value.

- **timestamp**: the wall clock (`time(2)` at build time of the message).
- **nonce**: eight bytes from `getrandom(2)` per connection; the old constant only if the syscall is unavailable.
- **addr_recv / addr_from port**: `node_listen_port_be`, set by the daemon from `-port` before every outbound handshake and every accepted one.
- **start_height**: `node_start_height`, set from the archive tip at the same points.

The self-address gossip (`addr`/`addrv2`) already stamped `time(NULL)` and announced the real port, so the 70-minute skew rule was not discarding our announcements; the version message was the only liar.

`test_bitcoind`: the timestamp within 5 s of now, two versions with different non-constant nonces, start_height and the port following the daemon's globals, the address bytes still zero after the port store (**watched to fail**: 5 assertions against the old builder). Assembled first on a scratch copy; the port stores had to re-zero AL before the next `rep stosb`, caught in review.
