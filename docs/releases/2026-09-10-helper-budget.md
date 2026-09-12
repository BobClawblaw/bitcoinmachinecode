# 2026-09-10 — A budget for the dial helpers

What snapshot v's first fifteen minutes showed: the node sat at three of four legs with no dial activity for the legs at all. The block-relay-only picker had dialled the same refused host on every rotation (its registry was full, so the host was never marked block-only and was first in the pool again each time; it ignored the dial memory), three helpers deep, and the legs' own re-dials logged "no dial helper free". The helper children also inherited the parent's last failure string, so a dial refused before it started read "connect timed out (10s)" after 1.4 s.

- **Extra legs leave two helpers for the legs.** Block-relay-only and anonymity-network dials run only while two helpers stay free and none of their own is out (`dh_extra_allowed`, `DH_SLOT_EXTRA`).
- **The block-relay-only picker** skips hosts under the dial memory's backoff, rotates through the pool from a cursor, and dials only a host it managed to register as block-only (an unregistered dial would come up with fRelay=1).
- **A helper child starts with a clean failure reason** ("refused before dialing" until the dial says otherwise).

Verified on production after the restart: the legs fill to their budget, the extra dials stop repeating one host, and failure lines name the real reason.
