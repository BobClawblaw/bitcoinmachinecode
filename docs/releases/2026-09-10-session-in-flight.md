# 2026-09-10 — A BIP324 session hands over with the message in flight

Follow-up to the pass helper (#169) and the session handover (#167). Snapshot ab's first hour closed three healthy v2 legs, 0-2 s old, as "the pass could not export its v2 session".

- **The export blob was 64 KB.** A pass helper exports the session when it reports; if the peer's next message was half received at that moment (a 162 KB headers reply on a fresh leg), the transport's receive buffer alone outgrew the blob and the export was refused, so the parent closed a leg that had done nothing wrong. The blob is 8 MB now (`DH_V2_BLOB_CAP`): a block in flight fits.
- **The refusal says why.** The report carries the bytes the export needed (`bmc_v2_export_need`), and the close line prints them against the cap, or says the send flush failed (the peer is gone) when the size was not the problem.
- **`bmc_v2_pump_once`**: one socket read into a session without delivering a message, for poll-driven callers and for the test below.

Verified: `test_v2transport` gained "a handover mid-message": the helper holds the first 64 KB of a 200 KB block, the 64 KB export is refused and the 1 MB export succeeds, the parent imports and the block completes byte for byte with the wire still encrypted; `test_dialhelper` pins the cap (watched to fail at 64 KB).
