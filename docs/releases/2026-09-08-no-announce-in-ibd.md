# 2026-09-08 — No tip announcements to the legs during initial block download, as Core

Core relays no blocks while IsInitialBlockDownload() holds (tip older than -maxtipage). This node announced every connected tip to its outbound legs regardless; on run 16 those legs were dead twenty minutes in (the peers' inactivity timeout, since the serve worker is inside the parallel catch-up), so the log carried 'announced tip ... to 0/4 legs' once per block for eight hours. Gated on the tip's timestamp against maxtipage, the rule the RPC's initialblockdownload field already uses; suppression logged once; announcements resume at the tip (production shows 13/13). test_dialhelper +3. Full gate 0 failures; 8 audits exit 0.

---

PR #91 (`batch/2026-09-08-no-announce-in-ibd`), merged 02:07Z as `9b466444`; tag `no-announce-in-ibd-2026-09-08`.
