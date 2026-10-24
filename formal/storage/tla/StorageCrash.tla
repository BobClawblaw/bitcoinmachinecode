---------------------------- MODULE StorageCrash ----------------------------
(***************************************************************************)
(* The UTXO store's durability protocol under process kill and power loss. *)
(* See ../PROTOCOL.md for the step list this follows, with file:line      *)
(* citations; every action below names the step it models.                *)
(*                                                                         *)
(* Data abstraction. Blocks 1..N form one chain: block b spends coin b-1   *)
(* and creates coin b; coin 0 is in the base run. So the set after block h *)
(* is exactly {h}, a resurrected spend shows as an extra coin and a lost   *)
(* creation as a missing one, and block b+1 can only be verified if b's    *)
(* output is present (chained spends make the LIFO rollback order matter). *)
(*                                                                         *)
(* File-system abstraction. Every file has a page-cache state (what the    *)
(* next process sees after a kill) and a durable state (what a power loss  *)
(* keeps). Data writes are durable after an fsync/fdatasync of that file.  *)
(* Name operations (create, rename, unlink) and file metadata (ftruncate,  *)
(* punch hole) are queued in `jnl` until committed:                        *)
(*   FS = "ext4": the ext4 data=ordered journal. Any successful sync       *)
(*     commits the whole journal (every metadata op so far); a power loss  *)
(*     keeps a PREFIX of the uncommitted journal. Appended data is         *)
(*     delalloc: it survives as a prefix, and nothing appended after a     *)
(*     lost metadata op of the same file survives.                         *)
(*   FS = "weak": POSIX only. A name op is durable after an fsync of the   *)
(*     directory; a file's own metadata after an fsync of that file; a     *)
(*     power loss keeps ANY SUBSET of the uncommitted ops, independently.  *)
(*     Unsynced overwrites persist or not independently per record.        *)
(***************************************************************************)
EXTENDS Naturals, Sequences, FiniteSets, TLC

CONSTANTS
    N,           \* blocks
    ASYNC,       \* TRUE: plan B3 async flush (the default); FALSE: inline mac_flush
    FS,          \* "ext4" or "weak"
    MaxFlush,    \* memtable flushes (threshold crossings) allowed per behaviour
    CompactOn,   \* allow one background compaction
    MaxCrash,    \* crashes per behaviour (a crash during recovery needs 2)
    PowerOn,     \* power loss is possible
    KillOn,      \* SIGKILL is possible
    MaxDirFail,  \* directory fsyncs that may fail (C sites ignore the result)
    FixUndo,     \* candidate fix: undo durable before any op of its block can be
    FixRecov,    \* candidate fix: rollback ops durable before the undo slot is cleared
    FixArch,     \* candidate fix: index.dat record durable before the block is applied
    FixDir,      \* candidate fix: the C sites halt on a failed directory fsync
    FixLogOff,   \* candidate fix: the WAL is fsynced before utxo.idx names a log_off in it
    FixWeakDir,  \* candidate fix (weak FS only): a directory fsync between a run's create and the
                 \* manifest rename, and one before the boot sweep unlinks orphans
    MUT          \* mutation of the protocol (see PROTOCOL.md "Mutations"), "none" = faithful

ASSUME FS \in {"ext4", "weak"}
ASSUME MUT \in {"none", "noWalFsync", "noUndoSync", "noDirSync", "truncBeforeDir",
                "punchBeforeIdx", "noRunFsync"}

Coins  == 0..N
Blocks == 1..N
RunIds == 0..(MaxFlush + 2)
Z      == [op |-> "Z", c |-> 0]                \* zeros: a punched or unwritten WAL record
Put(c) == [op |-> "put", c |-> c]
Del(c) == [op |-> "del", c |-> c]
None   == 99

(* WAL events since the WAL's last fsync. Uniform record shape for TLC. *)
App(r)      == [t |-> "app",   r |-> r, a |-> 0, b |-> 0, cm |-> FALSE]
Trunc(n)    == [t |-> "trunc", r |-> Z, a |-> n, b |-> 0, cm |-> FALSE]
Punch(x, y) == [t |-> "punch", r |-> Z, a |-> x, b |-> y, cm |-> FALSE]
(* journal entries: k = kind, v = value (a name's new value, a run id, or a walEv index) *)
J(k, v) == [k |-> k, v |-> v]
NameKinds == {"man", "idx", "hgt", "mk", "rm"}

VARIABLES
    pc, nb, ret, ret2,
    memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun, liveStart,
    cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo,
    walD, walEv, revD, revU, slotD, slotC,
    manD, manC, idxD, idxC, hgtD, hgtC, runsD, runsC, runCont, runDur, jnl,
    archD, archC,
    crashes, dirFails, ckDur, maxApplied, flag

vars == <<pc, nb, ret, ret2,
          memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun, liveStart,
          cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo,
          walD, walEv, revD, revU, slotD, slotC,
          manD, manC, idxD, idxC, hgtD, hgtC, runsD, runsC, runCont, runDur, jnl,
          archD, archC,
          crashes, dirFails, ckDur, maxApplied, flag>>

-----------------------------------------------------------------------------
(* helpers *)
Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b
Range(s) == {s[i] : i \in DOMAIN s}

RECURSIVE FoldOps(_, _)
FoldOps(S, ops) ==
    IF ops = <<>> THEN S
    ELSE LET o == Head(ops) IN
         FoldOps(IF o.op = "put" THEN S \cup {o.c}
                 ELSE IF o.op = "del" THEN S \ {o.c} ELSE S, Tail(ops))

RECURSIVE FoldRuns(_, _, _)
FoldRuns(S, man, cont) ==
    IF man = <<>> THEN S ELSE FoldRuns(FoldOps(S, cont[Head(man)]), Tail(man), cont)

(* write record r at 1-based position p of content c; a gap reads as zeros *)
Write(c, p, r) ==
    IF p <= Len(c) THEN [c EXCEPT ![p] = r]
    ELSE [i \in 1..p |-> IF i <= Len(c) THEN c[i] ELSE IF i = p THEN r ELSE Z]

ZeroRange(c, x, y) == [i \in 1..Len(c) |-> IF i >= x /\ i <= y THEN Z ELSE c[i]]

(* the WAL as the page cache holds it: every event applied *)
RECURSIVE WalFold(_, _, _)
WalFold(c, pos, ev) ==
    IF ev = <<>> THEN c
    ELSE LET e == Head(ev) IN
         IF e.t = "app"   THEN WalFold(Write(c, pos + 1, e.r), pos + 1, Tail(ev))
         ELSE IF e.t = "trunc" THEN WalFold(SubSeq(c, 1, Min(e.a, Len(c))), e.a, Tail(ev))
         ELSE WalFold(ZeroRange(c, e.a, e.b), pos, Tail(ev))
WalC == WalFold(walD, Len(walD), walEv)

(* the WAL after a power loss: the first k appends survive (delalloc order;   *)
(* a hole would stop the replay exactly where a lost append does), a metadata *)
(* event survives iff committed or its journal entry survives (set S of walEv *)
(* indexes). ext4: nothing appended after a lost metadata event survives.     *)
RECURSIVE WalCrash(_, _, _, _, _, _, _)
WalCrash(c, pos, ev, i, napp, k, S) ==
    IF i > Len(ev) THEN c
    ELSE LET e == ev[i] IN
         IF e.t = "app" THEN
             IF napp < k THEN WalCrash(Write(c, pos + 1, e.r), pos + 1, ev, i + 1, napp + 1, k, S)
             ELSE WalCrash(c, pos + 1, ev, i + 1, napp + 1, k, S)
         ELSE LET keep == e.cm \/ i \in S
                  k2   == IF ~keep /\ FS = "ext4" THEN napp ELSE k   \* ext4: later appends lost
              IN IF e.t = "trunc" THEN
                     WalCrash(IF keep THEN SubSeq(c, 1, Min(e.a, Len(c))) ELSE c, e.a, ev, i + 1, napp, k2, S)
                 ELSE WalCrash(IF keep THEN ZeroRange(c, e.a, e.b) ELSE c, pos, ev, i + 1, napp, k2, S)

NApps(ev) == Cardinality({i \in DOMAIN ev : ev[i].t = "app"})

(* the WAL replay from record idx+1 (utxo_store_reload): records up to the  *)
(* first zero record; Hole = its position (0: none, the whole tail replayed)*)
RECURSIVE ScanTo(_, _)
ScanTo(w, i) == IF i > Len(w) THEN 0 ELSE IF w[i] = Z THEN i ELSE ScanTo(w, i + 1)
Hole(w, from) == ScanTo(w, from + 1)
Replayed(w, from) ==
    LET h == Hole(w, from) IN
    IF from >= Len(w) THEN <<>>
    ELSE IF h = 0 THEN SubSeq(w, from + 1, Len(w)) ELSE SubSeq(w, from + 1, h - 1)

(* the undo store: rev entries <<block, run version>>; the run a slot names *)
RevC == revD \o revU
RecCount(rev, b, v) == Cardinality({i \in DOMAIN rev : rev[i] = <<b, v>>})

(* apply journal entries (indexes in set T, in order) to a name state *)
RECURSIVE ApplyJ(_, _, _)
ApplyJ(st, js, i) ==
    IF i > Len(js) THEN st
    ELSE LET e == js[i] IN
         ApplyJ(IF e.k = "man" THEN [st EXCEPT !.man = e.v]
                ELSE IF e.k = "idx" \/ e.k = "idxtrunc" THEN [st EXCEPT !.idx = e.v]
                ELSE IF e.k = "hgt" THEN [st EXCEPT !.hgt = e.v]
                ELSE IF e.k = "mk"  THEN [st EXCEPT !.runs = @ \cup {e.v}]
                ELSE IF e.k = "rm"  THEN [st EXCEPT !.runs = @ \ {e.v}]
                ELSE st, js, i + 1)

DurNames == [man |-> manD, idx |-> idxD, hgt |-> hgtD, runs |-> runsD]
Sub(js, T) == [i \in 1..Cardinality(T) |->
                 js[CHOOSE j \in T : Cardinality({x \in T : x <= j}) = i]]

-----------------------------------------------------------------------------
(* commits *)
\* ext4 journal commit of (jnl \o pre); afterwards the journal holds `post`
Commit(pre, post) ==
    LET st == ApplyJ(DurNames, jnl \o pre, 1) IN
    /\ manD' = st.man /\ idxD' = st.idx /\ hgtD' = st.hgt /\ runsD' = st.runs
    /\ walEv' = [i \in DOMAIN walEv |-> IF walEv[i].t = "app" THEN walEv[i]
                                         ELSE [walEv[i] EXCEPT !.cm = TRUE]]
    /\ ckDur' = Max(ckDur, st.hgt)
    /\ jnl' = post
NamesU == <<manD, idxD, hgtD, runsD, walEv, ckDur>>
\* a successful sync of a regular file other than the WAL, with the name ops
\* queued before it (pre) and after it (post): ext4 commits the journal
Sync(pre, post) ==
    IF FS = "ext4" THEN Commit(pre, post)
    ELSE jnl' = jnl \o pre \o post /\ UNCHANGED NamesU
\* a run's create + fsync, then (post) the manifest's tmp fsync + rename. With
\* FixWeakDir a directory fsync sits between them (weak: commits the create).
RunSync(r, post) ==
    IF FS = "ext4" \/ ~FixWeakDir THEN Sync(<<J("mk", r)>>, post)
    ELSE LET names == {i \in DOMAIN (jnl \o <<J("mk", r)>>) : (jnl \o <<J("mk", r)>>)[i].k \in NameKinds}
             js    == jnl \o <<J("mk", r)>>
             st    == ApplyJ(DurNames, Sub(js, names), 1)
         IN /\ manD' = st.man /\ idxD' = st.idx /\ hgtD' = st.hgt /\ runsD' = st.runs
            /\ ckDur' = Max(ckDur, st.hgt)
            /\ jnl' = Sub(js, {i \in DOMAIN js : js[i].k \notin NameKinds}) \o post
            /\ UNCHANGED walEv
\* a successful directory fsync: weak commits the name ops of the directory
DirCommit ==
    IF FS = "ext4" THEN Commit(<<>>, <<>>)
    ELSE LET names == {i \in DOMAIN jnl : jnl[i].k \in NameKinds}
             st    == ApplyJ(DurNames, Sub(jnl, names), 1)
             rest  == {i \in DOMAIN jnl : jnl[i].k \notin NameKinds}
         IN /\ manD' = st.man /\ idxD' = st.idx /\ hgtD' = st.hgt /\ runsD' = st.runs
            /\ ckDur' = Max(ckDur, st.hgt)
            /\ jnl' = Sub(jnl, rest)
            /\ UNCHANGED walEv
\* fsync of the WAL: its data and its own metadata are durable (ext4: the journal too)
WalSyncOf(ev) ==
    /\ walD' = WalFold(walD, Len(walD), ev) /\ walEv' = <<>>
    /\ IF FS = "ext4" THEN
          LET st == ApplyJ(DurNames, jnl, 1) IN
          /\ manD' = st.man /\ idxD' = st.idx /\ hgtD' = st.hgt /\ runsD' = st.runs
          /\ ckDur' = Max(ckDur, st.hgt) /\ jnl' = <<>>
       ELSE /\ jnl' = Sub(jnl, {i \in DOMAIN jnl : jnl[i].k # "walmeta"})
            /\ UNCHANGED <<manD, idxD, hgtD, runsD, ckDur>>

DrainEv == [i \in 1..Len(walBuf) |-> App(walBuf[i])]

-----------------------------------------------------------------------------
Init ==
    /\ pc = "poll" /\ nb = 1 /\ ret = "none" /\ ret2 = "none"
    /\ memSet = {0} /\ memApplied = 0 /\ walBuf = <<>> /\ gen = <<>>
    /\ frozen = <<>> /\ fzState = "none" /\ fzEnd = 0 /\ fzRun = 0 /\ liveStart = 0
    /\ cmpState = "none" /\ cmpIn = <<>> /\ cmpRun = 0 /\ nextRun = 1 /\ flushes = 0
    /\ uver = 0 /\ gh = 0 /\ lo = 0
    /\ walD = <<>> /\ walEv = <<>> /\ revD = <<>> /\ revU = <<>>
    /\ slotD = [b \in Blocks |-> 0] /\ slotC = [b \in Blocks |-> 0]
    /\ manD = <<0>> /\ manC = <<0>> /\ idxD = 0 /\ idxC = 0 /\ hgtD = 0 /\ hgtC = 0
    /\ runsD = {0} /\ runsC = {0}
    /\ runCont = [r \in RunIds |-> IF r = 0 THEN <<Put(0)>> ELSE <<>>]
    /\ runDur = [r \in RunIds |-> r = 0]
    /\ jnl = <<>> /\ archD = 0 /\ archC = 0
    /\ crashes = 0 /\ dirFails = 0 /\ ckDur = 0 /\ maxApplied = 0 /\ flag = "ok"

FilesU == <<walD, walEv, revD, revU, slotD, slotC, manD, manC, idxD, idxC, hgtD, hgtC,
            runsD, runsC, runCont, runDur, jnl, archD, archC, ckDur>>
ProcU  == <<memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun, liveStart,
            cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo>>
MetaU  == <<crashes, dirFails, maxApplied, flag>>

Goto(p) == pc' = p

-----------------------------------------------------------------------------
(* ---- the block boundary: background adopts, then the next block ---- *)
Poll ==
    /\ pc = "poll"
    /\ \/ /\ ASYNC /\ fzState = "frozen"                 \* fz_poll (utxo_live.c:844)
          /\ Goto("ad_man") /\ ret2' = "poll"
          /\ UNCHANGED <<nb, ret, FilesU, ProcU, MetaU>>
       \/ /\ cmpState = "running"                         \* compact_poll (utxo_live.c:528)
          /\ Goto("cm_man")
          /\ UNCHANGED <<nb, ret, ret2, FilesU, ProcU, MetaU>>
       \/ /\ nb <= N /\ Goto("append")
          /\ UNCHANGED <<nb, ret, ret2, FilesU, ProcU, MetaU>>
       \/ /\ nb > N /\ Goto("end")
          /\ UNCHANGED <<nb, ret, ret2, FilesU, ProcU, MetaU>>

(* store_append: block bytes fdatasync'd, then the 48-byte index.dat record, *)
(* never synced on this path (bitcoin_store.asm:1192-1201).                   *)
ArchAppend ==
    /\ pc = "append"
    /\ archC' = Max(archC, nb)
    /\ archD' = IF FixArch THEN Max(archC, nb) ELSE archD
    /\ Goto("guard")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, MetaU, walD, walEv, revD, revU, slotD, slotC, manD, manC,
                   idxD, idxC, hgtD, hgtC, runsD, runsC, runCont, runDur, jnl, ckDur>>

(* apply_block_at_inner's ghost guard (utxo_live.c:3048-3051) *)
Guard ==
    /\ pc = "guard"
    /\ IF slotC[nb] # 0
       THEN /\ gh' = nb /\ lo' = nb /\ ret' = "verify" /\ Goto("rb_restore")
       ELSE /\ Goto("verify") /\ UNCHANGED <<gh, lo, ret>>
    /\ UNCHANGED <<nb, ret2, FilesU, memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun,
                   liveStart, cmpState, cmpIn, cmpRun, nextRun, flushes, uver, MetaU>>

(* tx_verify resolves every prevout before any mutation; a missing one is a *)
(* consensus REJECT, and the first one invalidates the block (4271-4290)    *)
Verify ==
    /\ pc = "verify"
    /\ IF (nb - 1) \in memSet
       THEN Goto("uslot") /\ UNCHANGED flag
       ELSE Goto("stop") /\ flag' = "reject"
    /\ UNCHANGED <<nb, ret, ret2, FilesU, ProcU, crashes, dirFails, maxApplied>>

(* undo_fd_for: the slot is registered (pwrite to undo.idx) at the first spend *)
USlot ==
    /\ pc = "uslot"
    /\ uver' = uver + 1
    /\ slotC' = [slotC EXCEPT ![nb] = uver + 1]
    /\ Goto("urec")
    /\ UNCHANGED <<nb, ret, ret2, MetaU, walD, walEv, revD, revU, slotD, manD, manC, idxD, idxC,
                   hgtD, hgtC, runsD, runsC, runCont, runDur, jnl, archD, archC, ckDur,
                   memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun, liveStart,
                   cmpState, cmpIn, cmpRun, nextRun, flushes, gh, lo>>

(* undo_append_record: writev to the rev file (O_APPEND), not synced *)
URec ==
    /\ pc = "urec"
    /\ IF FixUndo     \* candidate fix: the record and its slot durable before the spend's DEL
       THEN /\ revD' = RevC \o <<<<nb, slotC[nb]>>>> /\ revU' = <<>> /\ slotD' = slotC
       ELSE /\ revU' = Append(revU, <<nb, slotC[nb]>>) /\ UNCHANGED <<revD, slotD>>
    /\ Goto("del")
    /\ UNCHANGED <<nb, ret, ret2, MetaU, ProcU, walD, walEv, slotC, manD, manC, idxD,
                   idxC, hgtD, hgtC, runsD, runsC, runCont, runDur, jnl, archD, archC, ckDur>>

(* utxo_lsm_del -> utxo_store_del: the record goes to the 1 MB WAL buffer *)
DelOp ==
    /\ pc = "del"
    /\ walBuf' = Append(walBuf, Del(nb - 1)) /\ gen' = Append(gen, Del(nb - 1))
    /\ memSet' = memSet \ {nb - 1}
    /\ Goto("mf") /\ ret' = "put"
    /\ UNCHANGED <<nb, ret2, FilesU, memApplied, frozen, fzState, fzEnd, fzRun, liveStart,
                   cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo, MetaU>>

PutOp ==
    /\ pc = "put"
    /\ walBuf' = Append(walBuf, Put(nb)) /\ gen' = Append(gen, Put(nb))
    /\ memSet' = memSet \cup {nb}
    /\ Goto("mf") /\ ret' = "drain"
    /\ UNCHANGED <<nb, ret2, FilesU, memApplied, frozen, fzState, fzEnd, fzRun, liveStart,
                   cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo, MetaU>>

(* the flush threshold (op_count or fill) may be crossed after any put/del *)
MaybeFlush ==
    /\ pc = "mf"
    /\ \/ Goto(ret)
       \/ flushes < MaxFlush /\ Goto("fl_gate")
    /\ UNCHANGED <<nb, ret, ret2, FilesU, ProcU, MetaU>>

(* apply_block_at: undo_commit, then the block-end WAL drain (2994-3003) *)
Drain ==
    /\ pc = "drain"
    /\ walEv' = walEv \o DrainEv /\ walBuf' = <<>>
    /\ memApplied' = nb /\ maxApplied' = Max(maxApplied, nb)
    /\ Goto("ckq")
    /\ UNCHANGED <<nb, ret, ret2, walD, revD, revU, slotD, slotC, manD, manC, idxD, idxC, hgtD, hgtC,
                   runsD, runsC, runCont, runDur, jnl, archD, archC, ckDur, memSet,
                   gen, frozen, fzState, fzEnd, fzRun, liveStart, cmpState, cmpIn, cmpRun,
                   nextRun, flushes, uver, gh, lo, crashes, dirFails, flag>>

(* utxo_live_ckpt_due: a checkpoint after any block (batching), always at the end *)
CkQ ==
    /\ pc = "ckq"
    /\ \/ Goto("ck_undo") /\ UNCHANGED nb
       \/ nb < N /\ Goto("poll") /\ nb' = nb + 1
    /\ UNCHANGED <<ret, ret2, FilesU, ProcU, MetaU>>

(* persist_applied_height (utxo_live.c:1259-1325) *)
CkUndo ==   \* undo_sync: fdatasync the rev files and undo.idx (ST2-4)
    /\ pc = "ck_undo"
    /\ IF MUT = "noUndoSync"
       THEN UNCHANGED <<revD, revU, slotD, manD, idxD, hgtD, runsD, walEv, ckDur, jnl>>
       ELSE /\ revD' = RevC /\ revU' = <<>> /\ slotD' = slotC /\ Sync(<<>>, <<>>)
    /\ Goto("ck_wal")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, MetaU, walD, slotC, manC, idxC, hgtC, runsC, runCont,
                   runDur, archD, archC>>
CkWal ==    \* fsync(log_fd)
    /\ pc = "ck_wal"
    /\ IF MUT = "noWalFsync" THEN UNCHANGED <<walD, walEv, manD, idxD, hgtD, runsD, ckDur, jnl>>
       ELSE WalSyncOf(walEv)
    /\ Goto("ck_h")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, MetaU, revD, revU, slotD, slotC, manC, idxC, hgtC, runsC,
                   runCont, runDur, archD, archC>>
CkH ==      \* tmp write + fsync + rename
    /\ pc = "ck_h"
    /\ Sync(<<>>, <<J("hgt", memApplied)>>)
    /\ hgtC' = memApplied
    /\ Goto("ck_dir")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, MetaU, walD, revD, revU, slotD, slotC, manC, idxC,
                   runsC, runCont, runDur, archD, archC>>
CkDir ==    \* open(".") + fsync, result ignored (1317-1318)
    /\ pc = "ck_dir"
    /\ \/ /\ MUT # "noDirSync" /\ DirCommit /\ UNCHANGED dirFails
          /\ Goto("poll")
       \/ /\ dirFails < MaxDirFail /\ dirFails' = dirFails + 1
          /\ UNCHANGED <<manD, idxD, hgtD, runsD, walEv, ckDur, jnl>>
          /\ Goto(IF FixDir THEN "stop" ELSE "poll")
       \/ /\ MUT = "noDirSync"
          /\ UNCHANGED <<manD, idxD, hgtD, runsD, walEv, ckDur, jnl, dirFails>>
          /\ Goto("poll")
    /\ nb' = IF nb <= N THEN nb + 1 ELSE nb
    /\ UNCHANGED <<ret, ret2, ProcU, crashes, maxApplied, flag, walD, revD, revU, slotD, slotC,
                   manC, idxC, hgtC, runsC, runCont, runDur, archD, archC>>

-----------------------------------------------------------------------------
(* ---- the flush: mac_flush (inline) or fz_hook (async) ---- *)
(* the gate (mac_flush_hook -> compact_flush_hook) may start the one merge  *)
FlGate ==
    /\ pc = "fl_gate"
    /\ \/ /\ CompactOn /\ cmpState = "none" /\ Len(manC) >= 2
          /\ cmpState' = "running" /\ cmpIn' = SubSeq(manC, 1, 2)
          /\ cmpRun' = nextRun /\ nextRun' = nextRun + 1
       \/ UNCHANGED <<cmpState, cmpIn, cmpRun, nextRun>>
    /\ IF ASYNC
       THEN IF fzState # "none" THEN Goto("ad_man") /\ ret2' = "fl_freeze"   \* fz_wait, then adopt
            ELSE Goto("fl_freeze") /\ UNCHANGED ret2
       ELSE Goto("fl_drain") /\ UNCHANGED ret2
    /\ UNCHANGED <<nb, ret, FilesU, memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun,
                   liveStart, flushes, uver, gh, lo, MetaU>>

(* inline mac_flush (bitcoin_utxo_lsm.asm:3150-3365) *)
FlDrain ==
    /\ pc = "fl_drain"
    /\ walEv' = walEv \o DrainEv /\ walBuf' = <<>>
    /\ Goto("fl_run")
    /\ UNCHANGED <<nb, ret, ret2, MetaU, walD, revD, revU, slotD, slotC, manD, manC, idxD, idxC,
                   hgtD, hgtC, runsD, runsC, runCont, runDur, jnl, archD, archC, ckDur,
                   memSet, memApplied, gen, frozen, fzState, fzEnd, fzRun, liveStart,
                   cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo>>
FlRun ==    \* mac_build_run: create, write, fsync (checked, ST2-1), close
    /\ pc = "fl_run"
    /\ runCont' = [runCont EXCEPT ![nextRun] = gen]
    /\ runDur' = [runDur EXCEPT ![nextRun] = (MUT # "noRunFsync")]
    /\ runsC' = runsC \cup {nextRun}
    /\ IF MUT = "noRunFsync" THEN jnl' = jnl \o <<J("mk", nextRun)>> /\ UNCHANGED NamesU
       ELSE RunSync(nextRun, <<>>)
    /\ Goto("fl_man")
    /\ UNCHANGED <<nb, ret, ret2, MetaU, ProcU, walD, revD, revU, slotD, slotC, manC, idxC, hgtC,
                   archD, archC>>
FlMan ==    \* utxo_manifest.tmp: write, fsync (checked), rename
    /\ pc = "fl_man"
    /\ Sync(<<>>, <<J("man", Append(manC, nextRun))>>)
    /\ manC' = Append(manC, nextRun)
    /\ nextRun' = nextRun + 1 /\ flushes' = flushes + 1
    /\ Goto(IF MUT = "truncBeforeDir" THEN "fl_reset" ELSE "fl_dir")
    /\ UNCHANGED <<nb, ret, ret2, MetaU, walD, revD, revU, slotD, slotC, idxC, hgtC, runsC,
                   runCont, runDur, archD, archC, memSet, memApplied, walBuf, gen, frozen,
                   fzState, fzEnd, fzRun, liveStart, cmpState, cmpIn, cmpRun, uver, gh, lo>>
FlDir ==    \* open(".") + fsync, checked since ST2-1: a failure fails the flush
    /\ pc = "fl_dir"
    /\ \/ /\ MUT # "noDirSync" /\ DirCommit /\ UNCHANGED dirFails
          /\ Goto(IF MUT = "truncBeforeDir" THEN ret ELSE "fl_reset")
       \/ /\ dirFails < MaxDirFail /\ dirFails' = dirFails + 1
          /\ UNCHANGED <<manD, idxD, hgtD, runsD, walEv, ckDur, jnl>>
          /\ Goto("stop")
       \/ /\ MUT = "noDirSync"
          /\ UNCHANGED <<manD, idxD, hgtD, runsD, walEv, ckDur, jnl, dirFails>>
          /\ Goto(IF MUT = "truncBeforeDir" THEN ret ELSE "fl_reset")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, crashes, maxApplied, flag, walD, revD, revU, slotD, slotC,
                   manC, idxC, hgtC, runsC, runCont, runDur, archD, archC>>
FlReset ==  \* .fl_finish_reset: ftruncate(utxo.idx, 0), ftruncate(utxo.dat, 0), memtable cleared
    /\ pc = "fl_reset"
    /\ idxC' = 0
    /\ walEv' = Append(walEv, Trunc(0))
    /\ jnl' = jnl \o <<J("idxtrunc", 0), J("walmeta", Len(walEv) + 1)>>
    /\ gen' = <<>>
    /\ Goto(IF MUT = "truncBeforeDir" THEN "fl_dir" ELSE ret)
    /\ UNCHANGED <<nb, ret, ret2, MetaU, walD, revD, revU, slotD, slotC, manD, manC, idxD, hgtD,
                   hgtC, runsD, runsC, runCont, runDur, archD, archC, ckDur, memSet, memApplied,
                   walBuf, frozen, fzState, fzEnd, fzRun, liveStart, cmpState, cmpIn, cmpRun,
                   nextRun, flushes, uver, gh, lo>>

(* async: utxo_lsm_freeze (asm:2549-2640) + fork of the writer (fz_hook) *)
FlFreeze ==
    /\ pc = "fl_freeze"
    /\ walEv' = walEv \o DrainEv /\ walBuf' = <<>>
    /\ frozen' = gen /\ gen' = <<>>
    /\ fzEnd' = Len(WalFold(walD, Len(walD), walEv \o DrainEv))
    /\ fzRun' = nextRun /\ nextRun' = nextRun + 1 /\ flushes' = flushes + 1
    /\ fzState' = "frozen"
    /\ Goto(ret)
    /\ UNCHANGED <<nb, ret, ret2, MetaU, walD, revD, revU, slotD, slotC, manD, manC, idxD, idxC,
                   hgtD, hgtC, runsD, runsC, runCont, runDur, jnl, archD, archC, ckDur,
                   memSet, memApplied, liveStart, cmpState, cmpIn, cmpRun, uver, gh, lo>>

(* fz_adopt (utxo_live.c:806-841): the writer's run (built + fsynced in the child), *)
(* lsm_manifest_publish (lsm_manifest.c:64-80): tmp, fsync, rename, dir fsync ignored *)
AdMan ==
    /\ pc = "ad_man"
    /\ runCont' = [runCont EXCEPT ![fzRun] = frozen]
    /\ runDur' = [runDur EXCEPT ![fzRun] = (MUT # "noRunFsync")]
    /\ runsC' = runsC \cup {fzRun}
    /\ manC' = Append(manC, fzRun)
    /\ IF MUT = "noRunFsync"
       THEN jnl' = jnl \o <<J("mk", fzRun), J("man", Append(manC, fzRun))>> /\ UNCHANGED NamesU
       ELSE RunSync(fzRun, <<J("man", Append(manC, fzRun))>>)   \* run fsync, then tmp fsync + rename
    /\ Goto("ad_dir1")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, MetaU, walD, revD, revU, slotD, slotC, idxC, hgtC,
                   archD, archC>>
DirIgnored(next) ==   \* a C-side open(".") + fsync whose result is ignored
    \/ /\ MUT # "noDirSync" /\ DirCommit /\ UNCHANGED dirFails /\ Goto(next)
    \/ /\ dirFails < MaxDirFail /\ dirFails' = dirFails + 1
       /\ UNCHANGED <<manD, idxD, hgtD, runsD, walEv, ckDur, jnl>>
       /\ Goto(IF FixDir THEN "stop" ELSE next)
    \/ /\ MUT = "noDirSync"
       /\ UNCHANGED <<manD, idxD, hgtD, runsD, walEv, ckDur, jnl, dirFails>> /\ Goto(next)
AdDir1 ==
    /\ pc = "ad_dir1" /\ DirIgnored(IF MUT = "punchBeforeIdx" THEN "ad_punch"
                                    ELSE IF FixLogOff THEN "ad_walsync" ELSE "ad_idx")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, crashes, maxApplied, flag, walD, revD, revU, slotD, slotC,
                   manC, idxC, hgtC, runsC, runCont, runDur, archD, archC>>
AdWalSync ==   \* candidate fix: fsync(log_fd) so the WAL's durable length reaches fz_wal_end
    /\ pc = "ad_walsync"
    /\ WalSyncOf(walEv)
    /\ Goto("ad_idx")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, MetaU, revD, revU, slotD, slotC, manC, idxC, hgtC, runsC,
                   runCont, runDur, archD, archC>>
(* fz_retire_wal (utxo_live.c:767-797): utxo.idx.tmp {log_off = fz_wal_end}, *)
(* fsync, rename, dir fsync ignored, then PUNCH_HOLE over the retired bytes  *)
AdIdx ==
    /\ pc = "ad_idx"
    /\ Sync(<<>>, <<J("idx", fzEnd)>>)
    /\ idxC' = fzEnd
    /\ Goto("ad_dir2")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, MetaU, walD, revD, revU, slotD, slotC, manC, hgtC,
                   runsC, runCont, runDur, archD, archC>>
AdDir2 ==
    /\ pc = "ad_dir2" /\ DirIgnored(IF MUT = "punchBeforeIdx" THEN "ad_fin" ELSE "ad_punch")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, crashes, maxApplied, flag, walD, revD, revU, slotD, slotC,
                   manC, idxC, hgtC, runsC, runCont, runDur, archD, archC>>
AdPunch ==
    /\ pc = "ad_punch"
    /\ IF fzEnd > liveStart
       THEN /\ walEv' = Append(walEv, Punch(liveStart + 1, fzEnd))
            /\ jnl' = Append(jnl, J("walmeta", Len(walEv) + 1))
       ELSE UNCHANGED <<walEv, jnl>>
    /\ liveStart' = fzEnd
    /\ Goto(IF MUT = "punchBeforeIdx" THEN "ad_idx" ELSE "ad_fin")
    /\ UNCHANGED <<nb, ret, ret2, MetaU, walD, revD, revU, slotD, slotC, manD, manC, idxD, idxC,
                   hgtD, hgtC, runsD, runsC, runCont, runDur, archD, archC, ckDur,
                   memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun,
                   cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo>>
AdFin ==
    /\ pc = "ad_fin"
    /\ fzState' = "none" /\ frozen' = <<>>
    /\ Goto(ret2)
    /\ UNCHANGED <<nb, ret, ret2, FilesU, MetaU, memSet, memApplied, walBuf, gen, fzEnd, fzRun,
                   liveStart, cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo>>

(* the background merge: child writes + fsyncs the merged run and          *)
(* utxo_manifest.child; compact_adopt -> lsm_manifest_adopt_child publishes *)
(* (dir fsync ignored), then the inputs are unlinked (utxo_live.c:492-527)  *)
CmMan ==
    /\ pc = "cm_man"
    /\ runCont' = [runCont EXCEPT ![cmpRun] = runCont[cmpIn[1]] \o runCont[cmpIn[2]]]
    /\ runDur' = [runDur EXCEPT ![cmpRun] = (MUT # "noRunFsync")]
    /\ runsC' = runsC \cup {cmpRun}
    /\ manC' = <<cmpRun>> \o SubSeq(manC, 3, Len(manC))
    /\ IF MUT = "noRunFsync"
       THEN jnl' = jnl \o <<J("mk", cmpRun), J("man", <<cmpRun>> \o SubSeq(manC, 3, Len(manC)))>>
            /\ UNCHANGED NamesU
       ELSE RunSync(cmpRun, <<J("man", <<cmpRun>> \o SubSeq(manC, 3, Len(manC)))>>)
    /\ Goto("cm_dir")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, MetaU, walD, revD, revU, slotD, slotC, idxC, hgtC,
                   archD, archC>>
CmDir ==
    /\ pc = "cm_dir" /\ DirIgnored("cm_unlink")
    /\ UNCHANGED <<nb, ret, ret2, ProcU, crashes, maxApplied, flag, walD, revD, revU, slotD, slotC,
                   manC, idxC, hgtC, runsC, runCont, runDur, archD, archC>>
CmUnlink ==
    /\ pc = "cm_unlink"
    /\ runsC' = runsC \ Range(cmpIn)
    /\ jnl' = jnl \o <<J("rm", cmpIn[1]), J("rm", cmpIn[2])>>
    /\ cmpState' = "done"
    /\ Goto("poll")
    /\ UNCHANGED <<nb, ret, ret2, MetaU, walD, walEv, revD, revU, slotD, slotC, manD, manC, idxD,
                   idxC, hgtD, hgtC, runsD, runCont, runDur, archD, archC, ckDur,
                   memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun, liveStart,
                   cmpIn, cmpRun, nextRun, flushes, uver, gh, lo>>

-----------------------------------------------------------------------------
(* ---- the rollback of a ghost block (rollback_unapplied_block, 3297-3326) ---- *)
RbRestore ==   \* undo_replay_tolerant -> undo_restore_cb: put the spent coin back if absent
    /\ pc = "rb_restore"
    /\ IF RecCount(RevC, gh, slotC[gh]) >= 1 /\ (gh - 1) \notin memSet
       THEN /\ walBuf' = Append(walBuf, Put(gh - 1)) /\ gen' = Append(gen, Put(gh - 1))
            /\ memSet' = memSet \cup {gh - 1}
       ELSE UNCHANGED <<walBuf, gen, memSet>>
    /\ Goto("rb_del")
    /\ UNCHANGED <<nb, ret, ret2, FilesU, MetaU, memApplied, frozen, fzState, fzEnd, fzRun,
                   liveStart, cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo>>
RbDel ==       \* del_created_on_output: delete the block's output if present
    /\ pc = "rb_del"
    /\ IF gh \in memSet
       THEN /\ walBuf' = Append(walBuf, Del(gh)) /\ gen' = Append(gen, Del(gh))
            /\ memSet' = memSet \ {gh}
       ELSE UNCHANGED <<walBuf, gen, memSet>>
    /\ Goto(IF FixRecov THEN "rb_sync" ELSE "rb_discard")
    /\ UNCHANGED <<nb, ret, ret2, FilesU, MetaU, memApplied, frozen, fzState, fzEnd, fzRun,
                   liveStart, cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo>>
RbSync ==      \* candidate fix: drain + fsync the WAL before the slot is cleared
    /\ pc = "rb_sync"
    /\ walBuf' = <<>>
    /\ WalSyncOf(walEv \o DrainEv)
    /\ Goto("rb_discard")
    /\ UNCHANGED <<nb, ret, ret2, MetaU, revD, revU, slotD, slotC, manC, idxC, hgtC, runsC,
                   runCont, runDur, archD, archC, memSet, memApplied, gen, frozen, fzState,
                   fzEnd, fzRun, liveStart, cmpState, cmpIn, cmpRun, nextRun, flushes, uver, gh, lo>>
RbDiscard ==   \* undo_discard -> us_slot_clear: pwrite of a zero slot, not synced
    /\ pc = "rb_discard"
    /\ slotC' = [slotC EXCEPT ![gh] = 0]
    /\ IF gh > lo THEN gh' = gh - 1 /\ Goto("rb_restore") ELSE Goto(ret) /\ UNCHANGED gh
    /\ UNCHANGED <<nb, ret, ret2, MetaU, walD, walEv, revD, revU, slotD, manD, manC, idxD, idxC,
                   hgtD, hgtC, runsD, runsC, runCont, runDur, jnl, archD, archC, ckDur,
                   memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun, liveStart,
                   cmpState, cmpIn, cmpRun, nextRun, flushes, uver, lo>>

-----------------------------------------------------------------------------
(* ---- crashes ---- *)
ProcReset ==
    /\ walBuf' = <<>> /\ frozen' = <<>> /\ fzState' = "none" /\ fzEnd' = 0 /\ fzRun' = 0
    /\ cmpState' = IF cmpState = "done" THEN "done" ELSE "none"
    /\ cmpIn' = <<>> /\ cmpRun' = 0 /\ gh' = 0 /\ lo' = 0 /\ ret' = "none" /\ ret2' = "none"
    /\ Goto("rec_reload")
    /\ crashes' = crashes + 1

(* SIGKILL / OOM: process memory (WAL buffer, memtable, children) is lost; *)
(* the page cache survives, so the next process reads every written byte  *)
Kill ==
    /\ KillOn /\ crashes < MaxCrash
    /\ ProcReset
    /\ UNCHANGED <<nb, memSet, memApplied, gen, liveStart, nextRun, flushes, uver, FilesU,
                   dirFails, maxApplied, flag>>

(* power loss: each file falls back to a state the FS model allows *)
JChoices ==
    IF FS = "ext4" THEN {1..p : p \in 0..Len(jnl)} ELSE SUBSET (1..Len(jnl))
SlotChoices ==
    IF FS = "ext4" THEN {slotD, slotC}
    ELSE {[b \in Blocks |-> IF b \in X THEN slotC[b] ELSE slotD[b]] : X \in SUBSET Blocks}

Power ==
    /\ PowerOn /\ crashes < MaxCrash
    /\ \E T \in JChoices, k \in 0..NApps(walEv), sl \in SlotChoices,
          j \in 0..Len(revU), a \in archD..archC :
        LET st  == ApplyJ(DurNames, Sub(jnl, T), 1)
            S   == {jnl[i].v : i \in {x \in T : jnl[x].k = "walmeta"}}
            w   == WalCrash(walD, Len(walD), walEv, 1, 0, k, S)
            rs  == {r \in st.runs : runDur[r]}    \* a run never fsynced is empty or torn: unreadable
        IN /\ walD' = w /\ walEv' = <<>>
           /\ manD' = st.man /\ manC' = st.man /\ idxD' = st.idx /\ idxC' = st.idx
           /\ hgtD' = st.hgt /\ hgtC' = st.hgt /\ runsD' = rs /\ runsC' = rs
           /\ slotD' = sl /\ slotC' = sl
           /\ revD' = revD \o SubSeq(revU, 1, j) /\ revU' = <<>>
           /\ archD' = a /\ archC' = a
           /\ jnl' = <<>>
    /\ ProcReset
    /\ UNCHANGED <<nb, memSet, memApplied, gen, liveStart, nextRun, flushes, uver, runCont, runDur,
                   ckDur, dirFails, maxApplied, flag>>

-----------------------------------------------------------------------------
(* ---- recovery: utxo_live_init (reload, sweep) + utxo_live_recover_at_boot ---- *)
SeqOf(X) == [i \in 1..Cardinality(X) |-> CHOOSE r \in X : Cardinality({x \in X : x <= r}) = i]
RmAll(X) == [i \in 1..Cardinality(X) |-> J("rm", SeqOf(X)[i])]
RecReload ==
    /\ pc = "rec_reload"
    /\ LET w   == WalC
           rep == Replayed(w, idxC)
           h   == Hole(w, idxC)
           bad == \E i \in DOMAIN manC : manC[i] \notin runsC
       IN
       IF bad THEN /\ flag' = "broken" /\ Goto("stop")       \* a named run is missing: lookups fail
                   /\ UNCHANGED <<walEv, jnl, runsC, memSet, memApplied, gen, liveStart, nb, nextRun,
                                   manD, idxD, hgtD, runsD>>
       ELSE IF hgtC > archC
       THEN /\ flag' = "archhalt" /\ Goto("stop")            \* STO-1 guard (utxo_live.c:3471-3489)
            /\ UNCHANGED <<walEv, jnl, runsC, memSet, memApplied, gen, liveStart, nb, nextRun,
                            manD, idxD, hgtD, runsD>>
       ELSE
       /\ memSet' = FoldOps(FoldRuns({}, manC, runCont), rep)
       /\ gen' = rep
       /\ memApplied' = hgtC /\ nb' = hgtC + 1
       \* advance_counters: next_run_no = 1 + the largest run the manifest names
       /\ nextRun' = 1 + CHOOSE r \in Range(manC) : \A x \in Range(manC) : x <= r
       /\ liveStart' = idxC
       \* UTX-4 torn tail: ftruncate the WAL at the first record it cannot read
       /\ IF h # 0 /\ idxC < Len(w)
          THEN /\ walEv' = Append(walEv, Trunc(h - 1))
               /\ jnl' = Append(jnl, J("walmeta", Len(walEv) + 1)) \o RmAll(runsC \ Range(manC))
          ELSE /\ UNCHANGED walEv
               /\ jnl' = jnl \o RmAll(runsC \ Range(manC))
       \* lsm_manifest_sweep_orphans: unlink the run files the manifest does not name
       /\ runsC' = runsC \cap Range(manC)
       \* FixWeakDir (weak only): the directory is fsynced before the sweep, so the
       \* manifest the sweep trusts is durable before any unlink
       /\ IF FixWeakDir /\ FS = "weak"
          THEN LET names == {i \in DOMAIN jnl : jnl[i].k \in NameKinds}
                   st    == ApplyJ(DurNames, Sub(jnl, names), 1)
               IN /\ manD' = st.man /\ idxD' = st.idx /\ hgtD' = st.hgt /\ runsD' = st.runs
          ELSE UNCHANGED <<manD, idxD, hgtD, runsD>>
       /\ Goto("rec_scan") /\ UNCHANGED flag
    /\ UNCHANGED <<ret, ret2, walD, revD, revU, slotD, slotC, manC, idxC, hgtC,
                   runCont, runDur, archD, archC, ckDur, walBuf, frozen, fzState, fzEnd,
                   fzRun, cmpState, cmpIn, cmpRun, flushes, uver, gh, lo,
                   crashes, dirFails, maxApplied>>

(* utxo_live_recover_partial_block (3393-3431): the contiguous ghost run *)
RECURSIVE HiFrom(_)
HiFrom(h) == IF h <= N /\ slotC[h] # 0 THEN HiFrom(h + 1) ELSE h - 1
RecScan ==
    /\ pc = "rec_scan"
    /\ LET l == memApplied + 1
           hi == HiFrom(l)
       IN IF hi >= l THEN gh' = hi /\ lo' = l /\ ret' = "rec_done" /\ Goto("rb_restore")
          ELSE Goto("rec_done") /\ UNCHANGED <<gh, lo, ret>>
    /\ UNCHANGED <<nb, ret2, FilesU, memSet, memApplied, walBuf, gen, frozen, fzState, fzEnd, fzRun,
                   liveStart, cmpState, cmpIn, cmpRun, nextRun, flushes, uver, MetaU>>

RecDone ==
    /\ pc = "rec_done"
    /\ Goto("poll") /\ nb' = memApplied + 1
    /\ UNCHANGED <<ret, ret2, FilesU, ProcU, MetaU>>

Done == pc \in {"end", "stop"} /\ UNCHANGED vars

Next ==
    \/ Poll \/ ArchAppend \/ Guard \/ Verify \/ USlot \/ URec \/ DelOp \/ PutOp \/ MaybeFlush
    \/ Drain \/ CkQ \/ CkUndo \/ CkWal \/ CkH \/ CkDir
    \/ FlGate \/ FlDrain \/ FlRun \/ FlMan \/ FlDir \/ FlReset \/ FlFreeze
    \/ AdMan \/ AdDir1 \/ AdWalSync \/ AdIdx \/ AdDir2 \/ AdPunch \/ AdFin \/ CmMan \/ CmDir \/ CmUnlink
    \/ RbRestore \/ RbDel \/ RbSync \/ RbDiscard
    \/ RecReload \/ RecScan \/ RecDone
    \/ Kill \/ Power
    \/ Done

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* ---- properties, checked when recovery completes (pc = "rec_done") ---- *)
Expected(h) == {h}
NoResurrection == pc = "rec_done" => memSet \subseteq Expected(memApplied)
NoLoss         == pc = "rec_done" => Expected(memApplied) \subseteq memSet
RecConsistent  == pc = "rec_done" => memSet = Expected(memApplied)
HeightInRange  == pc = "rec_done" => ckDur <= memApplied /\ memApplied <= maxApplied
\* every applied block keeps its undo (a reorg must be able to disconnect it)
UndoAgrees     == pc = "rec_done" =>
                    \A b \in Blocks : b <= memApplied => slotC[b] # 0 /\ RecCount(RevC, b, slotC[b]) >= 1
\* no undo slot is left above the recovered height (informational: a stale slot of the
\* same chain is rolled back harmlessly by the apply's guard; see PROTOCOL.md)
NoStaleSlot    == pc = "rec_done" => \A b \in Blocks : b > memApplied => slotC[b] = 0
StoreReadable  == flag # "broken"
NoFalseReject  == flag # "reject"
ArchiveCovers  == flag # "archhalt"
\* a clean block boundary in normal operation always holds the expected set
SteadyState    == pc = "poll" => memSet = Expected(memApplied)
\* vacuity: these must be reachable (checked as violated invariants in run.sh)
NeverRecovers  == pc # "rec_done"
NeverEnds      == pc # "end"
=============================================================================
