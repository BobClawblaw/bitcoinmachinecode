# Note for the Windows side: two security fixes to build, test and merge

From the x86 side, 2026-11-20. These are the two findings from the #499
review. They are on branch `fix/2026-11-20-win-security` (off
`windows-port` at `466fe254`). **They have not been compiled or run
anywhere:** the x86 side has no Windows toolchain. Only the two new tests
were compiled there, with gcc as Linux C, and `test_win_crash_exit` passes
on Linux. Please build, gate and revert-check them before merging them
into `windows-port`.

## 1. Owner-only files (`winsys/ws_fd.c`)

Mode bits were only recorded (`BMCMODE`); a 0600 file kept its directory's
inherited DACL while `stat()` said 0600. Now:

- `owner_only_bind()`, called at the end of `ws_fd_init()`, loads advapi32
  at run time, as `fill_random` does, and builds two protected DACLs: this
  user and SYSTEM, `FILE_ALL_ACCESS`. The directory DACL is inheritable
  (OI|CI). If binding fails it prints one `[win] owner-only access
  unavailable (...)` line and the old behaviour stays.
- `sys_open`: `CreateFileW` gets owner-only security attributes when
  `O_CREAT` and `(mode & ~umask) & 077 == 0`. Windows applies them only to
  a file it creates. On the `ERROR_USER_MAPPED_FILE` replacement path the
  new file takes the old file's mode, and so its DACL; before, an
  `O_TRUNC` without `O_CREAT` made it 0644.
- `sys_mkdir`: the same through `CreateDirectoryW`.
- `sys_chmod` / `sys_fchmod`: to owner-only bits, the protected DACL is
  set (`SetSecurityInfo` on a `WRITE_DAC` reopen, or
  `SetNamedSecurityInfoW` by path). From owner-only to group/other bits,
  inheritance is restored by path (`UNPROTECTED_DACL` + an empty ACL). A
  file that was not owner-only keeps its DACL. A failure is returned as
  the call's errno; `ERROR_NOT_SUPPORTED` and `ERROR_INVALID_FUNCTION`
  (FAT/exFAT) count as success.

Points I could not settle without Windows:
- That `SetNamedSecurityInfoW` with `UNPROTECTED_DACL_SECURITY_INFORMATION`
  and an empty ACL brings the parent's inheritable ACEs back. The test
  checks it ("inheritance is back").
- `mkdtemp` makes its directory 0700, so it is owner-only and everything
  the tests create under `/tmp/...XXXXXX` inherits that. That is
  deliberate (stricter than Linux), but look for a test that expected
  something else.

Test: `tests/test_win_owner_only.c` reads each DACL back with `icacls`
through `popen` (`(I)` = inherited, `(F)` = full, in any display
language). **Revert check:** with the `psa`/`owner_only_chmod` calls taken
out, the "owner-only" checks must fail.

## 2. No WER dump on a crash (`winsys/ws_sig.c`)

`last_chance` returned `EXCEPTION_CONTINUE_SEARCH`, so an unhandled fault
went to Windows Error Reporting. `SEM_NOGPFAULTERRORBOX` hides only the
dialog; with `LocalDumps` set, or a report queued, WER can write a dump
holding the wallet seed. It now calls
`TerminateProcess(GetCurrentProcess(), ExceptionCode)` after the crash log
and the robust-lock release. The exit code is what Windows would have
used, so `status_of` (ws_fork.c) still reads SIGSEGV.

Test: `tests/test_win_crash_exit.c` checks that status for a forked child
and a `posix_spawn`ed program.

**Manual check (administrator; LocalDumps is HKLM only):**

```bat
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\test_win_crash_exit.exe" /v DumpFolder /t REG_EXPAND_SZ /d C:\wer-check /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\test_win_crash_exit.exe" /v DumpType /t REG_DWORD /d 2 /f
:: run test_win_crash_exit.exe with the fix reverted: C:\wer-check gets .dmp files
:: run it with the fix: C:\wer-check stays empty
reg delete "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps\test_win_crash_exit.exe" /f
```

## Docs

`port/WIN_PORT.md` has a new "Security: what stands in for Linux's"
section. Add a dated line to `WIN_STATE.md` once the gate has passed.
