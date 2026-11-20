/* test_win_crash_exit.c -- an unhandled fault ends the process in our
 * last-chance filter, not in Windows Error Reporting, and the exit status
 * still reads as the signal.
 *
 * last_chance (ws_sig.c) used to return EXCEPTION_CONTINUE_SEARCH, handing
 * the crash to WER, which can write a dump of the process (the wallet seed
 * is in its memory). It now calls TerminateProcess with the exception code,
 * the status Windows would have given. This checks that the status is the
 * same as before, for a forked child and for a spawned program:
 * WIFSIGNALED with SIGSEGV. Whether WER wrote a dump needs an administrator
 * (LocalDumps lives under HKLM); that check is manual, in
 * worklog/2026-11-20-note-for-win.md. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

extern char **environ;
static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

static void crash(void)
{
	static volatile uintptr_t where = 16;          /* volatile: the compiler cannot see it is invalid */
	*(volatile int *)where = 1;                    /* no SIGSEGV handler: unhandled */
}

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc > 1 && !strcmp(argv[1], "--crash")) {
		crash();
		return 0;
	}

	pid_t c = fork();
	if (c == 0) {
		crash();
		_exit(0);
	}
	int st = 0;
	ck("forked child: waitpid", c > 0 && waitpid(c, &st, 0) == c);
	printf("      status 0x%x\n", st);
	ck("forked child: killed by SIGSEGV", WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);

	char *args[] = { argv[0], "--crash", NULL };
	pid_t s = -1;
	ck("spawned program: posix_spawn", posix_spawn(&s, argv[0], NULL, NULL, args, environ) == 0);
	st = 0;
	ck("spawned program: waitpid", s > 0 && waitpid(s, &st, 0) == s);
	printf("      status 0x%x\n", st);
	ck("spawned program: killed by SIGSEGV", WIFSIGNALED(st) && WTERMSIG(st) == SIGSEGV);

	printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
	return fails ? 1 : 0;
}
