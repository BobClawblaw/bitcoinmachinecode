/* test_win_tty.c -- /dev/tty is the console: open it r+, isatty, termios
 * reports a cooked terminal (ICANON, ECHO, ISIG), echo can be switched off
 * and back (what a passphrase prompt does), and writes reach the console.
 * Without a console /dev/tty is ENXIO, as Linux says with no controlling
 * terminal; that is all it checks then. Run it in a console window to see
 * the rest. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static int fails;
static void ck(const char *l, int c) { printf("%s: %s\n", c ? "ok  " : "FAIL", l); fails += !c; }

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	FILE *tty = fopen("/dev/tty", "r+");
	if (!tty) {
		ck("no console: /dev/tty is ENXIO", errno == ENXIO);
		printf(fails ? "%d FAILED\n" : "ALL TESTS PASSED (no console)\n", fails);
		return fails != 0;
	}
	int fd = fileno(tty);
	ck("isatty(/dev/tty)", isatty(fd));
	struct termios old, t;
	ck("tcgetattr", tcgetattr(fd, &old) == 0);
	ck("a cooked terminal: ICANON ECHO ISIG",
	   (old.c_lflag & ICANON) && (old.c_lflag & ECHO) && (old.c_lflag & ISIG));
	t = old;
	t.c_lflag &= ~(tcflag_t)ECHO;
	ck("echo off (TCSAFLUSH)", tcsetattr(fd, TCSAFLUSH, &t) == 0);
	ck("...and reported off", tcgetattr(fd, &t) == 0 && !(t.c_lflag & ECHO) && (t.c_lflag & ICANON));
	ck("echo back on", tcsetattr(fd, TCSANOW, &old) == 0 && tcgetattr(fd, &t) == 0 && (t.c_lflag & ECHO));
	ck("a write reaches the console", fprintf(tty, "test_win_tty: hello, console\n") > 0 && fflush(tty) == 0);
	fclose(tty);
	printf(fails ? "%d FAILED\n" : "ALL TESTS PASSED\n", fails);
	return fails != 0;
}
