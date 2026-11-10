/* start.c -- process start on the SysV side (bmc_win).
 *
 * winsys' PE entry builds argv/envp (UTF-8) and calls __bmc_start, which
 * plays musl's __libc_start_main: a fake auxv after envp, __init_libc (it
 * calls our __init_tls below and musl's own __init_ssp), the constructors,
 * then exit(main()). */
#define _GNU_SOURCE
#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include "pthread_impl.h"
#include "libc.h"

__thread uintptr_t __bmc_win_tp;
volatile int __thread_list_lock;

__attribute__((ms_abi)) void __bmc_win_run_ctors(void);
__attribute__((ms_abi)) long __bmc_win_syscall(long, long, long, long, long, long, long);

static struct pthread main_thread;

/* musl's __init_tls: the main thread's descriptor, and the thread pointer */
void __init_tls(size_t *aux)
{
	pthread_t td = &main_thread;
	(void)aux;
	td->self = td;
	__bmc_win_tp = (uintptr_t)td;
	libc.can_do_threads = 1;
	libc.tls_size = sizeof main_thread;
	libc.tls_align = 16;
	td->detach_state = DT_JOINABLE;
	td->tid = __syscall(SYS_set_tid_address, &__thread_list_lock);
	td->locale = &libc.global_locale;
	td->robust_list.head = &td->robust_list.head;
	td->sysinfo = __sysinfo;
	td->next = td->prev = td;
	td->tsd = (void **)__pthread_tsd_main;
	td->stack_size = 16 << 20;
}

int main(int, char **, char **);

int __bmc_start(int argc, char **argv, char **envp)
{
	size_t n = 0;
	while (envp[n])
		n++;
	/* envp, NULL, then the auxv __init_libc expects right behind it */
	static unsigned char rnd[16];
	__syscall(SYS_getrandom, rnd, sizeof rnd, 0);
	char **ev = malloc((n + 1) * sizeof(char *) + 16 * sizeof(size_t));
	if (!ev)
		a_crash();
	memcpy(ev, envp, (n + 1) * sizeof(char *));
	size_t *aux = (size_t *)(ev + n + 1);
	size_t i = 0;
	aux[i++] = AT_PAGESZ;  aux[i++] = 4096;
	aux[i++] = AT_RANDOM;  aux[i++] = (size_t)rnd;
	aux[i++] = AT_HWCAP;   aux[i++] = 0;
	aux[i++] = AT_UID;     aux[i++] = 1000;
	aux[i++] = AT_EUID;    aux[i++] = 1000;
	aux[i++] = AT_GID;     aux[i++] = 1000;
	aux[i++] = AT_EGID;    aux[i++] = 1000;
	aux[i++] = 0;          aux[i++] = 0;
	/* argv[0] as a Linux-looking path, so __progname is the bare name */
	if (argv[0])
		for (char *p = argv[0]; *p; p++)
			if (*p == '\\')
				*p = '/';
	__init_libc(ev, argv[0]);
	__bmc_win_run_ctors();
	exit(main(argc, argv, ev));
}

/* musl's static-TLS reset (timer threads); bmc_win has no static TLS image */
void __reset_tls(void)
{
}
