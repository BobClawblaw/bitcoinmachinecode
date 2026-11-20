/* spawn.c -- musl's __clone for posix_spawn (bmc_win).
 *
 * musl's posix_spawn (and so system and popen) runs its child with
 * __clone(fn, stack, CLONE_VM|CLONE_VFORK|SIGCHLD, arg): fn applies the file
 * actions, then execs or _exits(127), reporting failure through a
 * close-on-exec pipe. A copy-on-write fork gives fn everything it relies on,
 * so __clone forks (the raw syscall: posix_spawn holds __abort_lock, which
 * _Fork would take again) and runs fn in the child. execve is winsys'. */
#include <unistd.h>
#include "pthread_impl.h"
#include "syscall.h"
#include "libc.h"

int __clone(int (*fn)(void *), void *stack, int flags, void *arg, ...)
{
	(void)stack;
	(void)flags;
	long r = __syscall(SYS_fork);
	if (r == 0) {
		pthread_t self = __pthread_self();
		self->tid = __syscall(SYS_gettid);
		self->next = self->prev = self;
		libc.threads_minus_1 = 0;
		if (libc.need_locks)
			libc.need_locks = -1;
		_exit(fn(arg));
	}
	return (int)r;
}
