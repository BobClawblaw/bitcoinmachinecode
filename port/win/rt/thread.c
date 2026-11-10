/* thread.c -- pthread_create/exit/join/detach on Win32 threads (bmc_win).
 *
 * musl's own thread code is clone/set_thread_area based; everything else in
 * its thread directory (mutexes, condvars, rwlocks, keys, once) runs as is on
 * the futex emulation. This file keeps musl's thread-descriptor protocol:
 * the descriptor is the thread pointer (__bmc_win_tp), the thread list is
 * kept under __tl_lock, detach_state arbitrates detach-vs-exit, and the
 * Win32 thread handle rides in the descriptor's otherwise unused map_base. */
#define _GNU_SOURCE
#include "pthread_impl.h"
#include "stdio_impl.h"
#include "libc.h"
#include "lock.h"
#include <string.h>
#include <stdlib.h>

extern __thread uintptr_t __bmc_win_tp;
__attribute__((ms_abi)) long __bmc_win_thread_create(void *(*fn)(void *), void *arg, size_t stack,
						     void **handle_out, int *tid_out);
__attribute__((ms_abi)) long __bmc_win_thread_join(void *handle);
__attribute__((ms_abi)) void __bmc_win_thread_close(void *handle);

static void init_file_lock(FILE *f)
{
	if (f && f->lock < 0)
		f->lock = 0;
}

/* musl's stdio defines these when it is linked; weak references here */
extern FILE *volatile __stdin_used weak;
extern FILE *volatile __stdout_used weak;
extern FILE *volatile __stderr_used weak;
#define STD_USED(x) (&(x) ? (x) : 0)

static int tl_lock_count;
static int tl_lock_waiters;

void __tl_lock(void)
{
	int tid = __pthread_self()->tid;
	int val = __thread_list_lock;
	if (val == tid) {
		tl_lock_count++;
		return;
	}
	while ((val = a_cas(&__thread_list_lock, 0, tid)))
		__wait(&__thread_list_lock, &tl_lock_waiters, val, 0);
}

void __tl_unlock(void)
{
	if (tl_lock_count) {
		tl_lock_count--;
		return;
	}
	a_store(&__thread_list_lock, 0);
	if (tl_lock_waiters)
		__wake(&__thread_list_lock, 1, 0);
}

void __tl_sync(pthread_t td)
{
	(void)td;
	a_barrier();
	int val = __thread_list_lock;
	if (!val)
		return;
	__wait(&__thread_list_lock, &tl_lock_waiters, val, 0);
	if (tl_lock_waiters)
		__wake(&__thread_list_lock, 1, 0);
}

static void release(pthread_t t)
{
	if (t->map_base)
		__bmc_win_thread_close(t->map_base);
	free(t->tsd);
	free(t);
}

static void unlink_thread(pthread_t self)
{
	__tl_lock();
	self->next->prev = self->prev;
	self->prev->next = self->next;
	self->prev = self->next = self;
	if (!--libc.threads_minus_1)
		libc.need_locks = -1;
	__tl_unlock();
}

_Noreturn void __pthread_exit(void *result)
{
	pthread_t self = __pthread_self();
	self->canceldisable = 1;
	self->cancelasync = 0;
	self->result = result;
	while (self->cancelbuf) {
		void (*f)(void *) = self->cancelbuf->__f;
		void *x = self->cancelbuf->__x;
		self->cancelbuf = self->cancelbuf->__next;
		f(x);
	}
	__pthread_tsd_run_dtors();
	if (self->next == self) {
		/* the last thread: the process ends, atexit handlers run */
		exit(0);
	}
	int state = a_cas(&self->detach_state, DT_JOINABLE, DT_EXITING);
	unlink_thread(self);
	self->tid = 0;
	if (state == DT_DETACHED) {
		if (self->map_base)           /* not the static main descriptor */
			release(self);
	} else {
		a_store(&self->detach_state, DT_EXITED);
		__wake(&self->detach_state, 1, 1);
	}
	for (;;)
		__syscall(SYS_exit, 0);
}

weak_alias(__pthread_exit, pthread_exit);

struct start_args {
	void *(*fn)(void *);
	void *arg;
	pthread_t self;
	volatile int ready;
};

static void *start(void *p)
{
	struct start_args *a = p;
	pthread_t self = a->self;
	void *(*fn)(void *) = a->fn;
	void *arg = a->arg;
	__bmc_win_tp = (uintptr_t)self;
	self->tid = __syscall(SYS_gettid);
	/* wait until the creator has linked us in and stored our handle */
	while (!a->ready)
		__futexwait(&a->ready, 0, 1);
	free(a);
	__pthread_exit(fn(arg));
}

int __pthread_create(pthread_t *restrict res, const pthread_attr_t *restrict attrp,
		     void *(*entry)(void *), void *restrict arg)
{
	pthread_attr_t attr = { 0 };
	if (attrp && attrp != __ATTRP_C11_THREAD)
		attr = *attrp;
	size_t stack = attr._a_stacksize ? attr._a_stacksize : (8 << 20);
	pthread_t self = __pthread_self();
	pthread_t t = calloc(1, sizeof *t);
	void **tsd = calloc(1, __pthread_tsd_size);
	struct start_args *a = calloc(1, sizeof *a);
	if (!t || !tsd || !a) {
		free(t);
		free(tsd);
		free(a);
		return EAGAIN;
	}
	if (!libc.threaded) {
		for (FILE *f = *__ofl_lock(); f; f = f->next)
			init_file_lock(f);
		__ofl_unlock();
		init_file_lock(STD_USED(__stdin_used));
		init_file_lock(STD_USED(__stdout_used));
		init_file_lock(STD_USED(__stderr_used));
		libc.threaded = 1;
	}
	t->self = t;
	t->tsd = tsd;
	t->locale = &libc.global_locale;
	t->robust_list.head = &t->robust_list.head;
	t->canary = self->canary;
	t->sysinfo = self->sysinfo;
	t->stack_size = stack;
	t->detach_state = attr._a_detach ? DT_DETACHED : DT_JOINABLE;
	a->fn = entry;
	a->arg = arg;
	a->self = t;
	__tl_lock();
	if (!libc.threads_minus_1++)
		libc.need_locks = 1;
	void *h = NULL;
	int tid = 0;
	long r = __bmc_win_thread_create(start, a, stack, &h, &tid);
	if (r < 0) {
		if (!--libc.threads_minus_1)
			libc.need_locks = 0;
		__tl_unlock();
		free(t);
		free(tsd);
		free(a);
		return EAGAIN;
	}
	t->map_base = h;
	t->tid = tid;
	t->next = self->next;
	t->prev = self;
	t->next->prev = t;
	t->prev->next = t;
	__tl_unlock();
	*res = t;
	a_store(&a->ready, 1);
	__wake(&a->ready, 1, 1);
	return 0;
}

weak_alias(__pthread_create, pthread_create);

static int join(pthread_t t, void **res)
{
	if (t->map_base)
		__bmc_win_thread_join(t->map_base);
	while (t->detach_state != DT_EXITED)
		__futexwait(&t->detach_state, t->detach_state, 1);
	if (res)
		*res = t->result;
	release(t);
	return 0;
}

int __pthread_join(pthread_t t, void **res)
{
	if (t == __pthread_self())
		return EDEADLK;
	return join(t, res);
}

weak_alias(__pthread_join, pthread_join);

int __pthread_tryjoin_np(pthread_t t, void **res)
{
	return t->detach_state == DT_JOINABLE || t->detach_state == DT_EXITING ? EBUSY : join(t, res);
}

weak_alias(__pthread_tryjoin_np, pthread_tryjoin_np);

int __pthread_timedjoin_np(pthread_t t, void **res, const struct timespec *at)
{
	int s = t->detach_state;
	while (s == DT_JOINABLE || s == DT_EXITING) {
		int r = __timedwait(&t->detach_state, s, CLOCK_REALTIME, at, 1);
		if (r == ETIMEDOUT)
			return r;
		s = t->detach_state;
	}
	return join(t, res);
}

weak_alias(__pthread_timedjoin_np, pthread_timedjoin_np);

static int __pthread_detach(pthread_t t)
{
	if (a_cas(&t->detach_state, DT_JOINABLE, DT_DETACHED) != DT_JOINABLE)
		return __pthread_join(t, 0);
	return 0;
}

weak_alias(__pthread_detach, pthread_detach);
weak_alias(__pthread_detach, thrd_detach);

int pthread_getattr_np(pthread_t t, pthread_attr_t *a)
{
	memset(a, 0, sizeof *a);
	a->_a_detach = t->detach_state >= DT_DETACHED;
	a->_a_stacksize = t->stack_size;
	return 0;
}

/* no asynchronous cancellation on bmc_win */
void pthread_testcancel(void)
{
}

/* musl runs __synccall to apply set*id to every thread; ids are fixed here */
void __synccall(void (*func)(void *), void *ctx)
{
	func(ctx);
}
