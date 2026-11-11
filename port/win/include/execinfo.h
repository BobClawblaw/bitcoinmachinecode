/* execinfo.h -- glibc's backtrace API (bmc_win; rt/execinfo.c). The SysV
 * code carries no unwind tables, so backtrace() scans the stack for words
 * that point into the executable's code: the likely return addresses, a
 * crash trace's raw material. backtrace_symbols* print "exe+0xRVA". */
#ifndef BMC_WIN_EXECINFO_H
#define BMC_WIN_EXECINFO_H
#ifdef __cplusplus
extern "C" {
#endif
int backtrace(void **buffer, int size);
char **backtrace_symbols(void *const *buffer, int size);
void backtrace_symbols_fd(void *const *buffer, int size, int fd);
#ifdef __cplusplus
}
#endif
#endif
