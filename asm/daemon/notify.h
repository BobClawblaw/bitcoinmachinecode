/* daemon/notify.h -- Core's -*notify hooks. See notify.c for why the
 * substituted value is sanitised and why the fork is doubled. */
#ifndef BMC_NOTIFY_H
#define BMC_NOTIFY_H
/* Run `cmd_template` with every "%s" replaced by a sanitised `value`.
 * Does nothing when the template is empty. Never blocks the caller.
 * `what` names the hook in log lines ("blocknotify", ...). */
void notify_run(const char* cmd_template, const char* value, const char* what);
#endif
