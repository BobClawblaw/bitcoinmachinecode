/* daemon/sd_watchdog.h -- systemd's service watchdog, fed by the serve parent
 * only while the download worker's progress stamp moves. See sd_watchdog.c. */
#ifndef BMC_SD_WATCHDOG_H
#define BMC_SD_WATCHDOG_H

/* Read NOTIFY_SOCKET / WATCHDOG_USEC / WATCHDOG_PID (the serve parent, before
 * it forks the worker) and unset them. Returns the timeout in ms, 0 = off. */
long long sdw_init(void);
/* The parent's loop: ping systemd if the worker's stamp moved since the last
 * ping and a quarter of the timeout has passed. */
void sdw_tick(long long now_ms, long long worker_beat_ms);
unsigned long sdw_pings(void);

/* exposed for tests/test_sd_watchdog.c */
int sdw_should_ping(long long now_ms, long long beat_ms, long long last_ping_ms,
                    long long last_beat_pinged, long long timeout_ms);
long long sdw_parse_usec(const char* s);

#endif
