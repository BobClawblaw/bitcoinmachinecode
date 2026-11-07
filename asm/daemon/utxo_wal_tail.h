/* daemon/utxo_wal_tail.h -- the WAL bytes a reload of the UTXO store replays.
 *
 * That is utxo.dat past utxo.idx's log_off, not utxo.dat's length. Plan B3
 * (2026-10-06) retires a flushed generation by advancing log_off and
 * punching the retired bytes out, so the file's LENGTH keeps every retired
 * byte as a hole for the life of the store: st_size alone calls a
 * steady-state store "a huge tail" at every boot after a sync.
 *
 * utxo_live.c measured it this way from the start; tx_accept.c sized its
 * validation snapshot from st_size until 2026-11-07, so production's serve
 * parent built a 2^24-slot table (767 MB, all of it written by utxo_init)
 * for a 4.3 GB utxo.dat that held 4.3 MB of data. utxo_live.c reads the
 * tail; tx_accept.c reads utxo_reload_bytes (the tail and the checkpoint).
 *
 * Run from the chain directory (both callers are). 0 when utxo.dat is
 * missing; an unreadable or old utxo.idx counts log_off as 0 (the whole
 * file), which is what a reload replays in that case too. */
#ifndef BMC_UTXO_WAL_TAIL_H
#define BMC_UTXO_WAL_TAIL_H
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
static inline unsigned long long utxo_wal_tail_bytes(void){
    struct stat wb; if (stat("utxo.dat", &wb) != 0) return 0;
    unsigned long long off = 0; FILE* f = fopen("utxo.idx", "rb");
    if (f){ unsigned char h[20]; if (fread(h, 1, 20, f) == 20){ uint32_t m; memcpy(&m, h, 4); if (m == 0x55545849u) memcpy(&off, h + 4, 8); } fclose(f); }
    return (unsigned long long)wb.st_size > off ? (unsigned long long)wb.st_size - off : 0;
}
/* Everything a reload reads into the memtable: utxo.idx's checkpoint (its n
 * live records, restored before the tail; 0 since the retire writes n = 0,
 * but a utxo_store_sync checkpoint can hold any number) plus the WAL tail.
 * Every record is at least 44 bytes in either file, so this bounds the
 * entries (bytes/44) and the scripts a reload can bring back. */
static inline unsigned long long utxo_reload_bytes(void){
    struct stat ib; unsigned long long idx = stat("utxo.idx", &ib) == 0 ? (unsigned long long)ib.st_size : 0;
    return utxo_wal_tail_bytes() + idx;
}
#endif
