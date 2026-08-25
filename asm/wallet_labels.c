/*
 * wallet_labels.c -- Core-shaped address labels for the wallet RPCs.
 *
 * WHY A NEW STORE, given wallet_book.c already exists: the two model
 * different things. wallet_book.c is keyed by LABEL and holds one address per
 * label -- it is the CLI's "my nicknames for other people's addresses" book.
 * Core's wallet labels are keyed by ADDRESS: every address in the wallet has
 * exactly one label (default ""), and one label may name MANY addresses. That
 * inversion cannot be expressed by a label-keyed file without changing its
 * format under the CLI, so labels get their own store rather than a
 * reinterpretation of someone else's.
 *
 * Format -- `data/labels.dat`, one record per line:
 *
 *     BMCLBL v1
 *     <address> <label...>
 *
 * The address is first and contains no spaces, so everything after the first
 * space is the label, verbatim to end-of-line. That is deliberate: Core
 * labels are arbitrary UTF-8 up to 255 bytes and routinely contain spaces
 * ("cold storage"), and a store that silently mangled them would be worse
 * than one that refused them. A label may not contain a newline, since the
 * record is line-delimited; setlabel reports that rather than truncating.
 *
 * An address with no record has the empty label, exactly as in Core -- so an
 * absent file is a valid, complete, all-default store, not an error.
 *
 * Writes are whole-file rewrites through a temp file + rename, so a crash
 * mid-write leaves the previous complete store rather than a torn one. The
 * file is small (one line per labelled address); this is not a hot path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BMCLBL_MAGIC "BMCLBL v1"
#define LBL_MAX_ADDR 128
#define LBL_MAX_LABEL 256      /* Core caps labels at 255 bytes + NUL */

typedef struct { char addr[LBL_MAX_ADDR]; char label[LBL_MAX_LABEL]; } lbl_e;

/* Core's cap. Returns 1 if the label is storable, 0 otherwise. Empty is
 * legal and means "the default label", which is stored as an absent record. */
int lbl_validate(const char* label){
    if (!label) return 0;
    size_t n = strlen(label);
    if (n > 255) return 0;
    if (memchr(label, '\n', n) || memchr(label, '\r', n)) return 0;
    return 1;
}

/* Read the whole store. Returns the record count (0 for an absent file, which
 * is a valid empty store), or -1 only on a malloc failure. *out is malloc'd
 * when the count is > 0 and must be free()d by the caller. */
static int lbl_read_all(const char* path, lbl_e** out){
    *out = NULL;
    FILE* f = fopen(path, "r");
    if (!f) return 0;                       /* absent == empty, not an error */
    char line[LBL_MAX_ADDR + LBL_MAX_LABEL + 8];
    int cap = 16, n = 0;
    lbl_e* arr = malloc((size_t)cap * sizeof *arr);
    if (!arr){ fclose(f); return -1; }
    while (fgets(line, sizeof line, f)){
        size_t l = strlen(line);
        while (l && (line[l-1] == '\n' || line[l-1] == '\r')) line[--l] = 0;
        if (!l || line[0] == '#' || !strncmp(line, BMCLBL_MAGIC, 9)) continue;
        char* sp = strchr(line, ' ');
        if (!sp) continue;                  /* no label field -> torn, skip */
        *sp = 0;
        if (!line[0] || strlen(line) >= LBL_MAX_ADDR) continue;
        if (strlen(sp+1) >= LBL_MAX_LABEL) continue;
        if (n == cap){
            lbl_e* g = realloc(arr, (size_t)(cap*2) * sizeof *arr);
            if (!g){ free(arr); fclose(f); return -1; }
            arr = g; cap *= 2;
        }
        snprintf(arr[n].addr,  sizeof arr[n].addr,  "%s", line);
        snprintf(arr[n].label, sizeof arr[n].label, "%s", sp+1);
        n++;
    }
    fclose(f);
    if (n == 0){ free(arr); return 0; }
    *out = arr;
    return n;
}

static int lbl_write_all(const char* path, const lbl_e* arr, int n){
    char tmp[512];
    if (snprintf(tmp, sizeof tmp, "%s.tmp", path) >= (int)sizeof tmp) return -1;
    FILE* f = fopen(tmp, "w");
    if (!f) return -1;
    int bad = fprintf(f, "%s\n", BMCLBL_MAGIC) < 0;
    for (int i = 0; i < n && !bad; i++)
        if (fprintf(f, "%s %s\n", arr[i].addr, arr[i].label) < 0) bad = 1;
    /* fflush+fsync before rename: the rename is only meaningful once the
     * bytes are durable, otherwise a crash can publish an empty file. */
    if (!bad && fflush(f) != 0) bad = 1;
    if (!bad && fsync(fileno(f)) != 0) bad = 1;
    if (fclose(f) != 0) bad = 1;
    if (bad){ unlink(tmp); return -1; }
    if (rename(tmp, path) != 0){ unlink(tmp); return -1; }
    return 0;
}

/* The label for `addr`, or "" when unlabelled. Never fails: an unreadable or
 * absent store means every address carries the default label. */
int lbl_get(const char* path, const char* addr, char* out, int cap){
    if (cap > 0) out[0] = 0;
    lbl_e* arr = NULL;
    int n = lbl_read_all(path, &arr);
    for (int i = 0; i < n; i++)
        if (!strcmp(arr[i].addr, addr)){ snprintf(out, (size_t)cap, "%s", arr[i].label); break; }
    free(arr);
    return 0;
}

/* Set (or clear, with "") the label of one address. An address has exactly
 * one label, so this REPLACES any existing record rather than adding a
 * second -- that is Core's model, and the reason labels live here and not in
 * the label-keyed wallet_book. Returns 0, or -1 on a bad label / IO failure. */
int lbl_set(const char* path, const char* addr, const char* label){
    if (!addr || !addr[0] || strlen(addr) >= LBL_MAX_ADDR) return -1;
    if (strchr(addr, ' ')) return -1;
    if (!lbl_validate(label)) return -1;
    lbl_e* arr = NULL;
    int n = lbl_read_all(path, &arr);
    if (n < 0) return -1;
    /* drop the address's existing record, if any */
    int w = 0;
    for (int i = 0; i < n; i++) if (strcmp(arr[i].addr, addr)) arr[w++] = arr[i];
    n = w;
    int rc;
    if (label[0]){
        lbl_e* g = realloc(arr, (size_t)(n + 1) * sizeof *arr);
        if (!g){ free(arr); return -1; }
        arr = g;
        snprintf(arr[n].addr,  sizeof arr[n].addr,  "%s", addr);
        snprintf(arr[n].label, sizeof arr[n].label, "%s", label);
        n++;
    }
    /* clearing to "" is a removal: the default label is stored as absence */
    rc = lbl_write_all(path, arr, n);
    free(arr);
    return rc;
}

/* Iterate. Returns the record count; lbl_get_i fills caller buffers. */
int lbl_count(const char* path){
    lbl_e* arr = NULL; int n = lbl_read_all(path, &arr); free(arr);
    return n < 0 ? 0 : n;
}

int lbl_get_i(const char* path, int i, char* addr, int addrcap, char* label, int labelcap){
    lbl_e* arr = NULL;
    int n = lbl_read_all(path, &arr);
    int ok = 0;
    if (i >= 0 && i < n){
        snprintf(addr,  (size_t)addrcap,  "%s", arr[i].addr);
        snprintf(label, (size_t)labelcap, "%s", arr[i].label);
        ok = 1;
    }
    free(arr);
    return ok;
}
