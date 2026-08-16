/*
 * wallet_book.c -- minimal persistent address book for the ASM wallet CLI.
 *
 * WHY: as we move to mainnet we need to remember real addresses by name (e.g.
 * "our wallet", "user's other wallet") instead of pasting raw 26-62-char
 * strings into send commands. This module adds a tiny, own-format, versioned
 * name->address mapping, consistent with the project's "no BDB, own format"
 * philosophy (see wallet_store.c).
 *
 * FILE FORMAT (textual, auditable, versioned):
 *   BMCABK v1
 *   <label> <address>
 *   # comments and blank lines ignored; one entry per line; address may not
 *   contain spaces.
 *
 * ABI (plain C, stdio-only, no new deps):
 *   int  book_add(const char* path, const char* label, const char* addr);
 *   int  book_set(const char* path, const char* label, const char* addr);
 *   int  book_rm (const char* path, const char* label);
 *   int  book_get(const char* path, const char* label, char* addr, int cap);
 *   int  book_list(const char* path, char* out, int cap);  // human-readable
 *   int  book_validate(const char* label); // label sanity
 * All return 0 on success, -1 on failure (missing file / label not found for
 * get/rm).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BMCABK_MAGIC "BMCABK v1"

/* ---- helpers ---------------------------------------------------------- */
static int label_ok(const char* lb) {
    if (!lb || !lb[0]) return 0;
    /* labels: alnum, '_', '-', '.', max 48 chars, no spaces */
    int n = 0;
    for (const char* p = lb; *p; p++) {
        if (*p == ' ' || *p == '\t') return 0;
        if (!((*p>='a'&&*p<='z')||(*p>='A'&&*p<='Z')||(*p>='0'&&*p<='9')||
              *p=='_'||*p=='-'||*p=='.')) return 0;
        if (++n > 48) return 0;
    }
    return 1;
}

/* Rewrite the whole book with in-memory entries, preserving valid entries and
 * applying the caller's edit via a callback style: this helper is generic. */

/* Read the book into a dynamically allocated array of (label,address) pairs.
 * Returns count, or -1 on error; caller frees via book_free if *out != NULL. */
struct book_e {
    char label[64];
    char addr[128];
};
static int book_read_all(const char* path, struct book_e** out) {
    *out = NULL;
    FILE* f = fopen(path, "r");
    if (!f) return -1;
    struct book_e* arr = NULL;
    int n = 0, cap = 0;
    char line[256];
    int first = 1;
    while (fgets(line, sizeof line, f)) {
        size_t l = strlen(line);
        while (l && (line[l-1]=='\n' || line[l-1]=='\r')) line[--l]=0;
        if (first) { first = 0; if (!strncmp(line, BMCABK_MAGIC, strlen(BMCABK_MAGIC))) continue; }
        if (!line[0] || line[0]=='#') continue;
        char* sp = strchr(line, ' ');
        if (!sp) continue;                 /* ignore malformed (label only) */
        *sp = 0;
        char* label = line; char* addr = sp + 1;
        if (!label[0] || !addr[0]) continue;
        if (n == cap) { cap = cap? cap*2 : 8; struct book_e* na = realloc(arr, (size_t)cap*sizeof(*arr)); if (!na){free(arr);fclose(f);return -1;} arr = na; }
        snprintf(arr[n].label, sizeof arr[n].label, "%s", label);
        snprintf(arr[n].addr,  sizeof arr[n].addr,  "%s", addr);
        n++;
    }
    fclose(f);
    *out = arr;
    return n;
}

/* ---- public API ------------------------------------------------------- */

int book_validate(const char* label) { return label_ok(label) ? 0 : -1; }

/* Add or update (set) a label. Returns 0 on success. */
int book_set(const char* path, const char* label, const char* addr, int overwrite) {
    if (!path || !label_ok(label) || !addr || !addr[0]) return -1;
    struct book_e* arr = NULL;
    int n = book_read_all(path, &arr);
    if (n < 0) n = 0;                        /* missing/unreadable -> empty book */
    int found = -1;
    for (int i = 0; i < n; i++) if (!strcmp(arr[i].label, label)) { found = i; break; }
    if (found >= 0) {
        if (!overwrite) { free(arr); return 1; }    /* exists, no overwrite */
        snprintf(arr[found].addr, sizeof arr[found].addr, "%s", addr);
    } else {
        struct book_e* tmp = realloc(arr, (size_t)(n+1)*sizeof(*arr));
        if (!tmp) { free(arr); return -1; }
        arr = tmp;
        snprintf(arr[n].label, sizeof arr[n].label, "%s", label);
        snprintf(arr[n].addr,  sizeof arr[n].addr,  "%s", addr);
        n++;
    }
    /* rewrite via book_write_all with a tiny adapter */
    /* simplest: write manually through book_write_all is awkward; do inline */
    char tmp[1024];
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE* f = fopen(tmp, "w");
    if (!f) { free(arr); return -1; }
    fprintf(f, BMCABK_MAGIC "\n");
    for (int i = 0; i < n; i++) fprintf(f, "%s %s\n", arr[i].label, arr[i].addr);
    fclose(f); chmod(tmp, 0600);
    if (rename(tmp, path) != 0) { remove(tmp); free(arr); return -1; }
    chmod(path, 0600);
    free(arr);
    return 0;
}

/* Remove a label. Returns 0 on success, -1 if not found. */
int book_rm(const char* path, const char* label) {
    struct book_e* arr = NULL;
    int n = book_read_all(path, &arr);
    int found = -1;
    for (int i = 0; i < n; i++) if (!strcmp(arr[i].label, label)) { found = i; break; }
    if (found < 0) { free(arr); return -1; }
    for (int i = found; i < n-1; i++) arr[i] = arr[i+1];
    n--;
    char tmp[1024]; snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE* f = fopen(tmp, "w");
    if (!f) { free(arr); return -1; }
    fprintf(f, BMCABK_MAGIC "\n");
    for (int i = 0; i < n; i++) fprintf(f, "%s %s\n", arr[i].label, arr[i].addr);
    fclose(f); chmod(tmp, 0600);
    if (rename(tmp, path) != 0) { remove(tmp); free(arr); return -1; }
    chmod(path, 0600);
    free(arr);
    return 0;
}

/* Look up a label -> address. Returns 0 + addr on success, -1 if not found. */
int book_get(const char* path, const char* label, char* addr, int cap) {
    struct book_e* arr = NULL;
    int n = book_read_all(path, &arr);
    for (int i = 0; i < n; i++) if (!strcmp(arr[i].label, label)) {
        snprintf(addr, (size_t)cap, "%s", arr[i].addr);
        free(arr);
        return 0;
    }
    free(arr);
    return -1;
}

/* List the whole book into a text buffer. Returns 0 on success. */
int book_list(const char* path, char* out, int cap) {
    struct book_e* arr = NULL;
    int n = book_read_all(path, &arr);
    int used = 0;
    for (int i = 0; i < n && used < cap-1; i++) {
        int w = snprintf(out+used, (size_t)(cap-used), "%s %s\n", arr[i].label, arr[i].addr);
        if (w < 0) break;
        used += w;
    }
    free(arr);
    return 0;
}
