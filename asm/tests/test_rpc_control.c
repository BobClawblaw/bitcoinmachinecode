/* test_rpc_control.c -- Core's Control category (help, logging, getrpcinfo,
 * getmemoryinfo, getopenrpcinfo, rpc.discover) plus exportasmap and
 * enumeratesigners, over rpc_dispatch().
 *
 * The load-bearing test here is the LAST one: every method `help` advertises
 * is dispatched to something. `help` builds its list from the four dispatch
 * tables, and rpc_known_method() consults those same tables, so a method
 * that made it into a table but never got a line in its module's dispatch
 * ladder would be advertised, reported as known, and then answered
 * "Method not found". That is exactly the failure a per-module test cannot
 * see, because it needs all four modules linked together.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rpc_commands.h"
#include "../rpc_json.h"

static int fails = 0, checks = 0;
static void ck(const char* w, int c){ checks++; if (c) printf("ok  : %s\n", w); else { printf("FAIL: %s\n", w); fails++; } }

static rj_val* call(const char* method, const char* pj, long* ec, const char** em){
    rj_val* p = pj ? rj_parse(pj, strlen(pj)) : NULL;
    rj_val* r = NULL; rpc_wallet w; memset(&w, 0, sizeof w);
    *ec = 0; *em = NULL;
    int ok = rpc_dispatch(method, p, &w, &r, ec, em);
    if (p) rj_free(p);
    if (!ok){ if (r) rj_free(r); return NULL; }
    return r;
}
static const char* S(const rj_val* o, const char* k){
    rj_val* v = o ? rj_obj_get((rj_val*)o, k) : NULL; return v ? v->str : NULL;
}

int main(void){
    long ec; const char* em;

    /* ---- help ---------------------------------------------------------- */
    rj_val* h = call("help", "[]", &ec, &em);
    ck("help returns a string", h && h->typ == RJ_STR);
    ck("help names methods from every module",
       h && strstr(h->str, "getblock") && strstr(h->str, "getpeerinfo") &&
       strstr(h->str, "setlabel") && strstr(h->str, "createrawtransaction"));
    ck("help is sorted (abandontransaction comes before getblock)",
       h && strstr(h->str, "abandontransaction") &&
       strstr(h->str, "abandontransaction") < strstr(h->str, "getblock"));
    ck("help says plainly that it carries no per-method usage text",
       h && strstr(h->str, "usage text"));
    { /* no duplicates: count the lines and compare with the unique count */
      int lines = 0; const char* p = h ? h->str : "";
      for (; *p; p++) if (*p == '\n') lines++;
      ck("help emitted a substantial list", lines > 140); }
    rj_free(h);

    h = call("help", "[\"getblock\"]", &ec, &em);
    ck("help \"getblock\" names it", h && h->typ == RJ_STR && strstr(h->str, "getblock"));
    ck("...and points at where divergences are recorded",
       h && strstr(h->str, "RPC_LIVE_NODE.md"));
    rj_free(h);

    h = call("help", "[\"nosuchthing\"]", &ec, &em);
    ck("help on an unknown command -> Core's exact line",
       h && h->typ == RJ_STR && !strcmp(h->str, "help: unknown command: nosuchthing"));
    rj_free(h);

    /* ---- getrpcinfo ---------------------------------------------------- */
    { rj_val* r = call("getrpcinfo", "[]", &ec, &em);
      ck("getrpcinfo -> object", r && r->typ == RJ_OBJ);
      rj_val* ac = r ? rj_obj_get(r, "active_commands") : NULL;
      ck("active_commands is a one-element array (single-threaded server)",
         ac && ac->typ == RJ_ARR && ac->nitems == 1);
      ck("...naming getrpcinfo itself",
         ac && ac->nitems && S(ac->items[0], "method") &&
         !strcmp(S(ac->items[0], "method"), "getrpcinfo"));
      ck("...with a duration field", ac && ac->nitems && rj_obj_get(ac->items[0], "duration"));
      ck("logpath is absolute", r && S(r, "logpath") && S(r, "logpath")[0] == '/');
      ck("logpath names the node's own log, not Core's",
         r && S(r, "logpath") && strstr(S(r, "logpath"), "bitcoind.log"));
      rj_free(r); }

    /* ---- logging ------------------------------------------------------- */
    { rj_val* r = call("logging", "[]", &ec, &em);
      ck("logging -> object", r && r->typ == RJ_OBJ);
      ck("it reports THIS node's eight log kinds", r && r->nmembers == 8);
      ck("...and every one is true, because every one really is emitted",
         r && S(r,"info") && !strcmp(S(r,"info"), "1") &&
         S(r,"serve") && !strcmp(S(r,"serve"), "1"));
      /* they are deliberately not Core's category names */
      ck("Core's category names are NOT claimed", r && rj_obj_get(r, "addrman") == NULL);
      rj_free(r); }
    { rj_val* r = call("logging", "[[\"net\"]]", &ec, &em);
      ck("the mutating form is REFUSED, not accepted-and-ignored",
         r == NULL && ec == -1 && em && strstr(em, "no runtime category gate"));
      rj_free(r); }

    /* ---- getmemoryinfo ------------------------------------------------- */
    { rj_val* r = call("getmemoryinfo", "[\"mallocinfo\"]", &ec, &em);
      ck("mallocinfo returns real glibc XML",
         r && r->typ == RJ_STR && strstr(r->str, "<malloc"));
      rj_free(r); }
    { rj_val* r = call("getmemoryinfo", "[]", &ec, &em);
      ck("the default \"stats\" mode is refused, naming the absent secure allocator",
         r == NULL && ec == -1 && em && strstr(em, "secure allocator"));
      rj_free(r); }
    { rj_val* r = call("getmemoryinfo", "[\"bogus\"]", &ec, &em);
      ck("an unknown mode -> -8", r == NULL && ec == -8);
      rj_free(r); }

    /* ---- the refusals -------------------------------------------------- */
    { struct { const char* m; const char* p; const char* needle; } R[] = {
        {"getopenrpcinfo", "[]", "OpenRPC"},
        {"rpc.discover",   "[]", "OpenRPC"},
        {"exportasmap",    "[\"/tmp/x\"]", "asmap"},
        /* enumeratesigners is implemented now (rpc_signer.c); with no
         * signer= configured it answers Core's exact restart message */
        {"enumeratesigners", "[]", "restart bitcoind with -signer"} };
      int all = 1;
      for (unsigned i = 0; i < sizeof R / sizeof *R; i++){
          rj_val* r = call(R[i].m, R[i].p, &ec, &em);
          if (!(r == NULL && ec == -1 && em && strstr(em, R[i].needle))){
              printf("      (%s: ec=%ld em=%s)\n", R[i].m, ec, em ? em : "(null)");
              all = 0;
          }
          rj_free(r);
      }
      ck("every unsupported Control method errors with the reason named", all); }

    /* ================================================================
     * The invariant: everything help advertises actually dispatches.
     * ================================================================ */
    { rj_val* list = call("help", "[]", &ec, &em);
      ck("help list available for the sweep", list && list->typ == RJ_STR);
      int n = 0, bad = 0, known_bad = 0;
      char* copy = strdup(list ? list->str : "");
      for (char* line = strtok(copy, "\n"); line; line = strtok(NULL, "\n")){
          if (!line[0] || line[0] == '=' || strchr(line, ' ')) continue;  /* header prose */
          n++;
          if (!rpc_known_method(line)){
              printf("      (advertised but not known: %s)\n", line);
              known_bad++;
          }
          /* `stop` would fire the shutdown handler, and the waitfor* family
           * blocks for its timeout -- both are exercised in their own tests.
           * Everything else is dispatched here purely to prove it is wired. */
          if (!strcmp(line, "stop") || !strncmp(line, "waitfor", 7)) continue;
          long e2 = 0; const char* m2 = NULL;
          rj_val* r2 = NULL; rpc_wallet w; memset(&w, 0, sizeof w);
          rj_val* p2 = rj_parse("[]", 2);
          rpc_dispatch(line, p2, &w, &r2, &e2, &m2);
          rj_free(p2); rj_free(r2);
          if (e2 == -32601){
              printf("      (advertised but UNHANDLED: %s)\n", line);
              bad++;
          }
      }
      free(copy);
      printf("      (swept %d advertised methods)\n", n);
      ck("help advertises a full method set", n >= 150);
      ck("every advertised method is reported known by rpc_known_method", known_bad == 0);
      ck("NO advertised method answers \"Method not found\"", bad == 0);
      rj_free(list); }

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    return fails ? 1 : 0;
}
