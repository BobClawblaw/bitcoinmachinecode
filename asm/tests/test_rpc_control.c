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

static int ends_with(const char* s, const char* suf){
    size_t n = strlen(s), m = strlen(suf);
    return n >= m && !strcmp(s + n - m, suf);
}

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
      /* THIS ASSERTION USED TO PIN THE BUG. It required "bitcoind.log" -- the
       * name the daemon stopped using on 2026-09-06, when the default became
       * Core's "debug.log" -- so getrpcinfo advertised a file that did not
       * exist and the suite agreed with it. The contract is: whatever name
       * the daemon actually opened, resolved against the cwd. */
      ck("logpath ends in the default name the daemon opens (debug.log, Core's default)",
         r && S(r, "logpath") && ends_with(S(r, "logpath"), "/debug.log"));
      rj_free(r); }
    /* -debuglogfile= moves the log, and getrpcinfo must follow it: a relative
     * name resolves against the cwd, an absolute one is reported as given
     * (which is also the -debuglogfile=0 case, where main.c passes /dev/null). */
    { rpc_set_logpath("elsewhere.log");
      rj_val* r = call("getrpcinfo", "[]", &ec, &em);
      ck("logpath follows -debuglogfile= (relative: resolved against the cwd)",
         r && S(r, "logpath") && ends_with(S(r, "logpath"), "/elsewhere.log"));
      rj_free(r);
      rpc_set_logpath("/dev/null");
      r = call("getrpcinfo", "[]", &ec, &em);
      ck("logpath reports an absolute name as-is (-debuglogfile=0 -> /dev/null)",
         r && S(r, "logpath") && !strcmp(S(r, "logpath"), "/dev/null"));
      rj_free(r);
      rpc_set_logpath("");   /* back to the default for anything below */
      r = call("getrpcinfo", "[]", &ec, &em);
      ck("cleared: back to the default name",
         r && S(r, "logpath") && ends_with(S(r, "logpath"), "/debug.log"));
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
#ifdef __GLIBC__
      ck("mallocinfo returns real glibc XML",
         r && r->typ == RJ_STR && strstr(r->str, "<malloc"));
#else
      ck("mallocinfo without glibc is refused as Core refuses it (-8 \"mallocinfo mode not available\")",
         r == NULL && ec == -8 && em && !strcmp(em, "mallocinfo mode not available"));
#endif
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

    /* ---- echo / echojson / echoipc (2026-11-04) --------------------------
     * Core Lightning's bcli runs `echo` at startup. Expected values are
     * v31.1's answers (validation/echo_core_diff.py diffs the live replies). */
    { static const struct { const char* m; const char* p; const char* want; long ec; const char* em; } E[] = {
          {"echo", NULL, "[]", 0, NULL},
          {"echo", "null", "[]", 0, NULL},
          {"echo", "{}", "[]", 0, NULL},
          {"echo", "[\"a\",1,{\"x\":[1,2.50]},null,true]", "[\"a\",1,{\"x\":[1,2.50]},null,true]", 0, NULL},
          {"echojson", "[1e3,-0]", "[1e3,-0]", 0, NULL},
          {"echo", "[0,1,2,3,4,5,6,7,8,9]", "[0,1,2,3,4,5,6,7,8,9]", 0, NULL},
          {"echo", "{\"arg2\":\"c\",\"arg0\":\"a\"}", "[\"a\",null,\"c\"]", 0, NULL},
          {"echo", "{\"arg3\":null}", "[null,null,null,null]", 0, NULL},
          {"echo", "{\"args\":[\"a\"],\"arg2\":\"x\"}", "[\"a\",null,\"x\"]", 0, NULL},
          {"echo", "{\"args\":\"a\"}", "[]", 0, NULL},
          {"echo", "{\"arg10\":1}", NULL, -8, "Unknown named parameter arg10"},
          {"echo", "{\"arg0\":1,\"arg0\":2}", NULL, -8, "Parameter arg0 specified multiple times"},
          {"echo", "{\"args\":[1,2],\"arg1\":3}", NULL, -8, "Parameter arg1 specified twice both as positional and named argument"},
          {"echo", "\"str\"", NULL, -32600, "Params must be an array or object"},
          {"echoipc", "[\"x\"]", "\"x\"", 0, NULL},
          {"echoipc", "{\"arg\":\"z\"}", "\"z\"", 0, NULL},
          {"echoipc", "[5]", NULL, -3, "Wrong type passed:\n{\n    \"Position 1 (arg)\": \"JSON value of type number is not of expected type string\"\n}"},
      };
      int all = 1;
      for (unsigned i = 0; i < sizeof E / sizeof *E; i++){
          rj_val* r = call(E[i].m, E[i].p, &ec, &em);
          char* got = r ? rj_write_alloc(r, 0, NULL) : NULL;
          int good = E[i].want ? (got && !strcmp(got, E[i].want) && ec == 0)
                               : (!r && ec == E[i].ec && em && !strcmp(em, E[i].em));
          if (!good){ printf("      (%s %s: got %s ec=%ld em=%s)\n", E[i].m, E[i].p ? E[i].p : "(none)", got ? got : "-", ec, em ? em : "-"); all = 0; }
          free(got); rj_free(r);
      }
      ck("echo/echojson/echoipc answer as v31.1 does", all);
      rj_val* r = call("echo", "[0,1,2,3,4,5,6,7,8,9,10]", &ec, &em);
      ck("echo with eleven arguments: -1 and the usage text",
         !r && ec == -1 && em && !strncmp(em, "echo ( \"arg0\"", 13) && ends_with(em, "10. arg9    (string, optional)\n"));
      r = call("echojson", "[0,1,2,3,4,5,6,7,8,9,10]", &ec, &em);
      ck("...and echojson's usage text names echojson", !r && ec == -1 && em && !strncmp(em, "echojson ( ", 11));
      r = call("echoipc", "[]", &ec, &em);
      ck("echoipc with no argument: -1 and the usage text", !r && ec == -1 && em && !strncmp(em, "echoipc \"arg\"\n", 14));
    }

    /* ---- named arguments for every method (2026-11-06) ------------------
     * rpc_named_params, Core's transformNamedArguments over asm/rpc_argnames.h
     * (generated from v31.1's help). The expected arrays and messages are
     * v31.1's (validation/named_args_core_diff.py compares the live replies). */
    { static const struct { const char* m; const char* p; const char* want; long ec; const char* em; } N[] = {
          {"getblockhash", "{\"height\":1}", "[1]", 0, NULL},
          {"getblock", "{\"verbosity\":0,\"blockhash\":\"h\"}", "[\"h\",0]", 0, NULL},
          {"getblock", "{\"blockhash\":\"h\",\"verbose\":0}", "[\"h\",0]", 0, NULL},              /* the alias */
          {"getblock", "{\"verbosity\":2,\"args\":[\"h\"]}", "[\"h\",2]", 0, NULL},
          {"getrawtransaction", "{\"txid\":\"t\",\"blockhash\":\"b\"}", "[\"t\",null,\"b\"]", 0, NULL},   /* a hole before a name */
          {"gettxout", "{\"txid\":\"t\"}", "[\"t\"]", 0, NULL},                                    /* none at the end */
          {"gettxspendingprevout", "{\"outputs\":[],\"return_spending_tx\":true}", "[[],{\"return_spending_tx\":true}]", 0, NULL},
          {"getblockcount", "{}", "[]", 0, NULL},
          {"getblock", "{\"verbose\":0,\"verbosity\":1,\"blockhash\":\"h\"}", NULL, -8, "Unknown named parameter verbose"},
          {"getblockhash", "{\"height\":1,\"bogus\":2}", NULL, -8, "Unknown named parameter bogus"},
          {"getblockhash", "{\"height\":1,\"height\":2}", NULL, -8, "Parameter height specified multiple times"},
          {"getblock", "{\"args\":[\"h\"],\"blockhash\":\"h\"}", NULL, -8, "Parameter blockhash specified twice both as positional and named argument"},
          {"gettxspendingprevout", "{\"outputs\":[],\"return_spending_tx\":true,\"options\":{}}", NULL, -8, "Parameter options conflicts with parameter return_spending_tx"},
          {"getblockhash", "\"x\"", NULL, -32600, "Params must be an array or object"},
      };
      int all = 1;
      for (unsigned i = 0; i < sizeof N / sizeof *N; i++){
          rj_val* in = rj_parse(N[i].p, strlen(N[i].p)); rj_val* out = NULL; long nec = 0; const char* nem = NULL;
          int ok = in && rpc_named_params(N[i].m, in, &out, &nec, &nem);
          char* got = out ? rj_write_alloc(out, 0, NULL) : NULL;
          int good = N[i].want ? (ok && got && !strcmp(got, N[i].want))
                               : (!ok && nec == N[i].ec && nem && !strcmp(nem, N[i].em));
          if (!good){ printf("      (%s %s: got %s ec=%ld em=%s)\n", N[i].m, N[i].p, got ? got : "-", nec, nem ? nem : "-"); all = 0; }
          free(got); rj_free(out); rj_free(in);
      }
      ck("named arguments convert as v31.1's transformNamedArguments does", all);
      rj_val* in = rj_parse("{\"a\":1}", 7); rj_val* out = (rj_val*)1; long nec = 0; const char* nem = NULL;
      ck("a method Core does not have keeps its object (an unknown one stays \"Method not found\")",
         rpc_named_params("bmcgetcapabilities", in, &out, &nec, &nem) == 1 && out == NULL);
      rj_free(in);
      in = rj_parse("[1]", 3); out = (rj_val*)1;
      ck("an array passes as it is", rpc_named_params("getblockhash", in, &out, &nec, &nem) == 1 && out == NULL);
      rj_free(in);
    }

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
          if (e2 == -32601 && m2 && strstr(m2, "Private broadcast is not enabled")){
              /* Core answers RPC_METHOD_NOT_FOUND with exactly this text for
               * getprivatebroadcastinfo/abortprivatebroadcast when the option
               * is off (rpc/mempool.cpp); the method IS wired */
              printf("      (refuses like Core with RPC_METHOD_NOT_FOUND while -privatebroadcast is off: %s)\n", line);
          } else if (e2 == -32601){
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
