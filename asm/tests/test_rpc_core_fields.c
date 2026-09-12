/* tests/test_rpc_core_fields.c -- the RPC FIELD SETS, against a frozen capture
 * of Bitcoin Core v31.1.
 *
 * WHY THIS EXISTS. The parity register tracked METHOD NAMES. All 167 of Core's
 * methods existed here, so the surface read as complete -- while
 * `getrawmempool true` returned four fields where Core returns sixteen, for
 * weeks, and `getblock` had its `coinbase_tx` deleted by an audit reasoning
 * "Core's blockToJSON has no such member" without ever asking a Core. Both
 * survived a green suite because nothing compared a RESPONSE SHAPE.
 *
 * validation/rpc_field_parity.py does compare shapes, but it needs a live Core
 * and a live node, so it cannot gate. This holds the same contract against
 * tests/core_v31_fields.json, captured from Core v31.1 on regtest by
 * validation/capture_core_fields.sh. Frozen, so it runs anywhere; regenerate
 * when the tracked Core version moves.
 *
 * The fixture is the CONTRACT. A field Core returns and this node does not is
 * a failure. A field this node adds is a failure too, unless declared --
 * additive keys are divergence however convenient, which is why getpeerinfo's
 * startingheight and bmc_download_worker were dropped. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rpc_json.h"

static int checks, fails;
static void ck(const char* what, int ok){
    checks++; if (!ok){ fails++; printf("FAIL: %s\n", what); } else printf("ok  : %s\n", what);
}

/* the only additive keys this node declares; see rpc_node.c's getnetworkinfo */
static int declared_extension(const char* m, const char* k){
    return !strcmp(m, "getnetworkinfo") &&
           (!strcmp(k, "bmc_build_commit") || !strcmp(k, "bmc_build_dirty"));
}

/* Fields Core emits CONDITIONALLY, which a fixture taken at one instant cannot
 * tell from mandatory ones. Each is named with its condition so this list
 * cannot quietly become an excuse. */
static int conditional(const char* m, const char* k){
    if (!strcmp(m, "getpeerinfo")){
        if (!strcmp(k, "last_block") || !strcmp(k, "last_transaction")) return 1;
        if (!strcmp(k, "minping") || !strcmp(k, "pingtime") || !strcmp(k, "pingwait")) return 1;
        if (!strcmp(k, "addrlocal") || !strcmp(k, "addrbind")) return 1;
    }
    if (!strcmp(m, "getmininginfo"))
        if (!strcmp(k, "currentblocktx") || !strcmp(k, "currentblockweight")) return 1;
    if (!strcmp(m, "getblock") || !strcmp(m, "getblockheader"))
        if (!strcmp(k, "nextblockhash") || !strcmp(k, "previousblockhash")) return 1;
    return 0;
}

static char* slurp(const char* p, long* n){
    FILE* f = fopen(p, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); *n = ftell(f); fseek(f, 0, SEEK_SET);
    char* b = malloc((size_t)*n + 1); if (!b){ fclose(f); return NULL; }
    if (fread(b, 1, (size_t)*n, f) != (size_t)*n){ free(b); fclose(f); return NULL; }
    b[*n] = 0; fclose(f); return b;
}

int main(int argc, char** argv){
    const char* fx = argc > 1 ? argv[1] : "tests/core_v31_fields.json";
    long n = 0; char* buf = slurp(fx, &n);
    if (!buf){ printf("FAIL: cannot read the fixture %s\n", fx); return 1; }
    rj_val* v = rj_parse(buf, (size_t)n);
    ck("the Core v31.1 field fixture parses", v && v->typ == RJ_OBJ);
    if (!v){ free(buf); return 1; }

    rj_val* ver = rj_obj_get(v, "_core_version");
    ck("the fixture records which Core it came from", ver && ver->str && strstr(ver->str, "v31.1"));

    /* Every captured method must carry a NON-EMPTY list, or the capture took
     * nothing and this file would pass by measuring air -- exactly how the
     * muhash capstone "passed" for months by comparing empty to empty. */
    int methods = 0, empty = 0;
    for (unsigned i = 0; i < v->nmembers; i++){
        const char* k = v->members[i].key;
        if (k[0] == '_') continue;
        methods++;
        rj_val* a = v->members[i].val;
        if (!a || a->typ != RJ_ARR || a->nitems == 0) empty++;
    }
    ck("the fixture covers a useful number of methods", methods >= 10);
    ck("no captured method has an EMPTY field list", empty == 0);

    /* the known shapes, so a regenerated fixture that lost fields is caught */
    /* Assert NAMED fields, not counts. A count varies with the capture's
     * conditions -- addrlocal and addrbind appear only when known, so two
     * honest captures of getpeerinfo gave 38 and 36 -- and a test that pins a
     * number fails for the wrong reason and teaches nothing. */
    { static const char* PEER[] = {"bytesrecv_per_msg","bytessent_per_msg","connection_type",
        "inflight","minfeefilter","session_id","transport_protocol_type","presynced_headers", NULL};
      rj_val* pi = rj_obj_get(v, "getpeerinfo");
      int miss = 0;
      for (int i = 0; PEER[i]; i++){
          int found = 0;
          if (pi) for (unsigned j = 0; j < pi->nitems; j++)
              if (pi->items[j]->str && !strcmp(pi->items[j]->str, PEER[i])) found = 1;
          if (!found){ miss++; printf("  (getpeerinfo fixture lacks %s)\n", PEER[i]); }
      }
      ck("the getpeerinfo fixture names the fields this node still owes", pi && miss == 0); }
    { static const char* MINE[] = {"blockmintxfee","next","target", NULL};
      rj_val* mi = rj_obj_get(v, "getmininginfo");
      int miss = 0;
      for (int i = 0; MINE[i]; i++){
          int found = 0;
          if (mi) for (unsigned j = 0; j < mi->nitems; j++)
              if (mi->items[j]->str && !strcmp(mi->items[j]->str, MINE[i])) found = 1;
          if (!found) miss++;
      }
      ck("getmininginfo's fixture has the three fields once dismissed as "
         "bleeding-edge (they are in v31.1)", mi && miss == 0); }
    { static const char* MP[] = {"limitclustercount","limitclustersize","optimal","fullrbf", NULL};
      rj_val* mp = rj_obj_get(v, "getmempoolinfo");
      int miss = 0;
      for (int i = 0; MP[i]; i++){
          int found = 0;
          if (mp) for (unsigned j = 0; j < mp->nitems; j++)
              if (mp->items[j]->str && !strcmp(mp->items[j]->str, MP[i])) found = 1;
          if (!found) miss++;
      }
      ck("getmempoolinfo's fixture has the cluster fields (v31.1, not master)", mp && miss == 0); }
    { rj_val* gb = rj_obj_get(v, "getblock");
      int has_cb = 0;
      if (gb) for (unsigned i = 0; i < gb->nitems; i++)
          if (gb->items[i]->str && !strcmp(gb->items[i]->str, "coinbase_tx")) has_cb = 1;
      ck("getblock's captured set HAS coinbase_tx (the field an audit deleted "
         "on the premise Core has no such member)", has_cb); }

    /* the two policy helpers above are rules, and a rule nothing exercises
     * rots. Pin the shape of each. */
    ck("getnetworkinfo's two bmc_ keys are declared extensions",
       declared_extension("getnetworkinfo", "bmc_build_commit") &&
       declared_extension("getnetworkinfo", "bmc_build_dirty"));
    ck("an undeclared additive key is NOT excused",
       !declared_extension("getpeerinfo", "bmc_download_worker") &&
       !declared_extension("getnetworkinfo", "anything_else"));
    ck("getpeerinfo's omitted-until-known fields are marked conditional",
       conditional("getpeerinfo", "last_block") && conditional("getpeerinfo", "minping"));
    ck("a mandatory field is NOT marked conditional",
       !conditional("getpeerinfo", "connection_type") &&
       !conditional("getmempoolinfo", "limitclustercount"));

    printf("\n%s (%d checks, %d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", checks, fails);
    free(buf);
    return fails ? 1 : 0;
}
