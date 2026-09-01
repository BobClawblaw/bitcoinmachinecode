/* tests/test_netperm.c -- Core -whitelist peer permissions (daemon/netperm.c).
 *
 * The point of this option is that a peer covered by it is NOT banned. So the
 * assertions that matter are not "the string parsed" but "this address gets
 * noban and that one does not", and above all that an unsupported permission
 * is REFUSED rather than accepted and ignored -- which is the failure mode
 * this codebase has shipped repeatedly (whitelist=rpc sat in the live config
 * for weeks doing nothing).
 */
#include <stdio.h>
#include <string.h>
#include "../daemon/netperm.h"

static int fails = 0;
static void ok(int c, const char* w){
    printf("  %s %s\n", c ? "ok " : "FAIL", w); if (!c) fails++;
}
static int add(const char* s){ const char* e = 0; return netperm_add(s, &e); }

int main(void){
    printf("== a plain address gets noban, and nothing else does ==\n");
    netperm_reset();
    ok(add("noban@127.0.0.1"), "noban@127.0.0.1 is accepted");
    ok(netperm_for("127.0.0.1") & NP_NOBAN, "127.0.0.1 has noban");
    ok(netperm_for("127.0.0.2") == 0, "127.0.0.2 does not");
    ok(netperm_for("8.8.8.8") == 0, "an unrelated address does not");

    printf("== CIDR, including the prefixes the ban list cannot do ==\n");
    netperm_reset();
    ok(add("noban@10.0.0.0/8"), "a /8 is accepted");
    ok(netperm_for("10.1.2.3") & NP_NOBAN, "10.1.2.3 is inside it");
    ok(netperm_for("11.1.2.3") == 0, "11.1.2.3 is outside it");
    netperm_reset();
    /* /28 is NOT byte-aligned: ctl_ban_covers() silently fails these, so this
     * is exactly the case a string-comparison matcher gets wrong. */
    ok(add("noban@192.168.1.16/28"), "a non-byte-aligned /28 is accepted");
    ok(netperm_for("192.168.1.16") & NP_NOBAN, "  .16 is inside");
    ok(netperm_for("192.168.1.31") & NP_NOBAN, "  .31 is inside (last of the /28)");
    ok(netperm_for("192.168.1.32") == 0,       "  .32 is outside");
    ok(netperm_for("192.168.1.15") == 0,       "  .15 is outside");

    printf("== IPv6, in both spellings the node prints ==\n");
    netperm_reset();
    ok(add("noban@::1"), "::1 is accepted");
    ok(netperm_for("::1") & NP_NOBAN, "::1 matches");
    ok(netperm_for("[::1]") & NP_NOBAN, "[::1] matches the same entry");
    ok(netperm_for("::2") == 0, "::2 does not");
    netperm_reset();
    ok(add("noban@2001:db8::/32"), "an IPv6 /32 is accepted");
    ok(netperm_for("2001:db8:1234::5") & NP_NOBAN, "an address inside it matches");
    ok(netperm_for("2001:db9::1") == 0, "one outside it does not");
    ok(netperm_for("127.0.0.1") == 0, "an IPv4 address never matches an IPv6 entry");

    printf("== a bare entry means noban here, and is not silently more ==\n");
    netperm_reset();
    ok(add("127.0.0.1"), "a bare address is accepted");
    ok(netperm_for("127.0.0.1") & NP_NOBAN, "and grants noban");
    ok(netperm_has_implicit(), "and is reported as implicit, so boot can say so");
    netperm_reset();
    ok(add("noban@127.0.0.1") && !netperm_has_implicit(),
       "an explicit entry is not reported as implicit");

    printf("== permissions this node cannot enforce are REFUSED ==\n");
    netperm_reset();
    {
        /* Each is a real Core token. Accepting any of them would mean the
         * operator believes something the node does not do. */
        const char* recognised[] = { "mempool",
                                     "download", "addr", "bloomfilter", 0 };
        int all = 1;
        for (int i = 0; recognised[i]; i++){
            char spec[64]; snprintf(spec, sizeof spec, "%s@127.0.0.1", recognised[i]);
            const char* e = 0;
            if (netperm_add(spec, &e)){ printf("      %s was ACCEPTED\n", recognised[i]); all = 0; }
            else if (!e || !strstr(e, "NOT enforced")){
                printf("      %s rejected with an unhelpful reason: %s\n",
                       recognised[i], e ? e : "(none)"); all = 0;
            }
        }
        ok(all, "every Core permission this node does not enforce is refused, saying so");
        ok(netperm_count() == 0, "and none of them was stored");
    }
    {
        const char* e = 0;
        ok(!netperm_add("nosuchperm@127.0.0.1", &e) && e && strstr(e, "unknown"),
           "an unknown token is refused as unknown, not as unimplemented");
    }
    {   /* noban alongside an unenforced one must still refuse: granting the
         * half we implement would be worse than refusing the whole line. */
        const char* e = 0;
        ok(!netperm_add("noban,mempool@127.0.0.1", &e),
           "noban,mempool is refused rather than half-honoured");
    }

    printf("== relay / forcerelay (2026-09-01: -whitelistrelay, -whitelistforcerelay) ==\n");
    netperm_reset(); netperm_set_implicit_defaults(1, 0);           /* Core's defaults */
    ok(add("relay@10.1.1.1") && (netperm_for("10.1.1.1") & NP_RELAY) && !(netperm_for("10.1.1.1") & NP_FORCERELAY),
       "relay@ grants relay, not forcerelay");
    ok(add("forcerelay@10.1.1.2") && (netperm_for("10.1.1.2") & NP_FORCERELAY) && (netperm_for("10.1.1.2") & NP_RELAY),
       "forcerelay@ grants forcerelay AND relay (Core: forcerelay implies relay)");
    ok(add("noban@10.1.1.3") && !(netperm_for("10.1.1.3") & NP_RELAY),
       "an explicit noban@ list grants only what it names");
    ok(add("10.1.1.4") && (netperm_for("10.1.1.4") & NP_NOBAN) && (netperm_for("10.1.1.4") & NP_RELAY) && !(netperm_for("10.1.1.4") & NP_FORCERELAY),
       "an implicit entry gets noban+relay with Core's defaults (whitelistrelay=1, forcerelay=0)");
    netperm_set_implicit_defaults(0, 0);
    ok(!(netperm_for("10.1.1.4") & NP_RELAY) && (netperm_for("10.1.1.1") & NP_RELAY),
       "whitelistrelay=0 strips relay from implicit entries only (explicit relay@ keeps it)");
    netperm_set_implicit_defaults(1, 1);
    ok((netperm_for("10.1.1.4") & NP_FORCERELAY) && (netperm_for("10.1.1.4") & NP_RELAY),
       "whitelistforcerelay=1 gives implicit entries forcerelay+relay");
    netperm_set_implicit_defaults(1, 0);

    printf("== malformed input is refused, not guessed at ==\n");
    netperm_reset();
    ok(!add(""), "empty");
    ok(!add("noban@"), "permissions with no address");
    ok(!add("noban@notanaddress"), "a hostname (Core takes addresses here)");
    ok(!add("noban@127.0.0.1/33"), "an IPv4 prefix over 32");
    ok(!add("noban@127.0.0.1/-1"), "a negative prefix");
    ok(!add("noban@127.0.0.1/abc"), "a non-numeric prefix");
    ok(netperm_count() == 0, "and nothing was stored from any of them");

    printf("== an unconfigured node grants nothing ==\n");
    netperm_reset();
    ok(netperm_for("127.0.0.1") == 0, "no entries means no permissions");

    printf("== whitebind: permissions by LISTENER, not by peer address ==\n");
    {
        const char* e = 0;
        ok(netperm_whitebind_add("noban@127.0.0.1:38333", &e), "noban@127.0.0.1:38333 is accepted");
        ok(netperm_whitebind_count() == 1, "and stored");
        ok(!strcmp(netperm_whitebind_addr(0), "127.0.0.1"), "the address is parsed off");
        ok(netperm_whitebind_port(0) == 38333, "so is the port");
        ok(netperm_whitebind_flags(0) & NP_NOBAN, "and it grants noban");

        /* The fd mapping is the whole mechanism: a peer's permissions come
         * from the socket that accepted it, which is how a peer whose address
         * you cannot predict gets them at all. */
        netperm_bind_fd(7, NP_NOBAN);
        ok(netperm_for_fd(7) & NP_NOBAN, "a bound listener fd grants its flags");
        ok(netperm_for_fd(8) == 0, "an unrelated fd grants nothing");
        ok(netperm_for_fd(-1) == 0, "and -1 is not a listener");

        /* A bare address with no port would be ambiguous with the main
         * listener, and sharing that socket would grant every inbound peer
         * these permissions. Core requires the port; so does this. */
        ok(!netperm_whitebind_add("noban@127.0.0.1", &e) && e && strstr(e, "port"),
           "an entry without a port is refused, saying so");
        ok(!netperm_whitebind_add("noban@127.0.0.1:0", &e), "port 0 is refused");
        ok(!netperm_whitebind_add("noban@127.0.0.1:70000", &e), "a port over 65535 is refused");
        ok(!netperm_whitebind_add("noban@nothost:8333", &e), "a hostname is refused");
        ok(!netperm_whitebind_add("mempool@127.0.0.1:8333", &e),
           "a permission this node does not enforce is refused here too");
        ok(!netperm_whitebind_add("", &e), "empty is refused");

        /* An implicit entry grants noban, same as whitelist. */
        ok(netperm_whitebind_add("127.0.0.2:8333", &e), "a bare addr:port is accepted");
        ok(netperm_whitebind_flags(1) & NP_NOBAN, "and grants noban");
    }

    printf("\n%s (%d failure%s)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
