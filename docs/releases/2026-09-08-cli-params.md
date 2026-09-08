# 2026-09-08 — bmc_cli takes bitcoin-cli's arguments and prints any reply whole

Three defects in the command-line client, found while scoping
mempool.space's backend against this node, and one in the config parser
found when the benchmark's console went quiet.

**Arguments.** `bmc_cli getblock <hash> 2` sent the verbosity as the
string `"2"`. bitcoin-cli converts a bare `true`, `false`, `null`, a number,
and anything that parses as a JSON array or object; everything else stays
a string. The CLI now does the same conversion, so `getblock <hash> 2`,
`getrawtransaction <txid> true`, and `createrawtransaction '[...]' '{...}'`
mean what they mean to Core.

**Reply size.** The reply buffer was 64 KB, so any larger answer was
"malformed JSON-RPC reply" while the server had answered correctly. The
reply and the rendered result now get 64 MB each, enough for a
verbosity-3 block with every prevout. Behind it sat a second cap: the
reply parser deep-copied the result through a 64 KB stack buffer and
silently returned no result past it, so the CLI printed nothing and
exited 0 for a 112 KB `getblock`. The result subtree is now detached from
the parsed document instead of copied, with no size at all. That parser
is linked into the daemon too (the banlist), so the limit is gone there
as well.

**Config comments.** Core drops everything from the first `#` on a config
line before it splits `key=value`. Ours did not, so `printtoconsole=1   #
why` read as "1   # why", was rejected as a number and became 0. The
benchmark's resume at 04:31Z logged only to `debug.log` and the harness
monitor, which reads the console, went blind. Same rule as Core now, same
limit: a `#` inside a value truncates it there too.

## Tests

- `test_cli_prompt` +4: the argument conversions, checked through the
  dry-run seam.
- `test_rpc_transport` +3: a 20,000-string result (about 700 KB) parses,
  is kept, and is complete. Watched to fail on the old parser (result
  NULL).
- `test_node_config` +1: comments behind `dbcache=` and `printtoconsole=`
  are stripped. Watched to fail on the old parser (1024/0).
- Live, against the bench node: `getblock <hash> 1` prints 120 KB and
  `getblock <hash> 2` prints 7.8 MB of valid JSON, 1,660 transactions.

Gate `make -j8 test`: 0 failures (the one expected test_rpc_signer
segfault); 8 static audits exit 0.
