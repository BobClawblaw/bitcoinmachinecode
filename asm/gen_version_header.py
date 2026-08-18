#!/usr/bin/env python3
"""Generate version_gen.h from the single source of truth, asm/version.inc.

This is a BUILD TOOL. It does NOT define the version -- it only reads the
%define directives in version.inc (the canonical, human-authored source) and
emits the derived values as C constants so C code can share the exact same
wire identity as the assembly (bitcoind.asm / bitcoin_p2p.asm, which get the
values at assembly time via NASM %strcat/%strlen).

To bump the version or protocol number: edit ONLY asm/version.inc. Do not
edit this file's constants and do not hand-edit the generated version_gen.h.
"""
import argparse
import re
import sys

DEF_RE = re.compile(r"^\s*%define\s+(\w+)\s+(.+?)\s*$", re.M)


def parse(path):
    with open(path, "r") as f:
        src = f.read()
    defs = {}
    for m in DEF_RE.finditer(src):
        key, val = m.group(1), m.group(2).strip()
        defs[key] = val
    return defs


def get_int(defs, name):
    val = defs[name].strip()
    # NASM numeric literal (hex like 70016 is decimal; allow 0x too)
    val = val.replace("'", "").strip()
    if val.lower().startswith("0x"):
        return int(val, 16)
    return int(val, 10)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--version-inc", required=True)
    args = ap.parse_args()

    defs = parse(args.version_inc)
    try:
        major = get_int(defs, "NODE_VERSION_MAJOR")
        minor = get_int(defs, "NODE_VERSION_MINOR")
        patch = get_int(defs, "NODE_VERSION_PATCH")
        proto = get_int(defs, "NODE_PROTOCOL_VER")
    except KeyError as e:
        print(f"FATAL: version.inc missing required {e}", file=sys.stderr)
        sys.exit(2)

    prefix = defs["NODE_UA_PREFIX"].strip('"').strip()
    suffix = defs["NODE_UA_SUFFIX"].strip('"').strip()
    # Build the same UA string NASM builds in version.inc:
    #   prefix + major.minor.patch + suffix
    ua = f"{prefix}{major}.{minor}.{patch}{suffix}"
    ua_len = len(ua)

    lines = [
        "/* version_gen.h -- GENERATED. Do not edit by hand. */",
        "/* Single source of truth: asm/version.inc. Regenerate via make. */",
        f"#ifndef VERSION_GEN_H_{major}_{minor}_{patch}_H",
        f"#define VERSION_GEN_H_{major}_{minor}_{patch}_H",
        "",
        f"#define NODE_VERSION_MAJOR {major}",
        f"#define NODE_VERSION_MINOR {minor}",
        f"#define NODE_VERSION_PATCH {patch}",
        f"#define NODE_PROTOCOL_VER {proto}",
        f"#define NODE_UA_STRING \"{ua}\"",
        f"#define NODE_UA_STRING_LEN {ua_len}",
        "",
        "#endif",
        "",
    ]
    with open(args.out, "w") as f:
        f.write("\n".join(lines))


if __name__ == "__main__":
    main()
