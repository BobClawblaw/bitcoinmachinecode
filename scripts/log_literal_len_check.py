#!/usr/bin/env python3
"""Refuse a node_log_* call whose length argument miscounts its string literal.

node_log_str(fd, kind, "text", LEN) writes exactly LEN bytes. A hand-counted LEN
one too high writes the literal's terminating NUL into the log; one too low cuts
the last character. Both shipped (2026-09-19): "node start (serve mode / download
worker)" passed 42 for 41 characters, so every download worker put a NUL in
debug.log, and GNU grep then treats the whole file as binary and prints nothing,
counts included. "node start (follow mode)" passed 23 for 24 and
"serve-test outbound mux" 22 for 23, so both lost their last character.

A call that passes a number is checked against its literal. strlen() of the
literal needs no check. Exit 0 = clean, 1 = a mismatch (each is printed).
"""
import glob, os, re, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'asm')
CALL = re.compile(r'node_log_\w+\([^;]*?"((?:[^"\\]|\\.)*)"\s*,\s*(\d+)\s*\)')

bad = checked = 0
for path in sorted(glob.glob(os.path.join(ROOT, '**', '*.c'), recursive=True)):
    rel = os.path.relpath(path, ROOT)
    if rel.startswith(('tests' + os.sep, '.claude')):
        continue
    with open(path, errors='replace') as f:
        for n, line in enumerate(f, 1):
            for m in CALL.finditer(line):
                text = m.group(1).encode().decode('unicode_escape')
                length = int(m.group(2)); checked += 1
                if length != len(text):
                    bad += 1
                    print(f'{rel}:{n}: "{m.group(1)}" is {len(text)} bytes, the call passes {length}'
                          + (' (writes the NUL into the log)' if length == len(text) + 1 else ''))
if bad:
    print(f'LOG LITERAL CHECK FAILED: {bad} call(s). Pass (int)strlen("...") instead of a count.')
    sys.exit(1)
print(f'LOG LITERAL CHECK OK: {checked} counted call(s) match their literals.')
