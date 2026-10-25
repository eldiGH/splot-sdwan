#!/usr/bin/env python3
"""Checks that the tests catch a change: one mutation at a time.

Usage: scripts/mutate.py FILE OLD NEW

Replaces OLD (which must occur exactly once in FILE) with NEW, runs
`cargo test`, prints which tests failed, and puts FILE back as it was. A
mutation that no test fails on is a test that's missing; one that doesn't
compile proves nothing, so rewrite it until it does.
"""

import glob
import os
import subprocess
import sys

path, old, new = sys.argv[1:4]
original = open(path).read()
if original.count(old) != 1:
    sys.exit(f"{old!r} occurs {original.count(old)} times in {path}, not once")

# Snapshots already waiting for review stay; the mutation's go.
pending = set(glob.glob("crates/**/*.snap.new", recursive=True))
open(path, "w").write(original.replace(old, new))
try:
    try:
        run = subprocess.run(
            ["cargo", "test", "--quiet"], capture_output=True, text=True, timeout=300
        )
    except subprocess.TimeoutExpired:
        # A test that never ends doesn't pass: the mutation is caught.
        print("TIMED OUT: a test hangs (caught)")
        sys.exit(0)
    output = run.stdout + run.stderr
    summary = [line for line in output.splitlines() if line.startswith("test result")]
    # The names listed under the last "failures:" heading.
    failed = [
        line.strip()
        for line in output.split("failures:")[-1].splitlines()
        if line.startswith("    ") and "::" in line and " " not in line.strip()
    ]

    if not summary:
        print("DID NOT COMPILE")
    else:
        print("FAILED:", ", ".join(failed) or "NONE (no test caught it)")
        # One line per test binary of the workspace: add them up.
        count = lambda word: sum(
            int(line.split(f" {word}")[0].split()[-1]) for line in summary
        )
        print(f"{count('passed')} passed, {count('failed')} failed")
finally:
    open(path, "w").write(original)
    # A snapshot the mutation changed leaves insta's .snap.new behind.
    for stray in set(glob.glob("crates/**/*.snap.new", recursive=True)) - pending:
        os.remove(stray)
