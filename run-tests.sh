#!/usr/bin/env bash
# Run every test in the repository. Each test file is standalone: it exits
# non-zero on the first failing assertion set and prints what it counted.
set -u
cd "$(dirname "$0")"
fail=0
for t in test_*.py; do
    printf '== %s\n' "$t"
    if ! python3 "$t"; then fail=1; fi
done
exit "$fail"
