#!/bin/sh
# Runs the whole test suite with coverage instrumentation and fails unless
# every line of src/ was executed by at least one test.
#
# Line coverage is computed from the merged lcov report. `cargo llvm-cov`'s
# summary table also counts each instantiation of a generic function in each
# test binary separately, so it can report a few "missed" lines that other
# binaries do execute.
set -eu

report="${1:-target/lcov.info}"
cargo llvm-cov --lcov --output-path "$report"
awk -F'[:,]' '
  /^SF:/ { file = $2; sub(".*/src/", "src/", file) }
  /^DA:/ { total++; if ($3 > 0) hit++; else missed[file] = missed[file] " " $2 }
  END {
    printf "line coverage: %d/%d\n", hit, total
    for (file in missed) { printf "not covered: %s:%s\n", file, missed[file]; failed = 1 }
    exit failed
  }' "$report"
