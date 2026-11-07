#!/usr/bin/env bash
# Run bounded libFuzzer campaigns for one or all parser targets.
#
# Usage:
#   fuzz/run_campaign.sh [pe|zip|vba|xlm|all] [seconds-per-target] [evidence-dir]
#
# The seed corpus comes from fuzz/seeds (generated from the parser fixtures).
# Each campaign keeps its evolving corpus, full log, and crash artifacts under
# the evidence directory, which defaults to target/evidence/phase1/fuzz.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
target=${1:-all}
seconds=${2:-120}
evidence=${3:-"$here/../target/evidence/phase1/fuzz"}
bin_dir="$here/target/x86_64-pc-windows-gnu/release"

case "$target" in
    pe|zip|vba|xlm) targets=("$target") ;;
    all) targets=(pe zip vba xlm) ;;
    *) echo "usage: $0 [pe|zip|vba|xlm|all] [seconds] [evidence-dir]" >&2; exit 2 ;;
esac

mkdir -p "$evidence"

for t in "${targets[@]}"; do
    bin="$bin_dir/fuzz_$t.exe"
    if [ ! -x "$bin" ]; then
        echo "missing $bin; run fuzz/build.sh first" >&2
        exit 1
    fi

    corpus="$evidence/corpus/$t"
    artifacts="$evidence/artifacts/$t"
    log="$evidence/fuzz-$t.log"
    mkdir -p "$corpus" "$artifacts"
    if [ ! -d "$here/seeds/$t" ]; then
        echo "missing seed directory: $here/seeds/$t" >&2
        exit 1
    fi
    # Always refresh the seeds. `cp -n` silently ignored a newly added seed
    # whenever the evidence corpus already existed, which made the checked-in
    # seed set diverge from what was actually fuzzed.
    if ! cp -f "$here/seeds/$t"/* "$corpus"/; then
        echo "failed to copy seeds for $t from $here/seeds/$t" >&2
        exit 1
    fi

    echo "== fuzz_$t: ${seconds}s, corpus=$corpus =="
    set +e
    "$bin" "$corpus" \
        -max_total_time="$seconds" \
        -max_len=65536 \
        -timeout=10 \
        -rss_limit_mb=2048 \
        -artifact_prefix="$artifacts/" \
        -print_final_stats=1 \
        >"$log" 2>&1
    status=$?
    set -e

    grep -E "Loaded [0-9]+ modules|Loaded [0-9]+ PC tables|INITED|DONE|stat::|ERROR|SUMMARY" "$log" | tail -12 || true
    if [ "$status" -ne 0 ]; then
        echo "fuzz_$t failed with exit $status; see $log" >&2
        exit "$status"
    fi
    # An uninstrumented binary also exits 0. Refuse to report a campaign unless
    # libFuzzer saw real counters and initial coverage from the seeds.
    if ! grep -Eq "Loaded [1-9][0-9]* modules" "$log" \
        || ! grep -Eq "INITED cov: [1-9][0-9]*" "$log"; then
        echo "fuzz_$t produced no coverage instrumentation or zero initial coverage; refusing to call this a campaign" >&2
        exit 1
    fi
    if find "$artifacts" -type f -print -quit | grep -q .; then
        echo "fuzz_$t produced crash/timeout artifacts in $artifacts" >&2
        exit 1
    fi
    echo "log: $log"
done
