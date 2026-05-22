#!/usr/bin/env bash
# Multi-thread aggregate microbench for (B).
#
# Spawns N parallel copies of river5-bench (each on its own CPU
# thread, each with its own cold-buffer pool), waits for all to
# finish, sums per-thread throughput. Reports aggregate GB/s.
#
# If aggregate scales linearly with N → no contention.
# If aggregate flattens → memory bandwidth / cache contention.
#
# Usage:
#   ./bench/mt_aggregate.sh [seconds]   # default 1.5
#
# Output: tab-separated rows of (hash, regime, n_threads, agg_gbps, per_thread_gbps)

set -euo pipefail

SECONDS_PER_CELL="${1:-1.5}"
SIZES="${2:-1024 4096 16384}"   # space-separated input sizes to sweep
WORKDIR=$(mktemp -d)
trap "rm -rf $WORKDIR" EXIT

printf "hash\tsize\tregime\tn_threads\tagg_gbps\tper_thread_gbps\n"

for SIZE in $SIZES; do
  for hash in river5 blake3; do
    for regime in "HOT" "L2-cold" "L3-cold"; do
      case $regime in
        HOT)     cold_arg="" ;;
        L2-cold) cold_arg="--cold 524288" ;;
        L3-cold) cold_arg="--cold 16777216" ;;
      esac
      for n in 1 2 4 8; do
        pids=()
        for ((i=0; i<n; i++)); do
          ./build/river5-bench micro \
            --hash "$hash" \
            --size $SIZE \
            --seconds "$SECONDS_PER_CELL" \
            $cold_arg \
            --csv \
            > "$WORKDIR/out-$i.csv" 2>/dev/null &
          pids+=($!)
        done
        for pid in "${pids[@]}"; do
          wait "$pid"
        done
        agg=$(cat "$WORKDIR"/out-*.csv | \
              awk -F, -v s=$SIZE 'NR>1 && $2==s { gb += $6 } END { printf "%.2f", gb }')
        per_thread=$(awk -v a="$agg" -v n="$n" 'BEGIN { printf "%.2f", a/n }')
        printf "%s\t%d\t%s\t%d\t%s\t%s\n" "$hash" "$SIZE" "$regime" "$n" "$agg" "$per_thread"
        rm -f "$WORKDIR"/out-*.csv
      done
    done
  done
done
