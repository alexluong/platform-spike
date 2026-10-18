#!/usr/bin/env bash
# Average CPU (cores) and memory of stack i's containers over a window, from cgroup counters on
# the docker host. Usage: bench/i/cpu.sh [seconds=60]   (DOCKER host: ssh cs-ws)
set -euo pipefail
WIN=${1:-60}
ssh cs-ws "WIN=$WIN bash -s" <<'SH'
ids=$(docker ps --filter name=ps-i-i- --format '{{.ID}} {{.Names}}')
declare -A start
while read -r id name; do
  full=$(docker inspect -f '{{.Id}}' "$id")
  f=/sys/fs/cgroup/system.slice/docker-$full.scope
  start[$name]=$(awk '/usage_usec/{print $2}' $f/cpu.stat)
done <<<"$ids"
sleep "$WIN"
while read -r id name; do
  full=$(docker inspect -f '{{.Id}}' "$id")
  f=/sys/fs/cgroup/system.slice/docker-$full.scope
  end=$(awk '/usage_usec/{print $2}' $f/cpu.stat)
  mem=$(( $(cat $f/memory.current) / 1048576 ))
  anon=$(( $(awk '/^anon /{print $2}' $f/memory.stat) / 1048576 ))
  echo "$name cpu=$(awk -v a=${start[$name]} -v b=$end -v w=$WIN 'BEGIN{printf "%.3f", (b-a)/1e6/w}') mem=${mem}MiB anon=${anon}MiB"
done <<<"$ids"
echo "host: $(uptime)"
SH
