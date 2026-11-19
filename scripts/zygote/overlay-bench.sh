#!/usr/bin/env bash
# overlay-bench.sh — zygote 路径 overlay 开/关的启动时延对比（需要 sudo）
#
# 口径：同母体、同 rootfs、同 payload(/tprobe)、终点= payload main 首句(PAYLOAD_NS)。
# 顺序反转交替（奇偶轮换先后），消除 page cache 顺序偏差——overlay-smoke 踩过这个坑。
# 热身 WARM 轮后再计 N 轮，取 p50。
#
# 用法：sudo ./scripts/zygote/overlay-bench.sh [N]     # 默认 30
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "需要 root：sudo $0 [N]" >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
N=${1:-30}
WARM=${WARM:-5}
WORK=$(mktemp -d /tmp/anolix-ovbench.XXXXXX)
SOCK=/tmp/anolix-ovbench.sock
LOG="$WORK/mother.log"
MPID=""

cleanup() {
  [ -n "$MPID" ] && kill "$MPID" 2>/dev/null || true
  rm -f "$SOCK"
  rm -rf "$WORK"
}
trap cleanup EXIT

USER_HOME=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
if ! command -v go >/dev/null 2>&1; then
  export PATH="$USER_HOME/.local/sdk/go/bin:$USER_HOME/go/bin:/usr/local/go/bin:$PATH"
fi
command -v go >/dev/null 2>&1 || { echo "找不到 go" >&2; exit 1; }
export GOPATH="${GOPATH:-$USER_HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$USER_HOME/go/pkg/mod}"
export GOCACHE="${GOCACHE:-/tmp/anolix-go-cache}"

echo "== 构建 =="
(cd "$ROOT" && go build -o "$WORK/zygote" ./cmd/zygote \
  && go build -o "$WORK/spawn" ./cmd/spawn \
  && go build -o "$WORK/worker-init" ./cmd/worker-init)
echo "OK"

"$WORK/zygote" --socket "$SOCK" >"$LOG" 2>&1 &
MPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || { echo "母体没起来" >&2; exit 1; }

# spawn_one <id> <overlay-flag>：spawn 并等 reap，保证串行、不互相干扰计时。
spawn_one() {
  "$WORK/spawn" --socket "$SOCK" --id "$1" -- \
    "$WORK/worker-init" $2 --rootfs "$ROOT/rootfs" -- /tprobe >/dev/null 2>&1
  for _ in $(seq 1 100); do
    grep -q "ANOLIX_REAP id=$1 " "$LOG" && return 0
    sleep 0.02
  done
  echo "!! $1 没被 reap" >&2
  return 1
}

echo "== 热身 $WARM 轮（overlay）=="
for i in $(seq 1 "$WARM"); do spawn_one "w$i" "--overlay"; done

echo "== 交替计 $N 轮 =="
for i in $(seq 1 "$N"); do
  if [ $((i % 2)) -eq 1 ]; then
    spawn_one "p$i" ""
    spawn_one "o$i" "--overlay"
  else
    spawn_one "o$i" "--overlay"
    spawn_one "p$i" ""
  fi
done

# 从日志按 id 提取 PAYLOAD_NS（PAYLOAD_NS 行紧跟 PAYLOAD_META run=<id> 行）。
awk '
  /^PAYLOAD_NS=/ { v = substr($0, 12) }
  /^PAYLOAD_META run=/ { split($0, a, " "); id = substr(a[2], 5); print id, v }
' "$LOG" >"$WORK/pairs.txt"

median() { sort -n | awk '{a[NR]=$1} END {
  if (NR==0) {print 0; exit}
  print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)
}'; }

P=$(grep '^p' "$WORK/pairs.txt" | awk '{print $2}' | median)
O=$(grep '^o' "$WORK/pairs.txt" | awk '{print $2}' | median)
echo
echo "== PAYLOAD_NS p50（N=$N）=="
printf "  plain   : %s ns\n" "$P"
printf "  overlay : %s ns\n" "$O"
awk -v p="$P" -v o="$O" 'BEGIN {
  if (p>0) printf "  比值    : %.2fx，差 %.2f ms\n", o/p, (o-p)/1e6
}'

echo
echo "== overlay_mount 单次耗时（ms_private → overlay_mount，µs）=="
awk '
  /ANOLIX_TIMING run=o/ {
    match($0, /run=[^ ]+/);   r = substr($0, RSTART+4, RLENGTH-4)
    match($0, /stage=[^ ]+/); s = substr($0, RSTART+6, RLENGTH-6)
    match($0, /ns=[0-9]+/);   n = substr($0, RSTART+3, RLENGTH-3) + 0
    if (s == "ms_private")    mp[r] = n
    if (s == "overlay_mount") om[r] = n
  }
  END { c=0; t=0; for (r in om) if (r in mp) { d=(om[r]-mp[r])/1000; t+=d; c++;
        if (d>mx) mx=d }
        if (c>0) printf "  均值 %.0f µs，最坏 %.0f µs（%d 次）\n", t/c, mx, c }
' "$LOG"