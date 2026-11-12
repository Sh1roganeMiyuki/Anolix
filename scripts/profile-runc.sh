#!/usr/bin/env bash
# profile-runc.sh — 用族 B（perf 采样）拆 runc 的 15ms，并与族 A（strace）对照
#
# 三个数据点（同一段启动、同一个终点 = tprobe 的第一条用户态指令）：
#   A 裸跑    ：基线
#   B perf 下 ：族 B 的税（不停机、不换人）
#   C strace 下：族 A 的税（停机 + 换人）
#
# 用法：
#   sudo ./scripts/profile-runc.sh [轮数]      # 默认 30 轮
#
# 为什么必须 sudo：
#   perf_event_paranoid=2 时，非 root 只能采用户态；要看内核函数必须 root。
#
# 说明：脚本编译到临时目录，不会覆盖仓库根目录的 anolix 二进制。
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "需要 root：sudo $0 [轮数]" >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ROUNDS=${1:-30}
OUT=$(mktemp -d /tmp/anolix-profile.XXXXXX)
trap 'rm -rf "$OUT"' EXIT

# sudo 会重置 PATH 与 Go 环境：把当前用户的工具链/模块缓存找回来。
USER_HOME=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
if ! command -v go >/dev/null 2>&1; then
  export PATH="$USER_HOME/.local/sdk/go/bin:$USER_HOME/go/bin:/usr/local/go/bin:$PATH"
fi
command -v go >/dev/null 2>&1 || { echo "找不到 go 工具链" >&2; exit 1; }
export GOPATH="${GOPATH:-$USER_HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$USER_HOME/go/pkg/mod}"
export GOCACHE="${GOCACHE:-/tmp/anolix-go-cache}"

cd "$ROOT"

echo "== 环境 =="
echo "内核   : $(uname -r)"
echo "perf   : $(perf --version 2>&1 | head -1)"
echo "strace : $(strace --version 2>&1 | head -1)"
echo "轮数   : $ROUNDS"
echo

echo "== 构建 =="
go build -o "$OUT/anolix" ./cmd/anolix
cp -a "$ROOT/rootfs" "$OUT/rootfs"
CGO_ENABLED=0 go build -o "$OUT/rootfs/tprobe" ./cmd/tprobe
ROOTFS="$OUT/rootfs"
echo "OK -> $OUT"
echo

median() {
  sort -n | awk '{a[NR]=$1} END {
    if (NR==0) {print "-"; exit}
    print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)
  }'
}

# run_once 跑一次完整启动，只取 tprobe 自报的纳秒数（口径见 cmd/tprobe）。
run_once() {
  local out=$1
  "$OUT/anolix" run --timing --rootfs "$ROOTFS" -- /tprobe \
    2>>"$OUT/timing.log" | sed -n 's/^PAYLOAD_NS=//p' >>"$out" || true
}
export -f run_once
export OUT ROOTFS

echo "== A：裸跑 $ROUNDS 次 =="
: >"$OUT/base.txt"
for _ in $(seq 1 "$ROUNDS"); do run_once "$OUT/base.txt"; done
BASE=$(median <"$OUT/base.txt")
echo "PAYLOAD_NS 中位数: $BASE ns"
echo

echo "== B：perf 采样下 $ROUNDS 次 =="
if command -v perf >/dev/null 2>&1; then
  : >"$OUT/perf.txt"
  perf record -q -a -F 9999 -o "$OUT/perf.data" -- \
    bash -c 'for i in $(seq 1 '"$ROUNDS"'); do run_once "$OUT/perf.txt"; done' \
    || echo "!! perf record 失败，B 组数据作废"
  PERF=$(median <"$OUT/perf.txt")
  echo "PAYLOAD_NS 中位数: $PERF ns"
else
  echo "没有 perf，跳过"
  PERF="-"
fi
echo

echo "== C：strace 下 $ROUNDS 次 =="
if command -v strace >/dev/null 2>&1; then
  : >"$OUT/strace.txt"
  for _ in $(seq 1 "$ROUNDS"); do
    strace -f -o /dev/null \
      "$OUT/anolix" run --timing --rootfs "$ROOTFS" -- /tprobe \
      2>/dev/null | sed -n 's/^PAYLOAD_NS=//p' >>"$OUT/strace.txt" || true
  done
  STRACE=$(median <"$OUT/strace.txt")
  echo "PAYLOAD_NS 中位数: $STRACE ns"
else
  echo "没有 strace，跳过"
  STRACE="-"
fi
echo

echo "== 对照 =="
awk -v b="$BASE" -v p="$PERF" -v s="$STRACE" 'BEGIN {
  printf "A 裸跑    : %s ns\n", b
  printf "B perf 下 : %s ns", p
  if (b != "-" && p != "-") printf "  (%.2fx)", p/b
  printf "\n"
  printf "C strace 下: %s ns", s
  if (b != "-" && s != "-") printf "  (%.2fx)", s/b
  printf "\n"
}'
echo

if [ -f "$OUT/perf.data" ]; then
  echo "== perf 采样落在哪（按进程 + 符号，前 40 行）=="
  echo "   [.] = 用户态，[k] = 内核"
  echo
  perf report --stdio -i "$OUT/perf.data" --no-children --sort comm,dso,symbol 2>/dev/null \
    | grep -E '^ +[0-9]+\.[0-9]+%' | head -40 || echo "perf report 解析失败"
  echo
  echo "== 只看内核符号（前 40 行）=="
  perf report --stdio -i "$OUT/perf.data" --no-children --sort symbol 2>/dev/null \
    | grep -E '\[k\]' | head -40 || echo "没有内核符号（perf 5.10 可能解析不了 6.18 的内核）"
fi