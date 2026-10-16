#!/usr/bin/env bash
# zygote 机制验证：./verify.sh <ns|memfd|cgroup|seccomp|all>
#
# 前置：先 ./build.sh && ./mother.sh up
# 每个子命令 = 一条"探针"，spawn 一个 worker 然后从宿主侧验它该验的东西。
# worker 的自打印（smaps/探针结果）在母体日志里：./mother.sh log
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
SOCK="${SOCK:-/tmp/anolix-zygote.sock}"
LOG="${LOG:-/tmp/zygote-mother.log}"

# 从 spawn 输出里抠字段（host_pid / worker_id）
field() { echo "$1" | grep -oE "$2:[[:space:]]+[^[:space:]]+" | awk '{print $2}'; }

# spawn 一个 worker，回显它的 host_pid
spawn() {
  local out
  out=$(sudo ./bin/spawn --socket "$SOCK" -- "$@")
  field "$out" host_pid
}

t_ns() {
  echo "=== ns 隔离 ==="
  local out pid
  out=$(sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker hold 5)
  pid=$(field "$out" host_pid)
  echo "  spawn → host_pid=$pid"
  sleep 0.3
  echo "  期望：NSpid 两字段（宿主PID + ns内PID=1）"
  echo "  实测：$(grep NSpid "/proc/$pid/status" 2>/dev/null || echo '(worker 已退出)')"
}

t_memfd() {
  echo "=== memfd 共享（并发 3 个，看 Pss 摊薄 + Shared_Dirty）==="
  local pids=() out pid
  for i in 1 2 3; do
    out=$(sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker hold 10)
    pid=$(field "$out" host_pid); pids+=("$pid")
    echo "  worker$i → pid=$pid"
  done
  sleep 0.5
  for pid in "${pids[@]}"; do
    echo "  [$pid] memfd VMA:"
    { sudo grep -A14 -i memfd "/proc/$pid/smaps" 2>/dev/null \
        | grep -E '^(Rss|Pss|Shared_Dirty|Shared_Clean|Private_Dirty|Private_Clean):' \
        | sed 's/^/      /'; } || echo "      (已退出/无)"
  done
  echo "  期望：Shared_Dirty≈全区；Pss 随并发数摊薄（N 个→约 1/N）"
}

t_cgroup() {
  echo "=== cgroup 围栏 ==="
  local out pid wid leaf
  out=$(sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker hold 10)
  pid=$(field "$out" host_pid); wid=$(field "$out" worker_id)
  leaf="/sys/fs/cgroup/anolix-$wid"
  echo "  spawn → pid=$pid  wid=$wid"
  sleep 0.3
  echo "  叶子：$leaf"
  echo "    cgroup.procs: $(sudo cat "$leaf/cgroup.procs" 2>/dev/null | tr '\n' ' ')   ← 期望含 $pid"
  echo "    memory.max  : $(sudo cat "$leaf/memory.max" 2>/dev/null || echo '(无)')"
  echo "    pids.max    : $(sudo cat "$leaf/pids.max" 2>/dev/null || echo '(无)')"
  echo "    cpu.max     : $(sudo cat "$leaf/cpu.max" 2>/dev/null || echo '(无)')"
  echo "  注：worker 自带 CLONE_NEWCGROUP，它自己看到的是 ns 根；要从宿主侧看这个叶子。"
}

t_seccomp() {
  echo "=== seccomp A/B ==="
  local before
  before=$(wc -l < "$LOG" 2>/dev/null || echo 0)
  echo "  A: 装 seccomp（默认）"
  sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker >/dev/null
  echo "  B: 不装（noseccomp 对照组）"
  sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker noseccomp >/dev/null
  sleep 0.5
  echo "  --- 母体日志里两个 worker 的探针行 ---"
  { tail -n "+$((before+1))" "$LOG" | grep -E 'seccomp|探针' | sed 's/^/    /'; } || echo "    (没抓到)"
  echo "  期望：A 的 sethostname→EPERM ✅（被盖章）；B 的 sethostname→成功 ❌（没拦）"
}

case "${1:-all}" in
  ns)      t_ns ;;
  memfd)   t_memfd ;;
  cgroup)  t_cgroup ;;
  seccomp) t_seccomp ;;
  all)     t_ns; echo; t_memfd; echo; t_cgroup; echo; t_seccomp ;;
  *)       echo "用法: $0 <ns|memfd|cgroup|seccomp|all>"; exit 1 ;;
esac