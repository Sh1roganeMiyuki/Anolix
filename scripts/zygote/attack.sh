#!/usr/bin/env bash
# 攻击向量：真去"撑爆/越界"，看 cgroup/seccomp 的【执法】是否生效。
# （verify.sh 只查"装备"；attack.sh 才去"触发"。）
#
# 用法：./attack.sh <oom|pids|syscall|all>
# 前置：./build.sh && ./mother.sh up
#   想让 OOM 更明显：CGMEM=64 ./mother.sh up（worker 默认申请 512MB）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
SOCK="${SOCK:-/tmp/anolix-zygote.sock}"
LOG="${LOG:-/tmp/zygote-mother.log}"

a_oom() {
  local MB="${MB:-512}" before out pid
  echo "=== attack: OOM（申请 ${MB}MB，应超 memory.max 被杀）==="
  before=$(wc -l < "$LOG" 2>/dev/null || echo 0)
  out=$(sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker attack-oom "$MB")
  pid=$(echo "$out" | grep -oE 'host_pid:[[:space:]]+[0-9]+' | grep -oE '[0-9]+$')
  echo "  spawn → pid=$pid"
  sleep 3
  echo "  --- 母体日志（新行）---"
  { tail -n "+$((before+1))" "$LOG" | grep -E 'attack-oom|退出异常|killed' | sed 's/^/    /'; } || true
  echo "  期望：有 '[attack-oom] 申请...'；【没有】'居然没死'；母体报 'worker $pid 退出异常: signal: killed'（=137）"
}

a_pids() {
  local before
  echo "=== attack: pids 爆（狂 fork → 应被 pids.max 拦 → EAGAIN）==="
  before=$(wc -l < "$LOG" 2>/dev/null || echo 0)
  sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker attack-pids >/dev/null
  sleep 3
  echo "  --- 母体日志（新行）---"
  { tail -n "+$((before+1))" "$LOG" | grep -E 'attack-pids' | sed 's/^/    /'; } || true
  echo "  期望：'第 N 个 fork 失败: ... resource temporarily unavailable'（EAGAIN = pids.max 生效）"
}

a_syscall() {
  local before
  echo "=== attack: 危险 syscall（应被 seccomp 盖章 EPERM）==="
  before=$(wc -l < "$LOG" 2>/dev/null || echo 0)
  echo "  A: 装 seccomp"; sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker attack-syscall >/dev/null
  echo "  B: 不装（对照）"; sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker noseccomp attack-syscall >/dev/null
  sleep 1
  echo "  --- 母体日志（新行）---"
  { tail -n "+$((before+1))" "$LOG" | grep -E 'attack-syscall|nr=' | sed 's/^/    /'; } || true
  echo "  期望：A 全 EPERM ✅（被盖章）；B 不是 EPERM ❌（没拦）"
}

case "${1:-all}" in
  oom)     a_oom ;;
  pids)    a_pids ;;
  syscall) a_syscall ;;
  all)     a_oom; echo; a_pids; echo; a_syscall ;;
  *)       echo "用法: $0 <oom|pids|syscall|all>"; exit 1 ;;
esac