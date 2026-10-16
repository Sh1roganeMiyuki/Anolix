#!/usr/bin/env bash
# 母体管理：./mother.sh <up|down|status|log [N]>
#
#   up     后台起母体（带 --warm + --cgroup），日志落 /tmp/zygote-mother.log
#   down   杀母体 + 清 socket + 清残留的 anolix-* cgroup 叶子
#   status 看母体在不在跑
#   log N  tail 最近 N 行日志（worker 的自打印都在这里）
#
# 可用环境变量覆盖默认：SOCK / LOG / WARM / CGMEM / CGPIDS / CGCPU
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SOCK="${SOCK:-/tmp/anolix-zygote.sock}"
LOG="${LOG:-/tmp/zygote-mother.log}"
WARM="${WARM:-64}"        # 共享 memfd 大小（MB）
CGMEM="${CGMEM:-256}"     # worker 内存上限（MB）；默认留足余量，别误 OOM
CGPIDS="${CGPIDS:-200}"   # worker 进程数上限
CGCPU="${CGCPU:-0}"       # worker CPU 配额百分比；0=不限

up() {
  sudo pkill -f 'bin/zygote' 2>/dev/null || true
  sleep 0.3
  sudo rm -f "$SOCK"
  cd "$ROOT"
  local cgargs=(--cgroup --cg-memory "$CGMEM" --cg-pids "$CGPIDS")
  if [ "$CGCPU" -gt 0 ]; then cgargs+=(--cg-cpu-pct "$CGCPU"); fi
  # setsid 脱离终端；</dev/null 断输入；日志落文件
  sudo bash -c "setsid ./bin/zygote --socket '$SOCK' --warm '$WARM' ${cgargs[*]} >'$LOG' 2>&1 </dev/null &"
  sleep 0.8
  if pgrep -f 'bin/zygote' >/dev/null; then
    echo "mother up: pid=$(pgrep -f 'bin/zygote' | head -1)  sock=$SOCK"
    echo "  log=$LOG"
    echo "  warm=${WARM}MB  cgroup: mem=${CGMEM}MB pids=${CGPIDS} cpu=${CGCPU}%"
  else
    echo "!! 母体没起来，日志末尾："; tail -n 20 "$LOG" || true; exit 1
  fi
}

down() {
  sudo pkill -f 'bin/zygote' 2>/dev/null || true
  sleep 0.3
  sudo rm -f "$SOCK"
  shopt -s nullglob
  for d in /sys/fs/cgroup/anolix-*; do
    sudo rmdir "$d" 2>/dev/null || echo "  留: $d（可能还有进程没退）"
  done
  echo "mother down, cleaned"
}

status() {
  pgrep -af 'bin/zygote' || echo "(母体没在跑)"
  ls -l "$SOCK" 2>/dev/null || true
}

log() { tail -n "${1:-30}" "$LOG"; }

case "${1:-status}" in
  up)     up ;;
  down)   down ;;
  status) status ;;
  log)    log "${2:-30}" ;;
  *)      echo "用法: $0 <up|down|status|log [N]>"; exit 1 ;;
esac