#!/usr/bin/env bash
# 测 --harden 的价格：同一条 zygote 路径、同一个 payload，只差 17 项加固
# （11 条掩蔽 + 6 条只读重挂，与 runc 的 maskedPaths/readonlyPaths 同构）。
#
# 目的：回答"你们的 4ms 是不是因为少做了加固"——如果是，加固后应该显著变慢。
#
# 用法：N=30 ./scripts/zygote/harden.sh
# 前置：./build.sh && ./mother.sh up
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
N="${N:-30}"; WARM="${WARM:-3}"
SOCK="${SOCK:-/tmp/anolix-zygote.sock}"
LOG="${LOG:-/tmp/zygote-mother.log}"
INIT="$ROOT/bin/worker-init"
ROOTFS="${ROOTFS:-$ROOT/rootfs}"

[ -S "$SOCK" ] || { echo "!! 母体没起：先 ./mother.sh up"; exit 1; }
[ -x "$ROOTFS/tprobe" ] || { echo "!! 缺 $ROOTFS/tprobe"; exit 1; }
sudo -n true 2>/dev/null || { echo "!! 先执行一次 sudo -v"; exit 1; }

run_mode() {
  local label=$1; shift
  local before; before=$(wc -l < "$LOG" 2>/dev/null || echo 0)
  for i in $(seq $((N + WARM))); do
    sudo ./bin/spawn --socket "$SOCK" --id "${label}$i" -- \
      "$INIT" "$@" --rootfs "$ROOTFS" -- /tprobe >/dev/null 2>&1 || true
  done
  sleep 1
  tail -n "+$((before + 1))" "$LOG" | sed -n 's/^PAYLOAD_NS=//p' | tail -n "$N" | sort -n |
    awk -v n="$label" '{a[NR]=$1}
      END{
        if (NR==0) { printf "%-8s (无数据)\n", n; exit }
        printf "%-8s n=%-3d p50=%-8.3f p95=%-8.3f min=%-8.3f max=%-8.3f (ms)\n",
          n, NR, a[int((NR+1)*0.5)]/1e6, a[int((NR+1)*0.95)]/1e6, a[1]/1e6, a[NR]/1e6
      }'
}

echo "=== zygote：无加固 vs 有加固（各 $N 次，热身 $WARM）==="
run_mode plain
run_mode harden --harden
