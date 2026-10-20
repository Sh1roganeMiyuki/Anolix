#!/usr/bin/env bash
# rootfs 演示：worker-init 换根（pivot_root）后，worker 只看得见 rootfs，看不见宿主。
#
# 用法：./rootfs.sh [rootfs 路径]
# 前置：./build.sh && ./mother.sh up
#
# 原理：worker-init 在新 mount ns（母体 clone 给的 CLONE_NEWNS）里做
#   MS_PRIVATE → bind rootfs → pivot_root → 挂 /proc → 装 seccomp → execve payload
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
SOCK="${SOCK:-/tmp/anolix-zygote.sock}"
LOG="${LOG:-/tmp/zygote-mother.log}"
INIT="$ROOT/bin/worker-init"
ROOTFS="${1:-${ROOTFS:-$ROOT/rootfs}}"

echo "=== rootfs 演示（worker-init 换根）==="
echo "  rootfs = $ROOTFS"
[ -x "$ROOTFS/bin/busybox" ] || { echo "!! $ROOTFS 里没有 bin/busybox"; exit 1; }

before=$(wc -l < "$LOG" 2>/dev/null || echo 0)
# payload：busybox（宿主的 /bin/busybox 进不去，得是 rootfs 里的 /bin/busybox）
sudo ./bin/spawn --socket "$SOCK" -- "$INIT" --rootfs "$ROOTFS" -- \
  /bin/busybox sh -c 'echo "[worker] 我看到的根（应只有 rootfs 内容）："; ls /; echo "[worker] 试宿主才有的 /home："; ls /home 2>&1'
sleep 1
echo "  --- 母体日志（新行）---"
{ tail -n "+$((before+1))" "$LOG" | sed 's/^/    /'; } || true
echo
echo "  期望：ls / 只有 rootfs 内容（bin/dev/proc/sys/tmp...）；"
echo "        ls /home 报 'No such file or directory'（看不见宿主文件系统）"