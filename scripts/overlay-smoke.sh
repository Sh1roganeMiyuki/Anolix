#!/usr/bin/env bash
# overlay-smoke.sh — 验证 overlay 写入隔离，并量出挂载开销（需要 sudo）
#
# 验三件事：
#   1. --overlay 起的容器能正常跑（runc 接受 merged 作为 rootfs）
#   2. 容器 A 写的文件，容器 B 看不到（写入隔离真的成立）
#   3. 不加 --overlay 时 B 能看到 A 写的（反证：隔离来自 overlay，不是别的）
#
# 顺带量：裸目录 vs overlay 的启动时延（PAYLOAD_NS 中位数，同 tprobe 口径）
#
# 用法：sudo ./scripts/overlay-smoke.sh [轮数]     # 默认 20 轮
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "需要 root：sudo $0 [轮数]" >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ROUNDS=${1:-20}
WORK=$(mktemp -d /tmp/anolix-overlay.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# sudo 会重置 PATH 与 Go 环境。
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
echo "内核 : $(uname -r)"
echo "轮数 : $ROUNDS"
echo

echo "== 构建 =="
go build -o "$WORK/anolix" ./cmd/anolix
cp -a "$ROOT/rootfs" "$WORK/rootfs"
ROOTFS="$WORK/rootfs"
CGO_ENABLED=0 go build -o "$ROOTFS/tprobe" ./cmd/tprobe

# marker：往容器根目录写一个标记文件 / 检查它是否存在。
# check 的退出码：0 = 存在（被污染），1 = 不存在（隔离成立）。
cat >"$WORK/marker.c" <<'C'
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    if (strcmp(argv[1], "write") == 0) {
        FILE *f = fopen("/marker", "w");
        if (!f) return 3;
        fputs("x", f); fclose(f); return 0;
    }
    if (strcmp(argv[1], "check") == 0) {
        FILE *f = fopen("/marker", "r");
        if (!f) return 1;
        fclose(f); return 0;
    }
    return 2;
}
C
gcc -static -O2 -o "$ROOTFS/marker" "$WORK/marker.c"
echo "OK -> $WORK"
echo

run() { # run <bundle名> <额外参数...> -- <容器内命令...>
  local bundle=$1; shift
  local -a extra=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do extra+=("$1"); shift; done
  [ "$#" -gt 0 ] && shift
  "$WORK/anolix" run --bundle "$WORK/$bundle" --rootfs "$ROOTFS" "${extra[@]}" -- "$@" \
    >/dev/null 2>>"$WORK/err.log"
}

echo "== 反证组：不加 --overlay =="
rm -f "$ROOTFS/marker"
run b-plain -- /marker write || echo "容器 A 退出码非 0（正常，marker write 应成功）"
set +e
run b-plain -- /marker check
PLAIN_CHECK=$?
set -e
if [ "$PLAIN_CHECK" -eq 0 ]; then
  echo "  容器 B 看到了 A 写的文件  → 共享 rootfs，无隔离（符合预期）"
else
  echo "  !! 容器 B 没看到 A 写的文件 → 反证失败，隔离可能来自别处"
fi
rm -f "$ROOTFS/marker"
echo

echo "== 实验组：加 --overlay =="
rm -f "$ROOTFS/marker"
run b-ov1 --overlay -- /marker write || true
set +e
run b-ov2 --overlay -- /marker check
OV_CHECK=$?
set -e
if [ "$OV_CHECK" -eq 1 ]; then
  echo "  容器 B 看不到 A 写的文件  → 写入隔离成立"
else
  echo "  !! 容器 B 看到了 A 写的文件 → 隔离失效"
fi
if [ -e "$ROOTFS/marker" ]; then
  echo "  !! 基座 rootfs 被污染了（lower 被写）→ overlay 没生效"
else
  echo "  基座 rootfs 干净          → 写入只落在 upper"
fi
echo

median() { sort -n | awk '{a[NR]=$1} END {if (NR==0) {print 0; exit}; print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)}'; }

echo "== 时延对比（$ROUNDS 轮，PAYLOAD_NS 中位数）=="
: >"$WORK/plain.txt"
for _ in $(seq 1 "$ROUNDS"); do
  "$WORK/anolix" run --bundle "$WORK/b-plain" --rootfs "$ROOTFS" --timing -- /tprobe 2>>"$WORK/timing.log" \
    | sed -n 's/^PAYLOAD_NS=//p' >>"$WORK/plain.txt" || true
done
BASE=$(median <"$WORK/plain.txt")

: >"$WORK/ov.txt"
for _ in $(seq 1 "$ROUNDS"); do
  "$WORK/anolix" run --bundle "$WORK/b-ov1" --rootfs "$ROOTFS" --overlay --timing -- /tprobe 2>>"$WORK/timing.log" \
    | sed -n 's/^PAYLOAD_NS=//p' >>"$WORK/ov.txt" || true
done
OV=$(median <"$WORK/ov.txt")

printf "  裸 rootfs  : %s ns\n" "$BASE"
printf "  + overlay  : %s ns" "$OV"
awk -v b="$BASE" -v o="$OV" 'BEGIN { if (b > 0 && o > 0) printf "  (%.2fx，差 %.2f ms)", o/b, (o-b)/1e6 }'
printf "\n"

echo
echo "== 挂载本身的耗时（从 --timing 的 ①.5 行取）=="
grep '①.5' "$WORK/timing.log" | tail -3 || echo "  （没有 ①.5 打点，见 $WORK/timing.log）"