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
# 容器内 payload 是 root，但 caps 被 drop（没有 CAP_DAC_OVERRIDE），
# 所以 rootfs 根目录的属主必须是 root，否则连新建一个 /written-marker 都会被 EACCES。
# 生产环境里 rootfs 本来就是 root 构建的，这一步是修掉测试环境的不真实。
chown root:root "$ROOTFS"
CGO_ENABLED=0 go build -o "$ROOTFS/tprobe" ./cmd/tprobe

# marker：往容器根目录写一个标记文件 / 检查它是否存在。
# check 的退出码：0 = 存在（被污染），1 = 不存在（隔离成立）。
#
# 用 Go 而不是 C：glibc 静态程序的启动 syscall 集和 Go 不同，
# 按 Go 调出来的 seccomp 白名单可能漏了 C runtime 需要的（rseq/getrandom/prlimit64…），
# 结果程序在启动阶段就死了，根本走不到写文件——第一版就是这么假失败的。
mkdir -p "$WORK/src"
cat >"$WORK/src/main.go" <<'GO'
package main

import (
	"os"
)

func main() {
	if len(os.Args) < 2 {
		os.Exit(2)
	}
	switch os.Args[1] {
	case "write":
		if err := os.WriteFile("/written-marker", []byte("x"), 0o644); err != nil {
			os.Stderr.WriteString(err.Error() + "\n")
			os.Exit(3)
		}
	case "check":
		if _, err := os.Stat("/written-marker"); err != nil {
			os.Exit(1) // 不存在 = 隔离成立
		}
	}
}
GO
printf 'module marker\n\ngo 1.21\n' >"$WORK/src/go.mod"
# 二进制叫 markerbin，写的文件叫 written-marker：
# 两者绝不能同路径，否则“写标记”会把可执行文件覆盖掉。
(cd "$WORK/src" && CGO_ENABLED=0 go build -o "$ROOTFS/markerbin" .)
[ -x "$ROOTFS/markerbin" ] || { echo "markerbin 编译失败" >&2; exit 1; }
echo "OK -> $WORK"
echo

run() { # run <bundle名> <额外参数...> -- <容器内命令...>
  local bundle=$1; shift
  local -a extra=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do extra+=("$1"); shift; done
  [ "$#" -gt 0 ] && shift
  "$WORK/anolix" run --bundle "$WORK/$bundle" --rootfs "$ROOTFS" "${extra[@]}" -- "$@" \
    >/dev/null 2>>"$WORK/err-$bundle.log"
}

show_err() { # 失败时把容器 stderr 的尾巴露出来，别只给一个退出码
  local f=$1
  [ -s "$f" ] && { echo "  --- 容器 stderr（尾部）---"; tail -5 "$f" | sed 's/^/  /'; }
}

echo "== 反证组：不加 --overlay =="
rm -f "$ROOTFS/written-marker"
: >"$WORK/err-b-plain.log"
if run b-plain -- /markerbin write; then
  echo "  容器 A 写入成功（预期）"
else
  echo "  !! 容器 A 写入失败，下面的反证不可信"
  show_err "$WORK/err-b-plain.log"
fi
set +e
run b-plain -- /markerbin check
PLAIN_CHECK=$?
set -e
if [ "$PLAIN_CHECK" -eq 0 ]; then
  echo "  容器 B 看到了 A 写的文件  → 共享 rootfs，无隔离（符合预期）"
else
  echo "  !! 容器 B 没看到 A 写的文件 → 反证失败，隔离可能来自别处"
  show_err "$WORK/err-b-plain.log"
fi
rm -f "$ROOTFS/written-marker"
echo

echo "== 实验组：加 --overlay =="
rm -f "$ROOTFS/written-marker"
: >"$WORK/err-b-ov1.log"
if run b-ov1 --overlay -- /markerbin write; then
  echo "  容器 A 写入成功（预期）"
else
  echo "  !! 容器 A 写入失败，下面的隔离结论不成立"
  show_err "$WORK/err-b-ov1.log"
fi
set +e
run b-ov2 --overlay -- /markerbin check
OV_CHECK=$?
set -e
if [ "$OV_CHECK" -eq 1 ]; then
  echo "  容器 B 看不到 A 写的文件  → 写入隔离成立"
else
  echo "  !! 容器 B 看到了 A 写的文件 → 隔离失效"
fi
if [ -e "$ROOTFS/written-marker" ]; then
  echo "  !! 基座 rootfs 被污染了（lower 被写）→ overlay 没生效"
else
  echo "  基座 rootfs 干净          → 写入只落在 upper"
fi
echo

median() { sort -n | awk '{a[NR]=$1} END {if (NR==0) {print 0; exit}; print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)}'; }

echo "== 时延对比（$ROUNDS 轮，顺序反转交替，PAYLOAD_NS 中位数）=="
# 为什么要反转交替：固定“先裸后 overlay”会让 overlay 总跟在热缓存后面，
# 测出它“更快”；奇偶轮换顺序才能把偏差平均掉。
: >"$WORK/plain.txt"
: >"$WORK/ov.txt"
for i in $(seq 1 "$ROUNDS"); do
  if [ $((i % 2)) -eq 0 ]; then
    # 偶数轮：先 overlay 后裸跑
    "$WORK/anolix" run --bundle "$WORK/b-ov1" --rootfs "$ROOTFS" --overlay --timing -- /tprobe 2>>"$WORK/timing.log" \
      | sed -n 's/^PAYLOAD_NS=//p' >>"$WORK/ov.txt" || true
    "$WORK/anolix" run --bundle "$WORK/b-plain" --rootfs "$ROOTFS" --timing -- /tprobe 2>>"$WORK/timing.log" \
      | sed -n 's/^PAYLOAD_NS=//p' >>"$WORK/plain.txt" || true
  else
    # 奇数轮：先裸跑后 overlay（顺序反转，把偏差平均掉）
    "$WORK/anolix" run --bundle "$WORK/b-plain" --rootfs "$ROOTFS" --timing -- /tprobe 2>>"$WORK/timing.log" \
      | sed -n 's/^PAYLOAD_NS=//p' >>"$WORK/plain.txt" || true
    "$WORK/anolix" run --bundle "$WORK/b-ov1" --rootfs "$ROOTFS" --overlay --timing -- /tprobe 2>>"$WORK/timing.log" \
      | sed -n 's/^PAYLOAD_NS=//p' >>"$WORK/ov.txt" || true
  fi
done
BASE=$(median <"$WORK/plain.txt")
OV=$(median <"$WORK/ov.txt")

printf "  裸 rootfs  : %s ns\n" "$BASE"
printf "  + overlay  : %s ns" "$OV"
awk -v b="$BASE" -v o="$OV" 'BEGIN { if (b > 0 && o > 0) printf "  (%.2fx，差 %.2f ms)", o/b, (o-b)/1e6 }'
printf "\n"

echo
echo "== 挂载本身的耗时（从 --timing 的 ①.5 行取）=="
grep '①.5' "$WORK/timing.log" | tail -3 || echo "  （没有 ①.5 打点，见 $WORK/timing.log）"