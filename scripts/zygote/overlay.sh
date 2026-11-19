#!/usr/bin/env bash
# overlay.sh — zygote 路径的 overlay 写入隔离验证（需要 sudo）
#
# 三组断言：
#   反证：不开 --overlay，A 写 /written-marker → B 能看到   （共享是真的）
#   实验：开 --overlay，A 写 → B 看不到                    （隔离是真的）
#   基座：实验后共享 rootfs 里没有 written-marker          （写入只落 upper）
#
# 退出码从母体日志的 ANOLIX_REAP err= 读：
#   err=<nil>          = worker exit 0 = check 看到了文件
#   err=exit status 1  = worker exit 1 = check 没看到
#
# 用法：sudo ./scripts/zygote/overlay.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "需要 root：sudo $0" >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d /tmp/anolix-zygote-ov.XXXXXX)
SOCK=/tmp/anolix-zygote-ov.sock
MPID=""

cleanup() {
  [ -n "$MPID" ] && kill "$MPID" 2>/dev/null || true
  rm -f "$SOCK"
  rm -rf "$WORK"
}
trap cleanup EXIT

# sudo 会重置 PATH 与 Go 环境。
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
cp -a "$ROOT/rootfs" "$WORK/rootfs"
# 容器内 payload 是 root 但 caps 被 drop（无 CAP_DAC_OVERRIDE），
# rootfs 根目录属主必须是 root，否则写 /written-marker 会 EACCES。
chown root:root "$WORK/rootfs"

mkdir -p "$WORK/src"
cat >"$WORK/src/main.go" <<'GO'
package main

import "os"

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
# 二进制叫 markerbin、写的文件叫 written-marker：绝不能同路径，否则写标记会覆盖自己。
(cd "$WORK/src" && CGO_ENABLED=0 go build -o "$WORK/rootfs/markerbin" .)
echo "OK -> $WORK"
echo

echo "== 起母体（独立 socket，不碰你常驻的那个）=="
"$WORK/zygote" --socket "$SOCK" >"$WORK/mother.log" 2>&1 &
MPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || { echo "母体没起来" >&2; cat "$WORK/mother.log"; exit 1; }

# run <id> <overlay-flag> <write|check>：spawn 一个 worker 并等它被 reap。
run() {
  local id=$1 ov=$2 act=$3
  "$WORK/spawn" --socket "$SOCK" --id "$id" -- \
    "$WORK/worker-init" $ov --rootfs "$WORK/rootfs" -- /markerbin "$act" >/dev/null 2>&1
  for _ in $(seq 1 100); do
    grep -q "ANOLIX_REAP id=$id " "$WORK/mother.log" && return 0
    sleep 0.05
  done
  echo "!! $id 没被 reap" >&2
  return 1
}
# reap_err <id>：返回该 worker 的退出状态字符串。
reap_err() { grep "ANOLIX_REAP id=$1 " "$WORK/mother.log" | sed 's/.*err=//'; }

echo "== 反证组：不开 --overlay =="
run a1 "" write
[ "$(reap_err a1)" = "<nil>" ] || { echo "!! A 写入失败: $(reap_err a1)"; grep -A2 "id=a1" "$WORK/mother.log" | tail -3; exit 1; }
run b1 "" check
if [ "$(reap_err b1)" = "<nil>" ]; then
  echo "  B 看到了 A 写的文件  → 共享 rootfs，无隔离（符合预期）"
else
  echo "!! B 没看到 → 反证失败，隔离可能来自别处"; exit 1
fi
rm -f "$WORK/rootfs/written-marker"
echo

echo "== 实验组：开 --overlay =="
run a2 "--overlay" write
[ "$(reap_err a2)" = "<nil>" ] || { echo "!! A 写入失败: $(reap_err a2)"; exit 1; }
run b2 "--overlay" check
if [ "$(reap_err b2)" = "exit status 1" ]; then
  echo "  B 看不到 A 写的文件  → 写入隔离成立"
else
  echo "!! B 看到了（$(reap_err b2)）→ 隔离不成立"; exit 1
fi
if [ ! -f "$WORK/rootfs/written-marker" ]; then
  echo "  基座 rootfs 干净     → 写入只落在 upper"
else
  echo "!! 基座被污染 → 写入漏到了 lower"; exit 1
fi
echo
echo "== 全部通过 =="