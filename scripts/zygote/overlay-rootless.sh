#!/usr/bin/env bash
# overlay-rootless.sh — rootless（普通用户，不 sudo）zygote overlay 写入隔离验证
#
# 与 overlay.sh 同三组断言，但全程普通用户：
#   母体不 sudo；rootfs 属主保持用户（kuid 匹配才可写）；overlay base 自动落 $HOME/.cache。
#
# 用法：./scripts/zygote/overlay-rootless.sh
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  echo "本脚本验证 rootless，请用普通用户跑（不要 sudo）" >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# 临时目录放仓库内 .gotmp（某些沙箱环境 /tmp 只读）；socket 也放里面。
mkdir -p "$ROOT/.gotmp"
WORK=$(mktemp -d "$ROOT/.gotmp/rl-ov.XXXXXX")
SOCK="$WORK/sock"
LOG="$WORK/mother.log"
MPID=""

cleanup() {
  [ -n "$MPID" ] && kill "$MPID" 2>/dev/null || true
  rm -f "$SOCK"
  rm -rf "$WORK"
}
trap cleanup EXIT

export GOCACHE="${GOCACHE:-$ROOT/.gocache}"
export GOTMPDIR="${GOTMPDIR:-$ROOT/.gotmp}"
export TMPDIR="${TMPDIR:-$ROOT/.gotmp}"

echo "== 构建 =="
(cd "$ROOT" && go build -o "$WORK/zygote" ./cmd/zygote \
  && go build -o "$WORK/spawn" ./cmd/spawn \
  && go build -o "$WORK/worker-init" ./cmd/worker-init)
# 逐个 cp 顶层非隐藏条目：跳过 rootful 残留的 .oldroot（root 0700，普通用户读不了）。
mkdir -p "$WORK/rootfs"
for f in "$ROOT/rootfs"/*; do cp -a "$f" "$WORK/rootfs/"; done
# rootless 不 chown：rootfs 属主保持当前用户，worker kuid=当前用户 才写得上。
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
			os.Exit(1)
		}
	}
}
GO
printf 'module marker\n\ngo 1.21\n' >"$WORK/src/go.mod"
(cd "$WORK/src" && CGO_ENABLED=0 go build -o "$WORK/rootfs/markerbin" .)
echo "OK -> $WORK"
echo

echo "== 起母体（普通用户）=="
"$WORK/zygote" --socket "$SOCK" >"$LOG" 2>&1 &
MPID=$!
for _ in $(seq 1 50); do [ -S "$SOCK" ] && break; sleep 0.05; done
[ -S "$SOCK" ] || { echo "母体没起来" >&2; cat "$LOG"; exit 1; }

run() {
  local id=$1 ov=$2 act=$3
  "$WORK/spawn" --socket "$SOCK" --id "$id" -- \
    "$WORK/worker-init" $ov --rootfs "$WORK/rootfs" -- /markerbin "$act" >/dev/null 2>&1
  for _ in $(seq 1 100); do
    grep -q "ANOLIX_REAP id=$id " "$LOG" && return 0
    sleep 0.05
  done
  echo "!! $id 没被 reap" >&2
  return 1
}
reap_err() { grep "ANOLIX_REAP id=$1 " "$LOG" | sed 's/.*err=//'; }

echo "== 反证组：不开 --overlay =="
run a1 "" write
[ "$(reap_err a1)" = "<nil>" ] || { echo "!! A 写入失败: $(reap_err a1)"; exit 1; }
run b1 "" check
if [ "$(reap_err b1)" = "<nil>" ]; then
  echo "  B 看到了 A 写的文件  → 共享 rootfs，无隔离（符合预期）"
else
  echo "!! B 没看到 → 反证失败"; exit 1
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
  echo "!! 基座被污染"; exit 1
fi
echo
echo "== rootless 全部通过 =="