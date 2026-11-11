#!/usr/bin/env bash
# net-smoke.sh — rootful 容器网络冒烟测试（需要 sudo）
#
# 覆盖四件事：
#   1. launcher 能建出 netns / veth / 网桥；
#   2. 宿主经端口映射（DNAT）能访问容器内服务；
#   3. 容器能通过网关访问宿主（出站路径）；
#   4. 容器退出后 netns 与端口映射 chain 被清理。
#
# 用法：
#   sudo ./scripts/net-smoke.sh
#
# 说明：脚本会编译到临时目录，不会覆盖仓库根目录的 anolix 二进制。
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 sudo 运行：sudo $0" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
ROOT=$(pwd)
# sudo 会重置 PATH 与 Go 环境：把当前用户的工具链/模块缓存找回来。
USER_HOME=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
if ! command -v go >/dev/null 2>&1; then
  export PATH="$USER_HOME/.local/sdk/go/bin:$USER_HOME/go/bin:/usr/local/go/bin:$PATH"
fi
command -v go >/dev/null 2>&1 || { echo "找不到 go 工具链" >&2; exit 1; }
export GOPATH="${GOPATH:-$USER_HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$USER_HOME/go/pkg/mod}"
export GOCACHE="${GOCACHE:-/tmp/anolix-go-cache}"
HOST_PORT=${HOST_PORT:-18081}
CONT_PORT=${CONT_PORT:-18080}
GATEWAY=${GATEWAY:-10.88.0.1}
CONTAINER_ID="anolix-smoke-$$"
WORK=$(mktemp -d /tmp/anolix-net-smoke.XXXXXX)
PID=""
HOST_SRV=""
# 用宿主 eth0 的地址做“本机访问映射端口”的测试；
# 127.0.0.1 需要 hairpin（route_localnet），第一版不支持，见 README。
HOST_IP=${HOST_IP:-$(ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1 | head -1)}
[ -n "$HOST_IP" ] || { echo "无法确定宿主 eth0 地址" >&2; exit 1; }

cleanup() {
  if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  if [ -n "$HOST_SRV" ] && kill -0 "$HOST_SRV" 2>/dev/null; then
    kill "$HOST_SRV" 2>/dev/null || true
    wait "$HOST_SRV" 2>/dev/null || true
  fi
  ip netns delete "$CONTAINER_ID" 2>/dev/null || true
  ip netns delete "${CONTAINER_ID}-egress" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() {
  echo "[fail] $*" >&2
  echo "--- 容器日志 ---" >&2
  cat "$WORK/container.log" 2>/dev/null >&2 || true
  exit 1
}

echo "== 构建 =="
go build -o "$WORK/anolix" ./cmd/anolix
cp -a "$ROOT/rootfs" "$WORK/rootfs"
CGO_ENABLED=0 go build -o "$WORK/rootfs/probe" ./cmd/probe
ROOTFS="$WORK/rootfs"

echo "== 启动容器（bridge + 端口映射 $HOST_PORT:$CONT_PORT）=="
"$WORK/anolix" run \
  --id "$CONTAINER_ID" \
  --network bridge \
  --publish "$HOST_PORT:$CONT_PORT" \
  --rootfs "$ROOTFS" \
  -- /probe net serve "$CONT_PORT" >"$WORK/container.log" 2>&1 &
PID=$!

# 等 netns 出现（最多 10 秒）。
for _ in $(seq 1 50); do
  if ip netns list | grep -q "$CONTAINER_ID"; then
    break
  fi
  sleep 0.2
done
ip netns list | grep -q "$CONTAINER_ID" || fail "netns $CONTAINER_ID 未出现"

echo "== 断言 1：宿主经 DNAT 访问容器服务（$HOST_IP:$HOST_PORT）=="
RESP=""
for _ in $(seq 1 50); do
  RESP=$(python3 - "$HOST_IP" "$HOST_PORT" <<'PY' 2>/dev/null || true
import socket, sys
try:
    s = socket.create_connection((sys.argv[1], int(sys.argv[2])), 1)
    print(s.recv(64).decode().strip())
    s.close()
except OSError:
    pass
PY
)
  [ -n "$RESP" ] && break
  sleep 0.2
done
[ "$RESP" = "anolix probe" ] || fail "端口映射未返回预期内容（实际: ${RESP:-空}）"
echo "[ok] $HOST_IP:$HOST_PORT → 容器 :$CONT_PORT"

echo "== 断言 2：容器经网关访问宿主 =="
python3 - "$WORK" <<'PY'
import http.server, socketserver, sys, threading, os
port = 18082
os.chdir(sys.argv[1])
httpd = socketserver.TCPServer(("0.0.0.0", port), http.server.SimpleHTTPRequestHandler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
open("ready", "w").close()
import time
time.sleep(30)
PY
HOST_SRV=$!
for _ in $(seq 1 30); do [ -f "$WORK/ready" ] && break; sleep 0.2; done
"$WORK/anolix" run \
  --id "${CONTAINER_ID}-egress" \
  --network bridge \
  --rootfs "$ROOTFS" \
  -- /probe net tcp "$GATEWAY:18082" >"$WORK/egress.log" 2>&1 \
  || { kill "$HOST_SRV" 2>/dev/null || true; fail "容器到网关的出站连接失败"; }
kill "$HOST_SRV" 2>/dev/null || true
wait "$HOST_SRV" 2>/dev/null || true
echo "[ok] 容器 → $GATEWAY:18082"

echo "== 断言 3：退出后清理 =="
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
PID=""

for _ in $(seq 1 50); do
  if ! ip netns list | grep -q "$CONTAINER_ID"; then
    break
  fi
  sleep 0.2
done
ip netns list | grep -q "$CONTAINER_ID" && fail "容器退出后 netns 未清理"
if nft list table inet anolix 2>/dev/null | grep -q "p_"; then
  fail "容器退出后端口映射 chain 未清理"
fi
echo "[ok] netns 与端口映射 chain 已清理"

echo "== 全部通过 =="