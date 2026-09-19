#!/usr/bin/env bash
# 构建 Anolix 最小 rootfs：静态编译探针（cmd/probe）并放入输出目录。
#
# 用法: ./scripts/mkrootfs.sh [输出目录]（默认 ./rootfs）
# 产物: <输出目录>/probe —— 静态二进制，即整个 rootfs 的全部内容。
set -euo pipefail
cd "$(dirname "$0")/.."

out="${1:-rootfs}"

if ! command -v go >/dev/null 2>&1; then
  echo "错误: 未找到 go，请先将 Go 加入 PATH（如 export PATH=\$HOME/.local/sdk/go/bin:\$PATH）" >&2
  exit 1
fi

mkdir -p "$out"
# 标准可写临时目录（1777）：容器 root 无 CAP_DAC_OVERRIDE，探针等程序需此目录写入。
mkdir -p "$out/tmp"
chmod 1777 "$out/tmp"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$out/probe" ./cmd/probe
echo "最小 rootfs 已就绪: $out/probe"
echo "运行: ./anolix run --policy examples/policy.json --rootfs $out -- /probe（非 root 自动 rootless）"