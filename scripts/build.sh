#!/usr/bin/env bash
# Anolix 一键编译脚本（abuild）
# 全链路：gofmt 检查 → go vet → 编译 anolix → 跑测试
#
# 用法:
#   ./scripts/build.sh      # 在仓库任意位置都能跑（脚本自己切到仓库根目录）
#   abuild                  # shell 里的"一个单词"版本（见 ~/.bash_aliases）
set -euo pipefail
cd "$(dirname "$0")/.."   # 仓库根目录 = 脚本所在目录的上一级

# Go 工具链装在 ~/.local/sdk/go，PATH 里没有时补上（sudo 环境也没有）
if [ -x "$HOME/.local/sdk/go/bin/go" ]; then
  export PATH="$HOME/.local/sdk/go/bin:$PATH"
fi

echo "== 1/4 gofmt 检查（输出为空即合规）=="
dirty=$(gofmt -l .)
if [ -n "$dirty" ]; then
  echo "以下文件需要 gofmt -w 格式化："
  echo "$dirty"
  exit 1
fi

echo "== 2/4 go vet =="
go vet ./...

echo "== 3/4 go build =="
go build -o anolix ./cmd/anolix

echo "== 4/4 go test =="
go test ./...

echo "OK：anolix 已更新（$(pwd)/anolix）"