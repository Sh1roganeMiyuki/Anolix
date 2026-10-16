#!/usr/bin/env bash
# 编译三个二进制到 bin/
set -euo pipefail
cd "$(dirname "$0")/../.."
export PATH="$HOME/.local/sdk/go/bin:$PATH"
go build -o bin/zygote ./cmd/zygote
go build -o bin/spawn  ./cmd/spawn
go build -o bin/worker ./cmd/worker
echo "OK: bin/{zygote,spawn,worker}"