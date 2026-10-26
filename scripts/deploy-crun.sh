#!/usr/bin/env bash
# 部署 crun 启动链路。
#
# 三种模式（默认 auto，按身份自动选）：
#   auto（缺省）  系统已有 crun → 直接用；root → apt 装系统包；否则 → 仓库内本地解包
#   --local      强制本地解包（不碰系统，不需要 root）
#   --system     强制系统安装（需要 root）
#
# 本地解包为什么可行：Ubuntu 的 crun 只额外依赖 libyajl2，
# 把两个 deb 解到 .tools/crun-root，再用 bin/crun 包装脚本补上
# LD_LIBRARY_PATH 即可运行。包装脚本只多一层 shell exec（约 1ms），
# 做启动性能测量时请改用系统安装的 crun。
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODE="${1:-auto}"
TOOLS="$ROOT/.tools"
DEB_DIR="$TOOLS/crun-deb"
PREFIX="$TOOLS/crun-root"
WRAPPER="$ROOT/bin/crun"

log() { printf '[crun] %s\n' "$*"; }

# 1) 系统已有 crun：什么都不用做。
if [ "$MODE" != "--local" ] && [ "$MODE" != "--system" ] && command -v crun >/dev/null 2>&1; then
  log "系统已安装: $(command -v crun)"
  crun --version | head -1
  log "用法: ./anolix run --runtime crun --rootfs ./rootfs -- /probe"
  exit 0
fi

# 2) root：装系统包（这是长期形态，也是性能测量的正确形态）。
if [ "$MODE" = "--system" ] || { [ "$MODE" = "auto" ] && [ "$(id -u)" -eq 0 ]; }; then
  if [ "$(id -u)" -ne 0 ]; then
    log "系统安装需要 root：sudo ./scripts/deploy-crun.sh --system"
    exit 2
  fi
  log "安装系统包 crun"
  apt-get update -qq
  apt-get install -y crun
  crun --version | head -1
  log "用法: ./anolix run --runtime crun --rootfs ./rootfs -- /probe"
  exit 0
fi

# 3) 本地解包：不需要 root，产物都在仓库内（.tools/ 与 bin/crun 均已忽略）。
arch="$(dpkg --print-architecture)"
if [ "$arch" != "amd64" ]; then
  log "本地解包目前只处理 amd64，当前 $arch；请用 sudo 安装系统包"
  exit 2
fi

if [ ! -x "$PREFIX/usr/bin/crun" ]; then
  mkdir -p "$DEB_DIR" "$PREFIX"
  log "下载 crun 与 libyajl2 的 deb（apt-get download，无需 root）"
  ( cd "$DEB_DIR" && apt-get download crun libyajl2 )
  for deb in "$DEB_DIR"/*.deb; do
    log "解包 $(basename "$deb")"
    dpkg-deb -x "$deb" "$PREFIX"
  done
fi

# 找出 multiarch 库目录（x86_64-linux-gnu），把相对路径写进包装脚本：
# 仓库整体搬迁后仍然可用，不必重新生成。
libdir="$(find "$PREFIX/usr/lib" -maxdepth 1 -type d -name '*-linux-gnu' | head -n1)"
if [ -z "$libdir" ]; then
  log "没找到 multiarch 库目录，解包不完整"
  exit 2
fi
librel="${libdir#"$PREFIX/"}"

mkdir -p "$ROOT/bin"
{
  printf '#!/bin/sh\n'
  printf '# 由 scripts/deploy-crun.sh 生成：本地解包的 crun + 依赖库目录。\n'
  printf 'set -e\n'
  printf 'root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"\n'
  printf 'exec env LD_LIBRARY_PATH="$root/.tools/crun-root/%s${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \\\n' "$librel"
  printf '  "$root/.tools/crun-root/usr/bin/crun" "$@"\n'
} > "$WRAPPER"
chmod +x "$WRAPPER"

log "本地部署完成: $WRAPPER"
"$WRAPPER" --version | head -1
log "用法: ./anolix run --runtime ./bin/crun --rootfs ./rootfs -- /probe"
log "提示: sudo ./scripts/deploy-crun.sh --system 可换成系统安装（无包装层）"