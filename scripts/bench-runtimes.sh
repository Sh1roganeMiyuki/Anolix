#!/usr/bin/env bash
# 启动开销：runc vs crun，口径与 07 篇一致。
#
# 口径（四个旋钮，缺一不可）：
#   起点  = anolix 参数解析完成后的 CLOCK_MONOTONIC（--timing 注入 ANOLIX_T0_NS）
#   终点  = payload main 的首条语句（Go runtime 初始化已完成；它仍包含在
#           t0 → main 这段墙钟里）。N=30 只够 p50；p95 需 200+，脚本里的
#           p95 仅作样本描述，不当结论。
#   条件  = 同一 rootfs、同一 payload、同一实验会话；默认 rootless + 干净 PATH
#   样本  = 每档热身 WARM 次 + 计 N 次，取 p50（另给 p95/min/max）
#
# 档位（与 07 对齐，另加两格做归因）：
#   最小         --minimal-rootfs + 关 seccomp
#   最小+seccomp --minimal-rootfs
#   完整-seccomp 默认 spec + 关 seccomp
#   完整         默认 spec（6 挂载 + 17 加固）+ 默认 seccomp
#
# 用法：
#   ./scripts/bench-runtimes.sh
#   N=50 WARM=5 ./scripts/bench-runtimes.sh
#   ORDER="crun runc" ./scripts/bench-runtimes.sh     # 反向顺序，排除缓存偏置
#   RUNC=/usr/sbin/runc CRUN=/usr/bin/crun ./scripts/bench-runtimes.sh
#
# 前置：
#   go build -o anolix ./cmd/anolix
#   CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe
#   crun 可用（./scripts/deploy-crun.sh）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

N="${N:-30}"
WARM="${WARM:-3}"
RUNC="${RUNC:-/usr/sbin/runc}"
CRUN="${CRUN:-}"
if [ -z "$CRUN" ]; then
  # 优先用本地解包的真实二进制：bin/crun 是包装脚本，多一次 shell exec，
  # 会把包装开销算进启动时间（做对照时必须避开）。
  if [ -x "$ROOT/.tools/crun-root/usr/bin/crun" ]; then
    CRUN="$ROOT/.tools/crun-root/usr/bin/crun"
  elif command -v crun >/dev/null 2>&1; then
    CRUN="$(command -v crun)"
  else
    CRUN="$ROOT/bin/crun"
  fi
fi
OUT="${OUT:-$ROOT/.bench-tmp/bench-runtimes}"
NOSEC="$OUT/no-seccomp.json"
mkdir -p "$OUT"
printf '{"seccomp":{"enabled":false}}\n' > "$NOSEC"

# 干净 PATH：WSL 的 61 目录 PATH 会给 rootless 的 LookPath 凭空加 60ms（07 篇）。
# 这里两种运行时都用绝对路径，PATH 只影响它们内部对辅助程序的查找。
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# 本地解包的 crun 需要依赖库；系统安装的 crun 这一步是空操作。
libdir="$ROOT/.tools/crun-root/usr/lib/x86_64-linux-gnu"
if [ -d "$libdir" ]; then
  export LD_LIBRARY_PATH="$libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

[ -x "$ROOT/anolix" ] || { echo "!! 缺 ./anolix：go build -o anolix ./cmd/anolix"; exit 1; }
[ -x "$ROOT/rootfs/tprobe" ] || { echo "!! 缺 rootfs/tprobe：CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe"; exit 1; }
[ -x "$RUNC" ] || { echo "!! runc 不可执行：$RUNC"; exit 1; }
[ -x "$CRUN" ] || { echo "!! crun 不可执行：$CRUN（先 ./scripts/deploy-crun.sh）"; exit 1; }

echo "=== 环境 ==="
echo "nproc=$(nproc) kernel=$(uname -r) user=$(id -un) uid=$(id -u) PATH目录=$(printf '%s' "$PATH" | tr ':' '\n' | wc -l)"
echo "runc=$RUNC ($("$RUNC" --version | head -1))"
echo "crun=$CRUN ($("$CRUN" --version | head -1))"
echo "样本：每档热身 $WARM + 计 $N；起点=anolix 参数解析后，终点=payload main 首条语句"
echo "顺序：${ORDER:-runc crun}；输出目录：$OUT"

measure() { # runtime kind path tier label extra...
  local kind=$1 path=$2 tier=$3 label=$4
  shift 4
  local dir="$OUT/$kind-$tier"
  mkdir -p "$dir/bundle" "$dir/state"
  local samples="$dir/samples.ns"
  : > "$samples"
  local i ns fail=0
  for i in $(seq $((N + WARM))); do
    ns=$("$ROOT/anolix" run --runtime "$path" --rootfs "$ROOT/rootfs" --timing \
      --bundle "$dir/bundle" --state-dir "$dir/state" "$@" -- /tprobe 2>/dev/null \
      | sed -n 's/^PAYLOAD_NS=//p' || true)
    if [ -n "${ns:-}" ] && [ "$ns" -gt 0 ] 2>/dev/null; then
      if [ "$i" -gt "$WARM" ]; then
        echo "$ns" >> "$samples"
      fi
    else
      fail=$((fail + 1))
    fi
  done
  sort -n "$samples" | awk -v rt="$kind" -v n="$label" -v f="$fail" '{a[NR]=$1}
    END{
      if (NR==0) { printf "%-5s %-16s (无数据) fail=%d\n", rt, n, f; exit }
      p50=a[int((NR+1)*0.5)]; p95=a[int((NR+1)*0.95)]
      printf "%-5s %-16s n=%-3d p50=%-8.3f p95=%-8.3f min=%-8.3f max=%-8.3f fail=%d\n",
        rt, n, NR, p50/1e6, p95/1e6, a[1]/1e6, a[NR]/1e6, f
    }'
}

run_suite() { # runtime kind
  local kind=$1
  local path
  case "$kind" in
    runc) path="$RUNC" ;;
    crun) path="$CRUN" ;;
    *) echo "!! 未知运行时：$kind"; exit 2 ;;
  esac
  measure "$kind" "$path" minimal-nosec "最小" --minimal-rootfs --policy "$NOSEC"
  measure "$kind" "$path" minimal-sec   "最小+seccomp" --minimal-rootfs
  measure "$kind" "$path" full-nosec    "完整-seccomp" --policy "$NOSEC"
  measure "$kind" "$path" full-sec      "完整"
}

for kind in ${ORDER:-runc crun}; do
  run_suite "$kind"
done

echo
echo "=== 汇总（ms；p50 越小越快）==="
for kind in ${ORDER:-runc crun}; do
  for tier in minimal-nosec minimal-sec full-nosec full-sec; do
    f="$OUT/$kind-$tier/samples.ns"
    [ -s "$f" ] || continue
    sort -n "$f" | awk -v k="$kind" -v t="$tier" '{a[NR]=$1}
      END{printf "%-5s %-14s p50=%-8.3f\n", k, t, a[int((NR+1)*0.5)]/1e6}'
  done
done

echo
echo "⚠️ 口径边界："
echo "   - 本脚本只能跑 rootless（root 档需要 sudo）：runc/crun 都含 userns 成本。"
echo "   - 与 07 的 root 绝对值不可直接比；同表内的 runc 才是本次对照。"
echo "   - 两轮之间请换 ORDER 再跑一次，用顺序相反的结果判断缓存/频率偏置。"