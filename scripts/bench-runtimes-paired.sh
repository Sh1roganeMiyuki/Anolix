#!/usr/bin/env bash
# runc vs crun：成对交替采样，专门对抗环境漂移。
#
# 为什么需要成对：
#   整块测量（scripts/bench-runtimes.sh）里 runc 的 p50 两轮差了 16ms
#   （57.7 vs 41.1），而 crun 稳定在 24-28ms。整块跑会把"这一段时间机器
#   变快/变慢"整段记到某个运行时头上。成对采样让 A、B 相邻各跑一次，
#   共享同一段环境状态；前 WARM 对丢弃。
#
# 口径仍然是 07 篇的四个旋钮：
#   起点 = anolix 参数解析完成后的 CLOCK_MONOTONIC
#   终点 = payload main 的首条语句（Go runtime 初始化已完成；它仍包含在
#          t0 → main 这段墙钟里）。N=30 只够 p50；p95 需 200+，脚本里的
#          p95 仅作样本描述，不当结论。
#   条件 = 同一 rootfs / 同一 payload / 同一会话；rootless + 干净 PATH
#   样本 = 每档 N 对，热身 WARM 对，取 p50
#
# 用法：
#   ./scripts/bench-runtimes-paired.sh
#   ORDER="crun runc" ./scripts/bench-runtimes-paired.sh   # 交换轮内顺序做第二轮
#   N=50 WARM=5 ./scripts/bench-runtimes-paired.sh
#
# 输出：
#   p50/p95（每个运行时）
#   paired diff = runc_ns - crun_ns 的 p50（正数 = crun 更快）
#   win rate    = crun 更快的配对数 / 总配对数
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

N="${N:-30}"
WARM="${WARM:-3}"
ORDER="${ORDER:-runc crun}"
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
OUT="${OUT:-$ROOT/.bench-tmp/bench-paired}"
NOSEC="$OUT/no-seccomp.json"
mkdir -p "$OUT"
printf '{"seccomp":{"enabled":false}}\n' > "$NOSEC"

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
libdir="$ROOT/.tools/crun-root/usr/lib/x86_64-linux-gnu"
if [ -d "$libdir" ]; then
  export LD_LIBRARY_PATH="$libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

[ -x "$ROOT/anolix" ] || { echo "!! 缺 ./anolix"; exit 1; }
[ -x "$ROOT/rootfs/tprobe" ] || { echo "!! 缺 rootfs/tprobe"; exit 1; }
[ -x "$RUNC" ] || { echo "!! runc 不可执行：$RUNC"; exit 1; }
[ -x "$CRUN" ] || { echo "!! crun 不可执行：$CRUN"; exit 1; }

echo "=== 环境 ==="
echo "nproc=$(nproc) kernel=$(uname -r) uid=$(id -u) PATH目录=$(printf '%s' "$PATH" | tr ':' '\n' | wc -l)"
echo "runc=$RUNC ($("$RUNC" --version | head -1))"
echo "crun=$CRUN ($("$CRUN" --version | head -1))"
echo "样本：每档 $N 对（热身 $WARM 对）；轮内顺序：$ORDER"
echo "输出目录：$OUT"

run_once() { # path dir extra...
  local path=$1 dir=$2
  shift 2
  "$ROOT/anolix" run --runtime "$path" --rootfs "$ROOT/rootfs" --timing \
    --bundle "$dir/bundle" --state-dir "$dir/state" "$@" -- /tprobe 2>/dev/null \
    | sed -n 's/^PAYLOAD_NS=//p' || true
}

stat_line() { # file label
  sort -n "$1" | awk -v n="$2" '{a[NR]=$1}
    END{
      if (NR==0) { printf "  %-5s (无数据)\n", n; exit }
      p50=a[int((NR+1)*0.5)]; p95=a[int((NR+1)*0.95)]
      printf "  %-5s n=%-3d p50=%-8.3f p95=%-8.3f min=%-8.3f max=%-8.3f\n",
        n, NR, p50/1e6, p95/1e6, a[1]/1e6, a[NR]/1e6
    }'
}

paired_tier() { # tier label extra...
  local tier=$1 label=$2
  shift 2
  local dr="$OUT/runc-$tier" dc="$OUT/crun-$tier"
  mkdir -p "$dr/bundle" "$dr/state" "$dc/bundle" "$dc/state"
  local paired="$OUT/$tier.tsv"
  : > "$paired"
  local i ns_r ns_c
  for i in $(seq $((N + WARM))); do
    ns_r=""
    ns_c=""
    for kind in $ORDER; do
      case "$kind" in
        runc) ns_r=$(run_once "$RUNC" "$dr" "$@") ;;
        crun) ns_c=$(run_once "$CRUN" "$dc" "$@") ;;
        *) echo "!! 未知运行时：$kind"; exit 2 ;;
      esac
    done
    if [ "$i" -le "$WARM" ]; then
      continue
    fi
    if [ -n "$ns_r" ] && [ -n "$ns_c" ]; then
      printf '%s\t%s\t%s\n' "$i" "$ns_r" "$ns_c" >> "$paired"
    fi
  done

  echo
  echo "=== $label（$N 对，热身 $WARM，顺序 $ORDER）==="
  awk '{print $2}' "$paired" > "$OUT/$tier.runc"
  awk '{print $3}' "$paired" > "$OUT/$tier.crun"
  awk '{print $2 - $3}' "$paired" > "$OUT/$tier.diff"
  stat_line "$OUT/$tier.runc" runc
  stat_line "$OUT/$tier.crun" crun

  awk '{a[NR]=$1} END{
    if (NR==0) { print "  paired diff (无数据)"; exit }
    printf "  paired diff p50=%+.3f ms（正 = crun 更快，n=%d）\n",
      a[int((NR+1)*0.5)]/1e6, NR
  }' "$OUT/$tier.diff"

  awk '$2 > $3 {c++} END{
    if (NR==0) { print "  win rate (无数据)"; exit }
    printf "  crun 更快: %d/%d = %.0f%%\n", c, NR, c*100/NR
  }' "$paired"

  local pr pc
  pr=$(awk '{a[NR]=$1} END{if(NR) print a[int((NR+1)*0.5)]}' "$OUT/$tier.runc")
  pc=$(awk '{a[NR]=$1} END{if(NR) print a[int((NR+1)*0.5)]}' "$OUT/$tier.crun")
  awk -v a="${pr:-0}" -v b="${pc:-0}" 'BEGIN{
    if (a > 0 && b > 0) printf "  比值 runc / crun = %.2f×\n", a/b
  }'
}

paired_tier minimal-nosec "最小（--minimal-rootfs + 关 seccomp）" --minimal-rootfs --policy "$NOSEC"
paired_tier full-sec "完整（默认 spec + seccomp）"

echo
echo "⚠️ 口径边界："
echo "   - rootless（root 档需要 sudo），两种运行时都含 userns 成本。"
echo "   - 与 07 的 root 绝对值不可直接比；同一张表里的 runc 才是本次对照。"
echo "   - 换 ORDER 再跑一轮，用顺序相反的两张表判断缓存/频率偏置。"