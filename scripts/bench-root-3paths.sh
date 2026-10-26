#!/usr/bin/env bash
# root 口径：runc / crun / zygote 三条路径同口径对照。
#
# 口径（与 07 篇、交接文档一致）：
#   起点 = 前端进程参数解析完成后的 CLOCK_MONOTONIC
#          anolix 路径：anolix --timing 注入 ANOLIX_T0_NS
#          zygote 路径：spawn 客户端取 t0，经协议 → 母体 → worker env
#   终点 = payload main 的首条语句（PAYLOAD_NS；Go runtime 初始化已完成，
#          但它仍包含在 t0 → main 这段墙钟里）
#   条件 = 同一 rootfs / 同一 payload / 同一会话；三条路径都以 root 运行
#   样本 = 每档热身 WARM 次 + 计 N 次，取 p50（N=30 只报 p50；不报 p95）
#
# 档位（与 07 对齐）：
#   runc/crun 最小 = --minimal-rootfs + 关 seccomp
#   runc/crun 完整 = 默认 spec（6 挂载 + 17 加固）+ 默认 seccomp
#   zygote   最小 = worker-init 默认（只挂 /proc、/dev；seccomp 始终安装）
#   zygote   完整 = worker-init --harden（补 4 挂载 + 11 掩蔽 + 6 只读）
#
# ⚠️ 已知不对称（07 也如此）：zygote 的 worker-init 总是装 seccomp，
#    所以它的“最小”比 runc/crun 的“最小”多一道 seccomp。结论里必须带这句。
#
# 用法：
#   1) 在终端执行一次  sudo -v        # 缓存 sudo，脚本内部用 sudo -n，避免中途弹密码
#   2) ./scripts/bench-root-3paths.sh
#   3) ORDER="zygote crun runc" OUT=$PWD/.bench-tmp/bench-root-b ./scripts/bench-root-3paths.sh
#
# 也可以直接以 root 跑（等价于 root 口径，但输出文件归 root）：
#   sudo ./scripts/bench-root-3paths.sh
#
# 母体配置沿用 07 的默认（WARM=64 / CGMEM=256 / CGPIDS=200），
# 所以 zygote 的数里含 per-worker cgroup 的建叶子成本。
#
# 前置：
#   go build -o anolix ./cmd/anolix
#   CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe
#   ./scripts/zygote/build.sh
#   crun 可用（./scripts/deploy-crun.sh）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

N="${N:-30}"
WARM="${WARM:-3}"
ORDER="${ORDER:-runc crun zygote}"
NEED_ZYGOTE=0
case " $ORDER " in
  *" zygote "*) NEED_ZYGOTE=1 ;;
esac
OUT="${OUT:-$ROOT/.bench-tmp/bench-root}"
RUNC="${RUNC:-/usr/sbin/runc}"
CRUN="${CRUN:-}"
ROOTFS="${ROOTFS:-$ROOT/rootfs}"
INIT="$ROOT/bin/worker-init"
SOCK="$OUT/zygote.sock"
LOG="$OUT/mother.log"
WORK="$OUT/work"
NOSEC="$OUT/no-seccomp.json"
RUNID="$(date +%s)-$$"

if [ -z "$CRUN" ]; then
  # 优先真实二进制；bin/crun 包装脚本会多一次 shell exec（约 2ms）。
  if [ -x "$ROOT/.tools/crun-root/usr/bin/crun" ]; then
    CRUN="$ROOT/.tools/crun-root/usr/bin/crun"
  elif command -v crun >/dev/null 2>&1; then
    CRUN="$(command -v crun)"
  else
    CRUN="$ROOT/bin/crun"
  fi
fi

# root 口径：本脚本自己可以是普通用户（内部 sudo -n），也可以直接是 root。
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
LIBDIR="$ROOT/.tools/crun-root/usr/lib/x86_64-linux-gnu"
if [ -d "$LIBDIR" ]; then
  export LD_LIBRARY_PATH="$LIBDIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

if [ "$(id -u)" -eq 0 ]; then
  SUDO=()
else
  sudo -n true 2>/dev/null || {
    echo "!! root 口径需要 sudo 缓存：先在终端执行一次  sudo -v"
    echo "   或者直接以 root 运行：sudo $0"
    exit 1
  }
  SUDO=(sudo -n)
fi

mkdir -p "$OUT" "$WORK"
printf '{"seccomp":{"enabled":false}}\n' > "$NOSEC"

[ -x "$ROOT/anolix" ] || { echo "!! 缺 ./anolix：go build -o anolix ./cmd/anolix"; exit 1; }
[ -x "$ROOTFS/tprobe" ] || { echo "!! 缺 rootfs/tprobe：CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe"; exit 1; }
[ -x "$RUNC" ] || { echo "!! runc 不可执行：$RUNC"; exit 1; }
[ -x "$CRUN" ] || { echo "!! crun 不可执行：$CRUN（先 ./scripts/deploy-crun.sh）"; exit 1; }
if [ "$NEED_ZYGOTE" -eq 1 ]; then
  [ -x "$ROOT/bin/zygote" ] || { echo "!! 缺 bin/zygote：./scripts/zygote/build.sh"; exit 1; }
  [ -x "$ROOT/bin/spawn" ] || { echo "!! 缺 bin/spawn：./scripts/zygote/build.sh"; exit 1; }
  [ -x "$INIT" ] || { echo "!! 缺 bin/worker-init：./scripts/zygote/build.sh"; exit 1; }
fi

# --- 母体：socket 不在就按 07 的默认配置起一个；脚本退出时只清自己起的 ---
STARTED_MOTHER=0
cleanup() {
  if [ "$STARTED_MOTHER" -eq 1 ]; then
    SOCK="$SOCK" LOG="$LOG" "$ROOT/scripts/zygote/mother.sh" down || true
  fi
}
trap cleanup EXIT

if [ "$NEED_ZYGOTE" -eq 1 ] && [ ! -S "$SOCK" ]; then
  echo "=== 起母体（WARM=${WARM_MB:-64}MB, cgroup mem=${CGMEM:-256}MB pids=${CGPIDS:-200}）==="
  SOCK="$SOCK" LOG="$LOG" WARM="${WARM_MB:-64}" CGMEM="${CGMEM:-256}" CGPIDS="${CGPIDS:-200}" \
    "$ROOT/scripts/zygote/mother.sh" up
  STARTED_MOTHER=1
  "${SUDO[@]}" chmod 0644 "$LOG" 2>/dev/null || true
elif [ "$NEED_ZYGOTE" -eq 1 ]; then
  echo "=== 复用已存在的母体：$SOCK ==="
  echo "    ⚠️ 它的 --warm/--cgroup 配置不由本脚本保证，结论里要写清"
else
  echo "=== ORDER 不含 zygote：本轮不起母体，只测 $ORDER ==="
fi

# 母体日志可能是 root 写的；不可读时用 sudo grep。
if [ -r "$LOG" ]; then GREP=(grep); else GREP=("${SUDO[@]}" grep); fi

echo
echo "=== 环境（root 口径）==="
echo "uid=$(id -u) nproc=$(nproc) kernel=$(uname -r) PATH目录=$(printf '%s' "$PATH" | tr ':' '\n' | wc -l)"
echo "runc=$RUNC ($("$RUNC" --version | head -1))"
echo "crun=$CRUN ($("$CRUN" --version | head -1))"
echo "zygote mother: sock=$SOCK log=$LOG"
echo "样本：每档热身 $WARM + 计 $N；轮内顺序：$ORDER；输出：$OUT"
echo "⚠️ zygote 的“最小”也装了 seccomp（worker-init 总是装）；与 runc/crun 最小档不完全对称"

run_anolix() { # runtime path dir extra...
  local path=$1 dir=$2
  shift 2
  "${SUDO[@]}" env PATH="$PATH" LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}" \
    "$ROOT/anolix" run --runtime "$path" --rootfs "$ROOTFS" --timing \
    --bundle "$dir/bundle" --state-dir "$dir/state" "$@" -- /tprobe 2>/dev/null \
    | sed -n 's/^PAYLOAD_NS=//p' || true
}

run_zygote() { # tag extra...
  local tag=$1
  shift
  local err="$OUT/zygote-$tag.err"
  if ! "${SUDO[@]}" "$ROOT/bin/spawn" --socket "$SOCK" --id "$tag" -- \
    "$INIT" "$@" --rootfs "$ROOTFS" -- /tprobe >/dev/null 2>"$err"; then
    echo "zygote spawn 失败 $tag: $(tail -1 "$err" 2>/dev/null)" >&2
    echo ""
    return 0
  fi
  # payload 异步运行：轮询日志，等这个 tag 的 PAYLOAD_META 出现。
  # 直接解析 PAYLOAD_META 里的 t0_ns/abs_ns 相减，不用 -B1 抓上一行——
  # 多个 goroutine 写日志时，PAYLOAD_NS 与 PAYLOAD_META 之间可能被插队。
  local deadline=$((SECONDS + 5)) ns=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    ns=$("${GREP[@]}" "^PAYLOAD_META run=$tag " "$LOG" 2>/dev/null | tail -1 | awk '
      {for(i=1;i<=NF;i++){split($i,kv,"="); v[kv[1]]=kv[2]}}
      END{if(v["t0_ns"] && v["abs_ns"]) print v["abs_ns"]-v["t0_ns"]}')
    if [ -n "$ns" ] && [ "$ns" -gt 0 ] 2>/dev/null; then
      echo "$ns"
      return 0
    fi
    sleep 0.01
  done
  echo ""
}

stat_line() { # file label
  sort -n "$1" | awk -v n="$2" '{a[NR]=$1}
    END{
      if (NR==0) { printf "  %-7s (无数据)\n", n; exit }
      printf "  %-7s n=%-3d p50=%-8.3f min=%-8.3f max=%-8.3f\n",
        n, NR, a[int((NR+1)*0.5)]/1e6, a[1]/1e6, a[NR]/1e6
    }'
}

p50_of() {
  sort -n "$1" 2>/dev/null | awk '{a[NR]=$1} END{if(NR) printf "%.0f", a[int((NR+1)*0.5)]; else printf "0"}'
}

measure_tier() { # tier label
  local tier=$1 label=$2
  local -a ax=() zx=()
  case "$tier" in
    minimal) ax=(--minimal-rootfs --policy "$NOSEC"); zx=() ;;
    full)    ax=(); zx=(--harden) ;;
    *) echo "!! 未知档位：$tier"; exit 2 ;;
  esac

  mkdir -p "$WORK/runc-$tier" "$WORK/crun-$tier"
  local f_r="$OUT/$tier.runc.ns" f_c="$OUT/$tier.crun.ns" f_z="$OUT/$tier.zygote.ns"
  : > "$f_r"; : > "$f_c"; : > "$f_z"

  local i kind tag ns
  for i in $(seq $((N + WARM))); do
    for kind in $ORDER; do
      case "$kind" in
        runc)
          ns=$(run_anolix "$RUNC" "$WORK/runc-$tier" "${ax[@]}")
          if [ "$i" -gt "$WARM" ] && [ -n "$ns" ]; then echo "$ns" >> "$f_r"; fi
          ;;
        crun)
          ns=$(run_anolix "$CRUN" "$WORK/crun-$tier" "${ax[@]}")
          if [ "$i" -gt "$WARM" ] && [ -n "$ns" ]; then echo "$ns" >> "$f_c"; fi
          ;;
        zygote)
          tag="z-$tier-$i-$RUNID"
          ns=$(run_zygote "$tag" "${zx[@]}")
          if [ "$i" -gt "$WARM" ] && [ -n "$ns" ]; then echo "$ns" >> "$f_z"; fi
          ;;
        *) echo "!! 未知路径：$kind"; exit 2 ;;
      esac
    done
  done

  echo
  echo "=== $label（$N 次，热身 $WARM，顺序 $ORDER）==="
  stat_line "$f_r" runc
  stat_line "$f_c" crun
  if [ "$NEED_ZYGOTE" -eq 1 ]; then
    stat_line "$f_z" zygote
  fi

  local pr pc pz
  pr=$(p50_of "$f_r"); pc=$(p50_of "$f_c"); pz=$(p50_of "$f_z")
  awk -v r="$pr" -v c="$pc" -v z="$pz" 'BEGIN{
    if (r>0 && c>0) printf "  runc / crun   = %.2f× （crun 用时 %.0f%%）\n", r/c, c*100/r
    if (r>0 && z>0) printf "  runc / zygote = %.2f× （zygote 用时 %.0f%%）\n", r/z, z*100/r
    if (c>0 && z>0) printf "  crun / zygote = %.2f× （zygote 用时 %.0f%%）\n", c/z, z*100/c
  }'
}

measure_tier minimal "最小（runc/crun: --minimal-rootfs+无 seccomp；zygote: 默认+seccomp）"
measure_tier full "完整（runc/crun: 默认 spec+seccomp；zygote: --harden+seccomp）"

echo
echo "=== 清理 root 所有的 bundle/state（保留 samples 与母体日志）==="
"${SUDO[@]}" rm -rf "$WORK"

echo
echo "⚠️ 口径边界："
echo "   - 墙钟，不是 CPU 时间；不含 sudo 启动（t0 在前端进程内部）。"
echo "   - N=30 只报 p50；min/max 仅作样本描述。"
echo "   - zygote 的“最小”也装了 seccomp，与 runc/crun 最小档不完全对称。"
echo "   - zygote 母体沿用 07 配置（含 per-worker cgroup），与 runc/crun 默认无 cgroup 限额不同。"
echo "   - 换 ORDER 再跑一轮，用顺序相反的两份结果判断漂移。"