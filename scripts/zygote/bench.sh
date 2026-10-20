#!/usr/bin/env bash
# 测一次 zygote spawn 的分段耗时，并与 03 篇里 runc 的冷启动分解对照。
#
# 用法：N=30 ./scripts/zygote/bench.sh
# 前置：./build.sh && ./mother.sh up
#
# 时间基准：母体在 clone 之前取一次 CLOCK_MONOTONIC，经 env 传给 worker-init；
# 每个 stage 打出的 ns 都是"相对那一刻"的累计值。相邻两站相减 = 该阶段耗时。
#
# ⚠️ 两边口径不同：runc 那组数是 strace 下的（每条 syscall 一次 ptrace 往返），
#    是上界；这里的数是裸跑。只能比数量级，不能比"精确到毫秒的胜负"。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"

SOCK="${SOCK:-/tmp/anolix-zygote.sock}"
LOG="${LOG:-/tmp/zygote-mother.log}"
INIT="$ROOT/bin/worker-init"
ROOTFS="${ROOTFS:-$ROOT/rootfs}"
N="${N:-30}"

[ -S "$SOCK" ] || { echo "!! 母体没起：先 ./mother.sh up"; exit 1; }
[ -x "$INIT" ] || { echo "!! 缺 $INIT：先 ./build.sh"; exit 1; }
[ -x "$ROOTFS/bin/busybox" ] || { echo "!! $ROOTFS 里没有 bin/busybox"; exit 1; }

before=$(wc -l < "$LOG" 2>/dev/null || echo 0)

echo "=== 跑 $N 次 spawn（payload = rootfs 里的 busybox true）==="
for i in $(seq "$N"); do
  sudo ./bin/spawn --socket "$SOCK" --id "b$i" -- \
    "$INIT" --rootfs "$ROOTFS" -- /bin/busybox true >/dev/null 2>&1 || true
done
sleep 1

RAW="$(mktemp)"
trap 'rm -f "$RAW"' EXIT
tail -n "+$((before+1))" "$LOG" | grep 'ANOLIX_TIMING' > "$RAW" || true

echo "  打点行数: $(wc -l < "$RAW")（期望 $((N * 8))）"

echo
echo "=== 累计耗时（相对母体 clone 前，ms）==="
printf '%-16s %-5s %-9s %-9s %-9s\n' "stage" "n" "p50" "p95" "max"
for st in init_start ms_private bind_rootfs pivot_root detach_oldroot mounts seccomp execve; do
  grep "stage=$st " "$RAW" | sed 's/.* ns=//' | sort -n | awk -v s="$st" '
    {a[NR]=$1}
    END {
      if (NR==0) { printf "%-16s %-5s %s\n", s, "-", "(无数据)"; exit }
      p50=a[int((NR+1)*0.5)]; p95=a[int((NR+1)*0.95)]
      printf "%-16s %-5d %-9.3f %-9.3f %-9.3f\n", s, NR, p50/1e6, p95/1e6, a[NR]/1e6
    }'
done

echo
echo "=== 逐段增量（相邻 stage 的 p50 之差，ms）==="
prev=0
for st in init_start ms_private bind_rootfs pivot_root detach_oldroot mounts seccomp execve; do
  cur=$(grep "stage=$st " "$RAW" | sed 's/.* ns=//' | sort -n |
    awk '{a[NR]=$1} END {if (NR) printf "%.3f", a[int((NR+1)*0.5)]/1e6; else print "0"}')
  awk -v s="$st" -v c="$cur" -v p="$prev" 'BEGIN{printf "%-16s %+8.3f\n", s, c-p}'
  prev=$cur
done

echo
echo "=== 对照：03 篇 runc 冷启动分解（strace 下，上界）==="
cat <<'EOF'
  execve runc → unshare(NEWUSER)   194.0 ms   runc 自身 Go 冷启动 + 自重执行
  unshare → 首个 mount              45.0 ms   pivot_root 前置 + 自绑定
  mounts（~38 次）                 148.0 ms   6 基础 + 11 掩蔽 + 6 只读 + bind
  NNP → seccomp 装载                42.0 ms   libseccomp 编译 159 条 BPF
  seccomp → execve probe            10.6 ms   收尾
  ----------------------------------------------------
  合计                             439.6 ms
EOF
