#!/usr/bin/env bash
# A/B 启动对比：控制变量后，比"从父进程入口到 payload main 首条语句"的耗时。
#
# 控制的变量：
#   ① 同一个 payload        —— 都跑 rootfs/tprobe（静态 Go，一进入 main 就报时）
#   ② 同一个终点            —— payload main 的首条语句（Go runtime 初始化已完成，
#                              但它仍包含在 t0 → main 这段墙钟里），不是"容器退出"或"init 起来"
#   ③ 同一个根目录          —— 都用 ./rootfs
#   ④ 同一个起点口径        —— 都在"参数解析完成"之后取 CLOCK_MONOTONIC
#        runc 路径：anolix main 里取 → 注入容器 env
#        zygote 路径：spawn 客户端里取 → 协议带给母体 → 注入 worker env
#   ⑤ 同样的样本数与热身    —— 两条路径都先跑 WARM 次热身，再计 N 次
#
# 没控制的（本质差异，不是噪声，结果里要分开讲）：
#   - runc 做 ~38 次 mount（掩蔽/只读重挂）并走完整 OCI 生命周期；我们只做 5 次
#   - runc 要 re-exec 自己一次；我们一次 execve
#   - runc 用 libseccomp 编 159 条；我们手写 cBPF 编 153 条
#
# 用法：N=30 ./scripts/zygote/ab.sh
# 前置：./build.sh && ./mother.sh up
#       CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"

N="${N:-30}"
WARM="${WARM:-3}"
SOCK="${SOCK:-/tmp/anolix-zygote.sock}"
LOG="${LOG:-/tmp/zygote-mother.log}"
INIT="$ROOT/bin/worker-init"
ROOTFS="${ROOTFS:-$ROOT/rootfs}"

[ -S "$SOCK" ] || { echo "!! 母体没起：先 ./mother.sh up"; exit 1; }
[ -x "$ROOTFS/tprobe" ] || { echo "!! 缺 $ROOTFS/tprobe（CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe）"; exit 1; }
[ -x "$ROOT/anolix" ] || { echo "!! 缺 ./anolix（go build -o anolix ./cmd/anolix）"; exit 1; }

# 权限：zygote 路径必须 root（clone 6 ns + cgroup），runc 路径必须保持 rootless（与基线一致）。
# 所以脚本整体用普通用户跑，内部只对 spawn 提权——整体 sudo 会把 runc 也变成 root，等于换了变量。
sudo -n true 2>/dev/null || {
  echo "!! 需要 sudo 缓存：先执行一次  sudo -v"
  echo "   （脚本只用它跑 spawn，不会整体提权）"
  exit 1
}

mkdir -p "$ROOT/.bench-tmp/bundle" "$ROOT/.bench-tmp/state"
A="$(mktemp)"; B="$(mktemp)"
trap 'rm -f "$A" "$B"' EXIT

echo "=== A: runc 路径（anolix → /tprobe），热身 $WARM + 计 $N ==="
for i in $(seq $((N + WARM))); do
  ns=$(./anolix run --rootfs "$ROOTFS" --timing \
        --bundle "$ROOT/.bench-tmp/bundle" --state-dir "$ROOT/.bench-tmp/state" \
        -- /tprobe 2>/dev/null | sed -n 's/^PAYLOAD_NS=//p' || true)
  if [ -n "$ns" ] && [ "$ns" -gt 0 ]; then
    [ "$i" -gt "$WARM" ] && echo "$ns" >> "$A"
  else
    echo "  !! 第 $i 次没拿到 PAYLOAD_NS"
  fi
done

echo "=== B: zygote 路径（spawn → worker-init → /tprobe），热身 $WARM + 计 $N ==="
before=$(wc -l < "$LOG" 2>/dev/null || echo 0)
for i in $(seq $((N + WARM))); do
  sudo ./bin/spawn --socket "$SOCK" --id "ab$i" -- \
    "$INIT" --rootfs "$ROOTFS" -- /tprobe >/dev/null 2>&1 || true
done
sleep 1
tail -n "+$((before + 1))" "$LOG" | sed -n 's/.*PAYLOAD_NS=//p' | tail -n "$N" > "$B"

# 汇总
stat() {
  local f=$1 name=$2
  sort -n "$f" | awk -v n="$name" '
    {a[NR]=$1}
    END {
      if (NR==0) { printf "%-8s (无数据)\n", n; exit }
      p50=a[int((NR+1)*0.5)]; p95=a[int((NR+1)*0.95)]
      printf "%-8s n=%-4d p50=%-9.3f p95=%-9.3f min=%-9.3f max=%-9.3f (ms)\n",
             n, NR, p50/1e6, p95/1e6, a[1]/1e6, a[NR]/1e6
    }'
}

echo
echo "=== 结果：父进程入口 → payload main 首条语句 ==="
stat "$A" runc
stat "$B" zygote

pa=$(sort -n "$A" | awk '{a[NR]=$1} END{if(NR) print a[int((NR+1)*0.5)]; else print 0}')
pb=$(sort -n "$B" | awk '{a[NR]=$1} END{if(NR) print a[int((NR+1)*0.5)]; else print 0}')
awk -v a="$pa" -v b="$pb" 'BEGIN{
  if (a>0 && b>0) printf "\np50 差: %.1f ms；runc / zygote = %.1f×\n", (a-b)/1e6, a/b
}'

echo
echo "⚠️ 这个比值不等于“我们的 runtime 比 runc 快 N 倍”："
echo "   runc 那侧还多做了 ~38 次 mount 加固和完整 OCI 生命周期，"
echo "   我们只做了 5 次最小挂载。比值反映的是“最小围栏 vs 完整运行时”的差距。"
