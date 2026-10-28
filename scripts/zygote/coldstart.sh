#!/usr/bin/env bash
# 母体冷启动：从"执行启动命令"到"能服务第一个请求"要多久。
#
# 三个指标（单位 ms）：
#   就绪      T1 − T0    socket 出现，母体进程起来了
#   首次服务  T2 − T1    第一个请求从发出到回包（含母体未热的成本）
#   热态      T3 − T2    紧接着的第二个请求（母体已热）
#
# 为什么不用"就绪时间"当结论：
#   用户不关心母体进程起没起，关心第一个沙箱多久能跑 —— 那是 T2 − T0。
#
# 回本点：
#   母体额外成本 = (T2 − T0) − (T3 − T2)
#   每次 spawn 省 9.61 ms（runc 13.66 → zygote 4.05，见 09/10 篇）
#   回本点 N = 额外成本 ÷ 9.61
#
# 口径边界：
#   - T2/T3 是 spawn 客户端的外部耗时，到"母体回包"为止，不含 payload 启动
#     （到 payload main 还要加约 5 ms 的 worker 侧成本，但那部分与母体启动无关）。
#   - --warm 64 会建 64MB memfd 并填 pattern，这段成本算在"就绪"里。
#   - 只测母体启动，不测并发；K 并发见 scripts/zygote/conc.sh。
#
# 用法：
#   sudo ./scripts/zygote/coldstart.sh
#   sudo N=10 ./scripts/zygote/coldstart.sh
#   sudo WARM=0 ./scripts/zygote/coldstart.sh      # 看 64MB 预热占多少
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

N="${N:-5}"
WARM="${WARM:-64}"
SOCK="${SOCK:-/tmp/anolix-zygote-coldstart.sock}"
LOG="${LOG:-/tmp/zygote-coldstart.log}"
CGMEM="${CGMEM:-256}"
CGPIDS="${CGPIDS:-200}"
SAVE_MS="${SAVE_MS:-9.61}"   # 每次 spawn 相对 runc 省下的时间（09 篇 root 口径）

[ "$(id -u)" -eq 0 ] || { echo "!! 需要 root：sudo $0" >&2; exit 1; }
[ -x ./bin/zygote ]      || { echo "!! 缺 bin/zygote：./scripts/zygote/build.sh" >&2; exit 1; }
[ -x ./bin/spawn ]       || { echo "!! 缺 bin/spawn" >&2; exit 1; }
[ -x ./bin/worker-init ] || { echo "!! 缺 bin/worker-init" >&2; exit 1; }
[ -x ./rootfs/tprobe ]   || { echo "!! 缺 rootfs/tprobe：CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe" >&2; exit 1; }

now_ns() { date +%s%N; }
ms() { awk -v d="$1" 'BEGIN{printf "%.1f", d/1e6}'; }

cleanup() {
  # 注意：按进程名匹配，会连带杀掉别的母体（包括 mother.sh 起的那个）。
  # 冷启动测量需要干净环境，所以这是故意的 —— 跑之前不要有正在用的母体。
  pkill -f 'bin/zygote --socket' 2>/dev/null || true
  rm -f "$SOCK"
}
trap cleanup EXIT

echo "=== 母体冷启动 ==="
echo "nproc=$(nproc) kernel=$(uname -r) 轮数=$N warm=${WARM}MB cgroup: mem=${CGMEM}MB pids=${CGPIDS}"
echo "日志：$LOG"
echo

printf '%-4s %8s %10s %8s %11s\n' 轮 就绪 首次服务 热态 首沙箱总
printf '%-4s %8s %10s %8s %11s\n' ---- -------- -------- -------- -----------

ready_list=""; first_list=""; hot_list=""; total_list=""

for i in $(seq 1 "$N"); do
  cleanup
  sleep 0.2   # 让上一轮的 cgroup 叶子与 socket 落定

  t0=$(now_ns)
  setsid ./bin/zygote --socket "$SOCK" --warm "$WARM" \
    --cgroup --cg-memory "$CGMEM" --cg-pids "$CGPIDS" \
    >"$LOG" 2>&1 </dev/null &

  # T1：socket 出现。busy loop，因为这段只有几十 ms，sleep 的粒度反而更粗。
  # 加一个上限，避免母体起不来时挂死。
  limit=$((t0 + 5000000000))
  while [ ! -S "$SOCK" ]; do
    [ "$(now_ns)" -gt "$limit" ] && { echo "!! 母体 5s 内未创建 socket，见 $LOG" >&2; exit 1; }
  done
  t1=$(now_ns)

  # T2：第一个请求（含母体未热的成本）。
  # socket 文件出现（bind）与 listen 完成之间有微秒级间隙，
  # 第一次可能被拒 —— 重试而不是退出，重试也算在“首沙箱总”里，
  # 因为这正是用户会经历的东西。
  ok=0
  for _try in 1 2 3 4 5; do
    if ./bin/spawn --socket "$SOCK" --id "cold-$i-a" --timeout 5s -- \
      ./bin/worker-init --rootfs "$ROOT/rootfs" -- /tprobe >/dev/null 2>&1; then
      ok=1; break
    fi
    sleep 0.01
  done
  t2=$(now_ns)
  [ "$ok" -eq 1 ] || { echo "!! 第 $i 轮：第一次 spawn 连续失败，见 $LOG" >&2; exit 1; }

  # T3：紧接着的第二个请求（母体已热）
  ./bin/spawn --socket "$SOCK" --id "cold-$i-b" --timeout 5s -- \
    ./bin/worker-init --rootfs "$ROOT/rootfs" -- /tprobe >/dev/null 2>&1
  t3=$(now_ns)

  ready=$((t1 - t0)); first=$((t2 - t1)); hot=$((t3 - t2)); total=$((t2 - t0))
  ready_list+="$ready "; first_list+="$first "; hot_list+="$hot "; total_list+="$total "
  printf '%-4s %8s %10s %8s %11s\n' "$i" "$(ms $ready)" "$(ms $first)" "$(ms $hot)" "$(ms $total)"
done

cleanup

median() { printf '%s' "$1" | tr ' ' '\n' | grep -v '^$' | sort -n | awk '{a[NR]=$1} END{if(NR%2) print a[(NR+1)/2]; else print int((a[NR/2]+a[NR/2+1])/2)}'; }

m_ready=$(median "$ready_list")
m_first=$(median "$first_list")
m_hot=$(median "$hot_list")
m_total=$(median "$total_list")
extra=$((m_total - m_hot))

echo
printf '%-4s %8s %10s %8s %11s\n' 中位 "$(ms "$m_ready")" "$(ms "$m_first")" "$(ms "$m_hot")" "$(ms "$m_total")"
echo
echo "=== 回本点 ==="
echo "母体额外成本 = 首沙箱总($(ms "$m_total")) − 热态($(ms "$m_hot")) = $(ms "$extra") ms"
awk -v e="$extra" -v s="$SAVE_MS" 'BEGIN{
  n = e / 1e6 / s
  printf "每次 spawn 省 %.2f ms → 回本点 ≈ %.1f 个（取整 %d 个）\n", s, n, (n==int(n)? n : int(n)+1)
}'
echo
echo "⚠️ 边界："
echo "   - 只测母体启动；socket 就绪到能回包之间还有一小段，已包含在「首次服务」里。"
echo "   - 首沙箱总 = 就绪 + 首次服务，不含 payload 启动（再到 main 约 +5ms）。"
echo "   - --warm 64 的 memfd 填充算在就绪里；用 WARM=0 可看它占多少。"
echo "   - 单次场景下 zygote 是亏的：母体额外成本 > 0 就是亏，要跑够回本点个数才划算。"