#!/usr/bin/env bash
# K 并发压测：同时拉起 K 个 spawn 客户端，输出启动延迟分布、分段、吞吐与环境 CPU。
#
# 口径（三个旋钮，缺一不可）：
#   起点 = 各客户端发请求前的 CLOCK_MONOTONIC（SPAWN_META.dispatch_ns）
#   终点 = payload 第一条用户态指令（PAYLOAD_META.abs_ns）
#   条件 = K / nproc / 母体配置（--warm / --cgroup）/ 是否热身
#
# 用法：
#   K=10 ./scripts/zygote/conc.sh          # 单档
#   ./scripts/zygote/conc.sh               # 默认三档：1 / nproc / 4×nproc
#   TIERS="4 16" W=5 ./scripts/zygote/conc.sh
#   CLIENT_PIN="taskset -c 0-7" K=64 ./scripts/zygote/conc.sh   # 客户端绑核（归因用）
#
# 前置：
#   ./scripts/zygote/build.sh
#   ./scripts/zygote/mother.sh up          # 必须是新二进制（日志含 ANOLIX_MOTHER/ANOLIX_REAP）
#   CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe
#
# 为什么不用 sudo：特权动作都在母体里，socket 是 0666；客户端提权只会引入
# sudo secure_path 这个额外变量（见 07 篇的 PATH 税）。
#
# 输出目录：$OUT/<tag>/（all.tsv = 三路打点原始归并，rows.tsv = 每条请求的纳秒差）
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"

SOCK="${SOCK:-/tmp/anolix-zygote.sock}"
LOG="${LOG:-/tmp/zygote-mother.log}"
INIT="$ROOT/bin/worker-init"
ROOTFS="${ROOTFS:-$ROOT/rootfs}"
W="${W:-3}"                        # 热身次数（串行，不计入结果）
POLL_TIMEOUT="${POLL_TIMEOUT:-10}" # 等 payload 打点的秒数
OUT="${OUT:-$ROOT/.bench-tmp/conc}"
NPROC="$(nproc)"

# 可选：给客户端加命令前缀（归因实验用，默认空；不影响默认行为）。例：
#   CLIENT_PIN="taskset -c 0-7" K=64 ./scripts/zygote/conc.sh
# 用途：客户端绑一组核、母体绑另一组，看 queue 段（dispatch→accept）是否下降。
# ⚠️ 本机拓扑：0-1/2-3/.../14-15 成对（每物理核 2 超线程），所以 0-7 与 8-15 不共享物理核。
CLIENT_PIN="${CLIENT_PIN:-}"
PIN=()
if [ -n "$CLIENT_PIN" ]; then read -ra PIN <<< "$CLIENT_PIN"; fi

[ -S "$SOCK" ] || { echo "!! 母体没起：./scripts/zygote/mother.sh up"; exit 1; }
[ -w "$SOCK" ] || { echo "!! $SOCK 不可写（权限？）"; exit 1; }
[ -x "$ROOTFS/tprobe" ] || { echo "!! 缺 $ROOTFS/tprobe（CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe）"; exit 1; }
[ -x "$INIT" ] || { echo "!! 缺 $INIT：./scripts/zygote/build.sh"; exit 1; }
[ -x "$ROOT/bin/spawn" ] || { echo "!! 缺 bin/spawn：./scripts/zygote/build.sh"; exit 1; }
mkdir -p "$OUT"

# /proc/stat 第 1 行：total = 各字段之和（guest 已含在 user/nice 里，不重复加）。
# 输出：total_jiffies idle_jiffies steal_jiffies
snap_cpu() {
  awk '/^cpu /{printf "%d %d %d\n", $2+$3+$4+$5+$6+$7+$8+$9, $5+$6, $9}' /proc/stat
}

# 输出一列纳秒的分布（ms）
emit() { # file label
  sort -n "$1" | awk -v n="$2" '{a[NR]=$1}
    END{
      if (NR==0) { printf "  %-22s (无数据)\n", n; exit }
      p50=int((NR+1)*0.5); if(p50>NR)p50=NR
      p95=int((NR+1)*0.95); if(p95>NR)p95=NR
      printf "  %-22s p50=%-8.3f p95=%-8.3f max=%-8.3f\n", n, a[p50]/1e6, a[p95]/1e6, a[NR]/1e6
    }'
}

run_tier() {
  local k="$1"
  local tag="k${k}-$(date +%s%N)"
  local dir="$OUT/$tag"
  mkdir -p "$dir"

  local cpu0; cpu0=$(snap_cpu)
  local pids=() failed=0 i id p
  for i in $(seq 1 "$k"); do
    id="${tag}-$i"
    "${PIN[@]}" "$ROOT/bin/spawn" --socket "$SOCK" --id "$id" -- \
      "$INIT" --rootfs "$ROOTFS" -- /tprobe \
      >"$dir/$id.spawn" 2>"$dir/$id.err" &
    pids+=("$!")
  done
  for p in "${pids[@]}"; do
    wait "$p" || failed=$((failed + 1))
  done

  # 母体回包 ≠ payload 已启动：等到 K 条 PAYLOAD_META 落地（或超时）。
  local deadline=$((SECONDS + POLL_TIMEOUT)) gotp=0
  while :; do
    gotp=$(grep -c "PAYLOAD_META run=$tag" "$LOG" 2>/dev/null || true); gotp=${gotp:-0}
    [ "$gotp" -ge "$k" ] && break
    [ "$SECONDS" -ge "$deadline" ] && break
    sleep 0.02
  done
  sleep 1   # 让收尸 goroutine 写完 ANOLIX_REAP；同时把 steal 的采样窗拉到 1s（jiffies 分辨率 10ms）
  local cpu1; cpu1=$(snap_cpu)

  # 三路打点各取所需，按 id 归并。grep 找不到时保留管道输出、不触发 pipefail。
  : > "$dir/all.tsv"
  awk '/^SPAWN_META /{
        split("", v); for(i=2;i<=NF;i++){split($i,kv,"="); v[kv[1]]=kv[2]}
        print "C", v["id"], v["dispatch_ns"], v["response_ns"], v["after_dial_ns"], v["write_ns"], v["after_write_ns"]
      }' "$dir"/*.spawn >> "$dir/all.tsv"
  { grep "ANOLIX_MOTHER id=$tag" "$LOG" 2>/dev/null | awk '{
        split("", v); for(i=2;i<=NF;i++){split($i,kv,"="); v[kv[1]]=kv[2]}
        print "M", v["id"], v["accept_ns"], v["cgroup_ns"], v["clone_done_ns"], v["accept_return_ns"], v["handle_start_ns"]
      }'; } >> "$dir/all.tsv" || true
  { grep "PAYLOAD_META run=$tag" "$LOG" 2>/dev/null | awk '{
        split("", v); for(i=2;i<=NF;i++){split($i,kv,"="); v[kv[1]]=kv[2]}
        print "P", v["run"], v["t0_ns"], v["abs_ns"]
      }'; } >> "$dir/all.tsv" || true

  # 归并成 rows.tsv：每行 = 一条请求的 6 个纳秒差
  #   dispatch→payload / dispatch→response / accept→dispatch / accept→cgroup /
  #   cgroup→clone_done / clone_done→payload
  # all.tsv 的 M 行现在是 7 列：M id accept_ns cgroup_ns clone_done_ns accept_return_ns handle_start_ns
  # C 行是 7 列：C id dispatch_ns response_ns after_dial_ns write_ns after_write_ns
  # （后两列是 v2 新增；旧母体二进制不会输出，值为空字符串，相减会得到 0）
  awk -v summary="$dir/summary" '
    $1=="C"{disp[$2]=$3+0; resp[$2]=$4+0; ids[$2]=1}
    $1=="M"{acc[$2]=$3+0; cg[$2]=$4+0; cl[$2]=$5+0; hasM++}
    $1=="P"{abs[$2]=$4+0}
    END{
      n=0; miss=0; missM=0; minD=0; maxD=0; maxA=0
      for(id in ids){
        if(!(id in abs) || !(id in disp)){ miss++; continue }
        if(!(id in acc) && hasM>0) missM++
        d=disp[id]; ab=abs[id]
        if(id in acc){
          a=acc[id]; q=a-d
          if((id in cg) && cg[id]>0){ cgt=cg[id]-a; clt=cl[id]-cg[id] }
          else { cgt=0; clt=cl[id]-a }
          tail=ab-cl[id]
        } else { q=0; cgt=0; clt=0; tail=0 }
        print ab-d, resp[id]-d, q, cgt, clt, tail
        n++
        if(minD==0||d<minD)minD=d
        if(d>maxD)maxD=d
        if(ab>maxA)maxA=ab
      }
      printf "%d %d %d %d %.0f %.0f %.0f\n", n, miss, missM, hasM+0, minD, maxD, maxA > summary
    }' "$dir/all.tsv" > "$dir/rows.tsv"

  local n miss missM hasM minD maxD maxA
  read -r n miss missM hasM minD maxD maxA < "$dir/summary"

  for col in 1 2 3 4 5 6; do
    awk -v c="$col" '{print $c}' "$dir/rows.tsv" > "$dir/col$col"
  done
  local span=$((maxA - minD)) skew=$((maxD - minD))

  local s0 s1
  read -r _ _ s0 <<< "$cpu0"
  read -r _ _ s1 <<< "$cpu1"
  local hz steal_ms
  hz=$(getconf CLK_TCK)
  steal_ms=$(awk -v a="$s0" -v b="$s1" -v hz="$hz" 'BEGIN{printf "%.1f", (b-a)*1000/hz}')

  local reap cpu_sum cpu_p50 cores
  reap=$(grep -c "ANOLIX_REAP id=$tag" "$LOG" 2>/dev/null || true); reap=${reap:-0}
  cpu_sum=$( { grep "ANOLIX_REAP id=$tag" "$LOG" 2>/dev/null | sed -n 's/.*cpu_ns=\([0-9]*\).*/\1/p' | awk '{s+=$1} END{print s+0}'; } || true )
  cpu_p50=$( { grep "ANOLIX_REAP id=$tag" "$LOG" 2>/dev/null | sed -n 's/.*cpu_ns=\([0-9]*\).*/\1/p' | sort -n | awk '{a[NR]=$1} END{if(NR) printf "%.3f", a[int((NR+1)*0.5)]/1e6; else printf "-"}'; } || true )
  cores=$(awk -v c="${cpu_sum:-0}" -v s="$span" 'BEGIN{printf(s>0 ? "%.2f" : "-"), (s>0 ? c/s : 0)}')

  echo
  echo "=== K=$k（nproc=$NPROC，热身 $W 次已完成） ==="
  printf '  样本      请求=%s 回包失败=%s payload=%s/%s 回收=%s 缺失=%s 分段缺失=%s\n' \
    "$k" "$failed" "$gotp" "$k" "$reap" "$miss" "$missM"
  printf '  起跑斜坡  %.1f ms（最早→最晚 dispatch）\n' "$(awk -v x="$skew" 'BEGIN{print x/1e6}')"
  printf '  窗口      %.1f ms（最早 dispatch → 最晚 abs）\n' "$(awk -v x="$span" 'BEGIN{print x/1e6}')"
  echo "  延迟（dispatch → payload 第一条指令，ms）"
  emit "$dir/col1" "端到端"
  echo "  分段（ms）"
  if [ "$hasM" -gt 0 ]; then
    emit "$dir/col3" "socket+排队"
    emit "$dir/col4" "cgroup"
    emit "$dir/col5" "clone+exec"
    emit "$dir/col6" "rootfs+seccomp+exec"
  else
    echo "  socket+排队 / cgroup / clone+exec   (母体未提供 ANOLIX_MOTHER：旧二进制？)"
  fi
  emit "$dir/col2" "客户端回包(对照)"
  printf '  吞吐      %s spawns/s（%s 个 / 窗口）\n' \
    "$(awk -v n="$n" -v s="$span" 'BEGIN{printf(s>0 ? "%.1f" : "-"), (s>0 ? n*1e9/s : 0)}')" "$n"
  printf '  CPU       每 worker p50=%s ms，合计=%s ms ≈ %s 核（窗口内）；采样窗 steal=%s ms（含 1s 静默）\n' \
    "$cpu_p50" "$(awk -v c="${cpu_sum:-0}" 'BEGIN{printf "%.1f", c/1e6}')" "$cores" "$steal_ms"
  printf '  原始数据  %s\n' "$dir"

  [ "$miss" -eq 0 ] && [ "$failed" -eq 0 ]
}

echo "=== 环境：nproc=$NPROC  kernel=$(uname -r)  load=$(cut -d' ' -f1-3 /proc/loadavg) ==="
echo "    母体日志：$LOG"
echo "    口径：起点=客户端 dispatch，终点=payload 第一条指令；窗口=最早 dispatch→最晚 abs"

if [ -n "${K:-}" ]; then
  TIERS="$K"
elif [ -z "${TIERS:-}" ]; then
  TIERS="1 $NPROC $((NPROC * 4))"
fi
# 去重（K 与 nproc 可能相等）
seen=""; dedup=""
for k in $TIERS; do
  case " $seen " in *" $k "*) ;; *) dedup="$dedup $k"; seen="$seen $k" ;; esac
done

echo
echo "=== 热身 $W 次（串行，不计入结果） ==="
for i in $(seq 1 "$W"); do
  "${PIN[@]}" "$ROOT/bin/spawn" --socket "$SOCK" --id "warm-$(date +%s%N)-$i" -- \
    "$INIT" --rootfs "$ROOTFS" -- /tprobe >/dev/null 2>&1 || true
done

rc=0
for k in $dedup; do
  case "$k" in ''|*[!0-9]*) echo "!! 非法 K：$k"; exit 2 ;; esac
  run_tier "$k" || rc=1
done

echo
echo "⚠️ 口径边界："
echo "   - 窗口外还有 K 个客户端的进程启动成本（每个约 1ms CPU），它不进延迟，但会抢 CPU。"
echo "   - 吞吐 = 到达 payload 第一条指令的速率，不是任务完成率（tprobe 打完点即退出）。"
exit "$rc"
