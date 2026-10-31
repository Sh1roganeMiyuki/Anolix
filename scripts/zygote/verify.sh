#!/usr/bin/env bash
# zygote 机制验证：./verify.sh <ns|memfd|cgroup|seccomp|caps|all>
#
# 前置：先 ./build.sh && ./mother.sh up
# 每个子命令 = 一条"探针"，spawn 一个 worker 然后从宿主侧验它该验的东西。
# worker 的自打印（smaps/探针结果）在母体日志里：./mother.sh log
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$ROOT"
SOCK="${SOCK:-/tmp/anolix-zygote.sock}"
LOG="${LOG:-/tmp/zygote-mother.log}"

# 从 spawn 输出里抠字段（host_pid / worker_id）
field() { echo "$1" | grep -oE "$2:[[:space:]]+[^[:space:]]+" | awk '{print $2}'; }

# spawn 一个 worker，回显它的 host_pid
spawn() {
  local out
  out=$(sudo ./bin/spawn --socket "$SOCK" -- "$@")
  field "$out" host_pid
}

t_ns() {
  echo "=== ns 隔离 ==="
  local out pid
  out=$(sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker hold 5)
  pid=$(field "$out" host_pid)
  echo "  spawn → host_pid=$pid"
  sleep 0.3
  echo "  期望：NSpid 两字段（宿主PID + ns内PID=1）"
  echo "  实测：$(grep NSpid "/proc/$pid/status" 2>/dev/null || echo '(worker 已退出)')"
}

t_memfd() {
  echo "=== memfd 共享（并发 3 个，看 Pss 摊薄 + Shared_Dirty）==="
  local pids=() out pid
  for i in 1 2 3; do
    out=$(sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker hold 10)
    pid=$(field "$out" host_pid); pids+=("$pid")
    echo "  worker$i → pid=$pid"
  done
  sleep 0.5
  for pid in "${pids[@]}"; do
    echo "  [$pid] memfd VMA:"
    { sudo grep -A14 -i memfd "/proc/$pid/smaps" 2>/dev/null \
        | grep -E '^(Rss|Pss|Shared_Dirty|Shared_Clean|Private_Dirty|Private_Clean):' \
        | sed 's/^/      /'; } || echo "      (已退出/无)"
  done
  echo "  期望：Shared_Dirty≈全区；Pss 随并发数摊薄（N 个→约 1/N）"
}

t_cgroup() {
  echo "=== cgroup 围栏 ==="
  local out pid wid leaf
  out=$(sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker hold 10)
  pid=$(field "$out" host_pid); wid=$(field "$out" worker_id)
  leaf="/sys/fs/cgroup/anolix-$wid"
  echo "  spawn → pid=$pid  wid=$wid"
  sleep 0.3
  echo "  叶子：$leaf"
  echo "    cgroup.procs: $(sudo cat "$leaf/cgroup.procs" 2>/dev/null | tr '\n' ' ')   ← 期望含 $pid"
  echo "    memory.max  : $(sudo cat "$leaf/memory.max" 2>/dev/null || echo '(无)')"
  echo "    pids.max    : $(sudo cat "$leaf/pids.max" 2>/dev/null || echo '(无)')"
  echo "    cpu.max     : $(sudo cat "$leaf/cpu.max" 2>/dev/null || echo '(无)')"
  echo "  注：worker 自带 CLONE_NEWCGROUP，它自己看到的是 ns 根；要从宿主侧看这个叶子。"
}

t_seccomp() {
  echo "=== seccomp A/B ==="
  local before
  before=$(wc -l < "$LOG" 2>/dev/null || echo 0)
  echo "  A: 装 seccomp（默认）"
  sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker >/dev/null
  echo "  B: 不装（noseccomp 对照组）"
  sudo ./bin/spawn --socket "$SOCK" -- ./bin/worker noseccomp >/dev/null
  sleep 0.5
  echo "  --- 母体日志里两个 worker 的探针行 ---"
  { tail -n "+$((before+1))" "$LOG" | grep -E 'seccomp|探针' | sed 's/^/    /'; } || echo "    (没抓到)"
  echo "  期望：A 的 sethostname→EPERM ✅（被盖章）；B 的 sethostname→成功 ❌（没拦）"
}

# 在 rootfs 里跑一条 busybox applet，回吐本次新增的日志行。
# ⚠️ 不能用 `sh -c '...'`：rootfs 的 /bin 下只有 busybox 和 sh 两个文件，
#    shell 按 PATH 找 cat/ls 会全部 not found（exit 127）。必须由 busybox 直接带 applet 名跑。
run_applet() {
  local mode=$1; shift
  local before; before=$(wc -l < "$LOG" 2>/dev/null || echo 0)
  sudo ./bin/spawn --socket "$SOCK" -- "$ROOT/bin/worker-init" $mode \
    --rootfs "${ROOTFS:-$ROOT/rootfs}" -- /bin/busybox "$@" >/dev/null 2>&1 || true
  sleep 0.4
  tail -n "+$((before+1))" "$LOG"
}

t_caps() {
  echo "=== 能力收敛（payload 应为零能力；--harden 不应有失败项）==="

  # 这 11 条是 worker-init maskedPaths 的全集。本机内核里不存在的，
  # 根本不可能被掩蔽，也不算失败——先把“存在几条”量出来。
  # ⚠️ 必须在 --harden 下量：plain 不挂 /sys，/sys/** 那些目标在 plain 里根本不存在。
  local ex exist
  ex=$(run_applet "--harden" ls -1d \
    /proc/acpi /proc/asound /proc/kcore /proc/keys /proc/latency_stats \
    /proc/timer_list /proc/timer_stats /proc/sched_debug /proc/scsi \
    /sys/firmware /sys/devices/virtual/powercap)
  exist=$(printf '%s\n' "$ex" | grep -cE '^/' || true)
  echo "  本机存在的掩蔽目标: ${exist}/11"
  printf '%s\n' "$ex" | grep -E '^/' | sed 's/^/    /'

  local mode st mp dn n
  for mode in "" "--harden"; do
    echo "  [${mode:-plain}]"
    st=$(run_applet "$mode" cat /proc/self/status)
    mp=$(run_applet "$mode" cat /proc/mounts)
    dn=$(run_applet "$mode" ls -l /dev/null)

    echo "$st" | grep -E '^(CapInh|CapPrm|CapEff|CapBnd|CapAmb)' | sed 's/^/    /' \
      || echo "    (没抓到 Cap 行)"

    n=$(printf '%s\n' "$mp" | awk -v mask='^/(proc/(acpi|asound|kcore|keys|latency_stats|timer_list|timer_stats|sched_debug|scsi)|sys/(firmware|devices/virtual/powercap))$' '$2 ~ mask' | wc -l)
    echo "    掩蔽落点: ${n} 条（应等于“存在几条”）"
    printf '%s\n' "$mp" | awk -v mask='^/(proc/(acpi|asound|kcore|keys|latency_stats|timer_list|timer_stats|sched_debug|scsi)|sys/(firmware|devices/virtual/powercap))$' \
      '$2 ~ mask {print "      " $1 " → " $2}'

    echo "    /dev/null: $(printf '%s\n' "$dn" | grep -E '^(crw|ls: )' | head -1 || echo '(无)')"
    echo "    harden 失败行: $(printf '%s\n' "$st" | grep -c 'harden 失败' || true)"
  done
}

case "${1:-all}" in
  ns)      t_ns ;;
  memfd)   t_memfd ;;
  cgroup)  t_cgroup ;;
  seccomp) t_seccomp ;;
  caps)    t_caps ;;
  all)     t_ns; echo; t_memfd; echo; t_cgroup; echo; t_seccomp ;;
  *)       echo "用法: $0 <ns|memfd|cgroup|seccomp|caps|all>"; exit 1 ;;
esac