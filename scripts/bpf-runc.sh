#!/usr/bin/env bash
# bpf-runc.sh — 用 eBPF（bpftrace）量 runc 启动期间的内核函数耗时
#
# 与 perf 的分工（两者都属族 B，但机制不同）：
#   perf    ：PMU 计数器溢出时中断，采样落在谁身上 → 给"占比"
#   bpftrace：kprobe/kretprobe 配对记时间戳         → 给"精确耗时 + 次数 + 最坏值"
#
# 用法：
#   sudo ./scripts/bpf-runc.sh [轮数]      # 默认 20 轮
#
# 前置：sudo apt install -y bpftrace
#
# 说明：脚本编译到临时目录，不会覆盖仓库根目录的 anolix 二进制。
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "需要 root：sudo $0 [轮数]" >&2
  exit 1
fi
if ! command -v bpftrace >/dev/null 2>&1; then
  echo "没装 bpftrace，先跑：sudo apt install -y bpftrace" >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
ROUNDS=${1:-20}
OUT=$(mktemp -d /tmp/anolix-bpf.XXXXXX)
trap 'rm -rf "$OUT"' EXIT

# sudo 会重置 PATH 与 Go 环境。
USER_HOME=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
if ! command -v go >/dev/null 2>&1; then
  export PATH="$USER_HOME/.local/sdk/go/bin:$USER_HOME/go/bin:/usr/local/go/bin:$PATH"
fi
command -v go >/dev/null 2>&1 || { echo "找不到 go 工具链" >&2; exit 1; }
export GOPATH="${GOPATH:-$USER_HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$USER_HOME/go/pkg/mod}"
export GOCACHE="${GOCACHE:-/tmp/anolix-go-cache}"

cd "$ROOT"

echo "== 环境 =="
echo "内核    : $(uname -r)"
echo "bpftrace: $(bpftrace --version 2>&1 | head -1)"
echo

echo "== 构建 =="
go build -o "$OUT/anolix" ./cmd/anolix
cp -a "$ROOT/rootfs" "$OUT/rootfs"
CGO_ENABLED=0 go build -o "$OUT/rootfs/tprobe" ./cmd/tprobe
ROOTFS="$OUT/rootfs"
echo "OK -> $OUT"
echo

# exec 的函数名在不同内核版本里变过；先挑一个能用的。
EXEC_FN=""
for cand in do_execveat_common bprm_execve do_execve; do
  if bpftrace -l "kprobe:$cand" 2>/dev/null | grep -q "kprobe:$cand"; then
    EXEC_FN=$cand
    break
  fi
done

echo "== 符号检查 =="
CANDIDATES="copy_process unmap_page_range next_uptodate_folio __handle_mm_fault do_filp_open $EXEC_FN"
AVAIL=""
for f in $CANDIDATES; do
  if bpftrace -l "kprobe:$f" 2>/dev/null | grep -q "kprobe:$f"; then
    AVAIL="$AVAIL $f"
    printf '  %-28s ok\n' "$f"
  else
    printf '  %-28s !! 不存在，跳过\n' "$f"
  fi
done
[ -n "$AVAIL" ] || { echo "没有任何可用符号，退出" >&2; exit 1; }
echo

# 每个函数独立一对 probe + 独立 map。
# 为什么不用 bpftrace 的 func 内建变量配对：实测 kretprobe 里 func 的取值和
# kprobe 不一致，@start[func,tid] 永远查不到（第一轮就是因此全空、只剩残留）。
{
  for f in $AVAIL; do
    cat <<EOF
kprobe:$f /comm == "runc" || comm == "runc:[2:INIT]" || comm == "anolix"/ {
  @s_$f[tid] = nsecs;
}

kretprobe:$f /@s_$f[tid]/ {
  \$d = (nsecs - @s_$f[tid]) / 1000;
  @us["$f"] = sum(\$d);
  @cnt["$f"] = count();
  @max_us["$f"] = max(\$d);
  delete(@s_$f[tid]);
}

EOF
  done
  cat <<'END'
END {
  printf("\n== 累计耗时（µs）==\n");
  print(@us);
  printf("\n== 调用次数 ==\n");
  print(@cnt);
  printf("\n== 单次最坏（µs）==\n");
  print(@max_us);
}
END
} >"$OUT/probe.bt"

echo "== A：裸跑 $ROUNDS 次（同场基线）=="
: >"$OUT/base.txt"
for _ in $(seq 1 "$ROUNDS"); do
  "$OUT/anolix" run --timing --rootfs "$ROOTFS" -- /tprobe \
    2>>"$OUT/timing.log" | sed -n 's/^PAYLOAD_NS=//p' >>"$OUT/base.txt" || true
done
BASE=$(sort -n "$OUT/base.txt" | awk '{a[NR]=$1} END {
  if (NR==0) {print 0; exit}
  print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)
}')
echo "PAYLOAD_NS 中位数: $BASE ns"
echo

echo "== B：挂 bpftrace 跑 $ROUNDS 次 =="
bpftrace -q "$OUT/probe.bt" >"$OUT/bpf.log" 2>&1 &
BP_PID=$!
sleep 3
if ! kill -0 "$BP_PID" 2>/dev/null; then
  echo "!! bpftrace 启动失败：" >&2
  cat "$OUT/bpf.log" >&2
  exit 1
fi
echo "pid=$BP_PID，probe 已挂"
echo

: >"$OUT/probed.txt"
for _ in $(seq 1 "$ROUNDS"); do
  "$OUT/anolix" run --timing --rootfs "$ROOTFS" -- /tprobe \
    2>>"$OUT/timing.log" | sed -n 's/^PAYLOAD_NS=//p' >>"$OUT/probed.txt" || true
done

kill -INT "$BP_PID" 2>/dev/null || true
wait "$BP_PID" 2>/dev/null || true

BP_MED=$(sort -n "$OUT/probed.txt" | awk '{a[NR]=$1} END {
  if (NR==0) {print 0; exit}
  print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)
}')
echo "PAYLOAD_NS 中位数（探针挂着）: $BP_MED ns"
awk -v b="$BASE" -v p="$BP_MED" 'BEGIN {
  if (b > 0 && p > 0) printf "eBPF 探针税: %.2fx\n", p/b
}'
echo
cat "$OUT/bpf.log"
# bpftrace 里没有"数 map 元素个数"的干净写法（count() 是无参聚合），
# 所以在 bash 层做自检：日志里一条 @us[...] 都没有，就说明 kretprobe 没命中。
if ! grep -q '@us\[' "$OUT/bpf.log"; then
  echo
  echo "!! 没有任何 kretprobe 命中：检查内核是否禁用了 kretprobe"
fi

echo
echo "== bpftrace 编译出的 eBPF 汇编（前 40 行）=="
echo "   这是 verifier 真正检查的东西：指令、跳转、helper 调用"
echo
bpftrace -d "$OUT/probe.bt" 2>&1 | tail -45 \
  || echo "（-d 输出不可用，bpftrace 版本差异）"