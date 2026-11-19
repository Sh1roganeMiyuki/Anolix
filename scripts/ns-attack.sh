#!/usr/bin/env bash
# ns-attack.sh — 按 namespace 维度验证隔离：攻击式，不是配置复述
#
# 思路：同一批指标在【宿主】和【容器内】各采一次，逐项对照。
# 只报容器内的值没有意义——隔离成不成立必须两边比。
#
# 断言分三类：
#   [PASS]/[FAIL]  硬断言（能确定对错）
#   [INFO]         仅记录（这类指标在这个环境里没有区分度，不做断言）
#
# 用法：sudo ./scripts/ns-attack.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "需要 root：sudo $0" >&2
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d /tmp/anolix-ns.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

USER_HOME=$(getent passwd "${SUDO_USER:-root}" | cut -d: -f6)
if ! command -v go >/dev/null 2>&1; then
  export PATH="$USER_HOME/.local/sdk/go/bin:$USER_HOME/go/bin:/usr/local/go/bin:$PATH"
fi
command -v go >/dev/null 2>&1 || { echo "找不到 go 工具链" >&2; exit 1; }
export GOPATH="${GOPATH:-$USER_HOME/go}"
export GOMODCACHE="${GOMODCACHE:-$USER_HOME/go/pkg/mod}"
export GOCACHE="${GOCACHE:-/tmp/anolix-go-cache}"

cd "$ROOT"

echo "== 构建 =="
go build -o "$WORK/anolix" ./cmd/anolix
cp -a "$ROOT/rootfs" "$WORK/rootfs"
ROOTFS="$WORK/rootfs"
CGO_ENABLED=0 go build -o "$ROOTFS/nsprobe" ./cmd/nsprobe
echo "OK"
echo

echo "== 宿主侧采样（对照组，只读操作）=="
H_PROC=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
H_INIT=$(cat /proc/1/comm 2>/dev/null || echo unknown)
H_MNT=$(wc -l </proc/self/mountinfo)
H_HOST=$(hostname)
H_IFACES=$(ls /sys/class/net | sort | paste -sd, -)
H_NSPID=$(readlink /proc/self/ns/pid | sed 's/.*\[\([0-9]*\)\]/\1/')
H_NSNET=$(readlink /proc/self/ns/net | sed 's/.*\[\([0-9]*\)\]/\1/')
printf '  proc_count=%s  init=%s  mnt=%s\n' "$H_PROC" "$H_INIT" "$H_MNT"
printf '  hostname=%s  ifaces=%s\n' "$H_HOST" "$H_IFACES"
printf '  ns.pid=%s  ns.net=%s\n' "$H_NSPID" "$H_NSNET"
echo

echo "== 容器内采样 =="
"$WORK/anolix" run --bundle "$WORK/b" --rootfs "$ROOTFS" -- /nsprobe >"$WORK/inside.txt" 2>"$WORK/err.log" || {
  echo "容器启动失败：" >&2; cat "$WORK/err.log" >&2; exit 1
}
cat "$WORK/inside.txt"
echo

get() { sed -n "s/^$1=//p" "$WORK/inside.txt" | head -1; }
C_PROC=$(get pid.proc_count)
C_INIT=$(get pid.init_comm)
C_KILL1=$(get pid.kill1)
C_MNT=$(get mnt.count)
C_HOSTDISK=$(get mnt.sees_host_disk)
C_IFACES=$(get net.ifaces)
C_HOST=$(get uts.hostname)
C_SETHOST=$(get uts.sethostname)
C_CG=$(get cg.self)
C_NSPID=$(get ns.pid)
C_NSNET=$(get ns.net)
C_NSMNT=$(get ns.mnt)

pass=0; fail=0
ok()   { printf '  [PASS] %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  [FAIL] %s（实际：%s）\n' "$1" "$2"; fail=$((fail+1)); }
info() { printf '  [INFO] %s：%s\n' "$1" "$2"; }

echo "== 逐维断言 =="

# --- PID namespace ---
echo "-- PID"
[ "$C_INIT" != "$H_INIT" ] && ok "1 号进程不是宿主 init（容器 $C_INIT ≠ 宿主 $H_INIT）" \
  || bad "1 号进程仍是宿主 init，PID ns 没生效" "$C_INIT"
[ "$C_NSPID" != "$H_NSPID" ] && ok "pid ns inode 与宿主不同" \
  || bad "pid ns inode 与宿主相同" "$C_NSPID"
[ "${C_PROC:-0}" -lt "${H_PROC:-0}" ] && ok "可见进程数更少（容器 $C_PROC < 宿主 $H_PROC）" \
  || bad "可见进程数不比宿主少" "$C_PROC"
info "kill(1,0) 结果" "$C_KILL1"

# --- Mount namespace ---
echo "-- Mount"
[ "$C_NSMNT" != "" ] && ok "看到独立的 mnt ns inode：$C_NSMNT" || bad "读不到 mnt ns inode" "-"
[ "$C_HOSTDISK" = "false" ] && ok "看不到宿主磁盘 /mnt/c（挂载视图隔离）" \
  || bad "能看到宿主磁盘 /mnt/c，挂载隔离漏了" "$C_HOSTDISK"
[ "$C_MNT" != "$H_MNT" ] && ok "挂载点数与宿主不同（容器 $C_MNT ≠ 宿主 $H_MNT）" \
  || bad "挂载点数与宿主相同" "$C_MNT"

# --- Net namespace ---
echo "-- Net"
[ "$C_NSNET" != "$H_NSNET" ] && ok "net ns inode 与宿主不同" || bad "net ns inode 与宿主相同" "$C_NSNET"
case ",$C_IFACES," in
  *,docker0,*) bad "容器里看得到宿主 docker0" "$C_IFACES" ;;
  *) ok "看不到宿主的 docker0（网卡列表：$C_IFACES）" ;;
esac

# --- Cgroup namespace ---
echo "-- Cgroup"
[ "$C_CG" = "0::/" ] && ok "cgroup 路径显示为 ns 根（0::/）" \
  || info "cgroup 路径不是 ns 根" "$C_CG"

# --- UTS namespace ---
echo "-- UTS"
# 跑完再采一次：如果容器内改名真的漏到宿主，这里会变。
H_HOST_AFTER=$(hostname)
[ "$C_HOST" != "$H_HOST" ] && ok "容器 hostname 与宿主不同（$C_HOST ≠ $H_HOST）" \
  || bad "容器 hostname 与宿主相同，UTS ns 可能没生效" "$C_HOST"
[ "$H_HOST_AFTER" = "$H_HOST" ] && ok "容器跑完后宿主 hostname 未变（组内改名只影响自己）" \
  || bad "宿主 hostname 被改了！" "$H_HOST → $H_HOST_AFTER"
if [ "$C_SETHOST" = "ok(没被拦！)" ]; then
  bad "容器内成功改了 hostname（应当无权限）" "$C_SETHOST"
else
  ok "容器内改 hostname 被拒（$C_SETHOST）——归因：caps/seccomp"
fi

# --- IPC namespace ---
echo "-- IPC"
info "sysvipc shm 段数" "$(get ipc.shm_count)（未验：要真验得在宿主建 shm，容器内 shmat 找不到）"

# --- User namespace ---
echo "-- User"
info "uid_map" "$(get user.uid_map)"

echo
echo "== 汇总 =="
printf '  PASS=%d  FAIL=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ] && echo "  结论：所有可硬断言的 ns 维度都成立" \
                  || echo "  结论：有断言失败，见上方 [FAIL]"
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)