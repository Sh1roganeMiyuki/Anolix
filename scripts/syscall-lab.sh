#!/usr/bin/env bash
# syscall-lab.sh —— 亲手复现第 01 课：同一张"申请单"，在三个世界里的三种结局。
#
# 三个世界：
#   世界 1 · 宿主机      ：没有任何 seccomp —— 系统调用的"原始画像"
#   世界 2 · 沙箱默认策略 ：seccomp 开，errnoRet=1  —— 被拦时返回 EPERM(1)
#   世界 3 · 沙箱 example ：seccomp 开，errnoRet=38 —— 被拦时返回 ENOSYS(38)，伪装成"内核没这功能"
#
# 用法：./scripts/syscall-lab.sh
#
# 号码从哪查？
#   grep __NR_socket /usr/include/x86_64-linux-gnu/asm/unistd_64.h   # 得到 41
#   这个数字就是递单时写进 rax 的"事项编号"。

set -euo pipefail

# "$(dirname "$0")" 永远指向脚本自己所在的目录；再 ../ 回到项目根目录，
# 这样从任何目录执行本脚本，都能找到 rootfs/ 与 anolix。
cd "$(dirname "$0")/.."

SYS=./rootfs/sysc   # rootfs 里的探针（静态二进制）
anolix=./anolix     # 沙箱启动器

if [ ! -x "$SYS" ]; then
  echo "找不到 $SYS —— 先构建探针："
  echo '  export PATH=$HOME/.local/sdk/go/bin:$PATH'
  echo '  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o rootfs/sysc ./cmd/sysc'
  exit 1
fi

# 小工具：先打印命令，再执行，最后展示退出码。
# "$@" = 把所有参数原样展开；|| = 前面失败才执行后面；$? = 上一条命令的退出码。
run() {
  echo "\$ $*"
  "$@" || echo "  (退出码 $?)"
  echo
}

echo "══════════ 世界 1：宿主机（无沙箱）══════════"
run "$SYS" 41 2 1 0    # socket(AF_INET=2, SOCK_STREAM=1, 0)：无拦截时应成功
run "$SYS" 9999        # 编号 9999 不存在：这是"真·内核"给出的 ENOSYS

echo "══════════ 世界 2：沙箱 · 默认策略（errnoRet=1）══════════"
run "$anolix" run --rootfs ./rootfs -- /sysc 41 2 1 0
run "$anolix" run --rootfs ./rootfs -- /sysc 39        # getpid：放行对照

echo "══════════ 世界 3：沙箱 · example 策略（errnoRet=38）══════════"
run "$anolix" run --policy examples/policy.json --rootfs ./rootfs -- /sysc 41 2 1 0
run "$anolix" run --policy examples/policy.json --rootfs ./rootfs -- /sysc 101 0 0 0 0
run "$anolix" run --policy examples/policy.json --rootfs ./rootfs -- /sysc 39