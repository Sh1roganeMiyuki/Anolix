// Command sysc 是一枚"系统调用探针"：直接按号码向内核递一张申请单，
// 观察它被放行、还是被 seccomp 安检站拦下。
//
// 它就是第 01 课"海关模型"的实物版：
//   - 第 1 个参数 = 事项编号（进 rax）
//   - 后面最多 6 个参数 = 六个格子（rdi/rsi/rdx/r10/r8/r9）
//
// 用法（在容器内，或宿主机直接跑）：
//
//	sysc <号码> [a1] [a2] [a3] [a4] [a5] [a6]
//	sysc raw <号码> [a1] ...   # raw 模式：不做 errno 转换，直接打印 rax 原始值
//
// 示例：
//
//	sysc 39            # getpid：安检应放行
//	sysc 41 2 1 0      # socket(AF_INET, SOCK_STREAM, 0)：应被拦截
//	sysc 101 0 0 0 0   # ptrace(PTRACE_TRACEME, 0, 0, 0)：应被拦截
//	sysc 9999          # 内核里不存在的号码：真正的 ENOSYS（显示为 errno=38）
//	sysc raw 9999      # 同上调用，但直接看内核写回的 rax 原始值：-38
//
// 退出码：成功 0；系统调用失败 1；用法错误 2。
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// rawSyscall6 直接执行 SYSCALL 指令并把 rax 原样返回（有符号 int64），
// 不做任何 errno 转换——用于观察"内核写回 rax 的原始值"。
// 实现见 raw_amd64.s；与 Go 标准库 syscall.Syscall6 的唯一差别：
// 没有末尾的 CMPQ/NEGQ 转换段（负值 -38 原样保留，而不是拆成 -1 + errno）。
//
//go:noescape
func rawSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) int64

func main() {
	os.Exit(run())
}

func run() int {
	args := os.Args[1:]

	// raw 模式：跳过 errno 转换，直接打印 rax 原始值。
	raw := false
	if len(args) > 0 && args[0] == "raw" {
		raw = true
		args = args[1:]
		if len(args) == 0 {
			fmt.Fprintln(os.Stderr, "用法: sysc raw <系统调用号> [最多 6 个参数]")
			return 2
		}
	}

	if len(args) == 0 || len(args) > 7 {
		fmt.Fprintln(os.Stderr, "用法: sysc <系统调用号> [最多 6 个参数]")
		return 2
	}

	nr, err := strconv.ParseUint(args[0], 0, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "系统调用号 %q 不是数字: %v\n", args[0], err)
		return 2
	}

	var regs [6]uintptr
	for i := range regs {
		if i+1 >= len(args) {
			break
		}
		v, err := strconv.ParseUint(args[i+1], 0, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "参数 %q 不是数字: %v\n", args[i+1], err)
			return 2
		}
		regs[i] = uintptr(v)
	}

	if raw {
		// 绕过转换层：直接看内核写回 rax 的原始值。
		rax := rawSyscall6(uintptr(nr), regs[0], regs[1], regs[2], regs[3], regs[4], regs[5])
		if rax < 0 && rax >= -4095 {
			// 【内核固定】x86-64 约定：rax ∈ [-4095,-1] 表示失败，errno = -rax。
			errno := -rax
			fmt.Printf("syscall %d (raw): rax = %d  [错误区间 ⇒ errno = %d (%s)]\n",
				nr, rax, errno, syscall.Errno(errno).Error())
			return 1
		}
		fmt.Printf("syscall %d (raw): rax = %d\n", nr, rax)
		return 0
	}

	// 递申请单：号码进 rax，六个参数进 rdi/rsi/rdx/r10/r8/r9。
	r1, _, errno := syscall.Syscall6(uintptr(nr), regs[0], regs[1], regs[2], regs[3], regs[4], regs[5])
	if errno != 0 {
		fmt.Printf("syscall %d 失败: errno=%d (%s)\n", nr, errno, errno.Error())
		return 1
	}
	fmt.Printf("syscall %d 成功: 返回值=%d\n", nr, r1)
	return 0
}
