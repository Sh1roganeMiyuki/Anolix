// Command rawfilter 是"原始过滤器实验"：不经过 libseccomp，手写一枚极简
// seccomp BPF 过滤器直接装到自己身上，回答一个问题——
//
//	系统调用表"表外"的号码（如 9999），过滤器到底看得见吗？
//
// 过滤器逻辑（手写经典 BPF 指令，见 install）：
//
//	nr ∈ 生存集（write/exit/futex 等，让程序活到打印结果）→ ALLOW
//	其它一切号码 → ERRNO(1234)   ← 本实验的"特征章"
//
// 安装后依次调用 39(getpid)、170(sethostname)、174(表内空槽)、9999(表外)：
//
//	errno=1234 → 被盖章（过滤器看得见这个号码）
//	其它      → 未被盖章（过滤器没参与，结果来自内核本身）
//
// 用法：CGO_ENABLED=0 go build -o /tmp/rawfilter ./cmd/rawfilter && /tmp/rawfilter
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// 经典 BPF 指令常量（内核 UAPI：bpf_common.h / filter.h）。
const (
	bpfLD  = 0x00 // BPF_LD
	bpfW   = 0x00 // BPF_W
	bpfABS = 0x20 // BPF_ABS
	bpfJMP = 0x05 // BPF_JMP
	bpfJEQ = 0x10 // BPF_JEQ
	bpfK   = 0x00 // BPF_K
	bpfRET = 0x06 // BPF_RET

	prSetNoNewPrivs   = 38 // PR_SET_NO_NEW_PRIVS
	prSetSeccomp      = 22 // PR_SET_SECCOMP
	seccompModeFilter = 2  // SECCOMP_MODE_FILTER

	retAllow = uint32(0x7fff0000) // SECCOMP_RET_ALLOW
	retErrno = uint32(0x00050000) // SECCOMP_RET_ERRNO
	stamp    = uint32(1234)       // 特征章：过滤器被触发时返回的 errno
)

// sockFilter / sockFprog 对应内核 struct sock_filter / sock_fprog。
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// survival 是"生存集"：装好过滤器后，Go 运行时与结果打印仍需要的调用。
var survival = []uint32{
	1,   // write
	60,  // exit
	231, // exit_group
	13,  // rt_sigaction
	14,  // rt_sigprocmask
	15,  // rt_sigreturn
	131, // sigaltstack
	186, // gettid
	202, // futex
	234, // tgkill
	24,  // sched_yield
	35,  // nanosleep
}

var (
	prog  []sockFilter
	fprog sockFprog
)

func main() {
	if err := install(); err != nil {
		fmt.Fprintf(os.Stderr, "安装过滤器失败: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("手写 seccomp 过滤器已安装（非 libseccomp）；盖章值 = %d\n", stamp)
	for _, nr := range []uintptr{39, 170, 174, 9999} {
		report(nr)
	}
}

// install 组装并安装过滤器：
//
//	LD  [0]                ; A = seccomp_data.nr（nr 在偏移 0）
//	JEQ nr → ALLOW         ; 对生存集逐个生成
//	RET ERRNO(1234)        ; 兜底：其它一切号码盖特征章
func install() error {
	prog = []sockFilter{{code: bpfLD | bpfW | bpfABS, k: 0}}
	for _, nr := range survival {
		prog = append(prog,
			sockFilter{code: bpfJMP | bpfJEQ | bpfK, jt: 0, jf: 1, k: nr},
			sockFilter{code: bpfRET | bpfK, k: retAllow},
		)
	}
	prog = append(prog, sockFilter{code: bpfRET | bpfK, k: retErrno | stamp})

	fprog = sockFprog{len: uint16(len(prog)), filter: &prog[0]}

	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %v", e)
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter,
		uintptr(unsafe.Pointer(&fprog)), 0, 0, 0); e != 0 {
		return fmt.Errorf("PR_SET_SECCOMP: %v", e)
	}
	return nil
}

func report(nr uintptr) {
	r1, _, e := syscall.Syscall6(nr, 0, 0, 0, 0, 0, 0)
	switch {
	case e == syscall.Errno(stamp):
		fmt.Printf("  nr=%-5d → 被盖章: errno=%d（过滤器看得见这个号码）\n", nr, e)
	case e != 0:
		fmt.Printf("  nr=%-5d → 未被盖章: errno=%d (%s)\n", nr, e, e.Error())
	default:
		fmt.Printf("  nr=%-5d → 未被盖章: 成功 返回值=%d\n", nr, r1)
	}
}
