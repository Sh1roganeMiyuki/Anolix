// seccomp.go 给 worker 装 syscall 白名单过滤器。
//
// 为什么必须由 worker 自己装（对照小知识点 #18/#19）：
//   - seccomp 不可撤销、且 fork/clone 继承、execve 保留；
//   - 母体若预装 → 母体自己也被限（#19 坑1 自缚），且所有 worker 共享同一份（不能按 worker 定制）；
//   - 所以规矩是「最终程序自己装、紧贴 execve」。本实现里 worker 一启动就先装，再做正事。
//
// 过滤器逻辑（经典 cBPF，复用 cmd/rawfilter 的范式）：
//
//	arch != x86-64        → KILL（防 32 位 syscall 绕过）
//	nr ∈ 白名单           → ALLOW
//	其余一切              → ERRNO(errno)   ← 默认盖章拒绝
//
// 白名单来源：config.DefaultAllowedSyscalls（names）→ 本文件的 x86-64 号码表 → numbers。
// ⚠️ 已知坑（#19 坑2 / Anolix 01-02 篇）：漏一条不报错，只会让程序在某刻神秘失败。
package zygote

import (
	"anolix/config"
	"fmt"
	"syscall"
	"unsafe"
)

// --- 经典 BPF 指令常量（内核 UAPI：bpf_common.h / filter.h）---
const (
	bpfLD  = 0x00 // BPF_LD
	bpfW   = 0x00 // BPF_W
	bpfABS = 0x20 // BPF_ABS
	bpfJMP = 0x05 // BPF_JMP
	bpfJEQ = 0x10 // BPF_JEQ
	bpfK   = 0x00 // BPF_K
	bpfRET = 0x06 // BPF_RET
)

// --- prctl / seccomp 常量 ---
const (
	prSetNoNewPrivs   = 38 // PR_SET_NO_NEW_PRIVS（装过滤器的前置）
	prSetSeccomp      = 22 // PR_SET_SECCOMP
	seccompModeFilter = 2  // SECCOMP_MODE_FILTER

	retAllow = uint32(0x7fff0000) // SECCOMP_RET_ALLOW
	retErrno = uint32(0x00050000) // SECCOMP_RET_ERRNO（低 16 位是 errno）
	retKill  = uint32(0x00000000) // SECCOMP_RET_KILL_THREAD

	auditArchX86_64 = 0xC000003E // AUDIT_ARCH_X86_64

	offsetNR   = 0 // seccomp_data.nr 的偏移
	offsetArch = 4 // seccomp_data.arch 的偏移
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

// x86_64SyscallNumbers 是 name → x86-64 syscall 号码的映射。
// 覆盖 config.DefaultAllowedSyscalls 的全部条目（号码来自内核 UAPI，x86-64 固定不变）。
// ⚠️ 仅 x86-64；换架构要重做这张表（这也是 libseccomp 帮你做的事，这里手写以零依赖）。
var x86_64SyscallNumbers = map[string]uint32{
	"read": 0, "write": 1, "open": 2, "close": 3, "stat": 4, "fstat": 5,
	"lstat": 6, "poll": 7, "lseek": 8, "mmap": 9, "mprotect": 10, "munmap": 11,
	"brk": 12, "rt_sigaction": 13, "rt_sigprocmask": 14, "rt_sigreturn": 15,
	"ioctl": 16, "pread64": 17, "pwrite64": 18, "readv": 19, "writev": 20,
	"access": 21, "pipe": 22, "sched_yield": 24, "mremap": 25, "madvise": 28,
	"dup": 32, "dup2": 33, "nanosleep": 35, "getpid": 39, "clone": 56,
	"fork": 57, "vfork": 58, "execve": 59, "exit": 60, "wait4": 61, "kill": 62,
	"uname": 63, "fcntl": 72, "flock": 73, "fsync": 74, "truncate": 76,
	"ftruncate": 77, "getcwd": 79, "chdir": 80, "rename": 82, "mkdir": 83,
	"rmdir": 84, "link": 86, "unlink": 87, "symlink": 88, "readlink": 89,
	"chmod": 90, "fchmod": 91, "chown": 92, "fchown": 93, "umask": 95,
	"gettimeofday": 96, "getrlimit": 97, "getrusage": 98, "getuid": 102,
	"getgid": 104, "geteuid": 107, "getegid": 108, "getppid": 110,
	"getgroups": 115, "setgroups": 116, "getresuid": 118, "getresgid": 120,
	"sigaltstack": 131, "statfs": 137, "fstatfs": 138, "prctl": 157,
	"arch_prctl": 158, "gettid": 186, "time": 201, "futex": 202,
	"sched_getaffinity": 204, "getdents64": 217, "set_tid_address": 218,
	"restart_syscall": 219, "clock_gettime": 228, "clock_getres": 229,
	"clock_nanosleep": 230,
	"exit_group":      231, "epoll_wait": 232, "epoll_ctl": 233, "tgkill": 234,
	"waitid": 247, "openat": 257, "mkdirat": 258, "newfstatat": 262,
	"unlinkat": 263, "renameat": 264, "linkat": 265, "symlinkat": 266,
	"readlinkat": 267, "fchmodat": 268, "faccessat": 269, "ppoll": 271,
	"set_robust_list": 273, "utimensat": 280, "epoll_pwait": 281,
	"eventfd2": 290, "epoll_create1": 291, "dup3": 292, "pipe2": 293,
	"preadv": 295, "pwritev": 296, "prlimit64": 302, "renameat2": 316,
	"getrandom": 318, "execveat": 322, "statx": 332, "rseq": 334,
	"clone3": 435, "close_range": 436, "openat2": 437, "faccessat2": 439,
	// —— 补充：常见工具（busybox 等）可能会用的（见 CommonPayloadSyscalls）——
	"select": 23, "getdents": 78, "fdatasync": 75,
	"readahead": 187, "getxattr": 191, "lgetxattr": 192, "fgetxattr": 193,
	"listxattr": 194, "llistxattr": 195, "flistxattr": 196, "fadvise64": 221,
	"get_robust_list": 274, "utime": 132, "utimes": 235, "getsid": 124,
	"getpgid": 121, "setpgid": 109, "sched_getparam": 143,
	"sched_getscheduler": 145, "sched_get_priority_max": 146,
	"sched_get_priority_min": 147, "sched_rr_get_interval": 148,
	"getpriority": 140, "sysinfo": 99, "sendfile": 40, "fallocate": 285,
	"membarrier": 324, "mincore": 27, "mlock": 149, "munlock": 150,
	"mlockall": 151, "munlockall": 152, "timerfd_create": 283,
	"timerfd_settime": 286, "timerfd_gettime": 287, "eventfd": 284,
	"signalfd4": 289, "pselect6": 270,
}

// CommonPayloadSyscalls 是"常见工具（busybox 等）可能会用、但未必在 config 名单里"的补充白名单。
//
// ⚠️ 这是务实做法（先把常见工具跑通）；严谨做法是 strace 抓出**唯一那条**再精确补（#26 坑1）。
// 都是非特权的"读信息 / 常规文件"类调用，不含 mount/ptrace/bpf 等危险项。
var CommonPayloadSyscalls = []string{
	"stat", "lstat", "getdents", "select", "pselect6", "fdatasync",
	"readahead", "getxattr", "lgetxattr", "fgetxattr", "listxattr",
	"llistxattr", "flistxattr", "fadvise64", "get_robust_list", "utime",
	"utimes", "getsid", "getpgid", "setpgid", "sched_getparam",
	"sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min",
	"sched_rr_get_interval", "getpriority", "sysinfo", "sendfile",
	"fallocate", "membarrier", "mincore", "mlock", "munlock", "mlockall",
	"munlockall", "timerfd_create", "timerfd_settime", "timerfd_gettime",
	"eventfd", "signalfd4",
}

// DefaultPayloadAllowlist 返回 config 默认名单 + 常见工具补充名单 的合并（去重）。
func DefaultPayloadAllowlist() []string {
	merged := append([]string(nil), config.DefaultAllowedSyscalls...)
	seen := make(map[string]bool, len(merged))
	for _, n := range merged {
		seen[n] = true
	}
	for _, n := range CommonPayloadSyscalls {
		if !seen[n] {
			seen[n] = true
			merged = append(merged, n)
		}
	}
	return merged
}

// SyscallNumber 把一个 syscall 名字翻译成 x86-64 号码。
func SyscallNumber(name string) (uint32, bool) {
	nr, ok := x86_64SyscallNumbers[name]
	return nr, ok
}

// BuildAllowlistFilter 构造一枚「白名单放行、其余盖章 errno」的 cBPF 过滤器。
//
// 结构（复用 cmd/rawfilter 的范式 + 加 arch 守卫）：
//
//	LD   arch                  ; A = seccomp_data.arch
//	JEQ  x86-64 → +1           ; 对 → 跳过 KILL；错 → 落到 KILL
//	RET  KILL                  ; 非 x86-64 直接杀（防 32 位号绕过）
//	LD   nr                    ; A = seccomp_data.nr
//	（对白名单每个号：）
//	JEQ  nr → +0 ; else +1     ; 命中 → 下一条 RET ALLOW；不中 → 跳过它
//	RET  ALLOW
//	...
//	RET  ERRNO(errno)          ; 兜底：盖章拒绝
func BuildAllowlistFilter(numbers []uint32, errno uint32) []sockFilter {
	prog := []sockFilter{
		{code: bpfLD | bpfW | bpfABS, k: offsetArch},
		{code: bpfJMP | bpfJEQ | bpfK, jt: 1, jf: 0, k: auditArchX86_64},
		{code: bpfRET | bpfK, k: retKill},
		{code: bpfLD | bpfW | bpfABS, k: offsetNR},
	}
	for _, nr := range numbers {
		prog = append(prog,
			sockFilter{code: bpfJMP | bpfJEQ | bpfK, jt: 0, jf: 1, k: nr},
			sockFilter{code: bpfRET | bpfK, k: retAllow},
		)
	}
	prog = append(prog, sockFilter{code: bpfRET | bpfK, k: retErrno | (errno & 0xffff)})
	return prog
}

// InstallSeccomp 把 names 翻成号码、构造过滤器、装到「当前进程」身上。
//
// 返回实际放行的 syscall 条数。未识别的名字会被跳过并计入 unknown（#19 坑2：
// 拼错的名字静默忽略 = 等于没写，所以这里把 unknown 回吐给调用方打印/告警）。
//
// ⚠️ 不可撤销：装上之后只能更严，不能放松；调用方必须是「即将跑最终逻辑」的那个进程。
func InstallSeccomp(names []string, errno uint32) (installed int, unknown []string, err error) {
	numbers := make([]uint32, 0, len(names))
	seen := make(map[uint32]bool, len(names))
	for _, name := range names {
		nr, ok := SyscallNumber(name)
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		if seen[nr] {
			continue // 去重（不同名可能同号，或重复条目）
		}
		seen[nr] = true
		numbers = append(numbers, nr)
	}

	prog := BuildAllowlistFilter(numbers, errno)
	fprog := sockFprog{len: uint16(len(prog)), filter: &prog[0]}

	// 前置：NO_NEW_PRIVS。没有它，非特权进程装 seccomp 会被 EPERM 拒绝。
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); e != 0 {
		return 0, unknown, fmt.Errorf("PR_SET_NO_NEW_PRIVS 失败: %w", error(e))
	}
	// 装过滤器。这一刻起，本进程后续所有 syscall 都过这枚 BPF。
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, prSetSeccomp, seccompModeFilter,
		uintptr(unsafe.Pointer(&fprog)), 0, 0, 0); e != 0 {
		return 0, unknown, fmt.Errorf("PR_SET_SECCOMP 失败: %w", error(e))
	}
	return len(numbers), unknown, nil
}
