// Package config 负责解析 Anolix 的 policy 配置。
//
// policy 以 JSON 描述沙箱运行策略，核心是 seccomp 行为：
// 是否启用 seccomp（enabled）、被拒绝的系统调用返回的 errno（errnoRet），
// 以及默认动作（defaultAction）与放行名单（allowedSyscalls）。
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// DefaultErrnoRet 是 errnoRet 未配置时的默认值：EPERM。
const DefaultErrnoRet uint = 1

// maxErrno 是合法 errno 的上界（Linux errno 为 12 位）。
const maxErrno uint = 4095

// 支持的 seccomp 默认动作，均为"拒绝"语义；
// 若需要完全放行，应直接关闭 seccomp（enabled=false）。
const (
	ActionErrno       = "SCMP_ACT_ERRNO"
	ActionKill        = "SCMP_ACT_KILL"
	ActionKillProcess = "SCMP_ACT_KILL_PROCESS"
	ActionTrap        = "SCMP_ACT_TRAP"
)

// DefaultAllowedSyscalls 是未显式配置放行名单时使用的最小系统调用集合，
// 覆盖执行常见命令（文件读写、内存管理、进程与信号、基础时间/随机数）所需的调用；
// 网络、ptrace、mount、bpf、keyctl 等高风险调用不在其中。
var DefaultAllowedSyscalls = []string{
	"access", "arch_prctl", "brk", "chdir", "chmod", "clock_getres",
	"clock_gettime", "clock_nanosleep", "clone", "clone3", "close",
	"close_range", "dup", "dup2", "dup3", "epoll_create1", "epoll_ctl",
	"epoll_pwait", "epoll_wait", "eventfd2", "execve", "execveat", "exit",
	"exit_group", "faccessat", "faccessat2", "fchmod", "fchmodat", "fchown",
	"fcntl", "flock", "fstat", "fstatfs", "fsync", "ftruncate", "futex",
	"getcwd", "getdents64", "getegid", "geteuid", "getgid", "getgroups",
	"getpid", "getppid", "getrandom", "getresgid", "getresuid", "getrlimit",
	"getrusage", "gettid", "gettimeofday", "getuid", "ioctl", "kill", "link",
	"linkat", "lseek", "madvise", "mkdir", "mkdirat", "mmap", "mprotect",
	"mremap", "munmap", "nanosleep", "newfstatat", "openat", "openat2",
	"pipe", "pipe2", "poll", "ppoll", "prctl", "pread64", "prlimit64",
	"pwrite64", "read", "readlink", "readlinkat", "readv", "rename",
	"renameat", "renameat2", "restart_syscall", "rmdir", "rseq",
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sched_getaffinity",
	"sched_yield", "set_robust_list", "set_tid_address", "sigaltstack",
	"statfs", "statx", "symlink", "symlinkat", "tgkill", "time", "truncate",
	"umask", "uname", "unlink", "unlinkat", "utimensat", "wait4", "waitid",
	"write", "writev",
}

// Policy 是 Anolix 的沙箱运行策略。
type Policy struct {
	// Seccomp 是 seccomp 过滤器的配置。
	Seccomp Seccomp `json:"seccomp"`
}

// Seccomp 描述容器内 seccomp 过滤器的行为。
type Seccomp struct {
	// Enabled 是 seccomp 总开关；false 时容器不加载任何 seccomp 过滤器。
	Enabled bool `json:"enabled"`
	// ErrnoRet 是命中拒绝规则时返回给进程的 errno；
	// 0 表示使用默认值 EPERM(1)。常见加固取值：38(ENOSYS)。
	ErrnoRet uint `json:"errnoRet"`
	// DefaultAction 是未显式放行的系统调用的默认动作；
	// 缺省为 SCMP_ACT_ERRNO，可选 SCMP_ACT_KILL / SCMP_ACT_KILL_PROCESS / SCMP_ACT_TRAP。
	DefaultAction string `json:"defaultAction"`
	// AllowedSyscalls 是放行（SCMP_ACT_ALLOW）的系统调用名单；
	// 为空时回退到 DefaultAllowedSyscalls。
	AllowedSyscalls []string `json:"allowedSyscalls"`
}

// Default 返回内置的默认策略：启用 seccomp，拒绝时返回 EPERM。
func Default() *Policy {
	return &Policy{
		Seccomp: Seccomp{
			Enabled:       true,
			ErrnoRet:      DefaultErrnoRet,
			DefaultAction: ActionErrno,
		},
	}
}

// Load 从 JSON 文件读取 policy 并完成校验。
func Load(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 policy 文件失败: %w", err)
	}
	p, err := Parse(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("解析 policy 文件 %s 失败: %w", path, err)
	}
	return p, nil
}

// Parse 从 r 解析 policy 并完成校验。
// 采用严格解析：JSON 中出现未知字段会直接报错，避免策略拼写错误被静默忽略。
func Parse(r io.Reader) (*Policy, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()

	p := &Policy{}
	if err := dec.Decode(p); err != nil {
		return nil, fmt.Errorf("policy JSON 非法: %w", err)
	}
	// 拒绝 JSON 文档之后的额外内容。
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("policy JSON 非法: 存在多余内容")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return p, nil
}

// Validate 校验策略取值是否合法。
func (p *Policy) Validate() error {
	s := &p.Seccomp

	if action := s.EffectiveDefaultAction(); !validAction(action) {
		return fmt.Errorf("不支持的 seccomp defaultAction %q，可选: %s, %s, %s, %s",
			s.DefaultAction, ActionErrno, ActionKill, ActionKillProcess, ActionTrap)
	}
	if s.ErrnoRet > maxErrno {
		return fmt.Errorf("seccomp errnoRet %d 超出合法范围 (0-%d)", s.ErrnoRet, maxErrno)
	}
	for _, name := range s.AllowedSyscalls {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("seccomp allowedSyscalls 中存在空条目")
		}
		if strings.ContainsAny(name, " \t") {
			return fmt.Errorf("seccomp allowedSyscalls 条目 %q 含空白字符", name)
		}
	}
	return nil
}

// EffectiveErrnoRet 返回生效的 errno：未配置（0）时为 EPERM。
func (s Seccomp) EffectiveErrnoRet() uint {
	if s.ErrnoRet == 0 {
		return DefaultErrnoRet
	}
	return s.ErrnoRet
}

// EffectiveDefaultAction 返回生效的默认动作：未配置时为 SCMP_ACT_ERRNO。
func (s Seccomp) EffectiveDefaultAction() string {
	if s.DefaultAction == "" {
		return ActionErrno
	}
	return strings.ToUpper(strings.TrimSpace(s.DefaultAction))
}

// EffectiveAllowedSyscalls 返回生效的放行名单：
// 未配置时返回 DefaultAllowedSyscalls 的副本。
func (s Seccomp) EffectiveAllowedSyscalls() []string {
	if len(s.AllowedSyscalls) == 0 {
		return append([]string(nil), DefaultAllowedSyscalls...)
	}
	return append([]string(nil), s.AllowedSyscalls...)
}

func validAction(action string) bool {
	switch action {
	case ActionErrno, ActionKill, ActionKillProcess, ActionTrap:
		return true
	default:
		return false
	}
}
