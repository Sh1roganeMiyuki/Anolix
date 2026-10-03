// Package config 负责解析 Anolix 的 policy 配置。
//
// 这个包只干三件事：读 JSON → 检查合法性 → 把"没填的字段"补上默认值。
// 它不碰容器、不碰进程——真正的翻译在 launcher/spec.go，执行在 runc。
//
// policy 以 JSON 描述沙箱运行策略，当前包含两部分：
//   - seccomp：是否启用（enabled）、被拒绝的系统调用返回的 errno（errnoRet）、
//     默认动作（defaultAction）与放行名单（allowedSyscalls）；
//   - resources：cgroup v2 资源围栏（内存上限、进程数上限、CPU 配额），
//     各字段为 0 表示不限制。
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// DefaultErrnoRet 是 errnoRet 未配置时的默认值：EPERM(=1)。
//
// 白话：errno 是内核（或安检机）拒绝请求时回的"理由编号"；
// EPERM 的字面意思就是"不允许"，所以拿它当默认。
const DefaultErrnoRet uint = 1

// maxErrno 是合法 errno 的上界（Linux errno 为 12 位）。
//
// 白话：seccomp 允许返回 0–4095 的编号，但"真实内核 errno"最大只到 133。
// 中间的差值就是"哨兵值"的空间——比如 1145：内核造不出来，见到它 = 被安检机盖章。
const maxErrno uint = 4095

// 支持的 seccomp 默认动作，均为"拒绝"语义；
// 若需要完全放行，应直接关闭 seccomp（enabled=false）。
//
// 四个动作的白话：ERRNO=盖章拒绝；KILL=杀线程（旧）；KILL_PROCESS=杀整个进程；
// TRAP=发一个 SIGSYS 信号给程序（高级用法）。
const (
	ActionErrno       = "SCMP_ACT_ERRNO"
	ActionKill        = "SCMP_ACT_KILL"
	ActionKillProcess = "SCMP_ACT_KILL_PROCESS"
	ActionTrap        = "SCMP_ACT_TRAP"
)

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// 【面试必会】安检名单：三条事实（名字精确匹配 / 未知名静默忽略 / fork-vfork-open 是后补的）。
//
//	为什么：你所有"神秘失败"故事（init 崩溃、busybox fork 被盖章）都从这份名单来。
//	问法："白名单怎么定的？漏一条会怎样？"
//
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// DefaultAllowedSyscalls 是"安检名单"：policy 里不写 allowedSyscalls 时就用它。
//
// 白话：名单里的系统调用放行，其余按 defaultAction 处理（默认盖章拒绝）。
// 三个必须知道的事实：
//  1. 名单按"名字"精确匹配：少一条不报错，只会让程序在某个时刻神秘失败；
//  2. runc/libseccomp 对无法识别的名字"静默忽略"——拼错等于没写（实测结论）；
//  3. 历史上补过三条（fork / vfork / open）：musl（busybox）用户态走的路径
//     与 Go/glibc 不同，clone 不覆盖 fork、openat 不覆盖 open（01/02 两篇有完整排查）。
//
// 以下为原有注释（保留）：
// 覆盖执行常见命令（文件读写、内存管理、进程与信号、基础时间/随机数）所需的调用；
// 进程创建同时放行 clone/clone3 与 fork/vfork：前者是 Go/glibc 的创建路径，
// 后者是 musl/busybox 等用户态实际使用的路径——漏掉不会报错，只会静默失败
// （实测：名单只有 clone 时，busybox 的 fork 被 defaultAction 盖章）。
// 网络、ptrace、mount、bpf、keyctl 等高风险调用不在其中。
var DefaultAllowedSyscalls = []string{
	"access", "arch_prctl", "brk", "chdir", "chmod", "clock_getres",
	"clock_gettime", "clock_nanosleep", "clone", "clone3", "close",
	"close_range", "dup", "dup2", "dup3", "epoll_create1", "epoll_ctl",
	"epoll_pwait", "epoll_wait", "eventfd2", "execve", "execveat", "exit",
	"exit_group", "faccessat", "faccessat2", "fchmod", "fchmodat", "fchown",
	"fcntl", "flock", "fork", "fstat", "fstatfs", "fsync", "ftruncate", "futex",
	"getcwd", "getdents64", "getegid", "geteuid", "getgid", "getgroups",
	"getpid", "getppid", "getrandom", "getresgid", "getresuid", "getrlimit",
	"getrusage", "gettid", "gettimeofday", "getuid", "ioctl", "kill", "link",
	"linkat", "lseek", "madvise", "mkdir", "mkdirat", "mmap", "mprotect",
	"mremap", "munmap", "nanosleep", "newfstatat", "open", "openat", "openat2",
	"pipe", "pipe2", "poll", "ppoll", "prctl", "pread64", "prlimit64",
	"pwrite64", "read", "readlink", "readlinkat", "readv", "rename",
	"renameat", "renameat2", "restart_syscall", "rmdir", "rseq",
	"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "sched_getaffinity",
	"sched_yield", "set_robust_list", "set_tid_address", "sigaltstack",
	"statfs", "statx", "symlink", "symlinkat", "tgkill", "time", "truncate",
	"umask", "uname", "unlink", "unlinkat", "utimensat", "vfork", "wait4", "waitid",
	"write", "writev",
}

// DefaultCPUPeriodMicros 是 cpuPeriodMicros 未配置时使用的默认计费周期：100ms。
// 白话：CPU 配额是"每个周期最多用多少"，周期默认 100 毫秒。
const DefaultCPUPeriodMicros uint64 = 100000

// CFS 计费参数的合法范围（内核约束）：quota 最小 1ms；period 取值 1ms–1s。
// 白话：CFS 是内核的 CPU 公平调度机制，这两个数字的上下限来自内核，写错会被拒绝。
const (
	minCPUQuotaMicros  int64  = 1000
	minCPUPeriodMicros uint64 = 1000
	maxCPUPeriodMicros uint64 = 1000000
)

// Policy 是 Anolix 的沙箱运行策略（= 你写给沙箱的"规矩说明书"）。
// 分两大块：seccomp（哪些系统调用能用）+ resources（能用多少资源）。
type Policy struct {
	// Seccomp 是 seccomp 安检机的配置（见下）。
	Seccomp Seccomp `json:"seccomp"`
	// Resources 是 cgroup v2 资源围栏（内存/进程数/CPU）；字段为 0 = 不限制。
	Resources Resources `json:"resources"`
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// 【面试必会】安检机的四个配置项：开不开 / 盖章 errno / 默认动作 / 放行名单。
//
//	为什么：两个 38、哨兵 1145、"1145 vs EAGAIN"的分层判据——全挂在这四个字段上。
//	问法："被拦时程序看到什么？这个编号由谁决定？"
//
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// Seccomp 描述"安检机"的行为。四个字段分别回答四个问题：
// 开不开？被拦时回什么编号？没写进名单的怎么处理？哪些放行？
type Seccomp struct {
	// Enabled：总开关。false = 不装安检机（容器里什么调用都能用）。
	Enabled bool `json:"enabled"`
	// ErrnoRet：被拦时回给程序的编号。0 = 用默认值 EPERM(1)。
	// 常见取值：38(ENOSYS，伪装成"功能不存在"，会有歧义)；1145(排障用哨兵值)。
	ErrnoRet uint `json:"errnoRet"`
	// DefaultAction：没被名单放行的调用，用什么动作处理（默认 ERRNO=盖章）。
	// 可选 SCMP_ACT_ERRNO / KILL / KILL_PROCESS / TRAP。
	DefaultAction string `json:"defaultAction"`
	// AllowedSyscalls：放行名单（安检白名单）。
	// 留空 = 回退到内置名单 DefaultAllowedSyscalls（见上）。
	AllowedSyscalls []string `json:"allowedSyscalls"`
}

// !!! 【值得会说】四个字段 ↔ 四个内核文件的一一对应（含 cpu.max 的左/右值）。
// Resources 描述资源围栏（会由 launcher 翻译成 OCI 字段，再被 runc 写进内核文件）。
// 每个字段的"0"都表示"这一项不限制"。
type Resources struct {
	// MemoryLimitBytes → 内核文件 memory.max（物理内存硬上限，单位字节）。
	// 超过时：先想办法回收（换出/丢弃缓存），实在无路可走就 OOM kill。
	MemoryLimitBytes int64 `json:"memoryLimitBytes"`
	// PidsLimit → 内核文件 pids.max（最多允许多少个进程/线程）。
	// 达到上限后：再 fork 会失败，返回 EAGAIN（"暂时生不出来"）。
	PidsLimit int64 `json:"pidsLimit"`
	// CPUQuotaMicros → 内核文件 cpu.max 的左值（每个周期最多用多少微秒 CPU）。
	// 可大于周期本身：如 200000/100000 = 允许用满 2 个核。
	CPUQuotaMicros int64 `json:"cpuQuotaMicros"`
	// CPUPeriodMicros → 内核文件 cpu.max 的右值（计费周期，微秒，1000–1000000）。
	// 只在设置了配额时才有效；不填就用默认 100ms。
	CPUPeriodMicros uint64 `json:"cpuPeriodMicros"`
}

// Default 返回内置默认策略：开 seccomp、拦截回 EPERM、用内置名单。
// 白话：什么参数都不给时，沙箱至少要有"默认的锁"。
func Default() *Policy {
	return &Policy{
		Seccomp: Seccomp{
			Enabled:       true,
			ErrnoRet:      DefaultErrnoRet,
			DefaultAction: ActionErrno,
		},
	}
}

// --- 【可略读】读取 + 转手给 Parse，一眼即可。
// Load 从文件读 policy：先读整个文件，再交给 Parse 解析 + 校验。
// 白话：它只管"读"，解析规则都在 Parse 里（方便测试直接喂字符串）。
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
//
// !!! 【值得会说】严格解析不是洁癖：字段拼错被静默忽略，会在运行期变成难查的怪现象。
// 严格解析（DisallowUnknownFields）：JSON 里出现不认识的字段会当场报错。
// 白话：宁可启动前拒绝，也不要"字段名拼错被悄悄忽略、运行时才神秘失败"。
// 末尾那次 Decode(&struct{}{})：再读一次，如果还能读到东西，说明文件末尾
// 有多余内容（比如两个 JSON 拼在一起），同样拒绝。
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
// 白话：这里只做"启动前能查出来的错"——动作名、errno 范围、名单条目形态，
// 以及资源的范围与组合（见 Resources.Validate）。
func (p *Policy) Validate() error {
	s := &p.Seccomp

	if action := s.EffectiveDefaultAction(); !validAction(action) {
		// 默认动作必须是四个支持值之一（用"生效值"判断，兼容留空的情况）。
		return fmt.Errorf("不支持的 seccomp defaultAction %q，可选: %s, %s, %s, %s",
			s.DefaultAction, ActionErrno, ActionKill, ActionKillProcess, ActionTrap)
	}
	if s.ErrnoRet > maxErrno {
		// errno 允许 0–4095；超过就不是 seccomp 能表达的编号了。
		return fmt.Errorf("seccomp errnoRet %d 超出合法范围 (0-%d)", s.ErrnoRet, maxErrno)
	}
	for _, name := range s.AllowedSyscalls {
		// 名单条目不允许空、也不允许含空白字符——这些都是"写错了"的征兆。
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("seccomp allowedSyscalls 中存在空条目")
		}
		if strings.ContainsAny(name, " \t") {
			return fmt.Errorf("seccomp allowedSyscalls 条目 %q 含空白字符", name)
		}
	}
	return p.Resources.Validate()
}

// --- 【可略读】细节校验：知道"启动前把非法值拒绝掉"即可，各条不必背。
// Validate 校验资源围栏取值是否合法。
// 白话：为什么这么多条条框框？因为内核对这些值有自己的范围要求；
// 与其让 runc 中途报错，不如在解析阶段就说清楚。
func (r Resources) Validate() error {
	if r.MemoryLimitBytes < 0 {
		return fmt.Errorf("resources.memoryLimitBytes %d 不能为负", r.MemoryLimitBytes)
	}
	if r.PidsLimit < 0 {
		return fmt.Errorf("resources.pidsLimit %d 不能为负", r.PidsLimit)
	}
	if r.CPUQuotaMicros < 0 {
		return fmt.Errorf("resources.cpuQuotaMicros %d 不能为负", r.CPUQuotaMicros)
	}
	if r.CPUQuotaMicros > 0 && r.CPUQuotaMicros < minCPUQuotaMicros {
		return fmt.Errorf("resources.cpuQuotaMicros %d 低于内核下限 (%d)", r.CPUQuotaMicros, minCPUQuotaMicros)
	}
	if r.CPUPeriodMicros != 0 {
		if r.CPUQuotaMicros == 0 {
			// 只设周期、不设配额没有意义（周期只在配额模式下生效），直接拒绝。
			return fmt.Errorf("resources.cpuPeriodMicros 已设置但 cpuQuotaMicros 未设置（周期仅在配额模式下生效）")
		}
		if r.CPUPeriodMicros < minCPUPeriodMicros || r.CPUPeriodMicros > maxCPUPeriodMicros {
			return fmt.Errorf("resources.cpuPeriodMicros %d 超出合法范围 (%d-%d)",
				r.CPUPeriodMicros, minCPUPeriodMicros, maxCPUPeriodMicros)
		}
	}
	return nil
}

// EffectiveErrnoRet 返回生效的 errno：未配置（0）时为 EPERM。
// 白话：配置里 0 表示"没填"，这里统一翻译成"实际会用到的值"——
// 校验与生成说明书都用同一套兜底，保证两边始终一致。
func (s Seccomp) EffectiveErrnoRet() uint {
	if s.ErrnoRet == 0 {
		return DefaultErrnoRet
	}
	return s.ErrnoRet
}

// EffectiveDefaultAction 返回生效的默认动作：未配置时为 SCMP_ACT_ERRNO。
// 白话：留空就用 ERRNO；顺手把大小写与首尾空白归一（" scmp_act_errno " 也能忍）。
func (s Seccomp) EffectiveDefaultAction() string {
	if s.DefaultAction == "" {
		return ActionErrno
	}
	return strings.ToUpper(strings.TrimSpace(s.DefaultAction))
}

// EffectiveAllowedSyscalls 返回生效的放行名单：未配置时返回 DefaultAllowedSyscalls 的副本。
// 白话：留空 = 用内置名单；无论哪种都复制一份再返回，
// 调用方拿到后改它也不会污染全局默认名单。
func (s Seccomp) EffectiveAllowedSyscalls() []string {
	if len(s.AllowedSyscalls) == 0 {
		return append([]string(nil), DefaultAllowedSyscalls...)
	}
	return append([]string(nil), s.AllowedSyscalls...)
}

// EffectiveCPUPeriodMicros 返回生效的 CPU 计费周期：未配置时为 100ms。
func (r Resources) EffectiveCPUPeriodMicros() uint64 {
	if r.CPUPeriodMicros == 0 {
		return DefaultCPUPeriodMicros
	}
	return r.CPUPeriodMicros
}

// validAction 判断动作名是否属于四个支持值之一。
func validAction(action string) bool {
	switch action {
	case ActionErrno, ActionKill, ActionKillProcess, ActionTrap:
		return true
	default:
		return false
	}
}
