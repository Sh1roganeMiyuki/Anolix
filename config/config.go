// Package config 负责解析 Anolix 的 policy 配置。
//
// 这个包只干三件事：读 JSON → 检查合法性 → 把"没填的字段"补上默认值。
// 它不碰容器、不碰进程——真正的翻译在 launcher/spec.go，执行在 runc。
//
// policy 以 JSON 描述沙箱运行策略，当前包含三部分：
//   - seccomp：是否启用（enabled）、被拒绝的系统调用返回的 errno（errnoRet）、
//     默认动作（defaultAction）与放行名单（allowedSyscalls）；
//   - resources：cgroup v2 资源围栏（内存上限、进程数上限、CPU 配额），
//     各字段为 0 表示不限制；
//   - network：网络档位（none / bridge）与 bridge 参数（网段、网关、DNS、端口映射）。
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
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

	// actionTrace 不在上面的可选集里（policy 暂不支持 SCMP_ACT_TRACE），
	// 但规范把它列为"支持 errno"的动作之一，判据里必须认它。
	actionTrace = "SCMP_ACT_TRACE"
)

// 三条事实：名字精确匹配 / 未知名静默忽略 / fork-vfork-open 是后补的。
//
// 所有"神秘失败"故事（init 崩溃、busybox fork 被盖章）都从这份名单来。
//
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

// NetworkAllowedSyscalls 是 network.mode=bridge 时自动并入白名单的网络调用。
//
// 为什么单独成组、而不是塞进 DefaultAllowedSyscalls：
//   - 默认（none）档位必须继续拒绝网络与套接字相关调用；
//   - 只有真正配了网卡，才需要放行这些调用。
//
// 注意这里刻意不含 socket：socket 需要按“地址族”做参数过滤（见 launcher/spec.go），
// 否则容器可以创建 AF_UNIX 套接字去连宿主的抽象命名空间（如 dbus），
// 而 abstract socket 不受 mount namespace 限制。
//
// 另外，网络调用放行后容器仍没有 CAP_NET_RAW：普通 TCP/UDP 可用，ping 不行。
var NetworkAllowedSyscalls = []string{
	"accept", "accept4", "bind", "connect",
	"getpeername", "getsockname", "getsockopt", "listen",
	"recvfrom", "recvmmsg", "recvmsg",
	"sendmmsg", "sendmsg", "sendto", "setsockopt", "shutdown",
	"socketpair",
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
// 分三大块：seccomp（哪些系统调用能用）+ resources（能用多少资源）
// + network（有没有网、怎么连）。
type Policy struct {
	// Seccomp 是 seccomp 安检机的配置（见下）。
	Seccomp Seccomp `json:"seccomp"`
	// Resources 是 cgroup v2 资源围栏（内存/进程数/CPU）；字段为 0 = 不限制。
	Resources Resources `json:"resources"`
	// Network 是网络档位与参数；零值 = none（只隔离、不联网），保持旧 policy 行为不变。
	Network Network `json:"network"`
}

// Seccomp 描述"安检机"的行为。四个字段分别回答四个问题：
// 开不开？被拦时回什么编号？没写进名单的怎么处理？哪些放行？
//
// 两个 38、哨兵 1145、"1145 vs EAGAIN"的分层判据——全挂在这四个字段上。
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

// Resources 描述资源围栏（会由 launcher 翻译成 OCI 字段，再被 runc 写进内核文件）。
// 四个字段 ↔ 四个内核文件一一对应（含 cpu.max 的左/右值）。
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

// --- 网络档位：none（默认，无网）/ bridge（veth + 宿主网桥 + NAT，需要 root）。
//
// 白话：none 不是“没做网络”，而是“只给容器一间上锁的网络房间”——
// 有独立的 network namespace，但里面没有网卡、没有地址、没有路由。
// bridge 才是在这间房里接入一张网卡，并通过宿主网桥出去。
const (
	// NetworkModeNone 是默认档位：只建 network namespace，不配置任何接口。
	NetworkModeNone = "none"
	// NetworkModeBridge 给容器接 veth + 宿主网桥 + NAT。
	// 需要在宿主侧创建/配置网络设备，因此要求 root（rootless 不支持）。
	NetworkModeBridge = "bridge"
	// NetworkModeProxy 也是 veth + 网桥，但只放行到宿主代理端口的流量。
	// 代理是七层的（HTTP CONNECT），所以它可以按**域名**而不是 IP 做白名单。
	// 其余转发一律 drop——容器只能“通过代理”出去，不能直连任何地址。
	NetworkModeProxy = "proxy"
)

// 网络参数的默认值。
//
// 网段选 10.88.0.0/16：避开 Docker 默认的 172.17/16、本机 WSL 的 172.24/20
// 以及 docker0 的 172.18/16。改网段前先确认宿主没有同网段路由，否则会冲突。
const (
	DefaultBridgeName = "anolix0"
	DefaultSubnet     = "10.88.0.0/16"
	DefaultMTU        = 1500

	minMTU = 576
	maxMTU = 65535
)

// Network 描述容器的网络档位与 bridge 参数。
//
// 字段全为零值时 = {mode: none}：容器有独立网络命名空间，但无网可用。
type Network struct {
	// Mode："none"（缺省）或 "bridge"。
	Mode string `json:"mode"`
	// Bridge：宿主侧网桥名；留空 = anolix0。
	Bridge string `json:"bridge"`
	// Subnet：容器网段（IPv4 CIDR）；留空 = 10.88.0.0/16。
	Subnet string `json:"subnet"`
	// Gateway：容器默认路由的下一跳，也是网桥上的地址；留空 = 网段第一个可用地址。
	Gateway string `json:"gateway"`
	// DNS：写入容器 /etc/resolv.conf 的服务器；留空 = 自动探测宿主 DNS。
	DNS []string `json:"dns"`
	// Publish：端口映射，格式 "宿主端口:容器端口[/tcp|/udp]"，如 "8080:80"。
	Publish []string `json:"publish"`
	// MTU：网桥与 veth 的 MTU；0 = 1500。
	MTU int `json:"mtu"`
	// ProxyAllow：proxy 档的域名白名单，如 ["api.example.com", "*.openai.com"]。
	// 支持两种写法：精确域名，或前缀 "*." 的子域通配。留空 = 拒绝一切（但 Validate 会报错，
	// 因为一个不放行任何域名的代理没有意义，更像配置漏写）。
	ProxyAllow []string `json:"proxyAllow"`
	// ProxyPort：proxy 档下代理在网桥地址上的监听端口。
	// **0 = 由内核分配**（推荐）：代理 port 不是给人看的，
	// 固定端口会让“同一座网桥上只能跑一个 proxy 档容器”。
	ProxyPort int `json:"proxyPort"`
}

// PublishSpec 是解析后的端口映射规则。
type PublishSpec struct {
	HostPort      int    // 宿主侧监听的端口
	ContainerPort int    // 容器内被转发的端口
	Protocol      string // "tcp" 或 "udp"
}

// ParsePublish 解析一条端口映射："8080:80" 或 "8080:80/udp"。
//
// 白话：冒号左边是“宿主上开的门”，右边是“容器里要敲的门”；
// 不写协议默认 TCP（绝大多数场景），写 /udp 才是 UDP。
func ParsePublish(s string) (PublishSpec, error) {
	var out PublishSpec
	text := strings.TrimSpace(s)
	if text == "" {
		return out, fmt.Errorf("端口映射不能为空")
	}

	proto := "tcp"
	if i := strings.LastIndexByte(text, '/'); i >= 0 {
		proto = strings.ToLower(strings.TrimSpace(text[i+1:]))
		text = text[:i]
	}
	if proto != "tcp" && proto != "udp" {
		return out, fmt.Errorf("端口映射 %q 的协议 %q 非法，可选 tcp / udp", s, proto)
	}

	parts := strings.Split(text, ":")
	if len(parts) != 2 {
		return out, fmt.Errorf("端口映射 %q 格式应为 宿主端口:容器端口[/tcp|/udp]", s)
	}
	hostPort, err := parsePort(parts[0])
	if err != nil {
		return out, fmt.Errorf("端口映射 %q 的宿主端口非法: %w", s, err)
	}
	containerPort, err := parsePort(parts[1])
	if err != nil {
		return out, fmt.Errorf("端口映射 %q 的容器端口非法: %w", s, err)
	}
	return PublishSpec{HostPort: hostPort, ContainerPort: containerPort, Protocol: proto}, nil
}

// parsePort 解析并校验端口号（1-65535）。
func parsePort(s string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("不是数字: %q", s)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("超出范围 (1-65535): %d", port)
	}
	return port, nil
}

// EffectiveMode 返回生效的网络档位：留空 = none；归一化大小写与空白。
func (n Network) EffectiveMode() string {
	mode := strings.ToLower(strings.TrimSpace(n.Mode))
	if mode == "" {
		return NetworkModeNone
	}
	return mode
}

// EffectiveProxyPort 返回配置里指定的代理端口；0 表示“交给内核分配”。
//
// 不提供默认固定值是有意的：代理端口只是一个内部握手地址，
// 写死会让并行启动的第二个容器 bind 失败。
func (n Network) EffectiveProxyPort() int {
	return n.ProxyPort
}

// EffectiveBridge 返回生效的网桥名：留空 = anolix0。
func (n Network) EffectiveBridge() string {
	if n.Bridge == "" {
		return DefaultBridgeName
	}
	return n.Bridge
}

// EffectiveSubnet 返回生效的容器网段：留空 = 10.88.0.0/16。
func (n Network) EffectiveSubnet() string {
	if n.Subnet == "" {
		return DefaultSubnet
	}
	return n.Subnet
}

// EffectiveGateway 返回生效的网关：留空 = 网段第一个可用地址。
//
// 例：10.88.0.0/16 → 10.88.0.1。
// 这里只做“从 CIDR 推一个默认值”，合法性由 Validate 统一检查。
func (n Network) EffectiveGateway() string {
	if n.Gateway != "" {
		return n.Gateway
	}
	_, ipnet, err := net.ParseCIDR(n.EffectiveSubnet())
	if err != nil {
		return ""
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return ""
	}
	gw := make(net.IP, 4)
	copy(gw, ip)
	// 网络地址 +1：从最后一字节往上加，遇 0 表示进位。
	for i := 3; i >= 0; i-- {
		gw[i]++
		if gw[i] != 0 {
			break
		}
	}
	return gw.String()
}

// EffectiveMTU 返回生效的 MTU：0 = 1500。
func (n Network) EffectiveMTU() int {
	if n.MTU == 0 {
		return DefaultMTU
	}
	return n.MTU
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
// 严格解析（DisallowUnknownFields）：JSON 里出现不认识的字段会当场报错。
// 字段拼错被静默忽略，会在运行期变成难查的怪现象。
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
// 白话：这里只做"启动前能查出来的错"——动作名、errno 范围、
// errno 与动作的搭配（见 ActionSupportsErrno）、名单条目形态，
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
	// errnoRet 只在动作"会返回值"时才有意义（见 ActionSupportsErrno）。
	// 这里只拦"用户显式配了"的情况：ErrnoRet==0 表示他压根没提过，
	// 翻译层不写这个字段就行（见 launcher.buildSeccomp），不必报错——
	// 那是我们自己补的默认值，不该让用户替它背锅。
	if s.Enabled && s.ErrnoRet != 0 {
		if action := s.EffectiveDefaultAction(); !ActionSupportsErrno(action) {
			return fmt.Errorf("seccomp errnoRet=%d 与动作 %q 不兼容：该动作不给返回值，没有地方盖章；"+
				"请改用 %s，或删掉 errnoRet", s.ErrnoRet, action, ActionErrno)
		}
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
	if err := p.Resources.Validate(); err != nil {
		return err
	}
	return p.Network.Validate()
}

// Validate 校验网络档位与参数是否合法。
//
// 白话：网络参数比资源围栏更容易“写错但看着没事”——比如网关不在子网里，
// 启动后容器就是不通，而报错发生在很远的地方。所以这里把能提前查的全查了。
func (n Network) Validate() error {
	mode := n.EffectiveMode()
	switch mode {
	case NetworkModeNone, NetworkModeBridge, NetworkModeProxy:
	default:
		return fmt.Errorf("不支持的 network.mode %q，可选: %s, %s, %s", n.Mode, NetworkModeNone, NetworkModeBridge, NetworkModeProxy)
	}

	// 网桥名就是宿主上的接口名：内核限制 15 字符（IFNAMSIZ 16 含结尾 0），
	// 且不能含路径分隔符或空白（ip 命令会把它当参数解析）。
	bridge := n.EffectiveBridge()
	if bridge == "." || bridge == ".." || strings.ContainsAny(bridge, "/ \t\n") {
		return fmt.Errorf("network.bridge %q 不是合法的接口名", bridge)
	}
	if len(bridge) > 15 {
		return fmt.Errorf("network.bridge %q 超过 15 字符（内核接口名上限）", bridge)
	}

	ipnet, err := parseSubnet(n.EffectiveSubnet())
	if err != nil {
		return err
	}
	// 至少要有“网络地址 + 网关 + 一个容器地址 + 广播地址”四格，
	// 所以 /31、/32 这类点对点/单机子网没有意义；
	// 上界 /16（最多 65536 个地址）是为了让 IPAM 的线性探测保持在可接受范围，
	// /8 这类大网段会让「地址池满」的探测变成百万级文件操作。
	if ones, bits := ipnet.Mask.Size(); bits-ones < 2 || bits-ones > 16 {
		return fmt.Errorf("network.subnet %q 不在支持范围（需 /16 .. /30）", n.EffectiveSubnet())
	}

	gw := n.EffectiveGateway()
	gwIP := net.ParseIP(gw)
	if gwIP == nil || gwIP.To4() == nil {
		return fmt.Errorf("network.gateway %q 不是合法的 IPv4 地址", gw)
	}
	if !ipnet.Contains(gwIP) {
		return fmt.Errorf("network.gateway %s 不在子网 %s 内", gw, n.EffectiveSubnet())
	}
	if isNetworkOrBroadcast(ipnet, gwIP.To4()) {
		return fmt.Errorf("network.gateway %s 不能是网络地址或广播地址", gw)
	}

	for _, dns := range n.DNS {
		if ip := net.ParseIP(strings.TrimSpace(dns)); ip == nil {
			return fmt.Errorf("network.dns 条目 %q 不是合法的 IP 地址", dns)
		}
	}

	// 端口映射：除了逐条语法，还要查“宿主端口重复”——
	// 两条规则抢同一个宿主端口时，后一条不会生效，静默失效比报错难查得多。
	seen := make(map[string]string, len(n.Publish))
	for _, raw := range n.Publish {
		pub, err := ParsePublish(raw)
		if err != nil {
			return fmt.Errorf("network.publish 非法: %w", err)
		}
		key := fmt.Sprintf("%s/%d", pub.Protocol, pub.HostPort)
		if prev, ok := seen[key]; ok {
			return fmt.Errorf("network.publish 重复占用宿主端口: %q 与 %q", prev, raw)
		}
		seen[key] = raw
	}

	if n.MTU != 0 && (n.MTU < minMTU || n.MTU > maxMTU) {
		return fmt.Errorf("network.mtu %d 超出合法范围 (%d-%d)", n.MTU, minMTU, maxMTU)
	}

	// proxy 档：白名单不能空（空 = 一个什么也不放行的代理，几乎一定是漏写）。
	if mode == NetworkModeProxy {
		if len(n.ProxyAllow) == 0 {
			return fmt.Errorf("network.proxyAllow 不能为空（proxy 档必须至少放行一个域名）")
		}
		for _, raw := range n.ProxyAllow {
			host := NormalizeAllowHost(raw)
			if host == "" {
				return fmt.Errorf("network.proxyAllow 条目 %q 为空", raw)
			}
			if !validHostPattern(host) {
				return fmt.Errorf("network.proxyAllow 条目 %q 不是合法的域名", raw)
			}
		}
	}
	if n.ProxyPort != 0 && (n.ProxyPort < 1 || n.ProxyPort > 65535) {
		return fmt.Errorf("network.proxyPort %d 超出范围 (1-65535)", n.ProxyPort)
	}
	return nil
}

// NormalizeAllowHost 把一条白名单条目规范成小写、无空白、无尾点的形式。
//
// 归一化只在这一处做，代理匹配和配置校验用的是同一套写法，
// 避免“配置里写 `API.Example.com.`、实际请求是 `api.example.com`”这种形状差异。
func NormalizeAllowHost(raw string) string {
	host := strings.ToLower(strings.TrimSpace(raw))
	host = strings.TrimSuffix(host, ".")
	return host
}

// validHostPattern 判断一条白名单是不是“看着像域名”。
//
// 只挡最明显的错写（空白、斜杠、无点），不做完整 RFC 校验——
// 这里的目标是「配置写错时启动就报错」，不是当 DNS 解析器。
func validHostPattern(host string) bool {
	if !strings.Contains(host, ".") {
		return false
	}
	for _, r := range host {
		// 0x5c 就是反斜杠的码位；写成数字是为了不用在源码里再转义一层。
		if r <= ' ' || r == '/' || r == 0x5c {
			return false
		}
	}
	return true
}

// parseSubnet 解析 IPv4 CIDR，并拒绝 IPv6（容器内只配 IPv4 栈）。
func parseSubnet(cidr string) (*net.IPNet, error) {
	ip, ipnet, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("network.subnet %q 不是合法的 CIDR: %w", cidr, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("network.subnet %q 不是 IPv4 网段（当前只支持 IPv4）", cidr)
	}
	return ipnet, nil
}

// isNetworkOrBroadcast 判断 IPv4 地址是否落在子网的网络地址/广播地址上。
func isNetworkOrBroadcast(ipnet *net.IPNet, ip net.IP) bool {
	network := ipnet.IP.To4()
	if network == nil || ip == nil {
		return false
	}
	broadcast := make(net.IP, 4)
	for i := 0; i < 4; i++ {
		broadcast[i] = network[i] | ^ipnet.Mask[i]
	}
	return ip.Equal(network) || ip.Equal(broadcast)
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

// ActionSupportsErrno 判断某个动作是否接受 errnoRet。
//
// 规范原文（runtime-spec config-linux.md）：
//
//	Some actions like SCMP_ACT_ERRNO and SCMP_ACT_TRACE allow to specify
//	the errno code to return. When the action doesn't support an errno,
//	the runtime MUST print an error and fail.
//
// 白话：动作决定"怎么拦"，errnoRet 只是"盖章时写哪个编号"。
// 只有会留下返回值的动作（盖章 ERRNO、追踪 TRACE）才有地方写这个编号；
// KILL / KILL_PROCESS / TRAP 直接把进程处理掉，写进去就是自相矛盾的字段。
//
// 实测差异：在 KILL_PROCESS 下写 defaultErrnoRet，crun 会拒绝整份 config.json
// （"errno value specified for action ..."），runc 则静默忽略——两种都不对。
func ActionSupportsErrno(action string) bool {
	switch strings.ToUpper(strings.TrimSpace(action)) {
	case ActionErrno, actionTrace:
		return true
	default:
		return false
	}
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
