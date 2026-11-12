// 本文件：把 policy（你写的规矩）翻译成 OCI spec（runc 看得懂的说明书）。
//
// 阅读提示：这个文件只做「翻译」——输入是一份策略 + 要跑的命令，
// 输出是一个 Go 结构体（specs.Spec），最后会被序列化成 bundle 里的 config.json。
// 先记住一句话：config.json = 交给 runc 的说明书，内容分四块：
//
//	root（在哪跑） / process（跑什么） / mounts（挂什么） / linux（怎么隔离与限制）。
//
// 阅读顺序建议：main.go → config.go → 本文件 → launcher.go。
package launcher

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"anolix/config"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// containerHostname 是容器内的主机名。
//
// 白话：容器有自己独立的「主机名空间」（UTS namespace），里面可以叫 anolix，
// 不会影响宿主机自己的名字；探针会检查这一项（hostname=anolix）。
const containerHostname = "anolix"

// DefaultEnv 是容器内默认环境变量（没特殊配置时就给程序准备这几项）。
var DefaultEnv = []string{
	// PATH：告诉 shell「敲一个命令时去哪些目录找这个程序」。
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	// TERM：终端类型，很多程序靠它决定输出格式（颜色/控制字符）。
	"TERM=xterm",
	// HOSTNAME：与说明书里的 Hostname 一致，方便程序读到自己的名字。
	"HOSTNAME=" + containerHostname,
}

// buildSpec 把「策略 + 要跑的命令 + 根目录路径」翻译成一份 OCI 说明书。
//
// 这是三段链（声明 → 翻译 → 执法）的中间段；错一个字段，
// 内核里的行为就换一个样子（01/02/03 三篇文档验的都是这里的输出）。
//
// 参数白话版：
//   - policy：你写的规矩（seccomp 开关/名单、内存/进程/CPU 限额）；
//   - command：容器里要执行的命令，例如 []string{"/probe"}；
//   - env：容器内的环境变量；
//   - rootfsPath：容器的「根目录」在哪（runc 会把它当成容器里的 /）；
//   - rootless：true = 非 root 运行，需要额外加「用户命名空间」（见下文 ③）。
//
// 函数体共三步：① 铺基础资源规则 → ② 填 linux 块 → ③ 组装最终结构。
func buildSpec(policy *config.Policy, command, env []string, rootfsPath string, rootless bool) *specs.Spec {
	// ① 先铺一层「基础资源规则」：默认拒绝一切设备，再放行 9 个标准设备（见 defaultResources）。
	resources := defaultResources()
	// 再把 policy 里的三样限额（内存/进程数/CPU）合并上去；没填的字段保持 0 = 不设限。
	applyResourceLimits(resources, policy.Resources)

	// ② 填写「linux 块」：所有内核级隔离与限制都写在这里。
	//   6 个 namespace = 隔离模型本体：PID=进程号 / NET=网络 / IPC=进程间通信 /
	//   UTS=主机名 / MNT=挂载视图 / CGROUP=cgroup 视图；用户命名空间见下面 rootless 分支。
	linux := &specs.Linux{
		// 隔离的第一层：给容器开 6 间独立的「房间」（namespace）。
		// 每间房 = 对某一类系统资源有自己的视图，逐个解释见行尾注释。
		Namespaces: []specs.LinuxNamespace{
			{Type: specs.PIDNamespace},     // 进程号独立：容器里第一个进程就是 1 号（探针会验证 pid=1）
			{Type: specs.NetworkNamespace}, // 网络独立：看不见宿主网卡，默认无网可用
			{Type: specs.IPCNamespace},     // 进程间通信（共享内存/消息队列）独立
			{Type: specs.UTSNamespace},     // 主机名独立：容器里 hostname=anolix
			{Type: specs.MountNamespace},   // 挂载表独立：容器里挂的东西宿主看不见（03 篇"单向玻璃"）
			{Type: specs.CgroupNamespace},  // cgroup 视图独立：容器只看到自己那一格
			{Type: specs.TimeNamespace},
		},
		// 掩蔽：用 /dev/null 盖住一批敏感文件，容器里读它们只会得到空内容。
		MaskedPaths: defaultMaskedPaths(),
		// 只读：这些路径挂成只读，容器里写不进去。
		ReadonlyPaths: defaultReadonlyPaths(),
		// 资源限制：第 ① 步算出来的那份。
		Resources: resources,
		// seccomp 安检机：由 policy 翻译而来（下一个函数）。
		Seccomp: buildSeccomp(policy.Seccomp),
	}
	// ③ 非 root 运行（rootless）：追加「用户命名空间」与 ID 映射。
	//   “替身”机制：容器里的 root 其实映射到宿主当前用户。
	// 白话：让容器以为自己以 root 身份在跑，实际映射到宿主的当前用户——
	// 于是容器内即便"是 root"，在宿主上也只相当于普通用户，干不了危险事。
	if rootless {
		// user 命名空间要放在第一个（其余房间随后进入）。
		linux.Namespaces = append([]specs.LinuxNamespace{{Type: specs.UserNamespace}}, linux.Namespaces...)
		// 映射：容器里的 0 号用户（root）= 宿主当前用户；Size=1 表示只映射这一个。
		linux.UIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Geteuid()), Size: 1},
		}
		linux.GIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Getegid()), Size: 1},
		}
	}

	// ④ 组装说明书本体。口诀：root 是"在哪跑"，process 是"跑什么"，
	// mounts 是"挂什么"，linux 是"怎么隔离、怎么限制"。
	return &specs.Spec{
		Version:  specs.Version,     // 说明书格式版本（OCI 规定）
		Hostname: containerHostname, // 容器主机名（配合 UTS 房间）
		Root: &specs.Root{
			Path:     rootfsPath, // 容器的「根目录」：货物（rootfs）所在位置
			Readonly: false,      // 根目录可写（探针会写入测试文件来验证）
		},
		Process: &specs.Process{
			Terminal: false,   // 不分配交互终端（最简模式）
			Args:     command, // 容器里要执行什么程序
			Env:      env,     // 环境变量
			Cwd:      "/",     // 工作目录
			// 安全基线的两把锁：NoNewPrivileges（不许再提权）+ 空能力集。
			// 从这一刻起，这个进程及其后代都不允许再“提权”（阻断 setuid 类路径）。
			NoNewPrivileges: true,
			// 能力集清空：Linux capability 是"特权清单"，这里一个都不授予。
			Capabilities: &specs.LinuxCapabilities{},
			// 资源上限：最多能同时打开 1024 个文件描述符（fd）。
			Rlimits: []specs.POSIXRlimit{
				{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024},
			},
		},
		Mounts: defaultMounts(rootless), // 容器里要挂哪些目录（见 defaultMounts）
		Linux:  linux,                   // 上面的隔离+限制汇总
	}
}

// 安检机的三个参数来源：开关、盖章 errno、放行名单——全在这里落进说明书。
// 01 篇的“两个 38 / 哨兵 1145”、名单静默忽略，全部挂在这几个字段上。
// buildSeccomp 把 policy 里的 seccomp 配置翻译成说明书里的 seccomp 一节。
//
// 白话：返回 nil = 说明书里不写这一节 = runc 不会给容器装"安检机"；
// 返回对象 = runc 会在容器启动前（execve 之前最后一刻）装好过滤器，
// 名单里的调用放行，其余按 defaultAction 处理。
func buildSeccomp(s config.Seccomp) *specs.LinuxSeccomp {
	if !s.Enabled {
		// 开关关掉了：不装安检机。
		return nil
	}
	action := s.EffectiveDefaultAction()
	sc := &specs.LinuxSeccomp{
		// 没被名单放行的调用，按什么方式处理（默认 ERRNO = 盖章拒绝）。
		DefaultAction: specs.LinuxSeccompAction(action),
		// 一条放行规则：名单里的名字 + 动作 ALLOW（放行）。
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  s.EffectiveAllowedSyscalls(),
				Action: specs.ActAllow,
			},
		},
	}
	// 只在动作支持 errno 时才写这一字段（见 config.ActionSupportsErrno）。
	//
	// 不是“把默认值填上”那么简单：OCI 里这是 OPTIONAL 字段，
	// 它的“存在”本身就携带信息（写了 = 我指定；不写 = 用运行时默认）。
	// 在 KILL / KILL_PROCESS / TRAP 下写它，crun 会拒绝整份说明书，
	// runc 则静默忽略——两种都不是用户想要的。
	if config.ActionSupportsErrno(action) {
		errnoRet := s.EffectiveErrnoRet()
		sc.DefaultErrnoRet = &errnoRet
	}
	return sc
}

// 资源围栏的翻译点：policy 数字 → OCI 字段 →（runc 写入）内核文件。
// 02 篇全部实测证据链的源头；swap 缺口（未映射）也标在这。
// applyResourceLimits 把 policy 的资源限额合并进说明书。
//
// 口诀：policy 里填了才写；填 0 就当作"不设这个限额"。
// 这些字段最终由 runc 写进内核文件：memory.max / pids.max / cpu.max。
// 已知缺口：内存 swap 上限（memory.swap.max）尚未映射——有 swap 的机器上，
// 超额内存可能被"换出"而不是被杀（02 篇第四章有实测）。
func applyResourceLimits(res *specs.LinuxResources, r config.Resources) {
	if r.MemoryLimitBytes > 0 {
		// 物理内存硬上限：超过就触发内存回收，回收无路则 OOM kill。
		res.Memory = &specs.LinuxMemory{Limit: int64Ptr(r.MemoryLimitBytes)}
	}
	if r.PidsLimit > 0 {
		// 进程数上限：达到后 fork 会返回 EAGAIN（02 篇第三章）。
		res.Pids = &specs.LinuxPids{Limit: r.PidsLimit}
	}
	if r.CPUQuotaMicros > 0 {
		// CPU 配额：每 period 微秒内最多用 quota 微秒（如 20000/100000 = 0.2 核）。
		period := r.EffectiveCPUPeriodMicros()
		res.CPU = &specs.LinuxCPU{
			Quota:  int64Ptr(r.CPUQuotaMicros),
			Period: &period,
		}
	}
}

// --- 【可略读】挂载清单：知道"挂了哪六样、各自干嘛"即可；选项细节不用背。
// defaultMounts 返回容器里的"最小挂载集"。
//
// 白话：容器是一间空房间，得先把几样"基础设施"挂进去程序才能正常跑：
// /proc 看得到进程信息、/dev 有设备文件、/sys 是只读系统信息……
// 这些挂载由 runc 在启动时完成（03 篇 trace 里的 mount 序列就是它们）。
func defaultMounts(rootless bool) []specs.Mount {
	// devpts 是"伪终端"文件系统；gid=5 指 tty 组。
	// rootless 时不带它：容器里的组号映射中没有 5，带上会直接挂载失败。
	devptsOptions := []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}
	if !rootless {
		devptsOptions = append(devptsOptions, "gid=5")
	}
	return []specs.Mount{
		// /proc：进程与内核信息的窗口（runc 启动时会验证"它确实是 procfs"）。
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
		// /dev：用一块 64MB 的临时内存盘当设备目录。
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		// /dev/pts：伪终端设备（本容器不开终端，但标准配置保留）。
		{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: devptsOptions},
		// /dev/shm：共享内存目录（1777 = 所有人可读写，标准约定）。
		{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
		// /dev/mqueue：POSIX 消息队列。
		{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
		// /sys：系统信息，只读挂载（ro）。
		{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
	}
}

// defaultResources 返回“基础资源规则”：设备访问白名单。
//
// 先全拒再逐放；“有设备文件 ≠ 能用设备”。
//
// 白话：即便 /dev 里有设备文件，也不代表能打开它——"能不能用"由 cgroup 的
// 设备控制器单独把关。默认策略：先拒绝全部（第一条 Allow:false），再逐个放行 9 个标准设备。
func defaultResources() *specs.LinuxResources {
	return &specs.LinuxResources{
		// Access 里的 r/w/m = 可读/可写/可创建设备。
		Devices: []specs.LinuxDeviceCgroup{
			{Allow: false, Access: "rwm"},
			{Allow: true, Type: "c", Major: int64Ptr(1), Minor: int64Ptr(3), Access: "rwm"},    // /dev/null
			{Allow: true, Type: "c", Major: int64Ptr(1), Minor: int64Ptr(5), Access: "rwm"},    // /dev/zero
			{Allow: true, Type: "c", Major: int64Ptr(1), Minor: int64Ptr(7), Access: "rwm"},    // /dev/full
			{Allow: true, Type: "c", Major: int64Ptr(1), Minor: int64Ptr(8), Access: "rwm"},    // /dev/random
			{Allow: true, Type: "c", Major: int64Ptr(1), Minor: int64Ptr(9), Access: "rwm"},    // /dev/urandom
			{Allow: true, Type: "c", Major: int64Ptr(5), Minor: int64Ptr(0), Access: "rwm"},    // /dev/tty
			{Allow: true, Type: "c", Major: int64Ptr(5), Minor: int64Ptr(2), Access: "rwm"},    // /dev/ptmx
			{Allow: true, Type: "c", Major: int64Ptr(136), Minor: int64Ptr(-1), Access: "rwm"}, // /dev/pts/*
		},
	}
}

// minimalMounts 是 defaultMounts 的“最小子集”：只留 /proc 与 /dev。
//
// 用途：A/B 对比时把 runc 侧削到与 zygote 路径同一个功能范围——
// worker-init 也只挂这两样。少掉的 /dev/pts、/dev/shm、/dev/mqueue、/sys
// 以及全部掩蔽/只读重挂，都属于加固而非隔离必需；要比机制效率就先对齐它们。
func minimalMounts(rootless bool) []specs.Mount {
	var out []specs.Mount
	for _, m := range defaultMounts(rootless) {
		switch m.Destination {
		case "/proc", "/dev":
			out = append(out, m)
		}
	}
	return out
}

// --- 【可略读】掩蔽/只读清单：知道类别（内核内部信息、可调参数）即可，不必背具体路径。
// defaultMaskedPaths 返回"掩蔽路径"：这些文件在容器里被 /dev/null 盖住，读出来是空的。
// 例：/proc/kcore 是内核内存镜像，/proc/keys 是内核密钥环——都不该给容器看见。
func defaultMaskedPaths() []string {
	return []string{
		"/proc/acpi",
		"/proc/asound",
		"/proc/kcore",
		"/proc/keys",
		"/proc/latency_stats",
		"/proc/timer_list",
		"/proc/timer_stats",
		"/proc/sched_debug",
		"/proc/scsi",
		"/sys/firmware",
		"/sys/devices/virtual/powercap",
	}
}

// defaultReadonlyPaths 返回"只读路径"：挂成只读，容器里改不了。
// 例：/proc/sys 下面全是内核参数开关，改一个就可能影响宿主机行为。
func defaultReadonlyPaths() []string {
	return []string{
		"/proc/asound",
		"/proc/bus",
		"/proc/fs",
		"/proc/irq",
		"/proc/sys",
		"/proc/sysrq-trigger",
	}
}

// int64Ptr 小工具：把 int64 变成指针。
// 为什么需要它：OCI 里这些限额字段是"可空的"（指针）——因为 0 有实际含义（=不限制），
// 不能用 0 表示"没设置"，所以只能用指针区分「nil＝没写」和「0＝写了但值为 0」。
func int64Ptr(v int64) *int64 { return &v }

// --- 网络翻译：把「launcher 已经建好的网络」写进说明书。

// applyNetwork 把预创建 netns、网络 syscall 放行与 resolv.conf 挂载写进 spec。
//
// 调用时机：必须在 network.Setup 成功之后、序列化 config.json 之前。
// 三层分工：
//
//	network 包  在宿主侧把 netns/veth/路由/NAT 建好（内核对象）；
//	本函数      把“加入哪个 netns、放行哪些调用”写进说明书（策略落点）；
//	runc        只是照着说明书加入 netns、装 seccomp（执行者）。
func applyNetwork(spec *specs.Spec, policy *config.Policy, netnsPath, resolvConfPath string) error {
	if spec == nil || spec.Linux == nil {
		return errors.New("spec 缺少 linux 段")
	}
	if m := policy.Network.EffectiveMode(); m != config.NetworkModeBridge && m != config.NetworkModeProxy {
		return nil
	}
	if netnsPath == "" {
		return errors.New("network.mode 需要网卡但 netns 路径为空")
	}
	if !filepath.IsAbs(netnsPath) {
		return fmt.Errorf("netns 路径必须是绝对路径: %q", netnsPath)
	}

	// 关键：把 network namespace 的 Path 填上。
	// Path 非空 = “加入这个已存在的 netns”，而不是“新建一个”。
	found := false
	for i := range spec.Linux.Namespaces {
		if spec.Linux.Namespaces[i].Type == specs.NetworkNamespace {
			spec.Linux.Namespaces[i].Path = netnsPath
			found = true
		}
	}
	if !found {
		return errors.New("spec 缺少 network namespace，无法加入预创建的 netns")
	}

	// 网络档位下自动扩充 seccomp 白名单。
	if spec.Linux.Seccomp != nil {
		mergeNetworkSeccomp(spec.Linux.Seccomp)
	}

	// DNS：把 bundle 里生成的 resolv.conf 只读挂进容器。
	// rootfs 里没有 /etc 也没关系：runc 会按 bind 源的类型自动创建空文件与父目录。
	if resolvConfPath != "" {
		if !filepath.IsAbs(resolvConfPath) {
			return fmt.Errorf("resolv.conf 路径必须是绝对路径: %q", resolvConfPath)
		}
		spec.Mounts = append(spec.Mounts, specs.Mount{
			Destination: "/etc/resolv.conf",
			Type:        "bind",
			Source:      resolvConfPath,
			Options:     []string{"bind", "ro"},
		})
	}
	return nil
}

// socket 允许的地址族：只给“真正的网络”开口子。
//
//   - AF_INET / AF_INET6：TCP/UDP；
//   - AF_NETLINK：Go 的 net.Interfaces()/InterfaceAddrs() 靠它枚举网卡；
//     容器能力集为空，netlink 只能读、不能改。
//
// 刻意不放行 AF_UNIX：abstract socket 不受 mount namespace 限制，
// 放行后容器可能连到宿主上的 dbus 等抽象命名空间服务。
var socketAllowedFamilies = []uint64{
	uint64(syscall.AF_INET),
	uint64(syscall.AF_INET6),
	uint64(syscall.AF_NETLINK),
}

// networkSocketFiltered 判断网络档位下 socket 是否仍受地址族过滤。
//
// 三种“不受过滤”的情形：seccomp 关闭；用户名单显式包含 socket；
// 网络未开启（此时 socket 本来就被默认动作拒掉，也不存在过滤问题）。
// 探针据此决定是否断言 AF_UNIX 被拦，避免把用户的自定义名单误判成失败。
func networkSocketFiltered(s config.Seccomp) bool {
	if !s.Enabled {
		return false
	}
	// KILL/KILL_PROCESS/TRAP 下 socket(AF_UNIX) 会被直接处理掉，
	// 探针根本来不及打印结果；这种动作下不做“被拦截”断言。
	if !config.ActionSupportsErrno(s.EffectiveDefaultAction()) {
		return false
	}
	for _, name := range s.EffectiveAllowedSyscalls() {
		if name == "socket" {
			return false
		}
	}
	return true
}

// mergeNetworkSeccomp 把网络调用并入现有放行名单。
//
// 两个细节：
//  1. 用户名单里已经有的名字不重复添加（libseccomp 不在意重复，但规则越干净越好查）；
//  2. socket 不用“整条放行”，而是追加三条带参数过滤的规则——
//     同一 syscall 的多条规则是 OR 关系，domain 不匹配时落到 defaultAction。
func mergeNetworkSeccomp(sc *specs.LinuxSeccomp) {
	existing := make(map[string]bool)
	for _, rule := range sc.Syscalls {
		for _, name := range rule.Names {
			existing[name] = true
		}
	}

	var extra []string
	for _, name := range config.NetworkAllowedSyscalls {
		if !existing[name] {
			extra = append(extra, name)
			existing[name] = true
		}
	}
	if len(extra) > 0 {
		sc.Syscalls = append(sc.Syscalls, specs.LinuxSyscall{
			Names:  extra,
			Action: specs.ActAllow,
		})
	}

	// 用户显式放行了 socket = 选择“全地址族放行”，不再追加参数过滤。
	if existing["socket"] {
		return
	}
	for _, family := range socketAllowedFamilies {
		sc.Syscalls = append(sc.Syscalls, specs.LinuxSyscall{
			Names:  []string{"socket"},
			Action: specs.ActAllow,
			Args: []specs.LinuxSeccompArg{
				{Index: 0, Value: family, Op: specs.OpEqualTo},
			},
		})
	}
}
