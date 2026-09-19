package launcher

import (
	"os"

	"anolix/config"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// containerHostname 是容器内的主机名（隔离的 UTS namespace）。
const containerHostname = "anolix"

// DefaultEnv 是容器内默认环境变量。
var DefaultEnv = []string{
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"TERM=xterm",
	"HOSTNAME=" + containerHostname,
}

// buildSpec 依据 policy 生成 OCI runtime spec。
// command 为容器内执行的命令，env 为环境变量，
// rootfsPath 为写入 spec.Root.Path 的 rootfs 路径（绝对路径或相对 bundle）；
// rootless 为 true 时追加 user namespace 与 uid/gid 映射（容器 root 映射到当前用户）。
func buildSpec(policy *config.Policy, command, env []string, rootfsPath string, rootless bool) *specs.Spec {
	linux := &specs.Linux{
		Namespaces: []specs.LinuxNamespace{
			{Type: specs.PIDNamespace},
			{Type: specs.NetworkNamespace},
			{Type: specs.IPCNamespace},
			{Type: specs.UTSNamespace},
			{Type: specs.MountNamespace},
			{Type: specs.CgroupNamespace},
		},
		MaskedPaths:   defaultMaskedPaths(),
		ReadonlyPaths: defaultReadonlyPaths(),
		Resources:     defaultResources(),
		Seccomp:       buildSeccomp(policy.Seccomp),
	}
	if rootless {
		linux.Namespaces = append([]specs.LinuxNamespace{{Type: specs.UserNamespace}}, linux.Namespaces...)
		linux.UIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Geteuid()), Size: 1},
		}
		linux.GIDMappings = []specs.LinuxIDMapping{
			{ContainerID: 0, HostID: uint32(os.Getegid()), Size: 1},
		}
	}

	return &specs.Spec{
		Version:  specs.Version,
		Hostname: containerHostname,
		Root: &specs.Root{
			Path:     rootfsPath,
			Readonly: false,
		},
		Process: &specs.Process{
			Terminal: false,
			Args:     command,
			Env:      env,
			Cwd:      "/",
			// 禁止容器进程再提权（阻断 setuid 类提权路径）。
			NoNewPrivileges: true,
			// 沙箱默认能力集为空：不授予任何 Linux capability。
			Capabilities: &specs.LinuxCapabilities{},
			Rlimits: []specs.POSIXRlimit{
				{Type: "RLIMIT_NOFILE", Hard: 1024, Soft: 1024},
			},
		},
		Mounts: defaultMounts(rootless),
		Linux:  linux,
	}
}

// buildSeccomp 依据 policy 生成 OCI seccomp 配置；未启用时返回 nil。
// policy 中的 errnoRet 映射到 OCI spec 的 defaultErrnoRet 字段。
func buildSeccomp(s config.Seccomp) *specs.LinuxSeccomp {
	if !s.Enabled {
		return nil
	}
	errnoRet := s.EffectiveErrnoRet()
	return &specs.LinuxSeccomp{
		DefaultAction:   specs.LinuxSeccompAction(s.EffectiveDefaultAction()),
		DefaultErrnoRet: &errnoRet,
		Syscalls: []specs.LinuxSyscall{
			{
				Names:  s.EffectiveAllowedSyscalls(),
				Action: specs.ActAllow,
			},
		},
	}
}

// defaultMounts 返回容器内最小挂载集：/proc、/dev 及其子目录、只读 /sys。
// rootless 时不设置 devpts 的 gid=5（tty 组不在 user namespace 的 gid 映射中）。
func defaultMounts(rootless bool) []specs.Mount {
	devptsOptions := []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}
	if !rootless {
		devptsOptions = append(devptsOptions, "gid=5")
	}
	return []specs.Mount{
		{Destination: "/proc", Type: "proc", Source: "proc", Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
		{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: devptsOptions},
		{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "noexec", "nodev", "mode=1777", "size=65536k"}},
		{Destination: "/dev/mqueue", Type: "mqueue", Source: "mqueue", Options: []string{"nosuid", "noexec", "nodev"}},
		{Destination: "/sys", Type: "sysfs", Source: "sysfs", Options: []string{"nosuid", "noexec", "nodev", "ro"}},
	}
}

// defaultResources 返回默认 cgroup 资源限制：
// 拒绝所有设备访问，仅放行标准设备节点（null/zero/full/random/urandom/tty/ptmx/pts）。
func defaultResources() *specs.LinuxResources {
	return &specs.LinuxResources{
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

// defaultMaskedPaths 返回默认掩蔽路径（以 /dev/null 覆盖，容器内不可见）。
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

// defaultReadonlyPaths 返回默认只读路径。
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

func int64Ptr(v int64) *int64 { return &v }
