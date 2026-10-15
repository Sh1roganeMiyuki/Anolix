// spec.go 生成母体容器的 OCI runtime spec。
//
// 母体与普通 Anolix 沙箱的关键差异：
//
//	┌────────────────┬──────────────────────┬──────────────────────────────┐
//	│ 维度           │ 普通沙箱 (launcher/)  │ 母体容器 (本文件)             │
//	├────────────────┼──────────────────────┼──────────────────────────────┤
//	│ PID namespace  │ 有（容器 init = 1 号）│ 无（母体活在宿主 PID ns）     │
//	│ Capabilities   │ 清空                  │ CAP_SYS_ADMIN（为 worker 建 ns）│
//	│ Seccomp        │ 严格白名单            │ 关闭（母体需要全量 syscall）   │
//	│ NoNewPrivileges│ true                  │ false（母体是受信进程）        │
//	│ 网络           │ 隔离（无网）          │ 隔离（通过 socket 通信即可）   │
//	└────────────────┴──────────────────────┴──────────────────────────────┘
//
// 为什么母体不带 PID namespace：
//   - 核心设计点：母体 clone 出的 worker，其返回值"天然就是宿主 PID"
//   - 如果母体在 PID ns 中，clone 返回的是 ns 内 PID，需要额外扫描 /proc 反查宿主 PID
//
// 安全代价：
//   - 母体持有 CAP_SYS_ADMIN + 无 seccomp → 它本身是"受信进程"
//   - 这是 zygote 架构的固有取舍：母体的信任等级必须高于普通沙箱
//   - worker 仍然拥有完整的 6 间房隔离（由 clone 的 CLONE_NEW* flags 保证）
package zygote

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// MotherConfig 是生成母体 spec 的输入参数。
type MotherConfig struct {
	// Rootfs 是母体容器的根文件系统路径（宿主侧绝对路径）。
	Rootfs string
	// SocketDir 是宿主侧的 socket 目录（会 bind-mount 进容器的 /run/spawn）。
	// 母体在此目录创建 spawn.sock，宿主侧 client 通过同一路径连接。
	SocketDir string
	// ZygoteBinary 是容器内 zygote 二进制的路径（如 /zygote）。
	ZygoteBinary string
	// WarmMB 是预热内存量（传给 zygote --warm）。
	WarmMB int
	// Hostname 是母体容器的 UTS 主机名。
	Hostname string
}

// BuildMotherSpec 生成母体容器的 OCI runtime spec。
//
// 返回的 spec 可直接序列化为 bundle/config.json，交给 runc 启动。
func BuildMotherSpec(cfg MotherConfig) *specs.Spec {
	if cfg.Hostname == "" {
		cfg.Hostname = "anolix-mother"
	}
	if cfg.ZygoteBinary == "" {
		cfg.ZygoteBinary = "/zygote"
	}

	// 构建 zygote 启动命令
	args := []string{cfg.ZygoteBinary, "--socket", "/run/spawn/spawn.sock"}
	if cfg.WarmMB > 0 {
		args = append(args, "--warm", fmt.Sprintf("%d", cfg.WarmMB))
	}

	return &specs.Spec{
		Version:  specs.Version,
		Hostname: cfg.Hostname,
		Root: &specs.Root{
			Path:     cfg.Rootfs,
			Readonly: false, // 母体需要写 socket 文件
		},
		Process: &specs.Process{
			Terminal: false,
			Args:     args,
			Env: []string{
				"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
				"TERM=xterm",
				"HOSTNAME=" + cfg.Hostname,
			},
			Cwd: "/",
			// 母体需要 CAP_SYS_ADMIN 来执行 unshare（为 worker 创建 namespace）。
			// 还需要 CAP_SYS_CHROOT（如果 worker 需要 pivot_root）。
			Capabilities: &specs.LinuxCapabilities{
				Bounding:    []string{"CAP_SYS_ADMIN", "CAP_SYS_CHROOT", "CAP_NET_ADMIN"},
				Effective:   []string{"CAP_SYS_ADMIN", "CAP_SYS_CHROOT", "CAP_NET_ADMIN"},
				Inheritable: []string{"CAP_SYS_ADMIN", "CAP_SYS_CHROOT", "CAP_NET_ADMIN"},
				Permitted:   []string{"CAP_SYS_ADMIN", "CAP_SYS_CHROOT", "CAP_NET_ADMIN"},
			},
			// 母体是受信进程：不设 NoNewPrivileges（否则无法使用 capabilities）
			NoNewPrivileges: false,
			Rlimits: []specs.POSIXRlimit{
				{Type: "RLIMIT_NOFILE", Hard: 4096, Soft: 4096},
				{Type: "RLIMIT_NPROC", Hard: 1024, Soft: 1024},
			},
		},
		Mounts: []specs.Mount{
			// 基础挂载
			{Destination: "/proc", Type: "proc", Source: "proc",
				Options: []string{"nosuid", "noexec", "nodev"}},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs",
				Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{Destination: "/sys", Type: "sysfs", Source: "sysfs",
				Options: []string{"nosuid", "noexec", "nodev", "ro"}},
			// 关键：bind-mount socket 目录
			// 宿主侧 client 连接 SocketDir/spawn.sock
			// 母体在容器内看到 /run/spawn/spawn.sock（同一个文件）
			{Destination: "/run/spawn", Type: "bind", Source: cfg.SocketDir,
				Options: []string{"bind", "rw"}},
			// worker 日志目录（可选，bind-mount 到宿主方便查看）
			{Destination: "/worker-logs", Type: "bind", Source: filepath.Join(cfg.SocketDir, "logs"),
				Options: []string{"bind", "rw"}},
		},
		Linux: &specs.Linux{
			// 核心设计：5 个 namespace，刻意不带 PID namespace
			Namespaces: []specs.LinuxNamespace{
				{Type: specs.MountNamespace},   // 挂载隔离
				{Type: specs.UTSNamespace},     // 主机名隔离
				{Type: specs.IPCNamespace},     // IPC 隔离
				{Type: specs.NetworkNamespace}, // 网络隔离（母体不需要网络）
				{Type: specs.CgroupNamespace},  // cgroup 视图隔离
				// 注意：没有 PIDNamespace！
				// 母体进程直接活在宿主 PID ns → fork 返回值 = 宿主 PID
			},
			// 母体不装 seccomp：它需要 clone/unshare/socket/mount 等全量 syscall。
			// 安全边界由"母体是受信进程 + 运行在容器内（有 MNT/NET/IPC 隔离）"保证。
			Seccomp: nil,
			// 设备白名单（最小集）
			Resources: &specs.LinuxResources{
				Devices: []specs.LinuxDeviceCgroup{
					{Allow: false, Access: "rwm"}, // 默认拒绝全部
					{Allow: true, Type: "c", Major: int64Ptr(1), Minor: int64Ptr(3), Access: "rwm"},    // /dev/null
					{Allow: true, Type: "c", Major: int64Ptr(1), Minor: int64Ptr(5), Access: "rwm"},    // /dev/zero
					{Allow: true, Type: "c", Major: int64Ptr(5), Minor: int64Ptr(0), Access: "rwm"},    // /dev/tty
					{Allow: true, Type: "c", Major: int64Ptr(5), Minor: int64Ptr(2), Access: "rwm"},    // /dev/ptmx
					{Allow: true, Type: "c", Major: int64Ptr(136), Minor: int64Ptr(-1), Access: "rwm"}, // /dev/pts/*
				},
			},
		},
	}
}

// WriteMotherBundle 将母体 spec 写入 OCI bundle 目录。
//
// bundle 结构：
//
//	<bundleDir>/
//	  config.json    ← 本函数生成
//	  rootfs/        ← 由调用方准备（符号链接或实际目录）
func WriteMotherBundle(bundleDir string, spec *specs.Spec) error {
	if err := os.MkdirAll(bundleDir, 0o755); err != nil {
		return fmt.Errorf("创建 bundle 目录失败: %w", err)
	}
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 spec 失败: %w", err)
	}
	configPath := filepath.Join(bundleDir, "config.json")
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		return fmt.Errorf("写入 config.json 失败: %w", err)
	}
	return nil
}

func int64Ptr(v int64) *int64 { return &v }
