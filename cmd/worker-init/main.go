// Command worker-init 是 zygote 的"薄 init"：装 rootfs + 装 seccomp，然后 execve payload。
//
// 为什么必须有它（而不是让 worker 自己干）：
//   - 母体 clone 出 worker 后**直接 execve 新程序**，Go 的 os/exec 不给"fork 与 exec 之间跑代码"的钩子；
//   - 所以给了 mount ns（CLONE_NEWNS）也**没地方 pivot_root** → 必须借道一个薄 init。
//   - init 干完 rootfs 与 seccomp 后 **execve 成 payload**（execve 不改身份卡，seccomp/fd 一路跟着）。
//
// 顺序（很重要）：
//
//	mount 私有化 → bind rootfs → pivot_root → 挂 /proc → 装 seccomp → execve payload
//
//	rootfs 相关的 syscall（mount/pivot_root）必须在**装 seccomp 之前**做完——
//	否则会被自己的过滤器拦（自缚）；装完过滤器后 init 只剩一条 execve。
//
// 用法（由母体 spawn；母体已给新 mount ns）：
//
//	sudo ./bin/spawn --socket /tmp/anolix-zygote.sock -- \
//	     ./bin/worker-init --rootfs /abs/path/rootfs -- /bin/busybox sh -c 'ls /'
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"anolix/config"
	"anolix/zygote"
)

func main() {
	// 计时第一站：到这里说明 clone + execve + Go runtime 启动已经走完。
	// 后续每站的 ns 值都是相对母体 clone 前那一刻的 CLOCK_MONOTONIC。
	zygote.Mark("init_start")

	rootfs, payload, extra := parseArgs(os.Args[1:])
	if rootfs == "" || payload == "" {
		fmt.Fprintln(os.Stderr, "用法: worker-init --rootfs <dir> -- <payload> [args...]")
		os.Exit(2)
	}

	// 安全闸：本程序只能在新 PID ns 里跑（母体 spawn 时给了 CLONE_NEWPID → 这里是 1 号）。
	// 单独在宿主上跑会 MS_PRIVATE + pivot_root 掉宿主的根 → 毁系统。
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "worker-init: 拒绝运行——必须在新的 PID/mount ns 里（由母体 spawn），单独跑会毁掉宿主挂载")
		os.Exit(2)
	}

	// 1) 装 rootfs（换根 + 挂基础设施）
	if err := setupRootfs(rootfs); err != nil {
		fmt.Fprintf(os.Stderr, "worker-init: rootfs 设置失败: %v\n", err)
		os.Exit(2)
	}

	// 2) 装 seccomp（此时 rootfs 已就绪、payload 尚未 execve）
	n, unknown, err := zygote.InstallSeccomp(zygote.DefaultPayloadAllowlist(), uint32(config.DefaultErrnoRet))
	if err != nil {
		fmt.Fprintf(os.Stderr, "worker-init: 装 seccomp 失败: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("worker-init: pivot_root 完成；seccomp 放行 %d 条 syscall\n", n)
	zygote.Mark("seccomp")
	if len(unknown) > 0 {
		fmt.Printf("worker-init: ⚠️ 名单里 %d 条没认出来（拼错=没写）: %v\n", len(unknown), unknown)
	}

	// 3) execve payload。带个 env 告诉 payload：seccomp 已由 init 装好（别再装一遍）。
	zygote.Mark("execve")
	env := append(os.Environ(), "ANOLIX_INIT_SECCOMP=1")
	if err := syscall.Exec(payload, append([]string{payload}, extra...), env); err != nil {
		fmt.Fprintf(os.Stderr, "worker-init: execve %s 失败: %v\n", payload, err)
		os.Exit(2)
	}
}

// parseArgs 解析 "--rootfs <dir> -- <payload> [args...]"。
func parseArgs(a []string) (rootfs, payload string, args []string) {
	i := 0
	for i < len(a) {
		switch {
		case a[i] == "--rootfs" && i+1 < len(a):
			rootfs = a[i+1]
			i += 2
		case a[i] == "--":
			if i+1 < len(a) {
				payload = a[i+1]
				args = a[i+2:]
			}
			return
		default:
			// 没写 "--"，第一个非选项就当 payload
			payload = a[i]
			args = a[i+1:]
			return
		}
	}
	return
}

// setupRootfs 铺 mount ns 并把根换到 rootfs。
//
// 要点（对照小知识点）：
//   - MS_PRIVATE：让本 mount ns 的改动不外泄给宿主（03 篇"单向玻璃"的前提）；
//   - bind rootfs→自身：pivot_root 要求 new_root 是个**挂载点**；
//   - put_old：必须在新根之下；换完后 detach 拆旧根、删目录；
//   - 挂 /proc：payload 常用（`ps`/读 /proc 等）。
func setupRootfs(rootfs string) error {
	// ① 整个 mount ns 私有化（递归），否则改动会漏到宿主。
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("MS_PRIVATE(/) 失败: %w", err)
	}
	zygote.Mark("ms_private")

	// ② rootfs bind 到自身 → 变成挂载点（pivot_root 前提）。
	if err := syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s 失败: %w", rootfs, err)
	}
	zygote.Mark("bind_rootfs")

	// ③ 准备 put_old（旧根的落脚处，必须在新根下面）。
	oldRoot := filepath.Join(rootfs, ".oldroot")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return fmt.Errorf("建 put_old 失败: %w", err)
	}

	// ④ 换根。
	if err := syscall.PivotRoot(rootfs, oldRoot); err != nil {
		return fmt.Errorf("pivot_root 失败: %w", err)
	}
	zygote.Mark("pivot_root")
	// ⑤ 切到新根（pivot_root 后 cwd 还在旧根，必须先切）。
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir(/) 失败: %w", err)
	}

	// ⑥ 摘掉旧根（detach 立即生效，旧根就彻底从视野消失）。
	_ = syscall.Unmount("/.oldroot", syscall.MNT_DETACH)
	_ = os.Remove("/.oldroot")
	zygote.Mark("detach_oldroot")

	// ⑦ 挂基础设施：/proc（必需）、/dev（tmpfs，best-effort）。
	_ = os.MkdirAll("/proc", 0555)
	if err := syscall.Mount("proc", "/proc", "proc",
		syscall.MS_NOSUID|syscall.MS_NOEXEC|syscall.MS_NODEV, ""); err != nil {
		return fmt.Errorf("挂 /proc 失败: %w", err)
	}
	_ = os.MkdirAll("/dev", 0755)
	_ = syscall.Mount("tmpfs", "/dev", "tmpfs",
		syscall.MS_NOSUID|syscall.MS_STRICTATIME, "mode=755,size=65536k")
	zygote.Mark("mounts")

	return nil
}
