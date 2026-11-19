// Command worker-init 是 zygote 的"薄 init"：装 rootfs + 装 seccomp，然后 execve payload。
//
// 为什么必须有它（而不是让 worker 自己干）：
//   - 母体 clone 出 worker 后**直接 execve 新程序**，Go 的 os/exec 不给"fork 与 exec 之间跑代码"的钩子；
//   - 所以给了 mount ns（CLONE_NEWNS）也**没地方 pivot_root** → 必须借道一个薄 init。
//   - init 干完 rootfs 与 seccomp 后 **execve 成 payload**（execve 不改身份卡，seccomp/fd 一路跟着）。
//
// 顺序（很重要）：
//
//	mount 私有化 → bind rootfs → pivot_root → 挂 /proc → 拉起 lo → 卸能力 → 装 seccomp → execve payload
//
//	rootfs 相关的 syscall（mount/pivot_root）必须在**装 seccomp 之前**做完——
//	否则会被自己的过滤器拦（自缚）；装完过滤器后 init 只剩一条 execve。
//
//	拉起 lo 必须在卸能力之前（SIOCSIFFLAGS 要 CAP_NET_ADMIN）。
//	worker 的 netns 是 clone(CLONE_NEWNET) 新建的，lo 默认 down；
//	不拉起它，worker 内连 127.0.0.1 都不通。
//
//	卸能力必须卡在 setupRootfs() 返回之后（那之前每个 mount 都要 CAP_SYS_ADMIN），
//	而 execve 之前要同时拆 Bounding + 清空五个集合：uid 0 在 execve 时会按
//	Bounding 把能力重新补满（小知识点 49）。
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
	"runtime"
	"strings"
	"syscall"
	"time"

	"anolix/config"
	"anolix/zygote"
)

func main() {
	// 把 goroutine 钉在当前 OS 线程上：seccomp filter 是 per-thread 的
	// （prctl(PR_SET_SECCOMP) 只作用于 current），而 Go 调度器可能在安全点把
	// goroutine 挪到别的 M 上——一旦挪走，后面 syscall.Exec 就在一条没有 filter
	// 的线程上执行，payload 会完全裸奔。runc 在同样位置也是先 LockOSThread。
	// 故意不解锁：下一步就是 execve，整个进程会被替换。
	runtime.LockOSThread()

	// 计时第一站：到这里说明 clone + execve + Go runtime 启动已经走完。
	// 后续每站的 ns 值都是相对母体 clone 前那一刻的 CLOCK_MONOTONIC。
	zygote.Mark("init_start")

	// rootless 握手：等母体把 uid_map 写好再动 rootfs。
	if err := waitUIDMap(); err != nil {
		fmt.Fprintf(os.Stderr, "worker-init: %v\n", err)
		os.Exit(2)
	}
	// rootless 的 caps 陷阱：母体 clone 后孩子立即 execve，那一刻 map 还空（uid=overflow），
	// 内核按“非 root exec”清空 effective caps；map 后写只改 uid、**不重算 caps**。
	// 所以等 map 好后 re-exec 自己一次，让 execve 在 uid=0 下重算出全满 caps。
	// REEXECED 标记防无限循环；rootful 不走这条（map 天生非空、exec 时 uid 已 0）。
	if os.Getenv(zygote.RootlessEnv) == "1" && os.Getenv("ANOLIX_REEXECED") != "1" {
		env := append(os.Environ(), "ANOLIX_REEXECED=1")
		if err := syscall.Exec("/proc/self/exe", os.Args, env); err != nil {
			fmt.Fprintf(os.Stderr, "worker-init: rootless re-exec 失败: %v\n", err)
			os.Exit(2)
		}
	}
	// 临时调试（ANOLIX_DEBUG=1）：看 rootless 下 map 与 CapEff 真实值。
	if os.Getenv("ANOLIX_DEBUG") == "1" {
		if b, e := os.ReadFile("/proc/self/uid_map"); e == nil {
			fmt.Fprintf(os.Stderr, "DEBUG uid_map=%q\n", string(b))
		}
		if b, e := os.ReadFile("/proc/self/status"); e == nil {
			for _, l := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(l, "CapEff") || strings.HasPrefix(l, "Uid:") {
					fmt.Fprintln(os.Stderr, "DEBUG", l)
				}
			}
		}
	}

	rootfs, payload, extra, harden, overlay := parseArgs(os.Args[1:])
	if rootfs == "" || payload == "" {
		fmt.Fprintln(os.Stderr, "用法: worker-init [--harden] [--overlay] --rootfs <dir> -- <payload> [args...]")
		os.Exit(2)
	}

	// 安全闸：本程序只能在新 PID ns 里跑（母体 spawn 时给了 CLONE_NEWPID → 这里是 1 号）。
	// 单独在宿主上跑会 MS_PRIVATE + pivot_root 掉宿主的根 → 毁系统。
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "worker-init: 拒绝运行——必须在新的 PID/mount ns 里（由母体 spawn），单独跑会毁掉宿主挂载")
		os.Exit(2)
	}

	// 1) 装 rootfs（换根 + 挂基础设施）
	if err := setupRootfs(rootfs, harden, overlay); err != nil {
		fmt.Fprintf(os.Stderr, "worker-init: rootfs 设置失败: %v\n", err)
		os.Exit(2)
	}

	// 2) 网络：worker 的 netns 是 clone(CLONE_NEWNET) 新建的，lo 默认 down。
	//    拉起 lo 需要 CAP_NET_ADMIN（必须在卸能力之前），
	//    同时需要 socket/ioctl（必须在装 seccomp 之前）。
	if err := zygote.BringLoopbackUp(); err != nil {
		fmt.Fprintf(os.Stderr, "worker-init: 拉起 lo 失败: %v\n", err)
		os.Exit(2)
	}
	// 这一行是 Z1 的可观测证据：worker netns 的 lo 从 down 变 up。
	// 它出现在母体日志里（worker 的 stdout 接母体），可用 mother.sh log 查。
	fmt.Println("worker-init: lo 已拉起（worker netns）")

	// 3) 卸能力。mount / pivot_root 都要 CAP_SYS_ADMIN，这些活已在 setupRootfs 里
	//    干完；payload 一个能力都不需要。必须同时拆 Bounding 天花板并清空五个集合——
	//    否则 uid 0 的 payload 会在 execve 时被内核按 Bounding 重新补满（小知识点 49）。
	if err := zygote.DropCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "worker-init: 卸能力失败: %v\n", err)
		os.Exit(2)
	}
	zygote.Mark("dropcaps")

	// 4) 装 seccomp（此时 rootfs 已就绪、能力已卸、payload 尚未 execve）
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

	// 5) execve payload。带个 env 告诉 payload：seccomp 已由 init 装好（别再装一遍）。
	zygote.Mark("execve")
	env := append(os.Environ(), "ANOLIX_INIT_SECCOMP=1")
	if err := syscall.Exec(payload, append([]string{payload}, extra...), env); err != nil {
		fmt.Fprintf(os.Stderr, "worker-init: execve %s 失败: %v\n", payload, err)
		os.Exit(2)
	}
}

// waitUIDMap 等母体把 uid_map 写好（rootless 握手）。
//
// clone 返回时 map 还是空的：本进程是 overflow uid、无 caps，mount/pivot 都会 EPERM。
// rootful 时初始 ns 的 map 天生非空（0 0 4294967295），立即返回，不影响原路径。
func waitUIDMap() error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		b, err := os.ReadFile("/proc/self/uid_map")
		if err == nil && len(strings.TrimSpace(string(b))) > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等 uid_map 超时（母体没写 map？）")
		}
		time.Sleep(50 * time.Microsecond)
	}
}

// parseArgs 解析 "[--harden] --rootfs <dir> -- <payload> [args...]"。
func parseArgs(a []string) (rootfs, payload string, args []string, harden, overlay bool) {
	i := 0
	for i < len(a) {
		switch {
		case a[i] == "--rootfs" && i+1 < len(a):
			rootfs = a[i+1]
			i += 2
		case a[i] == "--harden":
			// 补上与 runc 同构的掩蔽/只读清单（A/B 对比用，默认关闭）。
			harden = true
			i++
		case a[i] == "--overlay":
			// 每个 worker 一个独立可写层：lower=共享 rootfs，upper=自己的改动集。
			// 不开时所有 worker 共享同一份 rootfs（A 写 B 可见）。
			overlay = true
			i++
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
func setupRootfs(rootfs string, harden, overlay bool) error {
	// ① 整个 mount ns 私有化（递归），否则改动会漏到宿主。
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("MS_PRIVATE(/) 失败: %w", err)
	}
	zygote.Mark("ms_private")

	// ②~⑥ 换根：两条实现，时机相同——都必须在“还看得见宿主路径”的窗口内做完。
	if overlay {
		if err := pivotOverlay(rootfs); err != nil {
			return err
		}
	} else {
		if err := pivotBind(rootfs); err != nil {
			return err
		}
	}

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

	// ⑧ 完整档（可选）：补齐基础挂载 + 掩蔽 + 只读重挂。
	// 补上后，zygote 与 runc 默认 spec 做的“功”就一样多了（A/B 对比用）。
	if harden {
		hardenRootfs()
		zygote.Mark("harden")
	}

	return nil
}

// pivotBind 是默认换根：把共享 rootfs bind 到自身再 pivot_root。
// 所有 worker 换到同一份目录 → 同一批 inode → A 写 B 可见（无写入隔离）。
func pivotBind(rootfs string) error {
	// rootfs bind 到自身 → 变成挂载点（pivot_root 前提）。
	if err := syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind %s 失败: %w", rootfs, err)
	}
	zygote.Mark("bind_rootfs")

	// put_old：旧根的落脚处，必须在新根下面。
	oldRoot := filepath.Join(rootfs, ".oldroot")
	if err := os.MkdirAll(oldRoot, 0700); err != nil {
		return fmt.Errorf("建 put_old 失败: %w", err)
	}
	if err := syscall.PivotRoot(rootfs, oldRoot); err != nil {
		return fmt.Errorf("pivot_root 失败: %w", err)
	}
	zygote.Mark("pivot_root")
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir(/) 失败: %w", err)
	}
	_ = syscall.Unmount("/.oldroot", syscall.MNT_DETACH)
	// ⚠️ 不删 /.oldroot：rootfs 是所有 worker 共享的同一份目录，删掉它会和
	// 别的 worker 的 mkdir+pivot_root 竞态（并发实测 6/64 报 pivot_root ENOENT）。
	zygote.Mark("detach_oldroot")
	return nil
}

// pivotOverlay 用 overlayfs 换根：lower=共享 rootfs，upper=本 worker 的改动集。
//
// 为什么能在这里用宿主路径：此刻还没 pivot_root，worker 的挂载表是从母体
// （宿主裸进程）复制的，/tmp 和 rootfs 都还看得见。过了这一步就再也够不到。
//
// 目录约定 /tmp/anolix-overlay/<RUN_ID>：母体 reap 时按同一规则删（见 spawn.go）。
func pivotOverlay(rootfs string) error {
	id := os.Getenv(zygote.RunIDEnv)
	if id == "" {
		// 不经母体直接跑 worker-init 时没有 RUN_ID，用时间戳兜底；
		// 这种目录母体不认识，由调用方自己清理。
		id = fmt.Sprintf("anon-%d", time.Now().UnixNano())
	}
	base, ok := zygote.OverlayDir(id)
	if !ok {
		return fmt.Errorf("RUN_ID %q 含非法字符，不能用作目录名", id)
	}
	upper := filepath.Join(base, "upper")
	work := filepath.Join(base, "work")
	merged := filepath.Join(base, "merged")
	// 三条硬约束：upper/work 同一文件系统（否则 EXDEV）；
	// upper/work/merged 都不能落在 lower 里面（否则内核拒绝，会递归）。
	// 三个都建在 /tmp 下、lower 是 rootfs，天然满足。
	for _, d := range []string{upper, work, merged} {
		if err := os.MkdirAll(d, 0700); err != nil {
			return fmt.Errorf("建 %s 失败: %w", d, err)
		}
	}
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", rootfs, upper, work)
	if err := syscall.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		return fmt.Errorf("mount overlay 失败: %w", err)
	}
	zygote.Mark("overlay_mount")

	// 换根用 runc 的 "." 技巧，而不是在 merged 里建 .oldroot：
	// merged 是 overlay 视图，在里面 mkdir 会 copy-up 进 upper，留下垃圾目录。
	if err := os.Chdir(merged); err != nil {
		return fmt.Errorf("chdir(merged) 失败: %w", err)
	}
	if err := syscall.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root 失败: %w", err)
	}
	zygote.Mark("pivot_root")
	if err := syscall.Unmount(".", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("摘旧根失败: %w", err)
	}
	if err := os.Chdir("/"); err != nil {
		return fmt.Errorf("chdir(/) 失败: %w", err)
	}
	zygote.Mark("detach_oldroot")
	return nil
}

// 加固清单：与 launcher/spec.go 的 defaultMaskedPaths / defaultReadonlyPaths 保持一致。
var (
	maskedPaths = []string{
		"/proc/acpi", "/proc/asound", "/proc/kcore", "/proc/keys",
		"/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
		"/proc/sched_debug", "/proc/scsi",
		"/sys/firmware", "/sys/devices/virtual/powercap",
	}
	readonlyPaths = []string{
		"/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq",
		"/proc/sys", "/proc/sysrq-trigger",
	}
)

// 基础挂载：与 runc 默认 spec 的 6 项对齐（/proc 与 /dev 已在 setupRootfs 里挂过）。
// 少一项就不是“同一档配置”，比出来的数不可比。
var extraMounts = []struct {
	dest, fstype, source string
	flags                uintptr
	data                 string
}{
	{"/dev/pts", "devpts", "devpts", syscall.MS_NOSUID | syscall.MS_NOEXEC,
		"newinstance,ptmxmode=0666,mode=0620"},
	{"/dev/shm", "tmpfs", "shm", syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV,
		"mode=1777,size=65536k"},
	{"/dev/mqueue", "mqueue", "mqueue", syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV, ""},
	{"/sys", "sysfs", "sysfs", syscall.MS_NOSUID | syscall.MS_NOEXEC | syscall.MS_NODEV | syscall.MS_RDONLY, ""},
}

// hardenRootfs 把 zygote 的 rootfs 补到与 runc 默认 spec 同一档配置：
//  1. 基础挂载：/dev/pts、/dev/shm、/dev/mqueue、/sys
//  2. 掩蔽：用 /dev/null 盖住敏感文件
//  3. 只读重挂：把可调参数目录重挂成只读
//
// 每项失败都继续做下一项（best-effort），但不再静默吃掉错误：失败逐条打到
// stderr、末尾再给总数。上一版把错误吞进 `_ =`，mknod 因缺 CAP_MKNOD 失败后
// 11 条掩蔽跟着全灭，而日志里一个字都没有——A/B 对比由此失真。
func hardenRootfs() {
	fail := 0
	step := func(what string, err error) {
		if err != nil {
			fail++
			fmt.Fprintf(os.Stderr, "worker-init: harden 失败 [%s]: %v\n", what, err)
		}
	}

	for _, m := range extraMounts {
		step("mkdir "+m.dest, os.MkdirAll(m.dest, 0755))
		step("mount "+m.dest, syscall.Mount(m.source, m.dest, m.fstype, m.flags, m.data))
	}
	// 掩蔽靠 bind /dev/null，但 rootfs 的 /dev 是空 tmpfs——先自己建出 null 设备。
	// 这一步要 CAP_MKNOD；它建不出来，下面 11 条掩蔽会全部跟着失败。
	if _, err := os.Stat("/dev/null"); err != nil {
		if err := syscall.Mknod("/dev/null", syscall.S_IFCHR|0666, int(devNum(1, 3))); err != nil {
			step("mknod /dev/null", err)
		} else if err := os.Chmod("/dev/null", 0666); err != nil {
			// mknod 的模式会被 umask 掩一下（022 → crw-r--r--），
			// 但 /dev/null 必须是 0666，否则容器里的非 root 用户写不进去。
			step("chmod /dev/null", err)
		}
	}
	for _, p := range maskedPaths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		// 目录不能拿 /dev/null 盖：bind 一个文件到目录 = ENOTDIR。
		// runc 的做法一致：目录用 size=0 的只读 tmpfs，文件才 bind /dev/null。
		if fi.IsDir() {
			step("mask-dir "+p, syscall.Mount("tmpfs", p, "tmpfs", syscall.MS_RDONLY, "size=0k"))
			continue
		}
		step("mask "+p, syscall.Mount("/dev/null", p, "", syscall.MS_BIND, ""))
	}
	for _, p := range readonlyPaths {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		step("bind "+p, syscall.Mount(p, p, "", syscall.MS_BIND|syscall.MS_REC, ""))
		step("remount-ro "+p, syscall.Mount("", p, "", syscall.MS_REMOUNT|syscall.MS_BIND|syscall.MS_RDONLY, ""))
	}

	if fail > 0 {
		fmt.Fprintf(os.Stderr, "worker-init: ⚠️ --harden 有 %d 项没做成：这组 A/B 不可比\n", fail)
	}
}

// devNum 把 major/minor 编成 mknod 要的 dev_t（Linux 老式 8:8 编码，如 1:3 → 0x103）。
func devNum(major, minor uint32) uint64 {
	return uint64(major)<<8 | uint64(minor)
}
