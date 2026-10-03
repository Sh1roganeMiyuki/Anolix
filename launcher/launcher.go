// Package launcher 负责按 policy 组装 runc 启动参数，
// 生成 OCI bundle 并拉起容器执行命令。
//
// 全流程（读代码时对照这张图）：
//
//	① 准备说明书：建 bundle 目录 → 写 config.json（内容由 spec.go 生成）
//	② 喊 runc：把 runc 当独立程序启动（exec），参数 = runc run --bundle <目录> <ID>
//	③ 等它跑完：读 runc 的退出码，原样透传（被信号杀 = 128+信号号）
//	④ 超时/被打断：先对 runc 说"请退出"（SIGTERM），10 秒不走就强杀
//	⑤ 兜底清理：runc delete --force + 删临时 bundle 目录
//
// 一句话：本文件是"保姆"——负责把 runc 叫起来、看住它、收场；
// 真正干活的是 runc（它再去内核里建设施）。
package launcher

import (
	"anolix/config"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// killWaitDelay 是"取消后等对方优雅退出的最长时间"。
// 白话：收到取消（超时/Ctrl+C）时先好好说（发 SIGTERM）；
// 等超过这个时长还不走，就动手强杀（SIGKILL）。
const killWaitDelay = 10 * time.Second

// --- 【可略读】Options = 输入参数清单：知道每个开关干什么即可，不必背字段名。
// Options 是 Launcher 的构造参数（对应 CLI 的各个 flag，见 cmd/anolix/main.go）。
type Options struct {
	// ContainerID 容器 ID；为空时自动生成（anolix-<12 位十六进制>）。
	// 白话：容器也要有个名字，runc 靠它区分"这是哪个容器"。
	ContainerID string
	// Rootfs 容器的"根目录"（货物本身）；为空时使用 bundle 内的空 rootfs 目录。
	Rootfs string
	// BundleDir OCI bundle 目录（说明书+货物放哪）；为空时在系统临时目录创建，
	// 退出后自动删除（--keep-bundle 可保留，便于事后翻看）。
	BundleDir string
	// StateDir 传给 runc --root 的状态目录。
	// 白话：runc 的"记账本"放哪——它把每个容器的运行状态记在这里，
	// 之后 runc list / delete 都从这个本子里查；rootless 时必须放在用户可写的位置。
	StateDir string
	// RuncPath runc 可执行文件路径；为空时在 PATH 中查找 "runc"。
	RuncPath string
	// Policy 运行策略（规矩）；为空时使用 config.Default() 内置策略。
	Policy *config.Policy
	// Command 容器里要执行的命令，至少需要一个元素（比如 ["/probe"]）。
	Command []string
	// Env 容器内环境变量；为空时使用 DefaultEnv。
	Env []string
	// Stdin/Stdout/Stderr 标准流；nil 时分别使用 os.Stdin/os.Stdout/os.Stderr。
	// 白话：容器里程序的输入输出，默认直接连到你当前这个终端。
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Timeout 大于 0 时限制容器运行时长，超时后终止容器（0 = 不限）。
	Timeout time.Duration
	// KeepBundle 为 true 时保留自动创建的 bundle 目录（调试用：方便事后看 config.json）。
	KeepBundle bool
}

// Launcher 是一次容器运行的执行器（把一次运行所需的全部信息装在一起）。
type Launcher struct {
	opts      Options
	policy    *config.Policy
	runc      string // runc 可执行文件的绝对路径（New 时用 LookPath 找到的）
	id        string // 容器 ID
	bundle    string // 实际使用的 bundle 目录（Run 时才确定，所以 New 后是空的）
	bundleTmp bool   // bundle 是不是"我们自动建的临时目录"（决定退出时删不删它）
	rootfs    string // 写进说明书的 root 路径（Run 时才确定）
	rootless  bool   // 是否非 root 运行（是的话要开 user namespace）
}

// New 校验参数并构造 Launcher：解析 policy、定位 runc、生成容器 ID。
//
// 它按四步做：① 命令必须给 ② policy 必须合法（错在启动前，比错在半路好查）
// ③ 找到 runc 这个程序并记住它的绝对路径 ④ 起好容器 ID 并接好标准流
func New(opts Options) (*Launcher, error) {
	if len(opts.Command) == 0 {
		return nil, errors.New("必须指定容器内执行的命令")
	}

	// ② 策略：没给就用内置的；给了就先校验。
	policy := opts.Policy
	if policy == nil {
		policy = config.Default()
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("policy 非法: %w", err)
	}

	// ③ 找 runc：LookPath = "在 PATH 列出的那些目录里找有没有这个程序"。
	runcPath := opts.RuncPath
	if runcPath == "" {
		runcPath = "runc"
	}
	resolved, err := exec.LookPath(runcPath)
	if err != nil {
		return nil, fmt.Errorf("未找到 runc 可执行文件 (%s): %w", runcPath, err)
	}

	// ④ 容器 ID：没给就随机生成一个，避免与别人的容器重名。
	id := opts.ContainerID
	if id == "" {
		id, err = newContainerID()
		if err != nil {
			return nil, fmt.Errorf("生成容器 ID 失败: %w", err)
		}
	}

	// 标准流与环境：没给就用"当前终端 + 默认环境"。
	if opts.Env == nil {
		opts.Env = DefaultEnv
	}
	if opts.Stdin == nil {
		opts.Stdin = os.Stdin
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// 【面试必会】rootless 判定：非 root 即开 user namespace（也就这一行）。
	//   它牵出 02 篇的"cgroup 两分支"：无限额静默跳过 / 有限额硬报错。
	//   问法："非 root 下你怎么保证还能跑容器？有什么限制？"
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// 装进 Launcher。rootless 的判定：只要"当前有效用户不是 root"就开——
	// 这正是 README 里那句"非 root 自动启用 rootless，无需 sudo"。
	return &Launcher{
		opts:     opts,
		policy:   policy,
		runc:     resolved,
		id:       id,
		rootless: os.Geteuid() != 0,
	}, nil
}

// ID 返回容器 ID（外部想知道"这次容器叫什么"时用，测试里也在用）。
func (l *Launcher) ID() string { return l.id }

// BundleDir 返回实际使用的 bundle 目录。
// 白话：Run 之前，这里只有在 --bundle 显式指定时才有值；
// Run 之后是真正在用的目录（测试用它检查"退出后有没有删干净"）。
func (l *Launcher) BundleDir() string {
	if l.bundle != "" {
		return l.bundle
	}
	return l.opts.BundleDir
}

// stateDir 返回传给 runc --root 的"记账本"目录，优先级：
// ① 用户显式指定 → 用它；② rootless → 给个当前用户可写的位置；
// ③ rootful → 返回空串，让 runc 用自己的默认位置（/run/runc）。
func (l *Launcher) stateDir() string {
	if l.opts.StateDir != "" {
		return l.opts.StateDir
	}
	if l.rootless {
		return defaultRootlessStateDir()
	}
	return ""
}

// defaultRootlessStateDir 返回非 root 用户可写的状态目录：
// 优先 XDG_RUNTIME_DIR（正常登录的系统都会设置它），
// 没设置就退到系统临时目录（带上了自身 uid 避免多用户打架）。
func defaultRootlessStateDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "anolix-runc")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("anolix-runc-%d", os.Geteuid()))
}

// BuildRuncArgs 组装 `runc run` 的启动参数：
//
//	runc [--root <stateDir>] run --bundle <bundleDir> <containerID>
//
// 白话：拼出来的就是你在终端里手敲的那一串命令；
// 03 篇 trace 第 760 行的 execve("/usr/sbin/runc", [...]) 就是它被执行的一瞬间。
func BuildRuncArgs(stateDir, bundleDir, id string) []string {
	args := make([]string, 0, 6)
	if stateDir != "" {
		args = append(args, "--root", stateDir)
	}
	args = append(args, "run", "--bundle", bundleDir, id)
	return args
}

// Run 准备 OCI bundle、拉起容器执行命令并等待其退出。
//
// 返回容器内进程的退出码：正常退出为 0，非 0 退出码原样返回
// （因信号终止时为 128+信号值）。仅当启动、等待或清理本身出错，
// 或 ctx 被取消/超时时，才返回非 nil error。
func (l *Launcher) Run(ctx context.Context) (int, error) {
	// 第 1 步：如果设置了 --timeout，就派生一个"到点自动取消"的 ctx。
	if l.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, l.opts.Timeout)
		defer cancel() // defer = 本函数返回前一定会执行，用来回收计时器
	}

	// 第 2 步：准备 bundle（建目录 + 写说明书），失败就直接返回。
	// 第 3 步：登记"退出时删临时 bundle"——不管后面成功失败都会执行。
	if err := l.prepareBundle(); err != nil {
		return -1, err
	}
	defer l.cleanupBundle()

	// 第 4 步：确定 runc 的"记账本"目录；rootless 时保证它存在且只有自己能读。
	stateDir := l.stateDir()
	if stateDir != "" {
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return -1, fmt.Errorf("创建 runc 状态目录失败: %w", err)
		}
	}

	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// 【面试必会】CLI 子进程调用：anolix 不内嵌 runc，而是"喊"它起来干活。
	//   为什么：这是"两种集成方式"的选型落点（可替换/可审计/故障边界），
	//   也是取消、兜底、清理这些生命周期能力成立的前提。
	//   问法："你怎么用 runc？为什么不用 libcontainer？" → 答两道边界 + 三种收益。
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// 第 5 步：喊 runc——这就是"把另一个程序启动起来"的那一行（CLI 子进程调用）。
	cmd := exec.CommandContext(ctx, l.runc, BuildRuncArgs(stateDir, l.bundle, l.id)...)
	// 把容器里程序的输入输出，直接接到我们自己的终端上。
	cmd.Stdin, cmd.Stdout, cmd.Stderr = l.opts.Stdin, l.opts.Stdout, l.opts.Stderr
	// 取消时先发 SIGTERM（runc 会转发给容器进程，让它优雅退出）；
	// 若其未在 killWaitDelay 内退出，exec 会兜底强杀。
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// 【面试必会】取消语义两层就写在这两行：先 SIGTERM 优雅退出，超时再兜底强杀。
	//   为什么：容器树的杀灭靠"杀 init → 内核清空 PID namespace"，而入口必须可靠。
	//   问法："定时/被打断时，你怎么保证不留孤儿？"
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = killWaitDelay

	// 第 6 步：启动。启动都失败的话，尽力清理可能残留的容器。
	if err := cmd.Start(); err != nil {
		l.forceDeleteContainer()
		return -1, fmt.Errorf("启动容器 %s 失败: %w", l.id, err)
	}

	// 第 7 步：等它退出，并解析退出码。
	code, waitErr := waitExitCode(cmd)
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	// 【面试必会】退出码语义：被取消且拿不到容器的码时，自己填 128+SIGKILL=137。
	//   为什么：137 会与"内核 OOM"撞值——判据靠文案与 dmesg（02 篇、笔记 04）。
	//   问法："超时强杀后 echo $? 是多少？怎么和 OOM 区分？"
	// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	if ctxErr := ctx.Err(); ctxErr != nil {
		// 7a. ctx 被取消（超时 / Ctrl+C）：兜底强删容器；
		// 拿不到退出码时自己填 128+9=137（SIGKILL 的惯用表示）。
		l.forceDeleteContainer()
		if code < 0 {
			code = 128 + int(syscall.SIGKILL)
		}
		return code, fmt.Errorf("容器 %s 被强制终止: %w", l.id, ctxErr)
	}
	if waitErr != nil {
		// 7b. 等的时候出了别的问题（不是正常退出/非零码）：清理后上报。
		l.forceDeleteContainer()
		return code, fmt.Errorf("等待容器 %s 退出失败: %w", l.id, waitErr)
	}
	// `runc run` 在前台进程退出后会自动删除容器，无需额外清理。
	return code, nil
}

// prepareBundle 构建 OCI bundle：目录、rootfs 与 config.json。
//
// 白话分四步：找到/创建目录 → 路径规范化（runc 对符号链接有严格校验）→
// 确定 rootfs → 把说明书序列化成 JSON 写进 config.json。
func (l *Launcher) prepareBundle() error {
	// 用哪个目录？没指定就创建一个临时目录（不同容器互不干扰）。
	bundle := l.opts.BundleDir
	if bundle == "" {
		dir, err := os.MkdirTemp("", "anolix-bundle-")
		if err != nil {
			return fmt.Errorf("创建临时 bundle 目录失败: %w", err)
		}
		l.bundleTmp = true
		bundle = dir
	}
	// 转成绝对路径，并确保目录存在。
	abs, err := filepath.Abs(bundle)
	if err != nil {
		return fmt.Errorf("解析 bundle 路径失败: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return fmt.Errorf("创建 bundle 目录失败: %w", err)
	}
	// runc 要求 rootfs 路径全链路无符号链接，bundle 路径同样需要规范化。
	// EvalSymlinks = "把路径里所有软链接展开成真实路径"。
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("解析 bundle 真实路径失败: %w", err)
	}
	l.bundle = canonical

	// 确定 rootfs（两条分支见 prepareRootfs）。
	if err := l.prepareRootfs(); err != nil {
		return err
	}

	// 把 policy + 命令 + rootfs 翻译成说明书结构体，再序列化成 JSON。
	spec := buildSpec(l.policy, l.opts.Command, l.opts.Env, l.rootfs, l.rootless)
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 OCI spec 失败: %w", err)
	}
	configPath := filepath.Join(l.bundle, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return fmt.Errorf("写入 config.json 失败: %w", err)
	}
	return nil
}

// prepareRootfs 确定 rootfs，并计算写进说明书的 root 路径。
//
// 两条分支：
//   - 没给 --rootfs：在 bundle 里建个空目录，说明书里写相对路径 "rootfs"；
//   - 给了 --rootfs：转绝对路径 → 检查存在且是目录 → 展开软链接后写进说明书。
//
// !!! 【值得会说】EvalSymlinks 不是洁癖：runc 会校验"全链路无软链接"，
//
//	不规范化会被直接拒绝（01 篇故障 A 的根因）。
//
// 为什么要展开软链接（EvalSymlinks）：runc 会校验 rootfs 路径"全链路无软链接"
// （libcontainer/configs/validate 里比较 Clean 与 EvalSymlinks 的结果），
// 不规范化会被直接拒绝（01 篇故障 A）。
func (l *Launcher) prepareRootfs() error {
	if l.opts.Rootfs == "" {
		rootfs := filepath.Join(l.bundle, "rootfs")
		if err := os.MkdirAll(rootfs, 0o755); err != nil {
			return fmt.Errorf("创建 rootfs 目录失败: %w", err)
		}
		l.rootfs = "rootfs"
		return nil
	}

	abs, err := filepath.Abs(l.opts.Rootfs)
	if err != nil {
		return fmt.Errorf("解析 rootfs 路径失败: %w", err)
	}
	// 提前检查：不存在/不是目录，就给出清楚一点的错误。
	info, err := os.Stat(abs)
	if err != nil {
		return fmt.Errorf("rootfs 不可用: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("rootfs %s 不是目录", abs)
	}
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("解析 rootfs 真实路径失败: %w", err)
	}
	l.rootfs = canonical
	return nil
}

// cleanupBundle 清理自动创建的临时 bundle 目录。
// 白话：只删"我们自己建的"临时目录；用户显式指定的目录、或 --keep-bundle，都保留。
func (l *Launcher) cleanupBundle() {
	if l.bundleTmp && !l.opts.KeepBundle {
		_ = os.RemoveAll(l.bundle)
	}
}

// !!! 【值得会说】兜底清理的"先杀后删"：delete --force 走 cgroup 的 kill 路径——
//
//	它也解释了"cgroup 含活进程时 rmdir 报 EBUSY"那个坑。
//
// forceDeleteContainer 尽力强制删除可能仍存活的容器（忽略错误）。
// 白话：就是再喊一声 runc delete --force <ID>；失败也不报（尽力而为）。
func (l *Launcher) forceDeleteContainer() {
	args := make([]string, 0, 4)
	if dir := l.stateDir(); dir != "" {
		args = append(args, "--root", dir)
	}
	args = append(args, "delete", "--force", l.id)

	ctx, cancel := context.WithTimeout(context.Background(), killWaitDelay)
	defer cancel()
	_ = exec.CommandContext(ctx, l.runc, args...).Run()
}

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// 【面试必会】128+signal 的翻译就发生在这几行：被信号杀 = 128+N。
//
//	为什么：这是"跨进程边界回来的唯一消息"；②OOM=137 与③超时=143/137 的差异根源。
//	问法："为什么 shell 用 128+N 而不是直接报 N？"
//
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// waitExitCode 等待命令退出，并把结果翻译成退出码。三种情形：
//   - 正常退出：返回 (0, nil)；
//   - 非零退出 / 被信号杀：返回 (码, nil)——被信号杀时为 128+信号号（137=被 SIGKILL）；
//   - 等的过程本身出错：返回 (-1, err)。
func waitExitCode(cmd *exec.Cmd) (int, error) {
	err := cmd.Wait()
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	return -1, err
}

// --- 【可略读】纯工具函数：随机生成 12 位十六进制 ID，读一遍即可。
// newContainerID 生成随机容器 ID（anolix-<12 位十六进制>）。
// 白话：取 6 个随机字节（crypto/rand，真正的随机源），转成 12 个十六进制字符。
func newContainerID() (string, error) {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "anolix-" + hex.EncodeToString(buf[:]), nil
}
