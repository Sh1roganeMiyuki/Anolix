// Package launcher 负责按 policy 组装 runc 启动参数，
// 生成 OCI bundle 并拉起容器执行命令。
package launcher

import (
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

	"anolix/config"
)

// killWaitDelay 是取消/超时后强制终止 runc 进程的兜底等待时长。
const killWaitDelay = 10 * time.Second

// Options 是 Launcher 的构造参数。
type Options struct {
	// ContainerID 容器 ID；为空时自动生成。
	ContainerID string
	// Rootfs 容器根文件系统目录；为空时使用 bundle 内的空 rootfs 目录。
	Rootfs string
	// BundleDir 显式指定 OCI bundle 目录；为空时在临时目录创建并自动清理。
	BundleDir string
	// StateDir 传给 runc --root 的状态目录；为空时使用 runc 默认值。
	StateDir string
	// RuncPath runc 可执行文件路径；为空时在 PATH 中查找 "runc"。
	RuncPath string
	// Policy 运行策略；为空时使用 config.Default()。
	Policy *config.Policy
	// Command 容器内执行的命令，至少需要一个元素。
	Command []string
	// Env 容器内环境变量；为空时使用 DefaultEnv。
	Env []string
	// Stdin/Stdout/Stderr 标准流；nil 时分别使用 os.Stdin/os.Stdout/os.Stderr。
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Timeout 大于 0 时限制容器运行时长，超时后终止容器。
	Timeout time.Duration
	// KeepBundle 为 true 时保留自动创建的 bundle 目录（调试用）。
	KeepBundle bool
}

// Launcher 是一次容器运行的执行器。
type Launcher struct {
	opts      Options
	policy    *config.Policy
	runc      string // runc 可执行文件绝对路径
	id        string
	bundle    string // 实际使用的 bundle 目录（Run 时确定）
	bundleTmp bool   // bundle 是否为自动创建的临时目录
	rootfs    string // 写入 OCI spec 的 root 路径（Run 时确定）
	rootless  bool   // 非 root 运行时启用 rootless（user namespace）模式
}

// New 校验参数并构造 Launcher：解析 policy、定位 runc、生成容器 ID。
func New(opts Options) (*Launcher, error) {
	if len(opts.Command) == 0 {
		return nil, errors.New("必须指定容器内执行的命令")
	}

	policy := opts.Policy
	if policy == nil {
		policy = config.Default()
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("policy 非法: %w", err)
	}

	runcPath := opts.RuncPath
	if runcPath == "" {
		runcPath = "runc"
	}
	resolved, err := exec.LookPath(runcPath)
	if err != nil {
		return nil, fmt.Errorf("未找到 runc 可执行文件 (%s): %w", runcPath, err)
	}

	id := opts.ContainerID
	if id == "" {
		id, err = newContainerID()
		if err != nil {
			return nil, fmt.Errorf("生成容器 ID 失败: %w", err)
		}
	}

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

	return &Launcher{
		opts:     opts,
		policy:   policy,
		runc:     resolved,
		id:       id,
		rootless: os.Geteuid() != 0,
	}, nil
}

// ID 返回容器 ID。
func (l *Launcher) ID() string { return l.id }

// BundleDir 返回实际使用的 bundle 目录；Run 之前为空（除非显式指定）。
func (l *Launcher) BundleDir() string {
	if l.bundle != "" {
		return l.bundle
	}
	return l.opts.BundleDir
}

// stateDir 返回传给 runc --root 的状态目录：
// 显式配置优先；rootless 时回退到当前用户可写的默认目录。
func (l *Launcher) stateDir() string {
	if l.opts.StateDir != "" {
		return l.opts.StateDir
	}
	if l.rootless {
		return defaultRootlessStateDir()
	}
	return ""
}

// defaultRootlessStateDir 返回非 root 用户的 runc 状态目录
// （优先 XDG_RUNTIME_DIR，回退到系统临时目录）。
func defaultRootlessStateDir() string {
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "anolix-runc")
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("anolix-runc-%d", os.Geteuid()))
}

// BuildRuncArgs 组装 `runc run` 的启动参数：
//
//	runc [--root <stateDir>] run --bundle <bundleDir> <containerID>
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
	if l.opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, l.opts.Timeout)
		defer cancel()
	}

	if err := l.prepareBundle(); err != nil {
		return -1, err
	}
	defer l.cleanupBundle()

	stateDir := l.stateDir()
	if stateDir != "" {
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			return -1, fmt.Errorf("创建 runc 状态目录失败: %w", err)
		}
	}

	cmd := exec.CommandContext(ctx, l.runc, BuildRuncArgs(stateDir, l.bundle, l.id)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = l.opts.Stdin, l.opts.Stdout, l.opts.Stderr
	// 取消时先发 SIGTERM 让 runc 转发给容器进程优雅退出；
	// 若其未在 killWaitDelay 内退出，exec 会兜底强杀。
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = killWaitDelay

	if err := cmd.Start(); err != nil {
		l.forceDeleteContainer()
		return -1, fmt.Errorf("启动容器 %s 失败: %w", l.id, err)
	}

	code, waitErr := waitExitCode(cmd)
	if ctxErr := ctx.Err(); ctxErr != nil {
		l.forceDeleteContainer()
		if code < 0 {
			code = 128 + int(syscall.SIGKILL)
		}
		return code, fmt.Errorf("容器 %s 被强制终止: %w", l.id, ctxErr)
	}
	if waitErr != nil {
		l.forceDeleteContainer()
		return code, fmt.Errorf("等待容器 %s 退出失败: %w", l.id, waitErr)
	}
	// `runc run` 在前台进程退出后会自动删除容器，无需额外清理。
	return code, nil
}

// prepareBundle 构建 OCI bundle：目录、rootfs 与 config.json。
func (l *Launcher) prepareBundle() error {
	bundle := l.opts.BundleDir
	if bundle == "" {
		dir, err := os.MkdirTemp("", "anolix-bundle-")
		if err != nil {
			return fmt.Errorf("创建临时 bundle 目录失败: %w", err)
		}
		l.bundleTmp = true
		bundle = dir
	}
	abs, err := filepath.Abs(bundle)
	if err != nil {
		return fmt.Errorf("解析 bundle 路径失败: %w", err)
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return fmt.Errorf("创建 bundle 目录失败: %w", err)
	}
	// runc 要求 rootfs 路径全链路无符号链接，bundle 路径同样需要规范化。
	canonical, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("解析 bundle 真实路径失败: %w", err)
	}
	l.bundle = canonical

	if err := l.prepareRootfs(); err != nil {
		return err
	}

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

// prepareRootfs 确定 rootfs 并计算写入 OCI spec 的 root 路径。
//
// runc 校验要求 rootfs 为绝对路径且全链路不含符号链接
// （libcontainer/configs/validate 中比较 Clean 与 EvalSymlinks 结果），
// 因此这里统一 EvalSymlinks 规范化后以绝对路径写入 config.json；
// 未指定 --rootfs 时使用 bundle 内的空目录（相对路径 "rootfs"）。
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
func (l *Launcher) cleanupBundle() {
	if l.bundleTmp && !l.opts.KeepBundle {
		_ = os.RemoveAll(l.bundle)
	}
}

// forceDeleteContainer 尽力强制删除可能仍存活的容器（忽略错误）。
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

// waitExitCode 等待命令退出并解析退出码。
// 正常退出返回 (0, nil)；非 0 退出或信号终止返回 (code, nil)；
// 其他等待错误返回 (-1, err)。
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

// newContainerID 生成随机容器 ID（anolix-<12 位十六进制>）。
func newContainerID() (string, error) {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return "anolix-" + hex.EncodeToString(buf[:]), nil
}
