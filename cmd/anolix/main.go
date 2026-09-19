// Command anolix 是 Anolix 轻量沙箱运行时的命令行入口。
//
// 用法:
//
//	anolix run [flags] -- <command> [args...]
//
// 示例:
//
//	./anolix run --policy examples/policy.json --rootfs ./rootfs -- /probe
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"anolix/config"
	"anolix/launcher"
)

func main() {
	os.Exit(run())
}

func run() int {
	if len(os.Args) < 2 || os.Args[1] != "run" {
		usage()
		return 2
	}

	fs := flag.NewFlagSet("anolix run", flag.ContinueOnError)
	fs.Usage = usage
	policyPath := fs.String("policy", "", "policy JSON 文件路径；缺省使用内置策略")
	rootfs := fs.String("rootfs", "", "容器根文件系统目录；缺省使用空 rootfs")
	bundleDir := fs.String("bundle", "", "OCI bundle 目录；缺省使用临时目录并自动清理")
	stateDir := fs.String("state-dir", "", "runc --root 状态目录；缺省使用 runc 默认值")
	id := fs.String("id", "", "容器 ID；缺省自动生成")
	runcPath := fs.String("runc", "", "runc 可执行文件路径；缺省在 PATH 中查找")
	timeout := fs.Duration("timeout", 0, "容器运行超时（如 30s）；0 表示不限")
	keepBundle := fs.Bool("keep-bundle", false, "退出后保留 bundle 目录（调试用）")

	if err := fs.Parse(os.Args[2:]); err != nil {
		return 2
	}
	command := fs.Args()
	if len(command) == 0 {
		usage()
		return 2
	}

	policy := config.Default()
	if *policyPath != "" {
		p, err := config.Load(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "anolix: %v\n", err)
			return 1
		}
		policy = p
	}

	l, err := launcher.New(launcher.Options{
		ContainerID: *id,
		Rootfs:      *rootfs,
		BundleDir:   *bundleDir,
		StateDir:    *stateDir,
		RuncPath:    *runcPath,
		Policy:      policy,
		Command:     command,
		Timeout:     *timeout,
		KeepBundle:  *keepBundle,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "anolix: %v\n", err)
		return 1
	}

	// Ctrl+C / SIGTERM 触发取消，由 launcher 负责终止并清理容器。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code, err := l.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anolix: %v\n", err)
		if code < 0 {
			return 1
		}
	}
	return code
}

func usage() {
	fmt.Fprint(os.Stderr, `Anolix 轻量沙箱运行时

用法:
  anolix run [flags] -- <command> [args...]

非 root 运行时自动启用 rootless（user namespace + uid/gid 映射），无需 sudo。

flags:
  --policy PATH    policy JSON 文件路径；缺省使用内置策略
  --rootfs PATH    容器根文件系统目录；缺省使用空 rootfs
  --bundle PATH    OCI bundle 目录；缺省使用临时目录并自动清理
  --state-dir PATH runc --root 状态目录；缺省使用 runc 默认值
  --id NAME        容器 ID；缺省自动生成
  --runc PATH      runc 可执行文件路径；缺省在 PATH 中查找
  --timeout DUR    容器运行超时（如 30s）；0 表示不限
  --keep-bundle    退出后保留 bundle 目录（调试用）

示例:
  anolix run --policy examples/policy.json --rootfs ./rootfs -- /probe
  anolix run --rootfs ./rootfs -- /probe hold 60   # 演示超时/中断
`)
}
