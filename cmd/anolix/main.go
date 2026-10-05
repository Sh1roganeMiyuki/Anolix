// Command anolix 是 Anolix 轻量沙箱运行时的命令行入口。
//
// 这个文件只干"接线"的活：收参数 → 读策略 → 交给 launcher → 把退出码还给 shell。
// 所有逻辑写在 run() 里、由 main() 统一 os.Exit，是 Go 命令行程序的常见写法
// （好处：run 里可以直接 return 退出码，defer 也能正常执行）。
//
// 用法:
//
//	anolix run [flags] -- <command> [args...]
//
// 示例:
//
//	./anolix run --policy examples/policy.json --rootfs ./rootfs -- /probe
//
// 阅读顺序建议：main.go → config.go → launcher/spec.go → launcher/launcher.go。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"anolix/config"
	"anolix/launcher"
)

func main() {
	// 惯用法：真正的工作在 run()，它返回退出码；main 只负责把它交给操作系统。
	os.Exit(run())
}

// !!! 【值得会说】main.go 是"接线层"：没有任何隔离逻辑；面试里它只用来讲清
//
//	"退出码从容器到 shell 的完整链路"（容器码 → runc → anolix → $?）。
func run() int {
	// 计时起点（--timing 的总账从这里算）：放在最前面，越早越接近真实启动。
	t0 := time.Now()

	// 第 1 步：必须是 `anolix run ...` 的形式（本版本只有一个子命令 run）。
	// 参数不对就打印用法并返回 2（"命令行用法错误"的惯例退出码）。
	if len(os.Args) < 2 || os.Args[1] != "run" {
		usage()
		return 2
	}

	// --- 【可略读】flag 清单：知道有哪些开关即可（前面几轮实验都用过）。
	// 第 2 步：定义所有 flag。每个的含义见行尾注释。
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
	timing := fs.Bool("timing", false, "打印各阶段耗时（测启动开销用）")

	if err := fs.Parse(os.Args[2:]); err != nil {
		return 2
	}
	// 第 3 步：`--` 之后的所有内容都算"容器里要执行的命令"
	//（比如 -- /probe，或 -- /bin/busybox sh -c '...'）。
	command := fs.Args()
	if len(command) == 0 {
		usage()
		return 2
	}

	// 第 4 步：准备策略。默认用内置策略；给了 --policy 就从文件读，
	// 读失败（文件不存在/字段写错）就报错退出 1。
	policy := config.Default()
	if *policyPath != "" {
		p, err := config.Load(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "anolix: %v\n", err)
			return 1
		}
		policy = p
	}

	// --timing 的"起点锚"：读一次系统开机秒数（/proc/uptime 格式：秒.百分秒）。
	// 容器里执行 `cat /proc/uptime` 可拿到同一时钟的读数，相减 = 真·冷启动时间；
	// 即使套着 strace（它只拖慢进程、不动时钟）也对得上。
	if *timing {
		if up, err := os.ReadFile("/proc/uptime"); err == nil {
			if fields := strings.Fields(string(up)); len(fields) > 0 {
				fmt.Fprintf(os.Stderr, "anolix: [timing] 起点 uptime=%s（可与容器内 /proc/uptime 对账）\n", fields[0])
			}
		}
	}

	// 第 5 步：把参数打包交给 launcher——校验、找 runc、生成容器 ID 都在里面做。
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
		Timing:      *timing,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "anolix: %v\n", err)
		return 1
	}

	// !!! 【值得会说】Ctrl+C 的语义就在这里：变成"取消信号"，由 launcher 负责收场。
	// 第 6 步：把 Ctrl+C / SIGTERM 变成"取消信号"（ctx）。
	// 白话：按 Ctrl+C 时不是直接暴力杀，而是通知 launcher"该收场了"——
	// 由它负责优雅终止容器并清理现场。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop() // 函数返回前取消订阅（好习惯）

	// 第 7 步：跑容器，并把退出码原样带回来。
	code, err := l.Run(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "anolix: %v\n", err)
		// 拿不到有效退出码（code<0）就统一返回 1；否则继续透传容器自己的码。
		if code < 0 {
			return 1
		}
	}
	// !!! 【值得会说】退出码链路最后一跳：容器码 → runc → anolix → shell。
	//     137 / 143 的含义见 launcher.waitExitCode 处的【面试必会】标记。
	// 退出码原样透传：0=成功；137=被 SIGKILL；143=被 SIGTERM……
	if *timing {
		// 总账：run() 入口 → 容器退出（含参数解析、策略加载、bundle 清理）。
		fmt.Fprintf(os.Stderr, "anolix: [timing] 总计（入口→退出）: %v\n", time.Since(t0).Round(100*time.Microsecond))
	}
	return code
}

// usage 打印帮助信息（写到标准错误，符合命令行惯例）。
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
  --timing         打印各阶段耗时（测启动开销用）

示例:
  anolix run --policy examples/policy.json --rootfs ./rootfs -- /probe
  anolix run --rootfs ./rootfs -- /probe hold 60   # 演示超时/中断
`)
}
