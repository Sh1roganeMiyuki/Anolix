// Command probe 是 Anolix 的最小沙箱探针。
//
// 静态编译（CGO_ENABLED=0）后放入最小 rootfs，作为容器 init 运行，
// 用于验证沙箱环境是否符合预期：PID/UTS 隔离、能力集清空、
// NoNewPrivileges 生效，以及 seccomp 是否按 policy 正确拦截危险系统调用。
//
// 用法：
//
//	./anolix run --policy examples/policy.json --rootfs ./rootfs -- /probe
//	./anolix run --rootfs ./rootfs -- /probe hold 60   # 仅休眠，演示超时/中断
//
// 退出码：容器内全部检查通过为 0，存在未通过项为 1；
// 在宿主机直接运行时不执行断言（仅输出诊断信息），退出码为 0。
package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// expectHostname 是 launcher 为容器 UTS namespace 设置的主机名。
const expectHostname = "anolix"

func main() {
	os.Exit(run())
}

func run() int {
	// `probe hold <秒>`：仅休眠，便于演示 --timeout 与 Ctrl+C 中断。
	if len(os.Args) > 2 && os.Args[1] == "hold" {
		secs, err := strconv.Atoi(os.Args[2])
		if err != nil || secs < 0 {
			fmt.Fprintln(os.Stderr, "用法: probe hold <秒>")
			return 2
		}
		fmt.Printf("[info] 休眠 %d 秒（可用 --timeout 或 Ctrl+C 终止）\n", secs)
		time.Sleep(time.Duration(secs) * time.Second)
		return 0
	}

	status := readStatus()
	inContainer := os.Getpid() == 1 || hostname() == expectHostname

	fmt.Println("=== Anolix 沙箱探针 ===")
	if !inContainer {
		fmt.Println("[info] 未检测到 Anolix 沙箱环境（疑似在宿主机直接运行），仅输出诊断信息")
	}
	fmt.Printf("[info] 进程: pid=%d ppid=%d uid=%d euid=%d gid=%d egid=%d\n",
		os.Getpid(), os.Getppid(), os.Getuid(), os.Geteuid(), os.Getgid(), os.Getegid())
	fmt.Printf("[info] 主机名: %s\n", hostname())
	fmt.Printf("[info] 命名空间: %s\n", namespaceInfo())
	fmt.Printf("[info] NoNewPrivs=%s CapEff=%s\n", orNone(status["NoNewPrivs"]), orNone(status["CapEff"]))

	failed := 0
	check := func(ok bool, name, detail string) {
		if !inContainer {
			fmt.Printf("[info] %s: %s\n", name, detail)
			return
		}
		if ok {
			fmt.Printf("[ok]   %s: %s\n", name, detail)
			return
		}
		failed++
		fmt.Printf("[fail] %s: %s\n", name, detail)
	}

	// 1. PID namespace：容器 init 应为 pid 1。
	check(os.Getpid() == 1, "PID 隔离", fmt.Sprintf("pid=%d（期望 1）", os.Getpid()))

	// 2. UTS namespace：主机名应为 anolix。
	check(hostname() == expectHostname, "UTS 隔离",
		fmt.Sprintf("hostname=%s（期望 %s）", hostname(), expectHostname))

	// 3. 提权防护与能力集。
	check(status["NoNewPrivs"] == "1", "NoNewPrivileges",
		fmt.Sprintf("NoNewPrivs=%s（期望 1）", orNone(status["NoNewPrivs"])))
	check(strings.TrimSpace(status["CapEff"]) == "0000000000000000", "能力集清空",
		fmt.Sprintf("CapEff=%s（期望全 0）", orNone(status["CapEff"])))

	// 4. rootfs 可写（openat/write/unlink 需在 policy 放行名单中）。
	if err := probeWrite(); err != nil {
		check(false, "rootfs 可写", fmt.Sprintf("写入测试文件失败: %v", err))
	} else {
		check(true, "rootfs 可写", "成功写入并删除测试文件")
	}

	// 5. seccomp 探测：socket / ptrace 默认不在放行名单中，应被拦截；
	// 两个调用均无需特权，若返回 EPERM/ENOSYS 即可确认是 seccomp 拦截；
	// 返回的 errno 由 policy 的 errnoRet 决定（EPERM 或 ENOSYS）。
	errno, err := probeSocket()
	check(blocked(errno), "seccomp 拦截 socket", describeProbe(errno, err))

	errno, err = probePtrace()
	check(blocked(errno), "seccomp 拦截 ptrace", describeProbe(errno, err))

	if !inContainer {
		fmt.Println("=== 结果: 宿主环境诊断完成（未执行沙箱断言） ===")
		return 0
	}
	if failed > 0 {
		fmt.Printf("=== 结果: %d 项检查未通过 ===\n", failed)
		return 1
	}
	fmt.Println("=== 结果: 全部检查通过 ===")
	return 0
}

// readStatus 解析 /proc/self/status 为字段映射。
func readStatus() map[string]string {
	fields := make(map[string]string)
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fields
	}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return fields
}

func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "?"
	}
	return name
}

// namespaceInfo 汇总各命名空间的 inode（不同 inode 即发生了隔离）。
func namespaceInfo() string {
	names := []string{"pid", "mnt", "uts", "net", "ipc", "cgroup"}
	parts := make([]string, 0, len(names))
	for _, ns := range names {
		target, err := os.Readlink("/proc/self/ns/" + ns)
		if err != nil {
			continue
		}
		// target 形如 pid:[4026531836]，仅保留 inode 编号。
		if i := strings.LastIndexByte(target, '['); i >= 0 {
			target = target[i+1:]
		}
		parts = append(parts, ns+":"+strings.Trim(target, "]"))
	}
	return strings.Join(parts, " ")
}

// probeWrite 验证 rootfs 可写：优先写入 /tmp（标准 1777 目录，
// 容器 root 无 CAP_DAC_OVERRIDE 时仍可写），无 /tmp 时回退到根目录。
func probeWrite() error {
	path := "/probe-write-test"
	if info, err := os.Stat("/tmp"); err == nil && info.IsDir() {
		path = "/tmp/probe-write-test"
	}
	if err := os.WriteFile(path, []byte("anolix probe\n"), 0o600); err != nil {
		return err
	}
	return os.Remove(path)
}

// probeSocket 尝试创建 AF_INET socket；返回 errno（0 表示调用成功）。
func probeSocket() (syscall.Errno, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err == nil {
		_ = syscall.Close(fd)
		return 0, nil
	}
	return errnoOf(err), err
}

// probePtrace 尝试 ptrace(PTRACE_TRACEME)：该调用无需任何特权，
// 若未被拦截会成功执行；返回 errno（0 表示调用成功）。
func probePtrace() (syscall.Errno, error) {
	const ptraceTraceme = 0
	_, _, errno := syscall.Syscall(syscall.SYS_PTRACE, ptraceTraceme, 0, 0)
	if errno != 0 {
		return errno, errno
	}
	return 0, nil
}

// blocked 判断 errno 是否表明系统调用被 seccomp 拦截。
func blocked(errno syscall.Errno) bool {
	return errno == syscall.EPERM || errno == syscall.ENOSYS
}

func describeProbe(errno syscall.Errno, err error) string {
	if err == nil {
		return "系统调用成功执行（未被拦截）"
	}
	return fmt.Sprintf("返回 %s（被拦截时应为 EPERM=1 或 ENOSYS=38，由 policy.errnoRet 决定）", errnoText(errno))
}

func errnoText(errno syscall.Errno) string {
	if name, ok := errnoNames[errno]; ok {
		return fmt.Sprintf("%s(%d)", name, int(errno))
	}
	return fmt.Sprintf("errno %d", int(errno))
}

var errnoNames = map[syscall.Errno]string{
	syscall.EPERM:  "EPERM",
	syscall.ENOENT: "ENOENT",
	syscall.ENOSYS: "ENOSYS",
}

func errnoOf(err error) syscall.Errno {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return ^syscall.Errno(0) // 理论上不会发生
}

func orNone(v string) string {
	if v == "" {
		return "(不可用)"
	}
	return v
}
