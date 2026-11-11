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
	"bufio"
	"errors"
	"fmt"
	"net"
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
	// `probe net [tcp host:port | dns name]`：网络数据面调试子命令。
	// 它不参与沙箱断言，只把容器里真实看到的接口/路由/DNS 打出来。
	if len(os.Args) > 1 && os.Args[1] == "net" {
		return runNet(os.Args[2:])
	}

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

	fmt.Println("=== Anolix sandbox 探针 ===")
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

	// 5. seccomp 探测：网络档位下 socket 应可用；默认无网档位下应被拦截。
	// 两个调用均无需特权，若返回 EPERM/ENOSYS 即可确认是 seccomp 拦截；
	// 返回的 errno 由 policy 的 errnoRet 决定（EPERM 或 ENOSYS）。
	if os.Getenv("ANOLIX_NETWORK_MODE") == "bridge" {
		checkNetworkEnabled(check)
	} else {
		errno, err := probeSocket()
		check(blocked(errno), "seccomp 拦截 socket", describeProbe(errno, err))
	}

	errno, err := probePtrace()
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

// runNet 是 `probe net` 的实现：打印网络快照，可选做连通性测试。
//
// 用法：
//
//	probe net                      # 快照
//	probe net tcp 10.88.0.1:80     # 尝试 TCP 连接
//	probe net dns example.com      # 尝试域名解析
func runNet(args []string) int {
	fmt.Println("=== Anolix 网络快照 ===")
	fmt.Printf("[env] mode=%s ip=%s gateway=%s\n",
		orNone(os.Getenv("ANOLIX_NETWORK_MODE")),
		orNone(os.Getenv("ANOLIX_CONTAINER_IP")),
		orNone(os.Getenv("ANOLIX_GATEWAY")))
	printInterfaces()
	printRoutes()
	printResolv()

	if len(args) == 0 {
		return 0
	}
	switch args[0] {
	case "tcp":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "用法: probe net tcp <host:port>")
			return 2
		}
		conn, err := net.DialTimeout("tcp", args[1], 3*time.Second)
		if err != nil {
			fmt.Printf("[fail] tcp %s: %v\n", args[1], err)
			return 1
		}
		_ = conn.Close()
		fmt.Printf("[ok]   tcp %s 可连通\n", args[1])
		return 0
	case "dns":
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "用法: probe net dns <域名>")
			return 2
		}
		addrs, err := net.LookupHost(args[1])
		if err != nil {
			fmt.Printf("[fail] dns %s: %v\n", args[1], err)
			return 1
		}
		fmt.Printf("[ok]   dns %s → %s\n", args[1], strings.Join(addrs, ", "))
		return 0
	case "serve":
		// 端口映射的测试服务：在容器内监听，宿主经 DNAT 访问。
		if len(args) != 2 {
			fmt.Fprintln(os.Stderr, "用法: probe net serve <端口>")
			return 2
		}
		ln, err := net.Listen("tcp", ":"+args[1])
		if err != nil {
			fmt.Printf("[fail] listen :%s: %v\n", args[1], err)
			return 1
		}
		defer ln.Close()
		fmt.Printf("[ok]   监听 :%s\n", args[1])
		for {
			conn, err := ln.Accept()
			if err != nil {
				fmt.Printf("[fail] accept: %v\n", err)
				return 1
			}
			fmt.Fprintln(conn, "anolix probe")
			_ = conn.Close()
		}
	default:
		fmt.Fprintf(os.Stderr, "未知子命令 %q（可选 tcp / dns）\n", args[0])
		return 2
	}
}

// checkNetworkEnabled 是网络档位下的正向断言。
//
// 与“无网档位断言 socket 被拦”恰好相反：同一份探针要能回答两种问题——
// “门关上了吗”和“门打开后路通不通”。
func checkNetworkEnabled(check func(bool, string, string)) {
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		check(false, "网络接口 eth0", fmt.Sprintf("不存在或不可读: %v", err))
	} else {
		check(true, "网络接口 eth0", fmt.Sprintf("mtu=%d flags=%s", iface.MTU, iface.Flags))
		check(iface.Flags&net.FlagUp != 0, "eth0 UP", iface.Flags.String())
		addrs, aerr := iface.Addrs()
		if aerr != nil {
			check(false, "eth0 地址", aerr.Error())
		} else {
			var v4 []string
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
					v4 = append(v4, ipnet.String())
				}
			}
			check(len(v4) > 0, "eth0 IPv4 地址", strings.Join(v4, ", "))
		}
	}
	check(hasDefaultRoute(), "默认路由", "从 /proc/net/route 读取")
	errno, err := probeSocket()
	check(errno == 0, "socket 可用（网络档位）", describeProbe(errno, err))

	// AF_UNIX 过滤只在“用户没有显式放行 socket”时由 launcher 打开断言，
	// 避免把用户的自定义名单误判成失败。
	if os.Getenv("ANOLIX_NETWORK_STRICT_SOCKET") == "1" {
		uerrno, uerr := probeSocketDomain(syscall.AF_UNIX)
		check(blocked(uerrno), "seccomp 拦截 AF_UNIX socket", describeProbe(uerrno, uerr))
	}
}

// printInterfaces 打印容器内所有接口与地址（走 netlink）。
func printInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Printf("[ifaces] 读取失败: %v\n", err)
		return
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		var list []string
		for _, addr := range addrs {
			list = append(list, addr.String())
		}
		fmt.Printf("[iface] %-8s mtu=%-5d flags=%-24s addrs=%s\n",
			iface.Name, iface.MTU, iface.Flags, strings.Join(list, ","))
	}
}

// printRoutes 把 /proc/net/route 的十六进制字段翻译成人能读的地址。
func printRoutes() {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		fmt.Printf("[route] 读取失败: %v\n", err)
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false // 跳过表头
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 {
			continue
		}
		flags, _ := strconv.ParseUint(fields[3], 16, 32)
		kind := ""
		if flags&0x2 != 0 {
			kind = " (gateway)"
		}
		fmt.Printf("[route] iface=%-6s dst=%-15s gw=%-15s mask=%-15s%s\n",
			fields[0], parseHexIPv4(fields[1]), parseHexIPv4(fields[2]), parseHexIPv4(fields[7]), kind)
	}
}

// printResolv 打印容器里实际看到的 DNS 配置。
func printResolv() {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		fmt.Printf("[resolv] 读取失败: %v\n", err)
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fmt.Printf("[resolv] %s\n", line)
	}
}

// hasDefaultRoute 判断容器里是否存在默认路由（Destination = 0.0.0.0）。
func hasDefaultRoute() bool {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return false
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 8 && fields[1] == "00000000" {
			return true
		}
	}
	return false
}

// parseHexIPv4 把 /proc/net/route 的小端十六进制地址转成点分十进制。
func parseHexIPv4(s string) string {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return s
	}
	return fmt.Sprintf("%d.%d.%d.%d", byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
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
	return probeSocketDomain(syscall.AF_INET)
}

// probeSocketDomain 尝试创建指定地址族的 socket；返回 errno（0 = 成功）。
// 网络档位下 AF_UNIX 应被 seccomp 参数过滤拦下，AF_INET 应放行。
func probeSocketDomain(domain int) (syscall.Errno, error) {
	fd, err := syscall.Socket(domain, syscall.SOCK_STREAM, 0)
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
