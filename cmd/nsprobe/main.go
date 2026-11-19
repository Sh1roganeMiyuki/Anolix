// Command nsprobe 在容器内采集“我能看到什么”，供宿主侧脚本逐项对照。
//
// 它**不做判断**——判断在脚本里，因为“隔离成不成立”必须两边比：
// 只看容器内的值没有意义，必须和宿主的值放在一起看。
//
// 输出是 key=value，一行一项，方便 shell 解析。
//
// 为什么不用 ps / ip / ls：rootfs 是最小静态 rootfs，没有这些工具；
// 而且外部工具的输出格式不稳定，直接读 /proc 和 /sys 更可靠。
//
// ⚠️ 必须静态编译：CGO_ENABLED=0 go build -o rootfs/nsprobe ./cmd/nsprobe
package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	// --- PID namespace：我应该只看到自己房间里的进程 ---
	fmt.Printf("pid.proc_count=%d\n", countNumericDirs("/proc"))
	fmt.Printf("pid.init_comm=%s\n", readTrim("/proc/1/comm"))
	fmt.Printf("pid.kill1=%s\n", probeKill1())

	// --- Mount namespace：挂载点集合应该和宿主不同 ---
	fmt.Printf("mnt.count=%d\n", countLines("/proc/self/mountinfo"))
	// WSL 上宿主的 C 盘挂在 /mnt/c；容器里能看到它 = 挂载隔离漏了。
	fmt.Printf("mnt.sees_host_disk=%v\n", exists("/mnt/c"))

	// --- Net namespace：网卡列表应该只有容器自己的 ---
	fmt.Printf("net.ifaces=%s\n", listDir("/sys/class/net"))
	fmt.Printf("net.route_count=%d\n", countLines("/proc/net/route"))

	// --- UTS namespace：主机名应该独立，且改不动宿主 ---
	fmt.Printf("uts.hostname=%s\n", hostname())
	fmt.Printf("uts.sethostname=%s\n", probeSethostname())

	// --- IPC namespace：共享内存段应该是空的/独立的 ---
	fmt.Printf("ipc.shm_count=%d\n", countLines("/proc/sysvipc/shm"))

	// --- Cgroup namespace：容器内看到的应该是自己 cgroup ns 的根 ---
	fmt.Printf("cg.self=%s\n", readTrim("/proc/self/cgroup"))

	// --- User namespace：rootless 时应能看到 uid 映射 ---
	fmt.Printf("user.uid_map=%s\n", readTrim("/proc/self/uid_map"))

	// --- ns inode：这一项是给脚本“两边比”用的 ---
	// 如果 /proc/1 是宿主 init（PID ns 没生效），这两个 inode 会不同。
	fmt.Printf("ns.mnt=%s\n", nsInode("/proc/self/ns/mnt"))
	fmt.Printf("ns.pid=%s\n", nsInode("/proc/self/ns/pid"))
	fmt.Printf("ns.net=%s\n", nsInode("/proc/self/ns/net"))
	fmt.Printf("ns.init_mnt=%s\n", nsInode("/proc/1/ns/mnt"))
}

// countNumericDirs 数一个目录下“纯数字”的子目录数量。
// /proc 下数字项就是进程，数它 = 我能看到几个进程。
func countNumericDirs(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err == nil {
			n++
		}
	}
	return n
}

// probeKill1 对 1 号进程发 0 号信号（只做权限检查，不真发）。
//
// 期望：
//   - ESRCH：1 号进程不存在（说明 PID ns 生效，1 是容器 init，但可能有别的 id）
//   - EPERM：存在但没权限（正常宿主 init 的情况）
//   - ok   ：能发，说明 1 号是自己人（容器内 init）
func probeKill1() string {
	err := syscall.Kill(1, 0)
	if err == nil {
		return "ok"
	}
	return errnoName(err)
}

// probeSethostname 尝试改主机名。
// 隔离成立时应该失败（没有 CAP_SYS_ADMIN 或 seccomp 拦着）。
func probeSethostname() string {
	err := syscall.Sethostname([]byte("anolix-probe"))
	if err == nil {
		return "ok(没被拦！)"
	}
	return errnoName(err)
}

// errnoName 把错误翻成短名，脚本按名字断言比按数字可读。
func errnoName(err error) string {
	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case syscall.EPERM:
			return "EPERM"
		case syscall.EACCES:
			return "EACCES"
		case syscall.ESRCH:
			return "ESRCH"
		case syscall.ENOENT:
			return "ENOENT"
		case syscall.EBADF:
			return "EBADF"
		case syscall.ENOSYS:
			return "ENOSYS"
		}
		return "errno" + strconv.Itoa(int(errno))
	}
	return err.Error()
}

// nsInode 返回某个 ns 文件的 inode 号。
// 同一个 namespace 的所有进程，其 /proc/<pid>/ns/<type> 指向同一个 inode。
func nsInode(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "err:" + errnoName(err)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return strconv.FormatUint(st.Ino, 10)
	}
	return "unknown"
}

// listDir 把目录项名字排好序拼成逗号分隔。
func listDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "err:" + errnoName(err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// countLines 数文件行数（读不到返回 -1，别和“0 行”混淆）。
func countLines(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return -1
	}
	if len(data) == 0 {
		return 0
	}
	return strings.Count(string(data), "\n")
}

// readTrim 读文件并去掉首尾空白（读不到返回 err:<原因>）。
func readTrim(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return "err:" + errnoName(err)
	}
	return strings.TrimSpace(string(data))
}

// exists 判断路径是否存在。
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// hostname 读 UTS namespace 里的主机名。
func hostname() string {
	name, err := os.Hostname()
	if err != nil {
		return "err:" + errnoName(err)
	}
	return name
}
