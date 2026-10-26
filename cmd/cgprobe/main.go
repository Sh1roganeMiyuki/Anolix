// Command cgprobe 是容器内的 cgroup 探针：打印当前进程看到的 cgroup 路径与限额。
//
// 用途：判断 rootless 下 crun 到底有没有把 OCI 的 resources 写进 cgroup，
// 还是静默跳过。必须在容器内运行（依赖容器自己的 cgroup namespace）。
//
// 构建（静态）：
//
//	CGO_ENABLED=0 go build -o rootfs/cgprobe ./cmd/cgprobe
package main

import (
	"fmt"
	"os"
	"strings"
)

func read(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "ERR: " + err.Error()
	}
	return strings.TrimSpace(string(b))
}

func main() {
	fmt.Println("=== cgprobe ===")
	fmt.Printf("pid:            %d\n", os.Getpid())
	fmt.Printf("/proc/self/cgroup: %s\n", read("/proc/self/cgroup"))
	for _, p := range []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/pids.max",
		"/sys/fs/cgroup/cpu.max",
		"/sys/fs/cgroup/cgroup.controllers",
		"/sys/fs/cgroup/cgroup.subtree_control",
	} {
		fmt.Printf("%-40s = %s\n", p, read(p))
	}
	// 列出直接子目录：如果 runtime 建了叶子但没有把 ns 根切过去，这里能看到。
	ents, err := os.ReadDir("/sys/fs/cgroup")
	if err != nil {
		fmt.Printf("readdir /sys/fs/cgroup: ERR: %v\n", err)
		return
	}
	for _, e := range ents {
		if e.IsDir() {
			fmt.Printf("subdir: %s\n", e.Name())
		}
	}
}
