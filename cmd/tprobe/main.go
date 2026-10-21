// Command tprobe 是“跑到就报时”的最小 payload，用来做 A/B 启动对比的裁判。
//
// 两条启动路径（runc 经 anolix / 自建 zygote 母体）都跑同一个 tprobe，
// 都在这里停下并输出"相对起点"的纳秒数。于是两侧的终点是同一个瞬间——
// payload 的第一条用户态指令，而不是"容器退出了""init 起来了"这种模糊口径。
//
// 起点由父进程经 ANOLIX_T0_NS 注入（CLOCK_MONOTONIC 纳秒）：
//   - runc 路径：anolix --timing 在入口处取，写进容器 env
//   - zygote 路径：spawn 客户端在参数解析后取，母体透传给 worker-init
//
// 输出两行（并发归因靠第二行）：
//
//	PAYLOAD_NS=<纳秒>                          ; 拿不到起点时输出 -1
//	PAYLOAD_META run=<id> t0_ns=<n> abs_ns=<n> ; abs_ns = CLOCK_MONOTONIC 绝对时刻
//
// 第一行保持旧格式（ab/bench/harden 脚本按它解析）；第二行给并发场景对账用：
// run id 把这一行对回某个 spawn 请求，abs_ns 与客户端 dispatch_ns、母体 accept_ns
// 是同一根时间轴（都是 CLOCK_MONOTONIC），可以直接相减算排队与完成时刻。
//
// ⚠️ 必须静态编译（rootfs 里没有动态链接器）：
//
//	CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

// clockMonotonic 是 CLOCK_MONOTONIC 在 x86-64 Linux 上的值。
const clockMonotonic = 1

func monotonicNS() int64 {
	var ts syscall.Timespec
	if _, _, e := syscall.RawSyscall(syscall.SYS_CLOCK_GETTIME,
		clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0); e != 0 {
		return 0
	}
	return ts.Nano()
}

func main() {
	t1 := monotonicNS()
	t0, _ := strconv.ParseInt(os.Getenv("ANOLIX_T0_NS"), 10, 64)
	if t0 == 0 {
		fmt.Println("PAYLOAD_NS=-1")
		return
	}
	fmt.Printf("PAYLOAD_NS=%d\n", t1-t0)
	fmt.Printf("PAYLOAD_META run=%s t0_ns=%d abs_ns=%d\n", os.Getenv("ANOLIX_RUN_ID"), t0, t1)
}
