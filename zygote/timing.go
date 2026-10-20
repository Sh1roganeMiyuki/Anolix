// timing.go 提供跨进程的分段计时。
//
// 为什么需要它：一次 spawn 的耗时分散在两处——母体的 clone，和 worker-init 里的
// rootfs 装修与 seccomp 编译。要把它们拆开看，两端必须读同一根时间轴。
//
// 做法：母体在 clone 之前取一次 CLOCK_MONOTONIC，经环境变量传给 worker-init；
// worker-init 在每个阶段结束时再取一次，相减即得相对起点的耗时。
// CLOCK_MONOTONIC 是系统级时钟，跨 execve 有效（time.Now() 的单调部分只在进程内
// 有效，换不了进程，用不了）。
//
// 输出（stderr 一行，便于脚本 grep 归组）：
//
//	ANOLIX_TIMING run=<id> stage=<stage> ns=<相对起点纳秒>
package zygote

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	// TimingEnv 是母体注入的起点时刻（CLOCK_MONOTONIC 纳秒）。
	TimingEnv = "ANOLIX_T0_NS"
	// RunIDEnv 是本次 spawn 的标识，打点时原样带出，供脚本按次归组。
	RunIDEnv = "ANOLIX_RUN_ID"
)

// clockMonotonic 是 CLOCK_MONOTONIC 在 x86-64 Linux 上的值。
// 标准库 syscall 不再导出 ClockGettime/CLOCK_MONOTONIC，只能自己发系统调用。
const clockMonotonic = 1

// MonotonicNS 返回 CLOCK_MONOTONIC 的纳秒数（系统级时钟，跨进程可比）。
func MonotonicNS() int64 {
	var ts syscall.Timespec
	_, _, e := syscall.RawSyscall(syscall.SYS_CLOCK_GETTIME,
		clockMonotonic, uintptr(unsafe.Pointer(&ts)), 0)
	if e != 0 {
		return 0
	}
	return ts.Nano()
}

// Mark 打一个点：往 stderr 写一行，带相对起点的纳秒数。
//
// 没有收到起点（比如单独运行 worker-init）时以当前时刻兜底，相对值为 0——
// 单独跑时这些数字没有横向意义，不影响正常 spawn 的测量。
func Mark(stage string) {
	// 先取起点再取当下。写成 MonotonicNS()-startNS() 是反的：Go 从左到右求值，
	// 会先取“现在”再取起点，兜底路径下相减就成了负数。
	t0 := startNS()
	rel := MonotonicNS() - t0
	fmt.Fprintf(os.Stderr, "ANOLIX_TIMING run=%s stage=%s ns=%d\n",
		os.Getenv(RunIDEnv), stage, rel)
}

// startNS 读母体注入的起点；读不到就以当前时刻兜底。
func startNS() int64 {
	if v := os.Getenv(TimingEnv); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return MonotonicNS()
}

// TimingEnvs 返回要注入给 worker 的环境变量（母体在 clone 前调用）。
func TimingEnvs(t0 int64, runID string) []string {
	return []string{
		fmt.Sprintf("%s=%d", TimingEnv, t0),
		fmt.Sprintf("%s=%s", RunIDEnv, runID),
	}
}
