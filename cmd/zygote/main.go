// Command zygote 是 Anolix 的母体预热守护进程。
//
// 常驻进程，核心职责：
//  1. 在指定路径监听 Unix socket
//  2. 收到 spawn 请求后直接 clone 出带 6 间房的 worker（见 zygote.SpawnWorker）
//  3. 将 worker 的宿主 PID 返回给 client
//  4. 后台 goroutine 收尸 worker（worker 是母体的直接子进程）
//
// 用法：
//
//	sudo ./zygote --socket /tmp/anolix-zygote.sock
//	sudo ./zygote --socket /tmp/anolix-zygote.sock --warm 64  # 64MB 共享 memfd，worker mmap 共享
//
// 设计要点：
//   - 用 SysProcAttr.Cloneflags 一句 clone 出带 6 间房的 worker，无需中间进程
//   - 母体不在 PID ns 中 → clone 返回值即宿主 PID，直传回 client
//   - 旧 double-fork + re-exec 版（多付一次 Go 冷启动）已入 git 历史
package main

import (
	"anolix/zygote"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	socketPath := flag.String("socket", "/tmp/anolix-zygote.sock", "AF_UNIX socket 监听路径")
	warmMB := flag.Int("warm", 0, "预热内存量（MB）：创建共享 memfd，worker 将 mmap 共享同一份物理页")
	cgEnable := flag.Bool("cgroup", false, "给每个 worker 建专属叶子 cgroup（资源围栏）")
	cgMemMB := flag.Int("cg-memory", 0, "worker 内存上限（MB），0=不限；需配合 --cgroup")
	cgSwapMB := flag.Int("cg-swap", 0, "worker 可换出到 swap 的上限（MB），0=不许换出（memory.max 才是硬上限）")
	cgPids := flag.Int("cg-pids", 0, "worker 进程/线程数上限，0=不限；需配合 --cgroup")
	cgCPUPct := flag.Int("cg-cpu-pct", 0, "worker CPU 配额百分比（50=半核，200=两核），0=不限；需配合 --cgroup")
	// 只输出机器可读行（ANOLIX_MOTHER / ANOLIX_REAP）。并发压测用：
	// 每条人类可读日志都要抢 log 包的全局 mutex + 一次 write，
	// K=64 时 5 条/请求 = 320 次串行写，本身就会改变被测对象。
	quiet := flag.Bool("quiet", false, "只输出机器可读行，关掉人类可读日志（并发压测用）")
	flag.Parse()

	// 母体默认的 worker 资源围栏（每个 worker 一份；请求里可覆盖）。
	defLim := zygote.CgroupLimits{}
	if *cgMemMB > 0 {
		defLim.MemoryMaxBytes = int64(*cgMemMB) * 1024 * 1024
	}
	defLim.SwapMaxBytes = int64(*cgSwapMB) * 1024 * 1024 // 默认 0 → 不许换出
	if *cgPids > 0 {
		defLim.PidsMax = int64(*cgPids)
	}
	if *cgCPUPct > 0 {
		defLim.CPUQuotaUS = int64(*cgCPUPct) * 1000 // 周期 100ms → 1% = 1000µs
		defLim.CPUPeriodUS = 100000
	}

	log.SetPrefix("zygote-mother: ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// --- 预热：创建共享 memfd（模拟母体已加载的重型状态） ---
	// 设想母体已完成重型初始化（加载运行时、建好模型），worker 不必各自重来一遍。
	// Go 里 fork-continue 不安全（多线程 runtime），改用 memfd + MAP_SHARED：
	// 母体把"热数据"写进一个 memfd，worker 通过 ExtraFiles 拿到 fd 后 mmap 共享同一份物理页。
	// 只读热状态永不复制，比 fork-CoW 更优（见 zygote/warm.go）。
	var warmFile *os.File
	if *warmMB > 0 {
		wf, werr := zygote.CreateWarmMemfd(*warmMB * 1024 * 1024)
		if werr != nil {
			log.Fatalf("创建 warm memfd 失败: %v", werr)
		}
		warmFile = wf
		log.Printf("预热完成: %d MB 共享 memfd 已就绪（worker 将 mmap 共享）", *warmMB)
	}

	// --- 清理残留 socket ---
	os.Remove(*socketPath)

	// --- 监听 ---
	ln, err := net.Listen("unix", *socketPath)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", *socketPath, err)
	}
	defer ln.Close()
	os.Chmod(*socketPath, 0666)

	log.Printf("母体就绪 pid=%d socket=%s", os.Getpid(), *socketPath)
	log.Printf("设计要点: 本进程不在 PID ns 中 → fork 返回值 = 宿主 PID")

	// --- 优雅退出 ---
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("收到 %v，关闭", sig)
		ln.Close()
		os.Remove(*socketPath)
		os.Exit(0)
	}()

	// --- 主循环 ---
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// 观测：连接已从内核队列取出、但还没交给处理函数的时刻。
		// 配合 handleSpawn 里的两个点，把原来的 queue 段（dispatch→accept）拆成三段：
		//   dispatch      → accept_return   客户端 Dial + 写 + 内核队列等待
		//   accept_return → handle_start    goroutine 创建 + 被调度
		//   handle_start  → accept_ns       ReadRequest（读 socket + JSON 解析）
		acceptReturnNS := zygote.MonotonicNS()
		go handleSpawn(conn, acceptReturnNS, warmFile, *cgEnable, defLim, *quiet)
	}
}

// handleSpawn 处理一次 spawn 请求。
// acceptReturnNS 是 ln.Accept() 返回的时刻（调用方传入）；本函数开头再取一个点，
// 两者相减就是“goroutine 从创建到真正开始执行”的延迟。
func handleSpawn(conn net.Conn, acceptReturnNS int64, warmFile *os.File, cgEnable bool, defLim zygote.CgroupLimits, quiet bool) {
	defer conn.Close()

	handleStartNS := zygote.MonotonicNS()

	req, err := zygote.ReadRequest(conn)
	if err != nil {
		log.Printf("协议错误: %v", err)
		zygote.WriteResponse(conn, &zygote.SpawnResponse{
			HostPID: -1,
			Error:   fmt.Sprintf("协议错误: %v", err),
		})
		return
	}

	// 观测：请求读完的时刻（ReadRequest 返回之后）。
	// 与 dispatch_ns / accept_return_ns / handle_start_ns / abs_ns 同一根 CLOCK_MONOTONIC，
	// 可直接相减，拆出“建连排队 / 调度 / 读请求 / cgroup / clone / worker 侧”六段。
	acceptNS := zygote.MonotonicNS()

	// worker id 先定死：cgroup 叶子名、日志、注入 worker 的 ANOLIX_RUN_ID 共用同一个。
	// 重名会让 os.Mkdir 直接 EEXIST，所以空值时必须带 pid + 纳秒，不能只靠时间取模。
	wid := req.WorkerID
	if wid == "" {
		wid = fmt.Sprintf("w-%d-%d", os.Getpid(), time.Now().UnixNano())
		req.WorkerID = wid
	}

	if !quiet {
		log.Printf("spawn 请求: binary=%s args=%v id=%s", req.Binary, req.Args, wid)
	}

	// 资源围栏：为这个 worker 建专属叶子 cgroup。
	// 关键：用 clone3(CLONE_INTO_CGROUP) 让 worker "出生即在册"，没有 #20 的启动空窗。
	var cg *zygote.WorkerCgroup
	var cgDoneNS int64 // 0 = 未启用 cgroup
	if cgEnable {
		lim := defLim
		if req.Limits != nil {
			lim = *req.Limits // 请求可覆盖母体默认
		}
		c, cerr := zygote.CreateWorkerCgroup(wid, lim)
		if cerr != nil {
			log.Printf("建 cgroup 失败: %v", cerr)
			zygote.WriteResponse(conn, &zygote.SpawnResponse{HostPID: -1, Error: cerr.Error()})
			return
		}
		cg = c
		cgDoneNS = zygote.MonotonicNS()
		if !quiet {
			log.Printf("cgroup 叶子已建: %s", cg.Path())
		}
	}

	pid, err := zygote.SpawnWorker(req, warmFile, cg)
	if err != nil {
		log.Printf("spawn 失败: %v", err)
		zygote.WriteResponse(conn, &zygote.SpawnResponse{
			HostPID: -1,
			Error:   err.Error(),
		})
		return
	}
	cloneDoneNS := zygote.MonotonicNS()

	// 机器可读：并发时用 id 把母体这段与客户端 dispatch、payload abs 对回同一请求。
	log.Printf("ANOLIX_MOTHER id=%s accept_return_ns=%d handle_start_ns=%d accept_ns=%d cgroup_ns=%d clone_done_ns=%d host_pid=%d",
		wid, acceptReturnNS, handleStartNS, acceptNS, cgDoneNS, cloneDoneNS, pid)
	if !quiet {
		log.Printf("worker 已生成: host_pid=%d (内部 getpid()=1)", pid)
	}
	zygote.WriteResponse(conn, &zygote.SpawnResponse{HostPID: pid})
}
