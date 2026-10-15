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
// 设计对照（bytedanceDoc 方案 B）：
//   - 文档：母体容器 rl-mother-v3，Python zygote_mother_v3.py，AF_UNIX /run/spawn.sock，
//     double-fork + unshare（Python 的 os.fork 不带 flags，只能 unshare+fork，故需中间进程）
//   - 本实现：Go 二进制，AF_UNIX 可配路径；用 SysProcAttr.Cloneflags 一步 clone，
//     省掉中间进程与那次 re-exec 的 Go 冷启动（旧 double-fork 版已入 git 历史）
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
)

func main() {
	socketPath := flag.String("socket", "/tmp/anolix-zygote.sock", "AF_UNIX socket 监听路径")
	warmMB := flag.Int("warm", 0, "预热内存量（MB）：创建共享 memfd，worker 将 mmap 共享同一份物理页")
	flag.Parse()

	log.SetPrefix("zygote-mother: ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// --- 预热：创建共享 memfd（模拟母体已加载的重型状态） ---
	// bytedanceDoc 中母体已 import torch + 建好模型（RSS ≈ 660MB），worker fork 后
	// 通过 CoW 共享这些页。Go 里 fork-continue 不安全，改用 memfd + MAP_SHARED：
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
		go handleSpawn(conn, warmFile)
	}
}

// handleSpawn 处理一次 spawn 请求。
func handleSpawn(conn net.Conn, warmFile *os.File) {
	defer conn.Close()

	req, err := zygote.ReadRequest(conn)
	if err != nil {
		log.Printf("协议错误: %v", err)
		zygote.WriteResponse(conn, &zygote.SpawnResponse{
			HostPID: -1,
			Error:   fmt.Sprintf("协议错误: %v", err),
		})
		return
	}

	log.Printf("spawn 请求: binary=%s args=%v id=%s", req.Binary, req.Args, req.WorkerID)

	pid, err := zygote.SpawnWorker(req, warmFile)
	if err != nil {
		log.Printf("spawn 失败: %v", err)
		zygote.WriteResponse(conn, &zygote.SpawnResponse{
			HostPID: -1,
			Error:   err.Error(),
		})
		return
	}

	log.Printf("worker 已生成: host_pid=%d (内部 getpid()=1)", pid)
	zygote.WriteResponse(conn, &zygote.SpawnResponse{HostPID: pid})
}
