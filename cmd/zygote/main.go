// Command zygote 是 Anolix 的母体预热守护进程。
//
// 两种运行模式（由参数决定）：
//
//	zygote                       → 母体模式：监听 AF_UNIX socket，等待 spawn 请求
//	zygote --zygote-intermediate → 中间进程模式（内部使用，由母体 re-exec 触发）
//
// 母体模式是常驻进程，核心职责：
//  1. 在指定路径监听 Unix socket
//  2. 收到 spawn 请求后执行 double-fork 协议（见 zygote.SpawnWorker）
//  3. 将 worker 的宿主 PID 返回给 client
//  4. 不管理 worker 生命周期（worker 被 reparent 后独立运行）
//
// 用法：
//
//	sudo ./zygote --socket /tmp/anolix-zygote.sock
//	sudo ./zygote --socket /tmp/anolix-zygote.sock --warm 256  # 预热 256MB 模拟重型加载
//
// 设计对照（bytedanceDoc 方案 B）：
//   - 文档：母体容器 rl-mother-v3，Python zygote_mother_v3.py，AF_UNIX /run/spawn.sock
//   - 本实现：Go 二进制，AF_UNIX 可配路径，相同的 double-fork + unshare 协议
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
	// --- 内部模式检测：intermediate ---
	// 母体通过 re-exec 自身 + --zygote-intermediate 启动中间进程。
	// 中间进程的执行逻辑完全在 zygote.RunIntermediate() 中（不会返回）。
	if len(os.Args) >= 2 && os.Args[1] == zygote.IntermediateFlag {
		zygote.RunIntermediate() // 永不返回
	}

	// --- 母体模式 ---
	socketPath := flag.String("socket", "/tmp/anolix-zygote.sock", "AF_UNIX socket 监听路径")
	warmMB := flag.Int("warm", 0, "预热内存量（MB）：分配并 touch，模拟重型初始化")
	flag.Parse()

	log.SetPrefix("zygote-mother: ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// 获取自身二进制路径（用于 re-exec intermediate）
	selfExe, err := os.Executable()
	if err != nil {
		selfExe = "/proc/self/exe"
	}

	// --- 预热（模拟母体的"重型初始化"） ---
	// bytedanceDoc 中母体已 import torch + 建好模型（RSS ≈ 660MB）。
	// 这里用显式内存分配模拟：分配 + touch → 物理页落地 →
	// 后续 fork 的 worker 通过 CoW 共享这些页。
	var warmMem []byte
	if *warmMB > 0 {
		warmMem = make([]byte, *warmMB*1024*1024)
		for i := range warmMem {
			if i%4096 == 0 {
				warmMem[i] = byte(i)
			}
		}
		log.Printf("预热完成: %d MB 内存已 touch", *warmMB)
	}
	_ = warmMem

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
		go handleSpawn(conn, selfExe)
	}
}

// handleSpawn 处理一次 spawn 请求。
func handleSpawn(conn net.Conn, selfExe string) {
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

	pid, err := zygote.SpawnWorker(selfExe, req)
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
