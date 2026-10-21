// Command spawn 是 Anolix zygote 的宿主侧客户端。
//
// 连接母体的 AF_UNIX socket，发送 spawn 请求，获取 worker 的宿主 PID。
// 拿到 PID 后即可通过 kill/wait 等标准手段管理 worker。
//
// 用法：
//
//	spawn --socket /tmp/anolix-zygote.sock -- /probe
//	spawn --socket /tmp/anolix-zygote.sock --id worker-1 -- /bin/busybox sleep 60
//	spawn --socket /tmp/anolix-zygote.sock -- /bin/busybox sh -c 'echo hello; sleep 10'
//
// 设计要点：
//   - JSON 协议触发母体 clone worker，返回 worker 的宿主 PID
//   - 拿到 PID 即可 kill/管理；写 runc state.json 让运行时纳管为后续迭代
//   - 成功时额外输出一行机器可读的对账字段：
//     SPAWN_META id=<id> dispatch_ns=<n> response_ns=<n> host_pid=<n>
//     dispatch_ns 是发请求前取的 CLOCK_MONOTONIC，与 payload 的 PAYLOAD_META.abs_ns 同一根时间轴。
package main

import (
	"anolix/zygote"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	socketPath := flag.String("socket", "/tmp/anolix-zygote.sock", "母体 AF_UNIX socket 路径")
	workerID := flag.String("id", "", "worker 标识符（可选，用于日志追踪）")
	timeout := flag.Duration("timeout", 10*time.Second, "连接+请求超时")
	flag.Parse()

	// -- 之后是 worker 要执行的命令
	args := flag.Args()
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: spawn [flags] -- <binary> [args...]")
		fmt.Fprintln(os.Stderr, "示例: spawn --socket /tmp/anolix-zygote.sock -- /probe")
		os.Exit(2)
	}

	// 端到端计时的起点：与 anolix 的 --timing 同口径，都在“参数解析完成”之后取。
	// 从这里到 payload 第一条指令之间的一切（socket 往返、母体排队、clone、
	// execve、rootfs 装修、seccomp 编译）都算进启动延迟。
	t0ns := zygote.MonotonicNS()

	// 自动生成 worker ID：带上 pid 与完整纳秒，避免并发/跨轮撞名
	//（worker ID 会进 cgroup 叶子名，重名会让 os.Mkdir 直接 EEXIST）。
	id := *workerID
	if id == "" {
		id = fmt.Sprintf("worker-%d-%d", os.Getpid(), time.Now().UnixNano())
	}

	// --- 连接母体 ---
	conn, err := net.DialTimeout("unix", *socketPath, *timeout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "连接母体失败 (%s): %v\n", *socketPath, err)
		fmt.Fprintln(os.Stderr, "提示: 母体是否已启动？需要 sudo 权限运行 zygote")
		os.Exit(1)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(*timeout))

	// --- 发送 spawn 请求 ---
	req := &zygote.SpawnRequest{
		Binary:   args[0],
		Args:     args[1:],
		WorkerID: id,
		T0NS:     t0ns,
	}

	if err := zygote.WriteRequest(conn, req); err != nil {
		fmt.Fprintf(os.Stderr, "发送请求失败: %v\n", err)
		os.Exit(1)
	}

	// --- 读取响应 ---
	resp, err := zygote.ReadResponse(conn)
	responseNS := zygote.MonotonicNS()
	elapsed := time.Duration(responseNS - t0ns)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取响应失败: %v\n", err)
		os.Exit(1)
	}

	if resp.Error != "" {
		fmt.Fprintf(os.Stderr, "母体报错: %s\n", resp.Error)
		os.Exit(1)
	}

	// --- 输出结果 ---
	fmt.Printf("worker 已生成\n")
	fmt.Printf("  host_pid:    %d\n", resp.HostPID)
	fmt.Printf("  worker_id:   %s\n", id)
	fmt.Printf("  command:     %v\n", args)
	fmt.Printf("  spawn 耗时:  %v\n", elapsed.Round(time.Microsecond))
	fmt.Printf("SPAWN_META id=%s dispatch_ns=%d response_ns=%d host_pid=%d\n",
		id, t0ns, responseNS, resp.HostPID)
	fmt.Printf("\n")
	fmt.Printf("管理 worker:\n")
	fmt.Printf("  kill %d          # 终止\n", resp.HostPID)
	fmt.Printf("  cat /proc/%d/status | grep NSpid  # 查看双 PID 身份\n", resp.HostPID)
}
