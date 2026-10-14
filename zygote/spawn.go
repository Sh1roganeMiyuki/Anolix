// spawn.go 实现 double-fork + unshare 的核心生成逻辑。
//
// 这是整个 zygote 机制的心脏。对照 bytedanceDoc 方案 B 的协议：
//
//	mother ──fork#1──► intermediate ──unshare(6ns)──► fork#2 ──► worker
//	                      │                              │
//	                      │ 写 host PID 到 pipe          │ PID=1 in new PID ns
//	                      │ 然后退出                      │ 继承 intermediate 的 6 间房
//	                      ▼                              ▼
//	              mother 读 pipe 得到 PID         worker 独立运行
//
// 为什么是 double-fork 而不是单次 fork：
//  1. unshare(CLONE_NEWPID) 不影响调用者自身，只影响"此后创建的子进程"
//     → 必须再 fork 一次，子进程才是新 PID ns 的 1 号
//  2. intermediate 退出后 worker 被 reparent（脱离母体进程树）
//     → 母体不需要 wait() worker，不会产生僵尸
//  3. 每个 worker 拥有独立的 namespace 集合（不是共享母体的）
//     → 化解了"unshare(NEWPID) 后 N 个孩子共享一个 PID ns"的问题
//
// Go 实现注意事项：
//   - Go runtime 是多线程的，直接 fork() 不安全
//   - 解法：mother 通过 exec.Command 重新执行自身（--intermediate 模式）
//     intermediate 进程在启动后立即 LockOSThread + unshare + ForkExec
//     此时 Go runtime 的后台 goroutine 不影响（ForkExec 创建新进程，不是线程）
//   - CoW 共享：intermediate 是 mother 的 exec 副本，共享二进制只读页；
//     worker 是 intermediate 的 fork 副本，共享其地址空间（CoW）
//     真正的"预热堆共享"需要 worker 不 exec（未来迭代）
package zygote

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

// IntermediateFlag 是 mother 重新执行自身时传的标志，表示"进入 intermediate 模式"。
const IntermediateFlag = "--zygote-intermediate"

// NamespaceFlags 是 worker 需要隔离的 6 个 namespace（与 bytedanceDoc 一致）。
// 注意：不含 CLONE_NEWUSER（母体以 root 运行，worker 继承 root 身份）。
const NamespaceFlags = syscall.CLONE_NEWNS |
	syscall.CLONE_NEWPID |
	syscall.CLONE_NEWUTS |
	syscall.CLONE_NEWIPC |
	syscall.CLONE_NEWNET |
	syscall.CLONE_NEWCGROUP

// SpawnWorker 是 mother 侧的入口：执行 double-fork 协议，返回 worker 的宿主 PID。
//
// 流程：
//  1. 创建 pipe（intermediate → mother 的 PID 回传通道）
//  2. 启动 intermediate（re-exec 自身 + --zygote-intermediate）
//  3. 通过 stdin 传递 SpawnRequest JSON
//  4. 从 pipe 读取 worker 的宿主 PID
//  5. Wait intermediate 退出（回收，避免僵尸）
//  6. 返回 PID
//
// selfExe 是当前二进制的路径（通常 /proc/self/exe）。
func SpawnWorker(selfExe string, req *SpawnRequest) (int, error) {
	// --- 第 1 步：创建 PID 回传管道 ---
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return 0, fmt.Errorf("创建 pipe 失败: %w", err)
	}
	defer pipeR.Close()

	// --- 第 2 步：启动 intermediate（fork#1 的等价物） ---
	// 重新执行自身，传入 --zygote-intermediate 标志。
	// intermediate 是一个短命进程：unshare → fork worker → 写 PID → 退出。
	cmd := exec.Command(selfExe, IntermediateFlag)
	cmd.Stdin = nil // 下面手动设置
	cmd.Stderr = os.Stderr

	// 通过 ExtraFiles 把 pipe 写端传给 intermediate（fd 3）
	cmd.ExtraFiles = []*os.File{pipeW}
	// 通过 stdin 传递请求 JSON
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		pipeW.Close()
		return 0, fmt.Errorf("创建 stdin pipe 失败: %w", err)
	}

	if err := cmd.Start(); err != nil {
		pipeW.Close()
		return 0, fmt.Errorf("启动 intermediate 失败: %w", err)
	}
	// intermediate 启动后，写端由它持有；mother 侧关闭
	pipeW.Close()

	// --- 第 3 步：通过 stdin 发送请求 ---
	reqJSON, err := json.Marshal(req)
	if err != nil {
		stdinPipe.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("序列化请求失败: %w", err)
	}
	if _, err := stdinPipe.Write(reqJSON); err != nil {
		stdinPipe.Close()
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("写入请求到 intermediate 失败: %w", err)
	}
	stdinPipe.Close() // EOF 信号：intermediate 读完就知道没有更多数据

	// --- 第 4 步：从 pipe 读取 worker 的宿主 PID ---
	var pidBuf [4]byte
	if _, err := io.ReadFull(pipeR, pidBuf[:]); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("读取 worker PID 失败: %w", err)
	}
	hostPID := int(binary.BigEndian.Uint32(pidBuf[:]))

	// --- 第 5 步：等待 intermediate 退出（它写完 PID 就会 exit） ---
	// intermediate 退出后，worker 被 reparent 到 init/subreaper。
	// mother 不需要管理 worker 的生命周期。
	if err := cmd.Wait(); err != nil {
		// intermediate 非零退出不一定意味着失败（PID 已经拿到了）
		// 但如果 PID 是 0，说明确实出了问题
		if hostPID == 0 {
			return 0, fmt.Errorf("intermediate 异常退出: %w", err)
		}
	}

	if hostPID <= 0 {
		return 0, fmt.Errorf("intermediate 返回了无效 PID: %d", hostPID)
	}

	// --- 第 6 步：返回 ---
	return hostPID, nil
}

// RunIntermediate 是 intermediate 进程的主逻辑。
// 由 mother 通过 re-exec 调用（--zygote-intermediate 标志）。
//
// 这个函数执行：
//  1. 从 stdin 读取 SpawnRequest
//  2. LockOSThread（确保 unshare 影响正确的线程）
//  3. unshare(6 个 namespace)
//  4. ForkExec 创建 worker（fork#2）
//  5. 将 worker 的宿主 PID 写入 fd 3（pipe 回传给 mother）
//  6. 退出（worker 被 reparent，intermediate 的生命结束）
//
// 重要：这个函数永远不会正常返回（要么 os.Exit，要么 panic）。
func RunIntermediate() {
	// --- 读取请求 ---
	reqJSON, err := io.ReadAll(os.Stdin)
	if err != nil || len(reqJSON) == 0 {
		fmt.Fprintf(os.Stderr, "zygote-intermediate: 读取请求失败: %v\n", err)
		os.Exit(1)
	}
	var req SpawnRequest
	if err := json.Unmarshal(reqJSON, &req); err != nil {
		fmt.Fprintf(os.Stderr, "zygote-intermediate: 解析请求失败: %v\n", err)
		os.Exit(1)
	}

	// --- 锁定 OS 线程 ---
	// unshare() 是 per-thread 的：只影响调用线程的 namespace 归属。
	// LockOSThread 确保后续 unshare + ForkExec 在同一个线程上执行。
	runtime.LockOSThread()

	// --- unshare 6 个 namespace ---
	// 调用后：
	//   - 本线程（intermediate）进入新的 MNT/UTS/IPC/NET/CGROUP ns
	//   - 本线程仍在宿主 PID ns 中（unshare(NEWPID) 只影响此后创建的子进程）
	//   - 下一次 fork 的子进程将成为新 PID ns 的 1 号
	if err := syscall.Unshare(NamespaceFlags); err != nil {
		fmt.Fprintf(os.Stderr, "zygote-intermediate: unshare 失败: %v\n", err)
		writePID(0) // 通知 mother 失败
		os.Exit(1)
	}

	// --- 准备 worker 的进程属性 ---
	argv := append([]string{req.Binary}, req.Args...)
	env := req.Env
	if len(env) == 0 {
		env = os.Environ() // 继承母体环境
	}

	// 构建 ProcAttr
	procAttr := &syscall.ProcAttr{
		Dir:   req.Cwd,
		Env:   env,
		Files: []uintptr{0, 1, 2}, // stdin/stdout/stderr 继承
		Sys: &syscall.SysProcAttr{
			// Setsid: worker 成为新 session leader（脱离 intermediate 的控制终端）
			Setsid: true,
		},
	}

	// --- fork#2：创建 worker ---
	// ForkExec 内部调用 clone()（不带 CLONE_NEWPID flag，因为已经 unshare 过了）。
	// 由于本线程已 unshare(CLONE_NEWPID)，clone 出的子进程自动进入新 PID ns。
	// 返回值 pid = worker 在宿主 PID ns 中的编号（因为 intermediate 仍在宿主 PID ns）。
	pid, err := syscall.ForkExec(req.Binary, argv, procAttr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zygote-intermediate: ForkExec 失败: %v\n", err)
		writePID(0)
		os.Exit(1)
	}

	// --- 回传宿主 PID ---
	// 这就是文档里"fork#2 返回的 PID 即为宿主 PID，无需 /proc 扫描"的落点。
	writePID(pid)

	// --- intermediate 退出 ---
	// 退出后：
	//   - worker 成为孤儿，被 reparent 到最近的 subreaper 或 host init
	//   - mother 的 Wait() 回收 intermediate（不产生僵尸）
	//   - worker 独立运行，mother 不持有其 wait 责任
	os.Exit(0)
}

// writePID 将 PID 写入 fd 3（mother 传过来的 pipe 写端）。
// 格式：4 字节大端 uint32。
func writePID(pid int) {
	// fd 3 = ExtraFiles[0]（Go 的 exec 把 ExtraFiles 映射到 fd 3, 4, 5...）
	f := os.NewFile(3, "pid-pipe")
	if f == nil {
		return
	}
	defer f.Close()
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(pid))
	f.Write(buf[:])
}
