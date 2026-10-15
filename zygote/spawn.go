// spawn.go 实现 worker 生成：直接用 clone(2) 带 namespace flags，一步到位。
//
// 对照 bytedanceDoc 方案 B 的演进（旧 double-fork 版已入 git 历史）：
//
//	旧版（double-fork + unshare）：
//	  mother ──fork#1──► intermediate ──unshare(6ns)──► fork#2 ──► worker
//	  问题：intermediate 是 re-exec 的一份全新 Go 进程，白付一次 Go runtime 冷启动
//	  （strace 实测约 25ms），而 zygote 的本意正是"省掉初始化"——方向相反。
//
//	新版（直接 clone）：
//	  mother ──clone(CLONE_NEW*)──► worker（直接出生在 6 间新房里，pid=1）
//	  省掉 intermediate：Go 的 SysProcAttr.Cloneflags 把 flags 透给 clone(2)，
//	  内核在 clone 那一刻原子建好 namespace——无需 unshare、无需中间进程。
//
// 为什么 Go 能一步、文档（Python）要两步：
//   - Python：os.fork() 不带 flags，只能 unshare()+fork()；且 unshare 改的是调用者自己，
//     母体不能去 unshare → 必须借道一次性中间进程。这是"机制选型"逼出来的，不是语言高下。
//   - Go：exec.Cmd.SysProcAttr.Cloneflags 直接支持 clone flags → 一步 clone 出带 ns 的孩子。
//     （C 同理：runc 的 nsexec.c 就是 clone 带 flags。）
//
// 代价（旧版 intermediate 的第二职责，现在母体自己接）：
//   - 旧版：intermediate 退出 → worker 自动 reparent → 母体免收尸。
//   - 新版：worker 是母体的直接子进程 → 母体必须自己 Wait 收尸，否则 worker 退出后留僵尸。
//     这里用一个后台 goroutine 兜住。
package zygote

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// NamespaceFlags 是 worker 需要隔离的 6 个 namespace（与 bytedanceDoc 一致）。
// 传给 clone(2)：孩子一出生就在这 6 间新房里；其中 CLONE_NEWPID 让孩子成为新 PID ns 的 1 号。
// 不含 CLONE_NEWUSER（母体以 root 运行，worker 继承 root 身份）。
const NamespaceFlags = syscall.CLONE_NEWNS |
	syscall.CLONE_NEWPID |
	syscall.CLONE_NEWUTS |
	syscall.CLONE_NEWIPC |
	syscall.CLONE_NEWNET |
	syscall.CLONE_NEWCGROUP

// SpawnWorker 生成一个 worker，返回其宿主 PID。
//
// 流程（一步到位，无中间进程）：
//  1. exec.Command + SysProcAttr{Cloneflags: 6ns} 构造命令
//  2. 若 warmFile 非空，通过 ExtraFiles 传给 worker（worker 侧看到 fd 3）
//  3. cmd.Start() → 内核 clone(2) 带 flags → worker 直接出生在新 namespace、是 pid 1
//  4. cmd.Process.Pid = worker 的宿主 PID（因为母体不在 PID ns 中）
//  5. 后台 goroutine Wait 回收，避免 worker 退出后变僵尸
//
// warmFile：母体的预热 memfd（见 warm.go）。传给它 → worker 能 mmap 共享同一份热数据；
// 传 nil → worker 不继承共享区（退化为普通 spawn）。
//
// 返回的 pid 就是 client 要的"宿主 PID"——可直接用于 kill / 读 /proc/<pid>/status。
// worker 内部 getpid() 返回 1；/proc/<hostpid>/status 的 NSpid 有两个字段（宿主 PID + ns 内 PID）。
func SpawnWorker(req *SpawnRequest, warmFile *os.File) (int, error) {
	if req == nil || req.Binary == "" {
		return 0, fmt.Errorf("请求缺少 binary")
	}

	cmd := exec.Command(req.Binary, req.Args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		// 核心：一步 clone 出带 6 间房的 worker，不需要中间进程。
		Cloneflags: NamespaceFlags,
		// 让 worker 成为新 session leader，脱离母体的终端/会话
		//（避免后台作业读终端被 SIGTTIN 停住——交接文档里踩过的坑）。
		Setsid: true,
	}

	// 把预热 memfd 传给 worker：ExtraFiles[0] → worker 侧的 fd 3（见 warm.go 约定）。
	// fd 会跨 clone+exec 继承，memfd 不依赖挂载 ns，新 mount ns 里照样能 mmap。
	if warmFile != nil {
		cmd.ExtraFiles = []*os.File{warmFile}
	}

	if len(req.Env) > 0 {
		cmd.Env = req.Env
	}
	if req.Cwd != "" {
		cmd.Dir = req.Cwd
	}
	// worker 的 stdout/stderr 接到母体的 stdout/stderr（= 母体所在终端）。
	// ⚠️ 必须显式设置：os/exec 里 Stdout 为 nil 时会被接到 /dev/null，
	// 不设则 worker 的打印（共享证据、校验结果）全部丢失。
	// 后续可改成写 per-worker 日志文件（见 spec 里 bind-mount 的 /worker-logs）。
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("clone worker 失败: %w", err)
	}

	// 关键：母体不在 PID namespace 中 → cmd.Process.Pid 就是宿主 PID。
	hostPID := cmd.Process.Pid

	// 收尸：worker 现在是母体的直接子进程（没有 intermediate 退出触发 reparent）。
	// 母体是常驻进程，必须自己 Wait，否则 worker 退出后留僵尸。
	go func() {
		_ = cmd.Wait()
	}()

	return hostPID, nil
}
