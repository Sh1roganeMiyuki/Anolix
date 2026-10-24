// cgroup.go 给每个 worker 配一个专属的叶子 cgroup（资源围栏）。
//
// 为什么需要它（对照小知识点）：
//   - #9：cgroup 是"记账系统"——限额是"记账失败"的后果，不是定期巡检。
//   - #19 坑3：cgroup 归属是"户口"，由外部（宿主/母体）上，不是进程自己上。
//   - #20：若"先 clone 再写 cgroup.procs"，两步之间有**启动空窗**——worker 已能跑却不受限。
//
// 本实现用 clone3(CLONE_INTO_CGROUP) 消掉空窗：
//
//	Go 的 SysProcAttr.UseCgroupFD + CgroupFD 底层就是 clone3 带 CLONE_INTO_CGROUP，
//	让 worker **一出生就落在目标 cgroup 里**——这和 L2 的"出生就带 ns"是同一个套路：
//	不是"事后补"，是"出生就带"。所以这里**没有 #20 那个空窗**。
//
// 数据流：
//
//	母体收到 spawn → CreateWorkerCgroup（mkdir 叶子 + 写限额 + 打开目录拿 fd）
//	             → SpawnWorker 把 fd 塞进 SysProcAttr.CgroupFD
//	             → cmd.Start() → clone3(CLONE_INTO_CGROUP) → worker 出生即在叶子 cgroup
//	             → worker 退出 → 后台 goroutine Destroy（关 fd + rmdir 叶子，防泄漏）
//
// 验证（宿主侧，因为 worker 自带 CLONE_NEWCGROUP、自己看到的是 ns 根）：
//
//	cat /sys/fs/cgroup/anolix-<id>/cgroup.procs   # 应含 worker 的宿主 PID
//	cat /sys/fs/cgroup/anolix-<id>/memory.max     # 应是你设的上限
package zygote

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// cgroupRoot 是 cgroup v2 的统一挂载点。
const cgroupRoot = "/sys/fs/cgroup"

// CgroupLimits 描述一个 worker 的资源围栏。零值字段 = 不设限。
//
// 对应 cgroup v2 的三个接口文件：
//   - MemoryMaxBytes → memory.max（字节）：物理内存上限，超了触发回收/OOM（#9：可回收资源先回收再 OOM）。
//   - PidsMax        → pids.max（个数）：进程/线程数上限，超了 fork 返回 EAGAIN（#9：计数资源直接拒）。
//   - CPUQuotaUS / CPUPeriodUS → cpu.max（"$配额 $周期"，µs）：每周期最多用多少 µs CPU，
//     超了被 throttle 暂停（#9：时间资源不可回收也不能报错，只能暂停）。
type CgroupLimits struct {
	MemoryMaxBytes int64 `json:"memory_max_bytes,omitempty"`
	// SwapMaxBytes → memory.swap.max（字节）。0 = 不许换出。
	// ⚠️ 关键坑：若系统有 swap 且这里不限，memory.max 会被"换出"绕过——
	// 只限常驻内存、超出部分换到 swap，**不会 OOM**。默认 0 = 真硬上限。
	SwapMaxBytes int64 `json:"swap_max_bytes,omitempty"`
	PidsMax      int64 `json:"pids_max,omitempty"`
	CPUQuotaUS   int64 `json:"cpu_quota_us,omitempty"`
	CPUPeriodUS  int64 `json:"cpu_period_us,omitempty"`

	// Minimal 只写 memory.max，跳过 swap/pids/cpu。仅用于归因实验：
	// 判断“写文件”本身对 clone3(CLONE_INTO_CGROUP) 造成了多少干扰。
	Minimal bool `json:"-"`
}

// WorkerCgroup 是一个 worker 专属的叶子 cgroup（建好、写好限额、目录 fd 已打开）。
type WorkerCgroup struct {
	id    string
	path  string
	dirFD *os.File // 目录 fd，交给 clone3(CLONE_INTO_CGROUP) 用
}

// CreateWorkerCgroup 建一个名为 "anolix-<id>" 的叶子 cgroup，写入限额，并打开目录拿 fd。
//
// 返回的 *WorkerCgroup 交给 SpawnWorker：它会把 dirFD 塞进 SysProcAttr.CgroupFD，
// 于是 cmd.Start() 走的 clone3 会带 CLONE_INTO_CGROUP —— worker 一出生就在这个叶子里。
//
// 失败时会自动清掉已建的目录（不留半成品）。
func CreateWorkerCgroup(id string, lim CgroupLimits) (*WorkerCgroup, error) {
	if id == "" {
		return nil, fmt.Errorf("worker id 不能为空（cgroup 叶子名靠它）")
	}
	path := filepath.Join(cgroupRoot, "anolix-"+id)

	// 1) 建叶子。cgroupfs 的 mkdir 就是"创建一个 cgroup"。
	if err := os.Mkdir(path, 0755); err != nil {
		return nil, fmt.Errorf("建 cgroup 叶子 %s 失败: %w", path, err)
	}

	// 2) 写限额（只写设了值的；写失败就回滚删叶子）。
	writeLim := func(name, val string) error {
		p := filepath.Join(path, name)
		if err := os.WriteFile(p, []byte(val), 0644); err != nil {
			return fmt.Errorf("写 %s=%s 失败: %w", p, val, err)
		}
		return nil
	}
	rollback := func(err error) (*WorkerCgroup, error) {
		_ = os.Remove(path)
		return nil, err
	}
	if lim.MemoryMaxBytes > 0 {
		if err := writeLim("memory.max", strconv.FormatInt(lim.MemoryMaxBytes, 10)); err != nil {
			return rollback(err)
		}
		// 顺手把 swap 也封上：否则 memory.max 会被“换出”绕过（只限常驻、不 OOM）。
		// best-effort：无 swap 记账的系统写失败就算了。
		if !lim.Minimal {
			_ = writeLim("memory.swap.max", strconv.FormatInt(lim.SwapMaxBytes, 10))
		}
	}
	if lim.PidsMax > 0 && !lim.Minimal {
		if err := writeLim("pids.max", strconv.FormatInt(lim.PidsMax, 10)); err != nil {
			return rollback(err)
		}
	}
	if lim.CPUQuotaUS > 0 && !lim.Minimal {
		period := lim.CPUPeriodUS
		if period <= 0 {
			period = 100000 // 默认 100ms 周期
		}
		val := fmt.Sprintf("%d %d", lim.CPUQuotaUS, period)
		if err := writeLim("cpu.max", val); err != nil {
			return rollback(err)
		}
	}

	// 3) 打开目录拿 fd —— 关键一步：clone3(CLONE_INTO_CGROUP) 要的就是这个 fd。
	//    fd 必须保持打开到 cmd.Start() 完成（内核在 clone 那一刻用它）。
	fd, err := os.Open(path)
	if err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("打开 cgroup 目录 %s 失败: %w", path, err)
	}
	return &WorkerCgroup{id: id, path: path, dirFD: fd}, nil
}

// FD 返回叶子 cgroup 的目录 fd（int），供 SysProcAttr.CgroupFD 使用。
func (c *WorkerCgroup) FD() int {
	if c == nil || c.dirFD == nil {
		return -1
	}
	return int(c.dirFD.Fd())
}

// Path 返回叶子 cgroup 的绝对路径（宿主侧验证用）。
func (c *WorkerCgroup) Path() string {
	if c == nil {
		return ""
	}
	return c.path
}

// Destroy 关闭目录 fd 并删除叶子 cgroup（worker 退出后调用，防止 cgroup 泄漏）。
//
// rmdir 只在 cgroup **为空**时成功；调用时机是 worker 已 Wait 回收之后——
// worker 是其 PID ns 的 1 号，它一死整个 ns 被内核清场 → 叶子必然空 → rmdir 成功。
// 删除失败（极少数 EBUSY 竞态）不致命：留一个空叶子无害，母体退出时可统一清。
func (c *WorkerCgroup) Destroy() {
	if c == nil {
		return
	}
	if c.dirFD != nil {
		_ = c.dirFD.Close()
		c.dirFD = nil
	}
	_ = os.Remove(c.path)
}
