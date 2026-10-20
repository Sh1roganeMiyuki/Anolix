// Command worker 是 Anolix zygote 的 worker 负载（payload）。
//
// 它必须由 zygote 母体 spawn（不能直接跑），因为：
//   - 依赖母体通过 ExtraFiles 传进来的 warm memfd（固定在 fd 3）
//   - 依赖母体 clone 时给的 6 间房（PID ns 里它是 1 号）
//
// 职责：① 自己装 seccomp 白名单（#19：最终程序自己装）→ ② 映射母体共享热数据 →
//
//	③ 校验 → ④ 打印"物理页真共享"的证据。
//
// 用法（由母体 spawn，不手动跑）：
//
//	sudo ./bin/spawn --socket /tmp/anolix-zygote.sock -- /path/to/bin/worker
//	sudo ./bin/spawn --socket /tmp/anolix-zygote.sock -- /path/to/bin/worker hold 30
package main

import (
	"anolix/config"
	"anolix/zygote"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func main() {
	// --- 第一步：装 seccomp（worker 自己装；#19 坑1：母体代装会自缚）---
	// seccomp 不可撤销 → 必须"最终程序自己装、紧贴干活之前"。这里 worker 一启动就先装。
	// 白名单复用 config.DefaultAllowedSyscalls（Anolix 沙箱那份 battle-tested 名单）。
	if os.Getenv("ANOLIX_INIT_SECCOMP") == "1" {
		fmt.Println("seccomp:      已由 worker-init 装好，跳过自装")
	} else if !hasArg("noseccomp") {
		n, unknown, err := zygote.InstallSeccomp(zygote.DefaultPayloadAllowlist(), uint32(config.DefaultErrnoRet))
		if err != nil {
			fmt.Fprintf(os.Stderr, "worker: 装 seccomp 失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("seccomp 已装:  放行 %d 条 syscall，默认动作=ERRNO(%d=EPERM)\n", n, config.DefaultErrnoRet)
		if len(unknown) > 0 {
			fmt.Printf("  ⚠️ 名单里 %d 条没认出来（拼错=没写，#19 坑2）: %v\n", len(unknown), unknown)
		}
		probeBlocked()
	} else {
		fmt.Println("seccomp:      已跳过（noseccomp）—— 对照组")
	}

	// --- 攻击模式：触发 cgroup/seccomp 的"执法"，验证限额真生效 ---
	// 用法：./bin/worker [noseccomp] attack-oom [MB] | attack-pids | attack-syscall
	for i, a := range os.Args[1:] {
		if strings.HasPrefix(a, "attack-") {
			runAttack(os.Args[1+i:])
			return
		}
	}

	// --- 映射母体的共享热数据（fd 3 = ExtraFiles[0]） ---
	// MAP_SHARED + 同一个 memfd → 与母体、与其他 worker 共享同一批物理页。
	region, err := zygote.MapWarm(zygote.WarmFD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "worker: 映射 warm 共享区失败: %v\n", err)
		fmt.Fprintln(os.Stderr, "提示: worker 必须由 zygote 母体 spawn（母体带 --warm），不能直接跑")
		os.Exit(1)
	}
	defer syscall.Munmap(region)

	payloadSize := zygote.WarmPayloadSize(region)

	fmt.Println("=== Anolix zygote worker ===")
	fmt.Printf("in-ns pid:    %d   (新 PID ns 的 1 号)\n", os.Getpid())
	fmt.Printf("NSpid:        %s   (宿主 PID + ns 内 PID)\n", nspid())
	fmt.Printf("hostname:     %s   (新 UTS ns，值继承自母体)\n", hostname())

	// --- 校验：证明读到的是母体写入的数据，不是垃圾/私有副本 ---
	fmt.Printf("warm 共享区:   fd=%d  payload=%d bytes (%.1f MB)  magic=OK\n",
		zygote.WarmFD, payloadSize, float64(payloadSize)/1024/1024)
	if bad := zygote.VerifyWarmPattern(region); bad >= 0 {
		fmt.Printf("pattern 校验:  FAIL @ offset %d\n", bad)
	} else {
		fmt.Printf("pattern 校验:  OK (全部 %d 字节与母体写入逐字节一致)\n", payloadSize)
	}

	// --- 内存共享证据：/proc/self/smaps 里该 VMA 的统计 ---
	// Shared_Clean ≈ 整个区 → 物理页真被共享；若落在 Private_Clean 则是各拷一份。
	addr := uintptr(unsafe.Pointer(&region[0]))
	if e, err := zygote.SmapsForAddr(addr); err == nil {
		fmt.Println("--- /proc/self/smaps（该共享 VMA）---")
		fmt.Printf("Size:          %d kB\n", e.Size)
		fmt.Printf("Rss:           %d kB   (每个 worker 都\"看着\"像独占这么多)\n", e.Rss)
		fmt.Printf("Pss:           %d kB   (共享区大小/N；N 个 worker 共享则各约 1/N) ← 说真话的指标\n", e.Pss)
		fmt.Printf("Shared_Clean:  %d kB\n", e.SharedClean)
		fmt.Printf("Shared_Dirty:  %d kB   ← 共享脏页（memfd 被 write 过、无后端回写→落这里）\n", e.SharedDirty)
		fmt.Printf("Private_Clean: %d kB   ← 本进程独占（fork-CoW 未写时会落这里）\n", e.PrivateClean)
		fmt.Printf("Private_Dirty: %d kB\n", e.PrivateDirty)
	} else {
		fmt.Printf("smaps 读取失败: %v\n", err)
	}

	// --- 可选 hold：让 worker 存活，便于宿主侧检查 /proc/<host_pid>/smaps ---
	if len(os.Args) >= 3 && os.Args[1] == "hold" {
		if secs, err := strconv.Atoi(os.Args[2]); err == nil && secs > 0 {
			fmt.Printf("[hold] 存活 %d 秒（宿主侧可 cat /proc/<host_pid>/smaps 对照）\n", secs)
			time.Sleep(time.Duration(secs) * time.Second)
		}
	}
}

// nspid 读 /proc/self/status 的 NSpid 行（宿主 PID + 各层 ns 内 PID）。
func nspid() string {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return "?"
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "NSpid:"))
		}
	}
	return "?"
}

// hostname 返回当前 UTS ns 里的主机名。
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "?"
	}
	return h
}

// hasArg 判断 os.Args 里是否含某个标记（如 "noseccomp"）。
func hasArg(flag string) bool {
	for _, a := range os.Args[1:] {
		if a == flag {
			return true
		}
	}
	return false
}

// probeBlocked 调一个"不在白名单"的 syscall（sethostname=170），证明过滤器真生效。
// worker 是 root、在自己的 UTS ns 里 → 若没被 seccomp 拦，sethostname 会成功；
// 被拦则返回我们配的 errno（EPERM）。所以"成功=没拦住，EPERM=拦住了"。
func probeBlocked() {
	name := []byte("blocked")
	_, _, errno := syscall.Syscall(syscall.SYS_SETHOSTNAME,
		uintptr(unsafe.Pointer(&name[0])), uintptr(len(name)), 0)
	switch errno {
	case 0:
		fmt.Println("seccomp 探针:  sethostname → 成功   ❌ 没拦住（过滤器没生效？）")
	case syscall.EPERM:
		fmt.Println("seccomp 探针:  sethostname → EPERM  ✅ 被盖章（不在白名单）")
	default:
		fmt.Printf("seccomp 探针:  sethostname → errno=%d (%s)\n", errno, errno)
	}
}

// runAttack 分派攻击模式（触发 cgroup/seccomp 的"执法"）。
func runAttack(args []string) {
	switch args[0] {
	case "attack-oom":
		mb := 512
		if len(args) > 1 {
			if v, err := strconv.Atoi(args[1]); err == nil && v > 0 {
				mb = v
			}
		}
		attackOOM(mb)
	case "attack-pids":
		attackPids()
	case "attack-syscall":
		attackSyscall()
	default:
		fmt.Printf("未知攻击模式: %s（可用: attack-oom [MB] / attack-pids / attack-syscall）\n", args[0])
	}
}

// attackOOM 申请并逐页 touch 大量内存；超过 cgroup memory.max 应被 OOM 杀（退出码 137）。
func attackOOM(mb int) {
	fmt.Printf("[attack-oom] 申请 + 逐页 touch %d MB（超过 memory.max 应被 OOM 杀）\n", mb)
	buf := make([]byte, mb*1024*1024)
	for i := range buf {
		buf[i] = byte(i) // 每页第一次写 → 缺页 → charge cgroup
	}
	fmt.Printf("[attack-oom] 居然没死？touch 完了 %d MB —— memory.max 没生效？\n", mb)
}

// attackPids 狂 fork 子进程（让它们睡着占坑），直到 pids.max 拦住 → 期望 EAGAIN。
func attackPids() {
	fmt.Println("[attack-pids] 狂 fork 子进程，直到 pids.max 拦住（期望 EAGAIN）")
	var cmds []*exec.Cmd
	defer func() {
		for _, c := range cmds {
			_ = c.Process.Kill()
		}
	}()
	for i := 0; i < 100000; i++ {
		c := exec.Command("/bin/sleep", "60")
		if err := c.Start(); err != nil {
			fmt.Printf("[attack-pids] 第 %d 个 fork 失败: %v（期望 EAGAIN = pids.max 生效）\n", i, err)
			return
		}
		cmds = append(cmds, c)
	}
	fmt.Println("[attack-pids] fork 了 10 万个还没被拦？pids.max 没生效？")
}

// attackSyscall 调几个"不在白名单"的危险 syscall，看 seccomp 拦不拦（期望全 EPERM）。
func attackSyscall() {
	fmt.Println("[attack-syscall] 调不在白名单的危险 syscall（期望全 EPERM = 被盖章）")
	probes := []struct {
		name string
		nr   uintptr
	}{
		{"sethostname", 170},
		{"bpf", 321},
		{"keyctl", 250},
	}
	arg := []byte("x")
	for _, p := range probes {
		_, _, errno := syscall.Syscall(p.nr, uintptr(unsafe.Pointer(&arg[0])), 1, 0)
		tag := "✅ 被盖章"
		if errno != syscall.EPERM {
			tag = "❌ 不是 EPERM（没拦住 / 或 errno 不同）"
		}
		fmt.Printf("  %-12s(nr=%d) → errno=%d (%s)  %s\n", p.name, p.nr, errno, errno, tag)
	}
}
