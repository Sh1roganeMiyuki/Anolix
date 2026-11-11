package zygote

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// TestIfreqSize 盯住与内核 ABI 的一致性：struct ifreq 必须是 40 字节。
// 尺寸错了，ioctl 会读写到栈上的相邻内存，表现为“偶尔成功、偶尔 EFAULT”。
func TestIfreqSize(t *testing.T) {
	if got := unsafe.Sizeof(ifreq{}); got != 40 {
		t.Fatalf("ifreq 尺寸 = %d, 期望 40（内核 struct ifreq）", got)
	}
}

// TestBringLoopbackUpInNewNetNS 在全新的 user+net namespace 里验证：
// 新 netns 的 lo 初始是 down，BringLoopbackUp() 之后变成 up。
//
// 为什么用子进程 + Cloneflags 而不是在当前进程 unshare：
// 测试进程不能换掉 go test 自己的 netns；子进程失败（例如发行版禁了
// 非特权 user namespace）时跳过，不把环境限制当成代码错误。
func TestBringLoopbackUpInNewNetNS(t *testing.T) {
	if os.Getenv("ANOLIX_TEST_LOOPBACK_HELPER") == "1" {
		os.Exit(runLoopbackHelper())
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestBringLoopbackUpInNewNetNS")
	cmd.Env = append(os.Environ(), "ANOLIX_TEST_LOOPBACK_HELPER=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Geteuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getegid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 3 {
			// 退出码 3 = 子进程已经进入新 netns，但验证本身失败。
			t.Fatalf("子进程验证失败:\n%s", out)
		}
		t.Skipf("无法创建测试 netns（userns 可能被禁用），跳过: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ANOLIX_LOOPBACK_OK") {
		t.Fatalf("子进程未报告成功标志:\n%s", out)
	}
}

// runLoopbackHelper 是子进程里的验证逻辑：成功返回 0，逻辑失败返回 3。
func runLoopbackHelper() int {
	flags, err := loopbackFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取 lo 标志失败: %v\n", err)
		return 3
	}
	if flags&iffUp != 0 {
		fmt.Fprintf(os.Stderr, "新 netns 的 lo 不应一开始就是 up, flags=0x%x\n", flags)
		return 3
	}
	if err := BringLoopbackUp(); err != nil {
		fmt.Fprintf(os.Stderr, "BringLoopbackUp() 出错: %v\n", err)
		return 3
	}
	flags, err = loopbackFlags()
	if err != nil {
		fmt.Fprintf(os.Stderr, "再次读取 lo 标志失败: %v\n", err)
		return 3
	}
	if flags&iffUp == 0 {
		fmt.Fprintf(os.Stderr, "BringLoopbackUp() 后 lo 仍是 down, flags=0x%x\n", flags)
		return 3
	}
	fmt.Println("ANOLIX_LOOPBACK_OK")
	return 0
}
