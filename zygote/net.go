package zygote

import (
	"fmt"
	"syscall"
	"unsafe"
)

// Linux 的网卡 ioctl 号与标志位（标准库 syscall 没有导出这几个 ioctl 号）。
//
// SIOCGIFFLAGS / SIOCSIFFLAGS 是 ioctl(2) 里“读/写接口标志”的两个请求，
// 参数是 struct ifreq。它们不需要外部命令（ip/ifconfig），很适合 thin init。
const (
	siocgifflags = 0x8913
	siocsifflags = 0x8914
	iffUp        = 0x1
	iffRunning   = 0x40
)

// ifreq 是 ioctl(SIOCGIFFLAGS/SIOCSIFFLAGS) 的参数结构。
//
// 内核的 struct ifreq 是 40 字节：16 字节名字 + 24 字节 union。
// 这里只用到 union 开头的 flags（2 字节），其余用填充补齐，
// 保证 Go 结构体尺寸与内核一致（net_test.go 里有 Sizeof 断言）。
type ifreq struct {
	Name  [16]byte
	Flags uint16
	_     [22]byte
}

// BringLoopbackUp 把当前网络命名空间里的 lo 接口拉起。
//
// 为什么需要它：worker 由母体 clone(CLONE_NEWNET) 一步创建，新 netns 的
// lo 默认是 down 的——任何依赖 127.0.0.1 的程序都会连不上。
// 这不是“给 worker 联网”，只是让隔离房间里的回环插座通电。
//
// 调用约束（worker-init 的顺序正好满足）：
//   - 必须在 DropCapabilities 之前：SIOCSIFFLAGS 需要 CAP_NET_ADMIN；
//   - 必须在 InstallSeccomp 之前：需要 socket(AF_INET) 与 ioctl。
//
// 耗时是“一次 socket + 两次 ioctl”，微秒级，因此没有单独打 ANOLIX_TIMING 点，
// 避免改变既有启动开销实验的分段口径。
func BringLoopbackUp() error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return fmt.Errorf("创建控制 socket 失败: %w", err)
	}
	defer syscall.Close(fd)

	var req ifreq
	copy(req.Name[:], "lo")
	if err := ioctlIfreq(fd, siocgifflags, &req); err != nil {
		return fmt.Errorf("读取 lo 标志失败: %w", err)
	}
	req.Flags |= iffUp | iffRunning
	if err := ioctlIfreq(fd, siocsifflags, &req); err != nil {
		return fmt.Errorf("拉起 lo 失败: %w", err)
	}
	return nil
}

// loopbackFlags 返回当前 netns 里 lo 的标志（测试与诊断用）。
func loopbackFlags() (uint16, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	var req ifreq
	copy(req.Name[:], "lo")
	if err := ioctlIfreq(fd, siocgifflags, &req); err != nil {
		return 0, err
	}
	return req.Flags, nil
}

// ioctlIfreq 把 ifreq 指针交给 ioctl。
func ioctlIfreq(fd int, request uintptr, req *ifreq) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, uintptr(unsafe.Pointer(req)))
	if errno != 0 {
		return errno
	}
	return nil
}
