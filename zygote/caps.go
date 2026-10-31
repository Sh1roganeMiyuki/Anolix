// caps.go 把「当前进程」的能力集合清到零。
//
// 为什么必须两步（见小知识点 49 节）：
//
//	uid 0 的进程 execve 时，内核按「root 规则」重算：
//	    P'(permitted) = P(bounding) ∪ P(permitted)
//	    P'(effective) = P'(permitted)
//
// 所以：
//   - 只清 Permitted / Effective：Bounding 还在 → 一 execve 就被补满
//   - 只拆 Bounding：Permitted 还在 → 补出来的仍然是旧的这几个
//
// 两步都做，payload 落地时才是真的零能力。
//
// 顺序也不能换：PR_CAPBSET_DROP 自身要 CAP_SETPCAP 在 effective 里，
// 所以它必须在 capset 清零之前做。
package zygote

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// prctl 选项与 capset 的 ABI 常量（内核 UAPI：prctl.h / capability.h）。
const (
	prCapbsetDrop           = 24         // PR_CAPBSET_DROP
	linuxCapabilityVersion3 = 0x20080522 // _LINUX_CAPABILITY_VERSION_3：64 位能力集用两组 32 位字表达
	maxCapNumber            = 63         // version 3 能表达的上限；内核里不存在的号由它回 EINVAL
)

// capHeader / capData 对应内核 struct __user_cap_header_struct / __user_cap_data_struct。
type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// DropCapabilities 把当前进程的能力清到零：先逐个拆 Bounding 天花板，再 capset 清空其余集合。
//
// 只能用在「已经干完所有需要能力的事、下一步就要 execve 成低权进程」的位置
// （本项目里是 worker-init 装完 rootfs 之后）。调用之后本进程基本什么也做不了。
//
// Ambient 不单独处理：本进程从未调 PR_CAP_AMBIENT_RAISE，它天然是空的；
// 而且 Inheritable 清空之后，ambient 也无法再被抬高。
func DropCapabilities() error {
	// ① 拆天花板。需要 CAP_SETPCAP，所以必须排在 capset 之前。
	for c := 0; c <= maxCapNumber; c++ {
		// EINVAL = 这个号在内核里不存在（也可以读 /proc/sys/kernel/cap_last_cap，
		// 但直接忽略 EINVAL 更省事，且不依赖文件存在）。
		if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, prCapbsetDrop, uintptr(c), 0, 0, 0, 0); e != 0 && e != syscall.EINVAL {
			return fmt.Errorf("PR_CAPBSET_DROP(%d) 失败: %w", c, e)
		}
	}

	// ② 清空 Effective / Permitted / Inheritable。pid=0 表示「当前线程」。
	hdr := capHeader{version: linuxCapabilityVersion3}
	data := [2]capData{}
	if _, _, e := syscall.Syscall6(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("capset 清零失败: %w", e)
	}

	return verifyNoCaps()
}

// verifyNoCaps 读回 /proc/self/status 自查：CapBnd 与 CapEff 必须都是 0。
//
// 不查的话「已卸掉」只是意图，不是事实——hardenRootfs 里的 mknod 就是这么静默失败的。
func verifyNoCaps() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return fmt.Errorf("读 /proc/self/status 失败: %w", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "CapBnd:") && !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		name, hexv, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v, err := strconv.ParseUint(strings.TrimSpace(hexv), 16, 64)
		if err != nil {
			return fmt.Errorf("解析 %s 失败: %w", name, err)
		}
		if v != 0 {
			return fmt.Errorf("%s = %#x，能力没清干净", name, v)
		}
	}
	return nil
}
