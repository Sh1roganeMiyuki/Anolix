package zygote

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

// TestWarmSeal 证明“只读热状态”是强制而非约定：
// 加封条后 write 与可写共享 mmap 都被拒（即使 fd 是 rdwr）；
// 只读重开的 fd 同样不可写映射；而只读映射 + pattern 校验仍正常。
func TestWarmSeal(t *testing.T) {
	const payload = 4096
	f, err := CreateWarmMemfd(payload)
	if err != nil {
		t.Fatalf("CreateWarmMemfd: %v", err)
	}
	defer f.Close()

	// ① 母体自己的 rdwr fd 也写不动（F_SEAL_WRITE）。
	if _, err := f.Write([]byte("x")); err == nil {
		t.Error("封条后 write 应失败，实际成功")
	}
	// ② 可写共享 mmap 被拒（F_SEAL_WRITE）。
	if _, err := syscall.Mmap(int(f.Fd()), 0, payload,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED); err == nil {
		t.Error("封条后可写共享 mmap 应失败，实际成功")
	}
	// ③ 只读重开 fd：不可写映射（O_RDONLY + seal 双保险）。
	ro, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", f.Fd()), os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("只读重开: %v", err)
	}
	defer ro.Close()
	if _, err := syscall.Mmap(int(ro.Fd()), 0, payload,
		syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_SHARED); err == nil {
		t.Error("只读 fd 的可写 mmap 应失败，实际成功")
	}
	// ④ 只读映射 + pattern 校验仍正常（读路径不被封条破坏）。
	region, err := MapWarm(int(ro.Fd()))
	if err != nil {
		t.Fatalf("MapWarm: %v", err)
	}
	defer syscall.Munmap(region)
	for i := 0; i < payload; i++ {
		if got := region[warmHeaderSize+i]; got != WarmPatternByte(i) {
			t.Fatalf("pattern[%d] = %d, 期望 %d", i, got, WarmPatternByte(i))
		}
	}
}
