// warm.go 实现"母体预热数据 → worker 共享"的机制。
//
// 为什么用共享内存（memfd + MAP_SHARED）而不是 fork-CoW：
//   - Go 的 runtime 是多线程的，fork 后子进程只剩一个线程，调度器/GC/锁全坏，
//     "fork 后不 exec、原地续行"在 Go 里是地雷（随机死锁/崩溃）。
//   - 共享内存把"热数据"放进一个 memfd，母体和所有 worker 都 mmap MAP_SHARED 同一份，
//     共享同一批物理页——零拷贝、永不复制。
//   - 对"只读热状态"（模型权重、词表、预热缓存）而言，共享内存其实比 fork-CoW 更优：
//     CoW 在任一 worker 首次写时会复制整页，共享内存则始终共享。
//
// 数据流：
//
//	母体启动 → CreateWarmMemfd(写 magic+size+pattern) → 持有 *os.File
//	spawn 时 → cmd.ExtraFiles = [warmFile] → worker 侧拿到 fd 3
//	worker   → MapWarm(3) → mmap MAP_SHARED → 校验 pattern → 读 smaps 看 Shared 页
//
// 约定：warm memfd 固定在 worker 的 fd 3（ExtraFiles[0]）。
package zygote

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	// WarmMagic 是共享区头部的 8 字节魔数，worker 用它确认"映射到的确实是母体的热数据"。
	WarmMagic = "ANOLIXWM"
	// WarmFD 是 worker 侧 warm memfd 的固定 fd 号（= ExtraFiles[0] → 3）。
	WarmFD = 3
	// warmHeaderSize = 8(magic) + 8(payload size) = 16 字节。
	warmHeaderSize = 16
)

// CreateWarmMemfd 创建一个 memfd，写入 header + size 字节的确定性 pattern，
// 模拟母体"已加载好的重型状态"（如 torch 模型权重）。
//
// 返回的 *os.File 由母体持有（保持 memfd 存活），并在每次 spawn 时
// 通过 cmd.ExtraFiles 传给 worker。
func CreateWarmMemfd(size int) (*os.File, error) {
	if size <= 0 {
		return nil, fmt.Errorf("warm size 必须为正")
	}
	f, err := memfdCreate("anolix-warm")
	if err != nil {
		return nil, err
	}

	// --- 写 header：magic(8) + payload size(8) ---
	header := make([]byte, warmHeaderSize)
	copy(header[0:8], WarmMagic)
	binary.BigEndian.PutUint64(header[8:16], uint64(size))
	if _, err := f.Write(header); err != nil {
		f.Close()
		return nil, fmt.Errorf("写 header 失败: %w", err)
	}

	// --- 写 payload：确定性 pattern，worker 可逐字节校验 ---
	// pattern[i] = byte(i*31 + 7) —— 便宜、可复现、能发现"映射到错的东西"。
	const chunk = 64 * 1024
	buf := make([]byte, chunk)
	for written := 0; written < size; {
		n := size - written
		if n > chunk {
			n = chunk
		}
		for i := 0; i < n; i++ {
			buf[i] = WarmPatternByte(written + i)
		}
		if _, err := f.Write(buf[:n]); err != nil {
			f.Close()
			return nil, fmt.Errorf("写 payload 失败: %w", err)
		}
		written += n
	}
	return f, nil
}

// WarmPatternByte 返回 payload 第 off 字节的期望值（母体写入与 worker 校验共用）。
func WarmPatternByte(off int) byte {
	return byte(off*31 + 7)
}

// MapWarm 把 fd 上的 warm memfd mmap 成只读 MAP_SHARED，返回整个映射区（含 header）。
//
// MAP_SHARED + 同一个 memfd → 母体与所有 worker 共享同一批物理页。
// 调用方用完后应 syscall.Munmap。
func MapWarm(fd int) ([]byte, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fmt.Errorf("fstat warm fd 失败: %w", err)
	}
	size := int(st.Size)
	if size < warmHeaderSize {
		return nil, fmt.Errorf("warm 区太小: %d 字节", size)
	}
	region, err := syscall.Mmap(fd, 0, size, syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap warm 区失败: %w", err)
	}
	if string(region[0:8]) != WarmMagic {
		syscall.Munmap(region)
		return nil, fmt.Errorf("magic 不匹配: got %q want %q", region[0:8], WarmMagic)
	}
	return region, nil
}

// WarmPayloadSize 从映射区 header 读出 payload 字节数。
func WarmPayloadSize(region []byte) int {
	return int(binary.BigEndian.Uint64(region[8:16]))
}

// VerifyWarmPattern 校验 payload 的确定性 pattern，返回首个不匹配的偏移（-1 = 全对）。
//
// 这是"worker 看到的确实是母体写的数据"的强证据：
// 若映射到错的东西或页没共享，pattern 会对不上。
func VerifyWarmPattern(region []byte) int {
	size := WarmPayloadSize(region)
	payload := region[warmHeaderSize:]
	if len(payload) < size {
		size = len(payload)
	}
	for i := 0; i < size; i++ {
		if payload[i] != WarmPatternByte(i) {
			return i
		}
	}
	return -1
}

// --- smaps：共享内存的"物理页共享"证据 ---

// SmapsEntry 是 /proc/self/smaps 里一个 VMA 的关键内存统计（单位 kB）。
type SmapsEntry struct {
	Addr         uintptr // VMA 起始地址
	Size         int
	Rss          int
	Pss          int // 按共享份数摊分后的常驻内存
	SharedClean  int // 与其他进程共享的干净页 ← 共享内存的关键证据
	SharedDirty  int
	PrivateClean int // 本进程独占的干净页 ← fork-CoW 未写时会落在这里
	PrivateDirty int
}

// SmapsForAddr 读取 /proc/self/smaps，返回包含 addr 的那个 VMA 的统计。
//
// 判读：
//   - 共享内存（MAP_SHARED memfd）：SharedClean ≈ 整个区大小，PrivateClean ≈ 0
//     → 物理页真的被多进程共享。
//   - 若是 fork-CoW 且子进程未写：会落在 PrivateClean（看似独占，实则 CoW 待分裂）。
//     两者在 smaps 里签名不同，这是区分"真共享"与"CoW 副本"的硬证据。
func SmapsForAddr(addr uintptr) (*SmapsEntry, error) {
	f, err := os.Open("/proc/self/smaps")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)

	var cur *SmapsEntry
	for sc.Scan() {
		line := sc.Text()
		// 先尝试解析为 VMA 头行（"start-end perms ..."）
		if start, end, ok := parseSmapsHeader(line); ok {
			if cur != nil {
				return cur, nil // 目标 VMA 收集完毕，遇到下一个 VMA 头
			}
			if addr >= start && addr < end {
				cur = &SmapsEntry{Addr: start}
			}
			continue
		}
		if cur == nil {
			continue // 还没定位到目标 VMA，跳过字段行
		}
		key, val, ok := parseSmapsField(line)
		if !ok {
			continue
		}
		switch key {
		case "Size":
			cur.Size = val
		case "Rss":
			cur.Rss = val
		case "Pss":
			cur.Pss = val
		case "Shared_Clean":
			cur.SharedClean = val
		case "Shared_Dirty":
			cur.SharedDirty = val
		case "Private_Clean":
			cur.PrivateClean = val
		case "Private_Dirty":
			cur.PrivateDirty = val
		}
	}
	if cur != nil {
		return cur, nil
	}
	return nil, fmt.Errorf("在 smaps 中未找到包含地址 %#x 的 VMA", addr)
}

func parseSmapsHeader(line string) (start, end uintptr, ok bool) {
	// "7f8b4c000000-7f8b4c021000 rw-p ..."
	sp := strings.IndexByte(line, ' ')
	if sp < 0 {
		return 0, 0, false
	}
	dash := strings.IndexByte(line[:sp], '-')
	if dash < 0 {
		return 0, 0, false
	}
	s, err1 := strconv.ParseUint(line[:dash], 16, 64)
	e, err2 := strconv.ParseUint(line[dash+1:sp], 16, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uintptr(s), uintptr(e), true
}

func parseSmapsField(line string) (key string, valKB int, ok bool) {
	colon := strings.IndexByte(line, ':')
	if colon < 0 {
		return "", 0, false
	}
	key = strings.TrimSpace(line[:colon])
	rest := strings.TrimSpace(line[colon+1:])
	rest = strings.TrimSuffix(rest, " kB")
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return key, 0, true // VmFlags 之类无数值
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return "", 0, false
	}
	return key, n, true
}

// sysMemfdCreate 是 memfd_create 的系统调用号。
// 标准库 syscall 未导出该常量，这里按架构硬编码（本项目目标 x86-64）。
//
//	x86-64: 319 | arm64: 279 | i386: 356
const sysMemfdCreate = 319 // x86-64

// memfdCreate 用裸 syscall 创建 memfd（不引入 x/sys/unix 依赖）。
func memfdCreate(name string) (*os.File, error) {
	nb := append([]byte(name), 0) // C 字符串需 null 结尾
	fd, _, errno := syscall.RawSyscall(sysMemfdCreate,
		uintptr(unsafe.Pointer(&nb[0])), 0, 0)
	if errno != 0 {
		return nil, fmt.Errorf("memfd_create 失败: %w", error(errno))
	}
	return os.NewFile(fd, name), nil
}
