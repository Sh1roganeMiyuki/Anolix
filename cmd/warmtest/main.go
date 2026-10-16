// 临时实验（跑完即删）：memfd + N 个并发 MAP_SHARED 只读映射者，看 smaps 报 Shared 还是 Private。
// 验证假设：smaps 的 Shared/Private 看的是"页被几个进程映射"(mapcount)，不是映射标志。
//
// 用法：go run ./cmd/warmtest 1   /   go run ./cmd/warmtest 2
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const memfdCreateNr = 319

func memfd(name string) int {
	b := append([]byte(name), 0)
	fd, _, e := syscall.RawSyscall(memfdCreateNr, uintptr(unsafe.Pointer(&b[0])), 0, 0)
	if e != 0 {
		panic(e)
	}
	return int(fd)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		child()
		return
	}
	n := 1
	if len(os.Args) > 1 {
		n, _ = strconv.Atoi(os.Args[1])
	}
	fmt.Printf("== %d 个并发映射者（父子都只读 MAP_SHARED）==\n", n)

	fd := memfd("warmtest")
	f := os.NewFile(uintptr(fd), "warmtest")
	const size = 64 << 20
	buf := make([]byte, 1<<20)
	for i := range buf {
		buf[i] = byte(i*31 + 7)
	}
	for w := 0; w < size; w += len(buf) {
		f.Write(buf) // 母体侧 write → 脏页
	}

	var cmds []*exec.Cmd
	for i := 0; i < n; i++ {
		c := exec.Command(os.Args[0], "child")
		c.ExtraFiles = []*os.File{f} // 子进程拿到 fd 3
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Start(); err != nil {
			panic(err)
		}
		cmds = append(cmds, c)
	}
	for _, c := range cmds {
		c.Wait()
	}
}

func child() {
	const fd = 3
	var st syscall.Stat_t
	syscall.Fstat(fd, &st)
	size := int(st.Size)
	region, e := syscall.Mmap(fd, 0, size, syscall.PROT_READ, syscall.MAP_SHARED)
	if e != nil {
		panic(e)
	}
	_ = region[0] // touch 一字节
	// fault 所有页（逐字节读，像 VerifyWarmPattern）
	sum := 0
	for _, b := range region {
		sum += int(b)
	}
	_ = sum
	fmt.Printf("  [pid %d] region checksum=%d，睡 1s 等兄弟\n", os.Getpid(), sum)
	// 睡 1s，确保所有兄弟都映射上了（mapcount 重叠）
	syscall.Nanosleep(&syscall.Timespec{Sec: 1}, nil)
	printVMA(uintptr(unsafe.Pointer(&region[0])))
}

// printVMA 打印包含 addr 的那个"共享"VMA 的 smaps 关键行。
func printVMA(addr uintptr) {
	f, _ := os.Open("/proc/self/smaps")
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	in := false
	for sc.Scan() {
		line := sc.Text()
		fl := strings.Fields(line)
		if len(fl) >= 5 && strings.Contains(fl[0], "-") {
			// VMA 头行
			if in {
				break
			}
			se := strings.SplitN(fl[0], "-", 2)
			if len(se) == 2 {
				s, e1 := strconv.ParseUint(se[0], 16, 64)
				e, e2 := strconv.ParseUint(se[1], 16, 64)
				if e1 == nil && e2 == nil && addr >= uintptr(s) && addr < uintptr(e) {
					in = true
					fmt.Printf("  [pid %d] VMA %s %s\n", os.Getpid(), fl[0], fl[1])
				}
			}
			continue
		}
		if !in {
			continue
		}
		for _, k := range []string{"Size", "Rss", "Pss", "Shared_Dirty", "Private_Dirty"} {
			if strings.HasPrefix(line, k+":") {
				fmt.Printf("    %s\n", strings.TrimSpace(line))
			}
		}
	}
}
