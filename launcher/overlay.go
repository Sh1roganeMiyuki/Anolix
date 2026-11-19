package launcher

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// overlayMount 是一次 overlayfs 挂载的现场记录。
//
// 白话：lower 是所有容器共享的只读底片，upper 是这个容器自己的"改动集"，
// merged 是两者叠起来给容器看的视图。容器退出后要按"先卸载、再删目录"的顺序收尾，
// 否则挂载点还活着，删目录会失败或留下看不见的残留。
type overlayMount struct {
	merged string // 挂载点，也就是写进 config.json 的 rootfs 路径
	dir    string // 存放 upper/work/merged 三兄弟的父目录
}

// setupOverlay 把 base（只读基础 rootfs）以 overlay 方式挂到 parent 下的 merged 目录。
//
// 三个目录都建在 parent（也就是 bundle）里，是为了同一个原因：
// workdir 与 upperdir 必须在**同一个文件系统**上，否则内核直接返回 EXDEV。
//
// 参数：
//   - base   ：lowerdir，只读基础层（多个容器共享，不会被写）
//   - parent ：放置 .overlay 目录的位置（bundle 目录）
func setupOverlay(base, parent string) (*overlayMount, error) {
	dir := filepath.Join(parent, "overlay")
	upper := filepath.Join(dir, "upper")
	work := filepath.Join(dir, "work")
	merged := filepath.Join(dir, "merged")
	for _, d := range []string{upper, work, merged} {
		// 0755：容器内进程要能读 merged，太严的权限会让容器起不来。
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("创建 overlay 目录 %s 失败: %w", d, err)
		}
	}

	// data 的格式是内核认的逗号分隔键值对，三个参数都不能省：
	//   lowerdir 只读层、upperdir 可写层、workdir 内核内部用的暂存区。
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", base, upper, work)
	if err := syscall.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		return nil, fmt.Errorf("挂载 overlay 失败（需要 root/CAP_SYS_ADMIN）: %w", err)
	}
	return &overlayMount{merged: merged, dir: dir}, nil
}

// Close 卸载 merged 并删除 overlay 目录。
//
// 顺序不能反：先 unmount 再删目录。反过来删目录会因为"目录仍是挂载点"而失败，
// 或者删掉后留下一个指向已删 inode 的挂载点。
func (m *overlayMount) Close() error {
	if m == nil {
		return nil
	}
	if err := syscall.Unmount(m.merged, 0); err != nil {
		// 卸载失败就不再删目录：留着现场比删一半更容易排查。
		return fmt.Errorf("卸载 overlay %s 失败: %w", m.merged, err)
	}
	if err := os.RemoveAll(m.dir); err != nil {
		return fmt.Errorf("清理 overlay 目录 %s 失败: %w", m.dir, err)
	}
	return nil
}
