package zygote

import (
	"os"
	"path/filepath"
	"strings"
)

// OverlayBaseDir 是 rootful 时 worker overlay 三兄弟目录的父目录。
//
// 为什么放 /tmp：宿主重启后自动消失，母体崩溃留下的残留最坏不会永久泄漏。
const OverlayBaseDir = "/tmp/anolix-overlay"

// RootlessEnv 是母体传给 worker 的 rootless 标记。
// worker 在 user ns 内 Geteuid()==0，无法靠 euid 判断 rootless，只能靠这个 env。
const RootlessEnv = "ANOLIX_ROOTLESS"

// OverlayBase 返回 overlay 三兄弟目录的父目录。
//
// rootless 时 worker 的 kuid=普通用户，/tmp/anolix-overlay 若由 root 建则写不进；
// 必须建在用户自己可写的地方（属主=kuid）。rootful 时 kuid=0，/tmp 下 root 建即可。
// 母体（靠 euid）与 worker-init（靠 RootlessEnv）走同一函数，保证两边路径不漂移。
func OverlayBase() string {
	if os.Getenv(RootlessEnv) == "1" || os.Geteuid() != 0 {
		home, err := os.UserHomeDir()
		if err == nil && home != "" {
			return filepath.Join(home, ".cache", "anolix-overlay")
		}
	}
	return OverlayBaseDir
}

// OverlayDir 按 workerID 推导 overlay 目录；非法 id 返回 ok=false。
//
// worker-init 建目录、母体 reap 删目录都走它，保证两边规则不漂移。
// 校验是安全闸：id 来自 client，若含 "/" 或 ".."，RemoveAll 会删到 base 之外。
func OverlayDir(id string) (string, bool) {
	if id == "" || id == "." || id == ".." || strings.ContainsAny(id, "/ \t\n") {
		return "", false
	}
	return filepath.Join(OverlayBase(), id), true
}
