// runtime.go 是"启动层"与具体 OCI 运行时之间的接缝。
//
// 分层（也是本文件存在的原因）：
//
//	config      策略层：只认 policy 字段，不知道谁去执行
//	spec.go     翻译层：policy → OCI spec，产出运行时中立的 config.json
//	本文件       启动层：决定"谁来执行这份 config.json"（runc / crun）
//	launcher.go 生命周期：拉起、等待、超时、清理
//
// 两个运行时消费的是同一份 config.json。差异只允许出现在启动层，
// 目前已知的一处是 ociVersion 上限（crun 1.14 只认到 1.1.0）。
package launcher

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// RuntimeKind 是启动层支持的运行时类型。
type RuntimeKind string

const (
	RuntimeRunc RuntimeKind = "runc"
	RuntimeCrun RuntimeKind = "crun"
)

// crunMaxSpecVersion 是 crun 1.14.x 能接受的最高 OCI 版本。
//
// 更高的版本会被直接拒绝（实测报 "unknown version specified"）。
// 我们生成的字段都在 1.0.2 范围内，声明 1.1.0 与实际内容相符；
// 更新版本的 crun 也仍然接受更低的版本号，所以这里取上限而非精确值。
const crunMaxSpecVersion = "1.1.0"

// Runtime 描述一次启动要用的 OCI 运行时。
//
// 它只保存"是谁、在哪"，不保存任何策略：同一份 policy 换运行时，
// 生成的 spec 内容不变，只有 ociVersion 可能被启动层改写。
type Runtime struct {
	kind RuntimeKind
	path string
}

// Kind 返回推断出的运行时类型（runc / crun，或自定义名字）。
func (r *Runtime) Kind() RuntimeKind { return r.kind }

// Name 返回用于日志的运行时名字。
func (r *Runtime) Name() string { return string(r.kind) }

// Path 返回运行时可执行文件的绝对路径。
func (r *Runtime) Path() string { return r.path }

// SpecVersion 返回该运行时可接受的 ociVersion。
//
// 这是"启动层适配"的唯一一处：spec 的内容由策略决定，
// 但版本号必须落在运行时认识的范围内，否则运行时会拒绝整份说明书。
func (r *Runtime) SpecVersion() string {
	if r.kind == RuntimeCrun {
		return crunMaxSpecVersion
	}
	return specs.Version
}

// RunArgs 组装启动参数：
//
//	<runtime> [--root <stateDir>] run --bundle <bundleDir> <containerID>
//
// runc 与 crun 的这段命令行语法一致；差异被收在 Runtime 内部，
// launcher 的生命周期逻辑不再关心具体是哪个运行时。
func (r *Runtime) RunArgs(stateDir, bundleDir, id string) []string {
	args := make([]string, 0, 6)
	if stateDir != "" {
		args = append(args, "--root", stateDir)
	}
	args = append(args, "run", "--bundle", bundleDir, id)
	return args
}

// DeleteArgs 组装强制清理参数：
//
//	<runtime> [--root <stateDir>] delete --force <containerID>
func (r *Runtime) DeleteArgs(stateDir, id string) []string {
	args := make([]string, 0, 4)
	if stateDir != "" {
		args = append(args, "--root", stateDir)
	}
	args = append(args, "delete", "--force", id)
	return args
}

// ResolveRuntime 把"名字或路径"解析成一个 Runtime。
//
//	nameOrPath 为空时使用 runc（保持原有默认行为）；含路径分隔符时按文件路径处理，
//	否则在 PATH 中查找。类型按可执行文件名推断（支持 bin/crun 这类包装脚本）。
func ResolveRuntime(nameOrPath string) (*Runtime, error) {
	spec := strings.TrimSpace(nameOrPath)
	if spec == "" {
		spec = string(RuntimeRunc)
	}

	// 分支一：显式路径。要求存在且可执行。
	if strings.ContainsRune(spec, os.PathSeparator) {
		abs, err := filepath.Abs(spec)
		if err != nil {
			return nil, fmt.Errorf("解析 OCI 运行时路径 %q 失败: %w", spec, err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("OCI 运行时 %q 不可用: %w", abs, err)
		}
		if info.IsDir() || info.Mode()&0o111 == 0 {
			return nil, fmt.Errorf("OCI 运行时 %q 不是可执行文件", abs)
		}
		return &Runtime{kind: kindFromName(filepath.Base(abs)), path: abs}, nil
	}

	// 分支二：名字。交给 LookPath 在 PATH 里找。
	resolved, err := exec.LookPath(spec)
	if err != nil {
		return nil, fmt.Errorf("未找到 OCI 运行时 %q: %w", spec, err)
	}
	abs, err := filepath.Abs(resolved)
	if err != nil {
		abs = resolved // 极少见：拿不到绝对路径也不影响执行
	}
	return &Runtime{kind: kindFromName(filepath.Base(abs)), path: abs}, nil
}

// kindFromName 依据可执行文件名判断运行时类型。
//
// 先判 crun 再判 runc："crun" 不含子串 "runc"，但顺序写反会误伤带前缀的名字。
// 认不出来的（如测试里的假运行时）保留文件名，只用于日志，不影响执行。
func kindFromName(base string) RuntimeKind {
	name := strings.ToLower(base)
	switch {
	case strings.Contains(name, "crun"):
		return RuntimeCrun
	case strings.Contains(name, "runc"):
		return RuntimeRunc
	default:
		return RuntimeKind(name)
	}
}
