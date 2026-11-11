package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"anolix/config"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// fakeRuncScript 是 runc 的测试替身：
// 记录调用参数，并按 FAKE_RUNC_BEHAVIOR 模拟不同行为（ok/exit42/sleep）。
const fakeRuncScript = `#!/bin/sh
log="${FAKE_RUNC_LOG:-/dev/null}"
echo "$@" >> "$log"
case "$*" in
  *delete*) exit 0 ;;
esac
echo "$@"
case "${FAKE_RUNC_BEHAVIOR:-ok}" in
  ok) exit 0 ;;
  exit42) exit 42 ;;
  sleep) exec sleep 30 ;;
esac
exit 0
`

// newFakeRunc 在临时目录创建可执行的假 runc，并返回其路径与调用日志路径。
func newFakeRunc(t *testing.T) (path, logPath string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, "runc")
	if err := os.WriteFile(path, []byte(fakeRuncScript), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath = filepath.Join(dir, "calls.log")
	t.Setenv("FAKE_RUNC_LOG", logPath)
	return path, logPath
}

func readCalls(t *testing.T, logPath string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(data)), "\n")
}

func TestBuildRuncArgs(t *testing.T) {
	cases := []struct {
		name     string
		stateDir string
		bundle   string
		id       string
		want     []string
	}{
		{
			name:   "无 stateDir",
			bundle: "/bundle",
			id:     "c1",
			want:   []string{"run", "--bundle", "/bundle", "c1"},
		},
		{
			name:     "带 stateDir",
			stateDir: "/state",
			bundle:   "/bundle",
			id:       "c1",
			want:     []string{"--root", "/state", "run", "--bundle", "/bundle", "c1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BuildRuncArgs(tc.stateDir, tc.bundle, tc.id)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("BuildRuncArgs() = %v, 期望 %v", got, tc.want)
			}
		})
	}
}

func TestBuildSpecSeccompFromPolicy(t *testing.T) {
	policy := &config.Policy{
		Seccomp: config.Seccomp{
			Enabled:         true,
			ErrnoRet:        38,
			DefaultAction:   config.ActionErrno,
			AllowedSyscalls: []string{"read", "write"},
		},
	}
	command := []string{"/bin/echo", "hello"}
	spec := buildSpec(policy, command, DefaultEnv, "rootfs", false)

	if spec.Version != specs.Version {
		t.Errorf("spec.Version = %q, 期望 %q", spec.Version, specs.Version)
	}
	if spec.Root == nil || spec.Root.Path != "rootfs" {
		t.Errorf("spec.Root.Path 应为 rootfs, 实际 %+v", spec.Root)
	}
	if !reflect.DeepEqual(spec.Process.Args, command) {
		t.Errorf("Process.Args = %v, 期望 %v", spec.Process.Args, command)
	}
	if !reflect.DeepEqual(spec.Process.Env, DefaultEnv) {
		t.Errorf("Process.Env = %v, 期望 %v", spec.Process.Env, DefaultEnv)
	}
	if !spec.Process.NoNewPrivileges {
		t.Error("Process.NoNewPrivileges 应为 true")
	}

	sc := spec.Linux.Seccomp
	if sc == nil {
		t.Fatal("policy 启用 seccomp 时 spec.Linux.Seccomp 不应为 nil")
	}
	if sc.DefaultAction != specs.ActErrno {
		t.Errorf("DefaultAction = %q, 期望 %q", sc.DefaultAction, specs.ActErrno)
	}
	if sc.DefaultErrnoRet == nil || *sc.DefaultErrnoRet != 38 {
		t.Errorf("DefaultErrnoRet = %v, 期望 38", sc.DefaultErrnoRet)
	}
	if len(sc.Syscalls) != 1 {
		t.Fatalf("Syscalls 应有 1 条规则, 实际 %d 条", len(sc.Syscalls))
	}
	if sc.Syscalls[0].Action != specs.ActAllow {
		t.Errorf("Syscalls[0].Action = %q, 期望 %q", sc.Syscalls[0].Action, specs.ActAllow)
	}
	if !reflect.DeepEqual(sc.Syscalls[0].Names, []string{"read", "write"}) {
		t.Errorf("Syscalls[0].Names = %v, 期望 [read write]", sc.Syscalls[0].Names)
	}

	// 命名空间隔离必须包含 PID/网络/IPC/UTS/挂载。
	types := make(map[specs.LinuxNamespaceType]bool)
	for _, ns := range spec.Linux.Namespaces {
		types[ns.Type] = true
	}
	for _, want := range []specs.LinuxNamespaceType{specs.PIDNamespace, specs.NetworkNamespace, specs.IPCNamespace, specs.UTSNamespace, specs.MountNamespace} {
		if !types[want] {
			t.Errorf("缺少 %s namespace", want)
		}
	}
}

func TestBuildSeccompDefaults(t *testing.T) {
	sc := buildSeccomp(config.Seccomp{Enabled: true})
	if sc == nil {
		t.Fatal("启用 seccomp 时不应为 nil")
	}
	if sc.DefaultErrnoRet == nil || *sc.DefaultErrnoRet != config.DefaultErrnoRet {
		t.Errorf("未配置 errnoRet 时应回退 EPERM(%d), 实际 %v", config.DefaultErrnoRet, sc.DefaultErrnoRet)
	}
	if got := len(sc.Syscalls[0].Names); got != len(config.DefaultAllowedSyscalls) {
		t.Errorf("未配置放行名单时应使用默认名单（%d 项）, 实际 %d 项", len(config.DefaultAllowedSyscalls), got)
	}
}

func TestBuildSeccompErrnoRetOnlyForSupportedAction(t *testing.T) {
	// ERRNO（盖章）：动作会留下返回值，errno 必须有地方落脚，字段要写。
	sc := buildSeccomp(config.Seccomp{Enabled: true, ErrnoRet: 1145, DefaultAction: config.ActionErrno})
	if sc.DefaultErrnoRet == nil || *sc.DefaultErrnoRet != 1145 {
		t.Fatalf("ERRNO 动作应写 DefaultErrnoRet=1145，实际 %v", sc.DefaultErrnoRet)
	}
	// KILL / KILL_PROCESS / TRAP：进程直接被处理掉，没有返回值，字段必须不写。
	// 写了会被 crun 判为非法、整份 config.json 拒收（runc 则静默忽略）——两种都不对。
	for _, action := range []string{config.ActionKill, config.ActionKillProcess, config.ActionTrap} {
		sc := buildSeccomp(config.Seccomp{Enabled: true, ErrnoRet: 1145, DefaultAction: action})
		if sc.DefaultErrnoRet != nil {
			t.Errorf("%s 不支持 errno，不应写 DefaultErrnoRet，实际 %d", action, *sc.DefaultErrnoRet)
		}
	}
}

func TestBuildSeccompDisabled(t *testing.T) {
	if sc := buildSeccomp(config.Seccomp{Enabled: false}); sc != nil {
		t.Errorf("关闭 seccomp 时 buildSeccomp 应返回 nil, 实际 %+v", sc)
	}
}

func TestBuildSpecResources(t *testing.T) {
	policy := &config.Policy{
		Resources: config.Resources{
			MemoryLimitBytes: 64 << 20,
			PidsLimit:        20,
			CPUQuotaMicros:   20000,
			CPUPeriodMicros:  100000,
		},
	}
	spec := buildSpec(policy, []string{"/probe"}, DefaultEnv, "rootfs", false)
	res := spec.Linux.Resources
	if res == nil {
		t.Fatal("spec.Linux.Resources 不应为 nil（设备规则始终存在）")
	}
	if res.Memory == nil || res.Memory.Limit == nil || *res.Memory.Limit != 64<<20 {
		t.Errorf("Memory.Limit = %+v, 期望 %d", res.Memory, int64(64<<20))
	}
	if res.Pids == nil || res.Pids.Limit != 20 {
		t.Errorf("Pids.Limit = %+v, 期望 20", res.Pids)
	}
	if res.CPU == nil || res.CPU.Quota == nil || *res.CPU.Quota != 20000 ||
		res.CPU.Period == nil || *res.CPU.Period != 100000 {
		t.Errorf("CPU 配额 = %+v, 期望 quota=20000 period=100000", res.CPU)
	}
	// 设备白名单必须保留（资源限额是合并而非覆盖）。
	if len(res.Devices) == 0 {
		t.Error("设备白名单规则应在合并后保留")
	}

	// 只设配额：周期应回退默认 100ms。
	policy = &config.Policy{Resources: config.Resources{CPUQuotaMicros: 20000}}
	spec = buildSpec(policy, []string{"/probe"}, DefaultEnv, "rootfs", false)
	cpu := spec.Linux.Resources.CPU
	if cpu == nil || cpu.Period == nil || *cpu.Period != config.DefaultCPUPeriodMicros {
		t.Errorf("未配置周期时应回退到 %d, 实际 %+v", config.DefaultCPUPeriodMicros, cpu)
	}

	// 对照组：全 0（未设置）时不应生成任何限额字段。
	spec = buildSpec(config.Default(), []string{"/probe"}, DefaultEnv, "rootfs", false)
	res = spec.Linux.Resources
	if res == nil {
		t.Fatal("即使未设限额，Resources 也应保留设备规则")
	}
	if res.Memory != nil || res.Pids != nil || res.CPU != nil {
		t.Errorf("未设置限额时不应生成 Memory/Pids/CPU: %+v", res)
	}
}

func TestBuildSpecRootless(t *testing.T) {
	spec := buildSpec(config.Default(), []string{"/probe"}, DefaultEnv, "rootfs", true)

	if len(spec.Linux.Namespaces) == 0 || spec.Linux.Namespaces[0].Type != specs.UserNamespace {
		t.Fatalf("rootless 时首个命名空间应为 user, 实际 %+v", spec.Linux.Namespaces)
	}
	if len(spec.Linux.UIDMappings) != 1 || spec.Linux.UIDMappings[0].HostID != uint32(os.Geteuid()) {
		t.Errorf("UIDMappings = %+v, 期望映射到 euid %d", spec.Linux.UIDMappings, os.Geteuid())
	}
	if len(spec.Linux.GIDMappings) != 1 || spec.Linux.GIDMappings[0].HostID != uint32(os.Getegid()) {
		t.Errorf("GIDMappings = %+v, 期望映射到 egid %d", spec.Linux.GIDMappings, os.Getegid())
	}
	for _, m := range spec.Mounts {
		if m.Destination != "/dev/pts" {
			continue
		}
		for _, opt := range m.Options {
			if opt == "gid=5" {
				t.Error("rootless 时 /dev/pts 不应带 gid=5（该 gid 不在 userns 映射中）")
			}
		}
	}

	// 对照组：rootful 保留 gid=5 且不含 user namespace。
	spec = buildSpec(config.Default(), []string{"/probe"}, DefaultEnv, "rootfs", false)
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			t.Error("rootful 时不应包含 user namespace")
		}
	}
	found := false
	for _, m := range spec.Mounts {
		if m.Destination == "/dev/pts" {
			for _, opt := range m.Options {
				found = found || opt == "gid=5"
			}
		}
	}
	if !found {
		t.Error("rootful 时 /dev/pts 应带 gid=5")
	}
}

func TestStateDirDefault(t *testing.T) {
	l, err := New(Options{Command: []string{"/probe"}, RuncPath: "/bin/true"})
	if err != nil {
		t.Fatalf("New() 出错: %v", err)
	}
	got := l.stateDir()
	if os.Geteuid() != 0 {
		if got == "" {
			t.Error("非 root 运行时状态目录应有用户可写的默认值")
		}
	} else if got != "" {
		t.Errorf("root 时应使用 runc 默认状态目录, 实际 %q", got)
	}
}

func TestNewValidation(t *testing.T) {
	_, err := New(Options{Command: nil})
	if err == nil || !strings.Contains(err.Error(), "命令") {
		t.Errorf("空命令应报错, 实际: %v", err)
	}

	_, err = New(Options{Command: []string{"/bin/true"}, RuncPath: "/nonexistent/runc"})
	if err == nil || !strings.Contains(err.Error(), "runc") {
		t.Errorf("runc 不存在应报错, 实际: %v", err)
	}

	bad := config.Default()
	bad.Seccomp.ErrnoRet = 99999
	_, err = New(Options{Command: []string{"/bin/true"}, RuncPath: "/bin/true", Policy: bad})
	if err == nil || !strings.Contains(err.Error(), "policy") {
		t.Errorf("非法 policy 应报错, 实际: %v", err)
	}

	badRes := config.Default()
	badRes.Resources.PidsLimit = -1
	_, err = New(Options{Command: []string{"/bin/true"}, RuncPath: "/bin/true", Policy: badRes})
	if err == nil || !strings.Contains(err.Error(), "policy") {
		t.Errorf("非法资源围栏应报错, 实际: %v", err)
	}
}

func TestRunSmoke(t *testing.T) {
	runcPath, logPath := newFakeRunc(t)
	t.Setenv("FAKE_RUNC_BEHAVIOR", "ok")

	dir := t.TempDir()
	rootfs := filepath.Join(dir, "real-rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(dir, "bundle")

	policy := &config.Policy{
		Seccomp: config.Seccomp{
			Enabled:         true,
			ErrnoRet:        38,
			DefaultAction:   config.ActionErrno,
			AllowedSyscalls: []string{"read", "write"},
		},
		Resources: config.Resources{
			MemoryLimitBytes: 64 << 20,
			PidsLimit:        20,
			CPUQuotaMicros:   20000,
			CPUPeriodMicros:  100000,
		},
	}

	var stdout bytes.Buffer
	l, err := New(Options{
		ContainerID: "test-c1",
		Rootfs:      rootfs,
		BundleDir:   bundle,
		RuncPath:    runcPath,
		Policy:      policy,
		Command:     []string{"/bin/echo", "hello"},
		Stdout:      &stdout,
	})
	if err != nil {
		t.Fatalf("New() 出错: %v", err)
	}

	code, err := l.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() 出错: %v", err)
	}
	if code != 0 {
		t.Errorf("退出码 = %d, 期望 0", code)
	}

	// 假 runc 应收到组装好的启动参数。
	wantArgs := fmt.Sprintf("run --bundle %s test-c1", bundle)
	if !strings.Contains(stdout.String(), wantArgs) {
		t.Errorf("runc 实际收到的参数 %q 不包含 %q", stdout.String(), wantArgs)
	}

	// 成功后不应调用 runc delete。
	for _, call := range readCalls(t, logPath) {
		if strings.Contains(call, "delete") {
			t.Errorf("成功路径不应调用 delete, 实际调用: %q", call)
		}
	}

	// config.json 应是合法的 OCI spec，且 seccomp 与 policy 一致。
	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatalf("读取 config.json 失败: %v", err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("config.json 不是合法 OCI spec: %v", err)
	}
	if !reflect.DeepEqual(spec.Process.Args, []string{"/bin/echo", "hello"}) {
		t.Errorf("config.json 中 Process.Args = %v", spec.Process.Args)
	}
	if spec.Linux.Seccomp == nil || spec.Linux.Seccomp.DefaultErrnoRet == nil || *spec.Linux.Seccomp.DefaultErrnoRet != 38 {
		t.Errorf("config.json 中 seccomp errnoRet 与 policy 不一致: %+v", spec.Linux.Seccomp)
	}

	// 资源围栏应完整落进 config.json，且设备白名单规则保留。
	res := spec.Linux.Resources
	if res == nil {
		t.Fatal("config.json 缺少 linux.resources")
	}
	if res.Memory == nil || res.Memory.Limit == nil || *res.Memory.Limit != 64<<20 {
		t.Errorf("config.json 中内存限额与 policy 不一致: %+v", res.Memory)
	}
	if res.Pids == nil || res.Pids.Limit != 20 {
		t.Errorf("config.json 中进程数上限与 policy 不一致: %+v", res.Pids)
	}
	if res.CPU == nil || res.CPU.Quota == nil || *res.CPU.Quota != 20000 ||
		res.CPU.Period == nil || *res.CPU.Period != 100000 {
		t.Errorf("config.json 中 CPU 配额与 policy 不一致: %+v", res.CPU)
	}
	if len(res.Devices) == 0 {
		t.Error("config.json 中设备白名单规则不应为空")
	}

	// runc 要求 rootfs 为规范化绝对路径（拒绝符号链接），
	// 因此 config.json 中应直接写入真实 rootfs 的绝对路径。
	canonical, err := filepath.EvalSymlinks(rootfs)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Root.Path != canonical {
		t.Errorf("config.json 中 root path = %s, 期望规范化绝对路径 %s", spec.Root.Path, canonical)
	}
	if _, err := os.Lstat(filepath.Join(bundle, "rootfs")); !os.IsNotExist(err) {
		t.Errorf("指定 --rootfs 时不应在 bundle 内创建 rootfs 符号链接, Lstat: %v", err)
	}
}

func TestRunPropagatesExitCode(t *testing.T) {
	runcPath, _ := newFakeRunc(t)
	t.Setenv("FAKE_RUNC_BEHAVIOR", "exit42")

	l, err := New(Options{
		RuncPath:   runcPath,
		Command:    []string{"/bin/false"},
		BundleDir:  filepath.Join(t.TempDir(), "bundle"),
		KeepBundle: true,
		Stdout:     &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("New() 出错: %v", err)
	}

	code, err := l.Run(context.Background())
	if err != nil {
		t.Fatalf("容器非 0 退出不应视为执行错误, 实际: %v", err)
	}
	if code != 42 {
		t.Errorf("退出码 = %d, 期望 42", code)
	}
}

func TestRunTimeout(t *testing.T) {
	runcPath, logPath := newFakeRunc(t)
	t.Setenv("FAKE_RUNC_BEHAVIOR", "sleep")

	l, err := New(Options{
		RuncPath:   runcPath,
		Command:    []string{"/bin/sleep", "30"},
		BundleDir:  filepath.Join(t.TempDir(), "bundle"),
		KeepBundle: true,
		Timeout:    300 * time.Millisecond,
		Stdout:     &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("New() 出错: %v", err)
	}

	start := time.Now()
	code, err := l.Run(context.Background())
	if err == nil {
		t.Fatal("超时应返回错误")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("错误应包裹 context.DeadlineExceeded, 实际: %v", err)
	}
	if code != 143 && code != 137 {
		t.Errorf("超时终止退出码 = %d, 期望 143(SIGTERM) 或 137(SIGKILL)", code)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("超时后应立即返回, 实际耗时 %v", elapsed)
	}

	// 超时后必须强制清理容器。
	found := false
	for _, call := range readCalls(t, logPath) {
		if strings.Contains(call, "delete --force anolix-") {
			found = true
		}
	}
	if !found {
		t.Errorf("超时后应调用 runc delete --force, 实际调用: %v", readCalls(t, logPath))
	}
}

func TestRunAutoBundleCleanedUp(t *testing.T) {
	runcPath, _ := newFakeRunc(t)
	t.Setenv("FAKE_RUNC_BEHAVIOR", "ok")

	l, err := New(Options{
		RuncPath: runcPath,
		Command:  []string{"/bin/true"},
		Stdout:   &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("New() 出错: %v", err)
	}

	if _, err := l.Run(context.Background()); err != nil {
		t.Fatalf("Run() 出错: %v", err)
	}
	if _, err := os.Stat(l.BundleDir()); !os.IsNotExist(err) {
		t.Errorf("自动创建的 bundle 应在退出后清理, Stat 结果: %v", err)
	}
}

func TestRunKeepBundle(t *testing.T) {
	runcPath, _ := newFakeRunc(t)
	t.Setenv("FAKE_RUNC_BEHAVIOR", "ok")

	l, err := New(Options{
		RuncPath:   runcPath,
		Command:    []string{"/bin/true"},
		KeepBundle: true,
		Stdout:     &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("New() 出错: %v", err)
	}

	if _, err := l.Run(context.Background()); err != nil {
		t.Fatalf("Run() 出错: %v", err)
	}
	bundle := l.BundleDir()
	defer os.RemoveAll(bundle)

	if _, err := os.Stat(filepath.Join(bundle, "config.json")); err != nil {
		t.Errorf("KeepBundle 时 bundle 应保留: %v", err)
	}
}

func TestRunCanonicalizesSymlinkedRootfs(t *testing.T) {
	runcPath, _ := newFakeRunc(t)
	t.Setenv("FAKE_RUNC_BEHAVIOR", "ok")

	dir := t.TempDir()
	realRootfs := filepath.Join(dir, "real-rootfs")
	if err := os.MkdirAll(realRootfs, 0o755); err != nil {
		t.Fatal(err)
	}
	linkRootfs := filepath.Join(dir, "link-rootfs")
	if err := os.Symlink(realRootfs, linkRootfs); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(realRootfs)
	if err != nil {
		t.Fatal(err)
	}

	bundle := filepath.Join(dir, "bundle")
	l, err := New(Options{
		RuncPath:  runcPath,
		Rootfs:    linkRootfs, // 传入符号链接，应被解析为真实目录
		BundleDir: bundle,
		Command:   []string{"/bin/true"},
		Stdout:    &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("New() 出错: %v", err)
	}
	if _, err := l.Run(context.Background()); err != nil {
		t.Fatalf("Run() 出错: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Root.Path != want {
		t.Errorf("符号链接 rootfs 应被规范化为 %s, 实际 %s", want, spec.Root.Path)
	}
}

func TestApplyNetwork(t *testing.T) {
	policy := config.Default()
	policy.Network = config.Network{Mode: config.NetworkModeBridge}
	spec := buildSpec(policy, []string{"/probe"}, DefaultEnv, "rootfs", false)

	if err := applyNetwork(spec, policy, "/run/netns/anolix-test", "/tmp/bundle/resolv.conf"); err != nil {
		t.Fatalf("applyNetwork() 出错: %v", err)
	}

	// 1. netns Path 必须填上（runc 靠它加入预创建的 netns）。
	netnsFound := false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace {
			netnsFound = true
			if ns.Path != "/run/netns/anolix-test" {
				t.Errorf("network namespace Path = %q", ns.Path)
			}
		}
	}
	if !netnsFound {
		t.Fatal("spec 缺少 network namespace")
	}

	// 2. seccomp：网络调用应被追加，socket 必须带地址族过滤。
	sc := spec.Linux.Seccomp
	if sc == nil {
		t.Fatal("seccomp 不应为 nil")
	}
	allowed := make(map[string]bool)
	var socketRules []specs.LinuxSyscall
	for _, rule := range sc.Syscalls {
		for _, name := range rule.Names {
			allowed[name] = true
			if name == "socket" {
				socketRules = append(socketRules, rule)
			}
		}
	}
	for _, want := range []string{"connect", "bind", "listen", "sendto", "recvfrom", "setsockopt"} {
		if !allowed[want] {
			t.Errorf("seccomp 应放行 %q", want)
		}
	}
	if len(socketRules) != len(socketAllowedFamilies) {
		t.Fatalf("socket 规则数 = %d, 期望 %d（每个地址族一条）", len(socketRules), len(socketAllowedFamilies))
	}
	for i, rule := range socketRules {
		if len(rule.Args) != 1 || rule.Args[0].Op != specs.OpEqualTo {
			t.Errorf("socket 规则 %d 缺少参数过滤: %+v", i, rule)
			continue
		}
		if rule.Args[0].Value != socketAllowedFamilies[i] {
			t.Errorf("socket 规则 %d 地址族 = %d, 期望 %d", i, rule.Args[0].Value, socketAllowedFamilies[i])
		}
	}

	// 3. resolv.conf 应作为只读 bind mount 追加。
	foundMount := false
	for _, m := range spec.Mounts {
		if m.Destination == "/etc/resolv.conf" {
			foundMount = true
			if m.Type != "bind" || m.Source != "/tmp/bundle/resolv.conf" {
				t.Errorf("resolv.conf mount = %+v", m)
			}
		}
	}
	if !foundMount {
		t.Error("缺少 /etc/resolv.conf 挂载")
	}
}

func TestApplyNetworkNoneIsNoop(t *testing.T) {
	policy := config.Default() // Network 零值 = none
	spec := buildSpec(policy, []string{"/probe"}, DefaultEnv, "rootfs", false)
	before := len(spec.Linux.Seccomp.Syscalls)

	if err := applyNetwork(spec, policy, "", ""); err != nil {
		t.Fatalf("none 档位不应报错: %v", err)
	}
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.NetworkNamespace && ns.Path != "" {
			t.Errorf("none 档位不应设置 netns Path: %q", ns.Path)
		}
	}
	if got := len(spec.Linux.Seccomp.Syscalls); got != before {
		t.Errorf("none 档位不应改变 seccomp 规则数: %d → %d", before, got)
	}
}

func TestApplyNetworkRequiresNetNSPath(t *testing.T) {
	policy := config.Default()
	policy.Network = config.Network{Mode: config.NetworkModeBridge}
	spec := buildSpec(policy, []string{"/probe"}, DefaultEnv, "rootfs", false)
	if err := applyNetwork(spec, policy, "", ""); err == nil {
		t.Error("bridge 档位缺少 netns 路径时应报错")
	}
}

func TestApplyNetworkUserSocketBypassesFilter(t *testing.T) {
	policy := config.Default()
	policy.Network = config.Network{Mode: config.NetworkModeBridge}
	// 用户显式把 socket 放进名单 = 选择全地址族放行。
	policy.Seccomp.AllowedSyscalls = append(append([]string{}, config.DefaultAllowedSyscalls...), "socket")
	spec := buildSpec(policy, []string{"/probe"}, DefaultEnv, "rootfs", false)
	if err := applyNetwork(spec, policy, "/run/netns/c1", ""); err != nil {
		t.Fatalf("applyNetwork() 出错: %v", err)
	}
	var socketRules []specs.LinuxSyscall
	for _, rule := range spec.Linux.Seccomp.Syscalls {
		for _, name := range rule.Names {
			if name == "socket" {
				socketRules = append(socketRules, rule)
			}
		}
	}
	if len(socketRules) != 1 {
		t.Fatalf("用户已放行 socket 时不应追加参数规则, 实际 %d 条", len(socketRules))
	}
	if len(socketRules[0].Args) != 0 {
		t.Errorf("用户规则不应被改写: %+v", socketRules[0])
	}
}
