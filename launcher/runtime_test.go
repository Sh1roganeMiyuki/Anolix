// runtime_test.go 把"启动层可替换"当成一条可验证的承诺来测：
//
//  1. 名字 / 路径都能解析成运行时，类型按文件名推断；
//  2. 同一份 policy 换运行时，config.json 除 ociVersion 外逐字段相同；
//  3. 选 crun 时真正被 exec 的是 crun，且版本号被改写成它认识的上限。
package launcher

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"anolix/config"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// newFakeRuntime 在临时目录创建一个指定名字的假运行时（runc / crun）。
// 脚本内容复用 launcher_test.go 里的 fakeRuncScript。
func newFakeRuntime(t *testing.T, name string) (path, logPath string) {
	t.Helper()
	dir := t.TempDir()
	path = filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(fakeRuncScript), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath = filepath.Join(dir, "calls.log")
	t.Setenv("FAKE_RUNC_LOG", logPath)
	return path, logPath
}

func TestResolveRuntime(t *testing.T) {
	// 路径分支：按可执行文件名推断类型。
	crunPath, _ := newFakeRuntime(t, "crun")
	rt, err := ResolveRuntime(crunPath)
	if err != nil {
		t.Fatalf("ResolveRuntime(%q) 出错: %v", crunPath, err)
	}
	if rt.Kind() != RuntimeCrun {
		t.Errorf("类型 = %q, 期望 %q", rt.Kind(), RuntimeCrun)
	}
	if rt.Path() != crunPath {
		t.Errorf("路径 = %q, 期望 %q", rt.Path(), crunPath)
	}

	// 名字分支：在 PATH 中查找。
	t.Setenv("PATH", filepath.Dir(crunPath))
	rt, err = ResolveRuntime("crun")
	if err != nil {
		t.Fatalf("按名字解析 crun 出错: %v", err)
	}
	if rt.Kind() != RuntimeCrun || rt.Path() != crunPath {
		t.Errorf("按名字解析结果 = {%q, %q}, 期望 crun @ %q", rt.Kind(), rt.Path(), crunPath)
	}

	// 缺省：保持原有行为，用 runc。
	runcPath, _ := newFakeRuntime(t, "runc")
	t.Setenv("PATH", filepath.Dir(runcPath))
	rt, err = ResolveRuntime("")
	if err != nil {
		t.Fatalf("缺省解析出错: %v", err)
	}
	if rt.Kind() != RuntimeRunc {
		t.Errorf("缺省类型 = %q, 期望 %q", rt.Kind(), RuntimeRunc)
	}
}

func TestResolveRuntimeErrors(t *testing.T) {
	_, err := ResolveRuntime(filepath.Join(t.TempDir(), "crun"))
	if err == nil || !strings.Contains(err.Error(), "crun") {
		t.Errorf("不存在的 crun 应报错且带上名字, 实际: %v", err)
	}

	// 存在但是目录：必须拒绝，不能等到 exec 才失败。
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "crun"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err = ResolveRuntime(filepath.Join(dir, "crun"))
	if err == nil || !strings.Contains(err.Error(), "可执行") {
		t.Errorf("目录不是可执行文件, 应报错, 实际: %v", err)
	}
}

func TestRuntimeSpecVersion(t *testing.T) {
	if got := (&Runtime{kind: RuntimeRunc}).SpecVersion(); got != specs.Version {
		t.Errorf("runc 的 ociVersion = %q, 期望 %q", got, specs.Version)
	}
	if got := (&Runtime{kind: RuntimeCrun}).SpecVersion(); got != crunMaxSpecVersion {
		t.Errorf("crun 的 ociVersion = %q, 期望 %q", got, crunMaxSpecVersion)
	}
}

func TestRuntimeArgs(t *testing.T) {
	crunRT := &Runtime{kind: RuntimeCrun, path: "crun"}

	if got, want := crunRT.RunArgs("/state", "/bundle", "c1"),
		[]string{"--root", "/state", "run", "--bundle", "/bundle", "c1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("RunArgs = %v, 期望 %v", got, want)
	}
	if got, want := crunRT.RunArgs("", "/bundle", "c1"),
		[]string{"run", "--bundle", "/bundle", "c1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("无 stateDir 的 RunArgs = %v, 期望 %v", got, want)
	}
	if got, want := crunRT.DeleteArgs("/state", "c1"),
		[]string{"--root", "/state", "delete", "--force", "c1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("DeleteArgs = %v, 期望 %v", got, want)
	}
}

// TestRunUsesCrunBackend 验证启动层真的换了执行者，而不是只改了个名字。
func TestRunUsesCrunBackend(t *testing.T) {
	crunPath, logPath := newFakeRuntime(t, "crun")
	t.Setenv("FAKE_RUNC_BEHAVIOR", "ok")

	bundle := filepath.Join(t.TempDir(), "bundle")
	var stdout bytes.Buffer
	l, err := New(Options{
		ContainerID: "crun-c1",
		Runtime:     crunPath,
		BundleDir:   bundle,
		Command:     []string{"/probe"},
		Stdout:      &stdout,
	})
	if err != nil {
		t.Fatalf("New() 出错: %v", err)
	}
	if _, err := l.Run(context.Background()); err != nil {
		t.Fatalf("Run() 出错: %v", err)
	}

	wantArgs := "run --bundle " + bundle + " crun-c1"
	if !strings.Contains(stdout.String(), wantArgs) {
		t.Errorf("crun 实际收到的参数 %q 不包含 %q", stdout.String(), wantArgs)
	}
	for _, call := range readCalls(t, logPath) {
		if strings.Contains(call, "delete") {
			t.Errorf("成功路径不应调用 delete, 实际调用: %q", call)
		}
	}

	data, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Version != crunMaxSpecVersion {
		t.Errorf("crun 的 config.json ociVersion = %q, 期望 %q", spec.Version, crunMaxSpecVersion)
	}
}

// TestSpecContentSameAcrossRuntimes 是"策略层/启动层解耦"的直接证据：
// 同一份 policy、同一个命令，只换运行时，config.json 的内容必须逐字段相同
// （版本号属于启动层适配，比较前剔除）。
func TestSpecContentSameAcrossRuntimes(t *testing.T) {
	runcPath, _ := newFakeRuntime(t, "runc")
	crunPath, _ := newFakeRuntime(t, "crun")
	t.Setenv("FAKE_RUNC_BEHAVIOR", "ok")

	policy := config.Default()
	policy.Resources.MemoryLimitBytes = 32 << 20
	policy.Resources.PidsLimit = 10

	build := func(runtimePath, dir string) map[string]any {
		t.Helper()
		l, err := New(Options{
			ContainerID: "same-c1",
			Runtime:     runtimePath,
			BundleDir:   filepath.Join(dir, "bundle"),
			Policy:      policy,
			Command:     []string{"/probe", "hold", "0"},
			Stdout:      &bytes.Buffer{},
		})
		if err != nil {
			t.Fatalf("New(%s) 出错: %v", runtimePath, err)
		}
		if _, err := l.Run(context.Background()); err != nil {
			t.Fatalf("Run(%s) 出错: %v", runtimePath, err)
		}
		data, err := os.ReadFile(filepath.Join(l.BundleDir(), "config.json"))
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}

	base := t.TempDir()
	specRunc := build(runcPath, filepath.Join(base, "runc"))
	specCrun := build(crunPath, filepath.Join(base, "crun"))

	// 版本号是唯一允许的差异。
	if specRunc["ociVersion"] == specCrun["ociVersion"] {
		t.Errorf("两个运行时的 ociVersion 应不同（runc=%v crun=%v）", specRunc["ociVersion"], specCrun["ociVersion"])
	}
	delete(specRunc, "ociVersion")
	delete(specCrun, "ociVersion")

	if !reflect.DeepEqual(specRunc, specCrun) {
		t.Error("同一份 policy 换运行时后，config.json 除 ociVersion 外出现了差异")
	}
}
