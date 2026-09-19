package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseFullPolicy(t *testing.T) {
	src := `{
		"seccomp": {
			"enabled": true,
			"defaultAction": "SCMP_ACT_ERRNO",
			"errnoRet": 38,
			"allowedSyscalls": ["read", "write"]
		}
	}`
	p, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatalf("Parse() 出错: %v", err)
	}
	if !p.Seccomp.Enabled {
		t.Error("Seccomp.Enabled 应为 true")
	}
	if got := p.Seccomp.EffectiveErrnoRet(); got != 38 {
		t.Errorf("EffectiveErrnoRet() = %d, 期望 38", got)
	}
	if got := p.Seccomp.EffectiveDefaultAction(); got != ActionErrno {
		t.Errorf("EffectiveDefaultAction() = %q, 期望 %q", got, ActionErrno)
	}
	names := p.Seccomp.EffectiveAllowedSyscalls()
	if len(names) != 2 || names[0] != "read" || names[1] != "write" {
		t.Errorf("EffectiveAllowedSyscalls() = %v, 期望 [read write]", names)
	}
}

func TestParseAppliesDefaults(t *testing.T) {
	p, err := Parse(strings.NewReader(`{"seccomp": {"enabled": true}}`))
	if err != nil {
		t.Fatalf("Parse() 出错: %v", err)
	}
	if got := p.Seccomp.EffectiveErrnoRet(); got != DefaultErrnoRet {
		t.Errorf("未配置 errnoRet 时应回退到 EPERM(%d)，实际 %d", DefaultErrnoRet, got)
	}
	if got := p.Seccomp.EffectiveDefaultAction(); got != ActionErrno {
		t.Errorf("未配置 defaultAction 时应回退到 %q，实际 %q", ActionErrno, got)
	}
	names := p.Seccomp.EffectiveAllowedSyscalls()
	if len(names) != len(DefaultAllowedSyscalls) {
		t.Errorf("未配置 allowedSyscalls 时应回退到默认名单（%d 项），实际 %d 项",
			len(DefaultAllowedSyscalls), len(names))
	}
	// 返回值必须是副本，修改不应影响全局默认名单。
	names[0] = "hacked"
	if DefaultAllowedSyscalls[0] == "hacked" {
		t.Error("EffectiveAllowedSyscalls 返回了默认名单本体，应为副本")
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	cases := map[string]string{
		"顶层未知字段":       `{"seccomp": {"enabled": true}, "unknown": 1}`,
		"seccomp 未知字段": `{"seccomp": {"enabled": true, "foo": 1}}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(src)); err == nil {
				t.Error("含未知字段的 policy 应报错")
			}
		})
	}
}

func TestParseRejectsMalformedInput(t *testing.T) {
	cases := map[string]string{
		"截断的 JSON": `{"seccomp":`,
		"多余内容":     `{"seccomp": {"enabled": true}} {"extra": 1}`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(strings.NewReader(src)); err == nil {
				t.Error("非法 JSON 应报错")
			}
		})
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantErr bool
	}{
		{"合法默认动作", `{"seccomp": {"enabled": true, "defaultAction": "SCMP_ACT_KILL"}}`, false},
		{"动作大小写不敏感", `{"seccomp": {"enabled": true, "defaultAction": "scmp_act_errno"}}`, false},
		{"不支持的动作 SCMP_ACT_ALLOW", `{"seccomp": {"enabled": true, "defaultAction": "SCMP_ACT_ALLOW"}}`, true},
		{"未知动作", `{"seccomp": {"enabled": true, "defaultAction": "SCMP_ACT_TRACE"}}`, true},
		{"errnoRet 上界合法值", `{"seccomp": {"enabled": true, "errnoRet": 4095}}`, false},
		{"errnoRet 越界", `{"seccomp": {"enabled": true, "errnoRet": 4096}}`, true},
		{"放行名单含空条目", `{"seccomp": {"enabled": true, "allowedSyscalls": ["read", ""]}}`, true},
		{"放行名单含空白", `{"seccomp": {"enabled": true, "allowedSyscalls": ["read file"]}}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(tc.src))
			if tc.wantErr && err == nil {
				t.Error("期望报错，实际通过")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("期望通过，实际报错: %v", err)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "policy.json")
	if err := os.WriteFile(valid, []byte(`{"seccomp": {"enabled": false}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := Load(valid)
	if err != nil {
		t.Fatalf("Load() 出错: %v", err)
	}
	if p.Seccomp.Enabled {
		t.Error("Seccomp.Enabled 应为 false")
	}

	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("不存在的文件应报错")
	}

	broken := filepath.Join(dir, "broken.json")
	if err := os.WriteFile(broken, []byte(`{"seccomp": {"enabled": "yes"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Load(broken)
	if err == nil {
		t.Fatal("非法内容应报错")
	}
	if !strings.Contains(err.Error(), broken) {
		t.Errorf("错误信息应包含文件路径 %s, 实际: %v", broken, err)
	}
}

func TestDefault(t *testing.T) {
	p := Default()
	if err := p.Validate(); err != nil {
		t.Errorf("默认策略应合法, 实际: %v", err)
	}
	if !p.Seccomp.Enabled {
		t.Error("默认策略应启用 seccomp")
	}
	if got := p.Seccomp.EffectiveErrnoRet(); got != DefaultErrnoRet {
		t.Errorf("默认 errnoRet = %d, 期望 %d", got, DefaultErrnoRet)
	}
}

func TestEffectiveErrnoRet(t *testing.T) {
	cases := []struct {
		in, want uint
	}{
		{0, DefaultErrnoRet},
		{38, 38},
	}
	for _, tc := range cases {
		s := Seccomp{ErrnoRet: tc.in}
		if got := s.EffectiveErrnoRet(); got != tc.want {
			t.Errorf("ErrnoRet=%d 时 EffectiveErrnoRet() = %d, 期望 %d", tc.in, got, tc.want)
		}
	}
}
