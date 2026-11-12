package config

import "testing"

// TestNetworkValidateProxy 盯的是“proxy 档的配置写错时能启动就报错”。
//
// 这一档的失败模式很贵：白名单写空 = 代理什么也不放行，
// 而容器里的表现是“所有请求 403”，排查会一路查到代理实现上去。
func TestNetworkValidateProxy(t *testing.T) {
	cases := []struct {
		name    string
		net     Network
		wantErr bool
	}{
		{
			name: "proxy 档合法",
			net:  Network{Mode: NetworkModeProxy, ProxyAllow: []string{"api.example.com", "*.openai.com"}},
		},
		{
			name:    "proxy 档白名单为空",
			net:     Network{Mode: NetworkModeProxy},
			wantErr: true,
		},
		{
			name:    "proxy 档白名单条目不是一个域名",
			net:     Network{Mode: NetworkModeProxy, ProxyAllow: []string{"localhost"}},
			wantErr: true,
		},
		{
			name:    "proxy 档白名单条目带斜杠",
			net:     Network{Mode: NetworkModeProxy, ProxyAllow: []string{"api.example.com/v1"}},
			wantErr: true,
		},
		{
			name:    "proxy 档端口越界",
			net:     Network{Mode: NetworkModeProxy, ProxyAllow: []string{"api.example.com"}, ProxyPort: 70000},
			wantErr: true,
		},
		{
			// bridge 档不认识 proxyAllow，写了也只是被忽略，不该因此失败。
			name: "bridge 档忽略 proxyAllow",
			net:  Network{Mode: NetworkModeBridge, ProxyAllow: []string{"随便写"}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.net.Validate()
			if c.wantErr && err == nil {
				t.Fatalf("期望报错，实际通过")
			}
			if !c.wantErr && err != nil {
				t.Fatalf("期望通过，实际报错: %v", err)
			}
		})
	}
}

func TestNormalizeAllowHost(t *testing.T) {
	cases := map[string]string{
		"API.Example.COM":  "api.example.com",
		" api.example.com": "api.example.com",
		"api.example.com.": "api.example.com",
		"":                 "",
	}
	for in, want := range cases {
		if got := NormalizeAllowHost(in); got != want {
			t.Errorf("NormalizeAllowHost(%q) = %q, want %q", in, got, want)
		}
	}
}
