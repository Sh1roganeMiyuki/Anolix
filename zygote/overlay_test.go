package zygote

import (
	"path/filepath"
	"testing"
)

// TestOverlayDir 盯住目录推导：合法 id 给出 base 下的路径，
// 非法 id 一律拒绝——因为母体拿它做 RemoveAll，放行 ".." 会删到 base 之外。
func TestOverlayDir(t *testing.T) {
	cases := []struct {
		id   string
		want string
		ok   bool
	}{
		{"ab1", filepath.Join(OverlayBase(), "ab1"), true},
		{"worker-0001", filepath.Join(OverlayBase(), "worker-0001"), true},
		{"", "", false},
		{".", "", false},
		{"..", "", false},
		{"../../etc", "", false},
		{"a/b", "", false},
		{"a b", "", false},
		{"a\nb", "", false},
	}
	for _, c := range cases {
		got, ok := OverlayDir(c.id)
		if ok != c.ok {
			t.Errorf("OverlayDir(%q) ok=%v, 期望 %v", c.id, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("OverlayDir(%q) = %q, 期望 %q", c.id, got, c.want)
		}
	}
}
