package network

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHostAllowed 盯的是白名单匹配本身——这是整个 proxy 档的安全边界，
// 错一个前缀就会变成“允许了不该允许的域”。
func TestHostAllowed(t *testing.T) {
	allow := []string{"api.example.com", "*.openai.com"}

	cases := []struct {
		host string
		want bool
	}{
		{"api.example.com", true},
		{"API.Example.COM", true},  // 大小写归一
		{"api.example.com.", true}, // 尾点归一
		{"evil.example.com", false},
		{"example.com", false},
		{"sub.openai.com", true},
		{"a.b.openai.com", true},
		{"openai.com", false},  // 通配符不覆盖裸域
		{"xopenai.com", false}, // 不能靠后缀撞车
		{"", false},
	}
	for _, c := range cases {
		if got := hostAllowed(allow, c.host); got != c.want {
			t.Errorf("hostAllowed(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct{ in, wantHost, wantPort string }{
		{"example.com:443", "example.com", "443"},
		{"example.com", "example.com", "443"},
		{"10.0.0.1:8080", "10.0.0.1", "8080"},
		{"[::1]:8080", "::1", "8080"},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.in, "443")
		if h != c.wantHost || p != c.wantPort {
			t.Errorf("splitHostPort(%q) = (%q,%q), want (%q,%q)", c.in, h, p, c.wantHost, c.wantPort)
		}
	}
}

// startEcho 起一个“收到什么就原样发回”的 TCP 服务器，用作上游替身。
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// TestProxyConnect 验证两条路径：白名单内建隧道能通，白名单外直接 403。
//
// dial 被替换成“不管去哪都连本地 echo”，所以测试不依赖真实 DNS 与外网。
func TestProxyConnect(t *testing.T) {
	echoAddr := startEcho(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p, err := serveProxy(ln, []string{"allowed.test"}, func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", echoAddr)
	})
	if err != nil {
		t.Fatalf("serveProxy: %v", err)
	}
	defer func() { _ = p.Close() }()

	t.Run("allowed", func(t *testing.T) {
		conn, err := net.Dial("tcp", p.Addr())
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()
		br := bufio.NewReader(conn)

		fmt.Fprintf(conn, "CONNECT allowed.test:443 HTTP/1.1\r\nHost: allowed.test:443\r\n\r\n")
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read status: %v", err)
		}
		if !strings.Contains(line, "200") {
			t.Fatalf("期望 200，拿到 %q", strings.TrimSpace(line))
		}
		if _, err := br.ReadString('\n'); err != nil { // 空行
			t.Fatalf("read blank line: %v", err)
		}

		if _, err := io.WriteString(conn, "ping"); err != nil {
			t.Fatalf("write payload: %v", err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			t.Fatalf("read echoed payload: %v", err)
		}
		if string(buf) != "ping" {
			t.Fatalf("回显内容 = %q, want %q", string(buf), "ping")
		}
	})

	t.Run("denied", func(t *testing.T) {
		conn, err := net.Dial("tcp", p.Addr())
		if err != nil {
			t.Fatalf("dial proxy: %v", err)
		}
		defer conn.Close()

		fmt.Fprintf(conn, "CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test:443\r\n\r\n")
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			t.Fatalf("read status: %v", err)
		}
		if !strings.Contains(line, "403") {
			t.Fatalf("期望 403，拿到 %q", strings.TrimSpace(line))
		}
	})
}

// TestProxyForwardHTTP 验证普通 HTTP 请求（非 CONNECT）也按 Host 过白名单。
func TestProxyForwardHTTP(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer backend.Close()
	backendAddr := strings.TrimPrefix(backend.URL, "http://")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	p, err := serveProxy(ln, []string{"allowed.test"}, func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", backendAddr)
	})
	if err != nil {
		t.Fatalf("serveProxy: %v", err)
	}
	defer func() { _ = p.Close() }()

	conn, err := net.Dial("tcp", p.Addr())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	fmt.Fprintf(conn, "GET http://allowed.test/x HTTP/1.1\r\nHost: allowed.test\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "hello" {
		t.Fatalf("body = %q, want %q", body, "hello")
	}
}
