// proxy.go 实现 proxy 档的出口代理：一个只放行白名单域名的 HTTP 代理。
//
// 为什么是 HTTP CONNECT 而不是“透明代理”：
//   - 客户端走代理时第一行是明文的 `CONNECT api.example.com:443`，
//     域名就在明面上——**不解密 TLS 就能拿到白名单判据**；
//   - 透明代理要 MITM（自签证书、往容器里装 CA），那是一条完全不同的路；
//   - 顺带解决 DNS：客户端不解析域名，直接把域名交给代理，绕不过去。
//
// 它只做两件事：
//  1. 看请求要去哪个域名，不在白名单就回 403；
//  2. 放行的话，把两条 TCP 管道对接，之后按字节原样倒（不解析内容）。
package network

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"anolix/config"
)

// proxyDialTimeout 是代理连上游的超时。太短会在慢目标上误杀，太长会让 403/502 迟迟不回。
const proxyDialTimeout = 10 * time.Second

// Proxy 是一个只放行白名单域名的 HTTP 代理。
//
// 两类请求都支持：
//   - CONNECT host:port —— HTTPS 隧道；
//   - 普通 HTTP 请求 —— 按 URL 里的 Host 判断，转发后把响应写回。
type Proxy struct {
	ln    net.Listener
	allow []string
	dial  func(ctx context.Context, network, addr string) (net.Conn, error)
	tr    *http.Transport

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// dialFunc 是代理连上游的方式；抽出来是为了测试能把它指到本地回显服务器，
// 而不必真的解析域名。
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// StartProxy 在 addr 上起一个代理，只放行 allow 里的域名。
//
// allow 的条目来自 config.Network.ProxyAllow，两种写法：精确域名，或 "*.example.com"。
// addr 通常是网桥地址（如 10.88.0.1:3128）——绑在网桥上意味着只有容器能连到它。
func StartProxy(addr string, allow []string) (*Proxy, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("代理监听 %s 失败: %w", addr, err)
	}
	return serveProxy(ln, allow, nil)
}

// serveProxy 在已就绪的 listener 上开始服务。dial 为 nil 时用真实拨号。
func serveProxy(ln net.Listener, allow []string, dial dialFunc) (*Proxy, error) {
	p := &Proxy{
		ln:    ln,
		allow: normalizeAllowList(allow),
		dial:  dial,
		conns: make(map[net.Conn]struct{}),
	}
	if p.dial == nil {
		p.dial = (&net.Dialer{Timeout: proxyDialTimeout}).DialContext
	}
	// Proxy: nil 是刻意的——代理自己绝不能再走一个上游代理，
	// 否则「容器只能通过我出去」这个前提会变成「我还能被指使去别处」。
	p.tr = &http.Transport{
		Proxy:               nil,
		DialContext:         p.dial,
		ForceAttemptHTTP2:   false,
		MaxIdleConnsPerHost: 4,
	}

	p.wg.Add(1)
	go p.serve()
	return p, nil
}

// Addr 返回实际监听的地址（测试里用 ":0" 拿到随机端口后靠它取回真实端口）。
func (p *Proxy) Addr() string { return p.ln.Addr().String() }

// Close 关掉监听并断开所有在途连接。
//
// 必须先断在途连接再等 Wait：一条 CONNECT 隧道可能挂很久，
// 只关 listener 的话 wg.Wait() 会被这条隧道拖住，Teardown 就卡住了。
func (p *Proxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	for conn := range p.conns {
		_ = conn.Close()
	}
	p.mu.Unlock()

	err := p.ln.Close()
	p.tr.CloseIdleConnections()
	p.wg.Wait()
	return err
}

func (p *Proxy) serve() {
	defer p.wg.Done()
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			p.handle(conn)
		}()
	}
}

func (p *Proxy) handle(conn net.Conn) {
	p.track(conn)
	defer func() {
		p.untrack(conn)
		_ = conn.Close()
	}()

	br := bufio.NewReader(conn)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if req.Method == http.MethodConnect {
			p.handleConnect(conn, br, req)
			return
		}
		if err := p.handleForward(conn, req); err != nil {
			return
		}
		if req.Close {
			return
		}
	}
}

// handleConnect 处理 `CONNECT host:port`：查白名单 → 建上游 → 双向倒字节。
func (p *Proxy) handleConnect(client net.Conn, br *bufio.Reader, req *http.Request) {
	host, port := splitHostPort(req.Host, "443")

	if !hostAllowed(p.allow, host) {
		writeProxyStatus(client, http.StatusForbidden, "domain not in allowlist: "+host)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), proxyDialTimeout)
	defer cancel()
	upstream, err := p.dial(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		writeProxyStatus(client, http.StatusBadGateway, "upstream unreachable: "+host)
		return
	}
	p.track(upstream)
	defer func() {
		p.untrack(upstream)
		_ = upstream.Close()
	}()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// 客户端 → 上游：必须从 br 读，因为 ReadRequest 可能已经把 TLS 的首包缓冲进去了。
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(upstream, br)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}()
	_, _ = io.Copy(client, upstream)
	<-done
}

// handleForward 处理普通 HTTP 请求（非 CONNECT）：按 Host 查白名单后转发。
func (p *Proxy) handleForward(client net.Conn, req *http.Request) error {
	target := req.Host
	if req.URL != nil && req.URL.Host != "" {
		target = req.URL.Host
	}
	host, _ := splitHostPort(target, "80")
	if !hostAllowed(p.allow, host) {
		writeProxyStatus(client, http.StatusForbidden, "domain not in allowlist: "+host)
		return errors.New("domain not allowed")
	}

	out := req.Clone(context.Background())
	out.RequestURI = ""
	if out.URL.Scheme == "" {
		out.URL.Scheme = "http"
	}
	if out.URL.Host == "" {
		out.URL.Host = target
	}
	// 逐跳头不能往上游传（RFC 7230 §6.1）。
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "Connection"} {
		out.Header.Del(h)
	}

	resp, err := p.tr.RoundTrip(out)
	if err != nil {
		writeProxyStatus(client, http.StatusBadGateway, "upstream unreachable: "+host)
		return err
	}
	defer resp.Body.Close()
	return resp.Write(client)
}

func (p *Proxy) track(c net.Conn) {
	if c == nil {
		return
	}
	p.mu.Lock()
	if p.conns == nil {
		p.conns = make(map[net.Conn]struct{})
	}
	p.conns[c] = struct{}{}
	closed := p.closed
	p.mu.Unlock()
	if closed {
		_ = c.Close()
	}
}

func (p *Proxy) untrack(c net.Conn) {
	if c == nil {
		return
	}
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

// writeProxyStatus 写一个最小的 HTTP 错误响应。
//
// 内容只给一句人能看懂的话：容器里的 curl 会把它显示出来，
// 排查时能看到「是被白名单挡的」还是「是上游连不上」。
func writeProxyStatus(w io.Writer, code int, msg string) {
	body := msg + "\n"
	_, _ = fmt.Fprintf(w,
		"HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
}

// splitHostPort 拆分 host:port；没有端口时用 defaultPort 兜底。
//
// `CONNECT example.com` 这种不带端口的写法是合法的，默认 443。
func splitHostPort(hostport, defaultPort string) (host, port string) {
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		return h, p
	}
	return strings.Trim(hostport, "[]"), defaultPort
}

// normalizeAllowList 把白名单统一成小写、无尾点的形式，并丢掉空条目。
func normalizeAllowList(list []string) []string {
	out := make([]string, 0, len(list))
	for _, raw := range list {
		if host := config.NormalizeAllowHost(raw); host != "" {
			out = append(out, host)
		}
	}
	return out
}

// hostAllowed 判断 host 是否命中白名单。
//
// 两种命中方式：
//   - 精确相等：`api.example.com` 只放行它自己；
//   - 子域通配：`*.example.com` 放行 `api.example.com`，**但不放行 `example.com` 本身**
//     （通配符代表“至少一级子域”，这是证书通配符的同款约定）。
func hostAllowed(patterns []string, host string) bool {
	h := config.NormalizeAllowHost(host)
	if h == "" {
		return false
	}
	for _, pat := range patterns {
		if pat == h {
			return true
		}
		if strings.HasPrefix(pat, "*.") {
			suffix := pat[1:] // ".example.com"
			if strings.HasSuffix(h, suffix) && len(h) > len(suffix) {
				return true
			}
		}
	}
	return false
}
