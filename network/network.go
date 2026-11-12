// Package network 负责 rootful 容器的网络数据面。
//
// 一句话：它把「容器要有一张网卡」翻译成一串宿主侧的内核操作——
//
//	预创建 netns → 建 veth pair → 一端接入宿主网桥 → 另一端配 IP/路由 → NAT/端口映射。
//
// 为什么必须「预创建 netns」而不是等 runc 建好再注入：
//   - `runc run` 是前台阻塞调用，容器建好与命令执行之间没有可注入的窗口；
//   - OCI spec 的 `linux.namespaces[network].path` 允许「加入一个已存在的 netns」，
//     所以 launcher 先在宿主侧把 netns 建好、配好，再让 runc 直接加入。
//
// 权限前提：所有操作都要宿主 CAP_NET_ADMIN，因此只支持 rootful（sudo）运行。
// rootless 的 netns 属于 runc 自己创建的 user namespace，宿主侧 launcher 摸不到，
// 需要 slirp4netns / rootlesskit 那一套架构，不在本包范围内。
package network

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"anolix/config"
)

const (
	// DefaultStateDir 是网络资源状态目录（IPAM 分配记录与全局锁）。
	DefaultStateDir = "/run/anolix"
	// DefaultNetNSDir 是 `ip netns add` 创建挂载点的目录。
	// iproute2 默认就是 /run/netns（/var/run 是 /run 的符号链接）。
	DefaultNetNSDir = "/run/netns"
	// DefaultResolverFile 是宿主 DNS 配置，用于给容器生成 resolv.conf。
	DefaultResolverFile = "/etc/resolv.conf"
	// nftTable 是所有 anolix 规则共用的 nftables 表。
	// 单独建表是为了不碰 Docker 的 DOCKER 链与系统 filter 表。
	nftTable = "anolix"
)

// Runner 是执行外部命令的抽象：真实实现走 os/exec，测试注入假实现。
//
// 为什么是「跑 ip/nft 命令」而不是手写 netlink：
//   - 第一版优先可读、可手敲复现；命令序列本身就是最好的排查记录；
//   - 网络对象多（netns/veth/bridge/addr/route/nft），手写 netlink 会把
//     这一层变成另一个需要单独验证的项目，偏离「沙箱运行时」的主线。
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// execRunner 是 Runner 的真实实现。
type execRunner struct{}

// Run 执行命令并返回 stdout；失败时把 stderr 拼进错误，方便定位。
func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail != "" {
			return stdout.String(), fmt.Errorf("%s %s: %w（%s）",
				name, strings.Join(args, " "), err, detail)
		}
		return stdout.String(), fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return stdout.String(), nil
}

// Options 是 Setup 的输入。
type Options struct {
	// ContainerID 是容器 ID，同时用作 netns 名（anolix-<hex>，全局唯一）。
	ContainerID string
	// Config 是已通过校验的网络策略（launcher 传入 policy.Network）。
	Config config.Network
	// StateDir 是 IPAM 状态目录；空 = /run/anolix。
	StateDir string
	// NetNSDir 是 netns 挂载点目录；空 = /run/netns。
	NetNSDir string
	// ResolverFile 是宿主 resolv.conf；空 = /etc/resolv.conf。
	ResolverFile string
	// Runner 用于测试注入；nil = 真实执行。
	Runner Runner
	// IPPath / NFTPath 可覆盖命令路径；空 = 自动查找。
	IPPath  string
	NFTPath string
}

// Result 描述一次成功 Setup 后的网络现场，Teardown 与 launcher 都靠它。
type Result struct {
	// NetNSPath 是写进 OCI spec 的 netns 路径（runc 会加入它而不是新建）。
	NetNSPath string
	// Bridge 是宿主网桥名。
	Bridge string
	// HostVeth 是网桥侧 veth 名。
	HostVeth string
	// ContainerIP 是容器 eth0 的地址。
	ContainerIP net.IP
	// PrefixLen 是容器地址的前缀长度。
	PrefixLen int
	// Gateway 是容器默认路由的下一跳。
	Gateway net.IP
	// DNS 是写进容器 resolv.conf 的服务器列表。
	DNS []string
	// Publish 是解析后的端口映射。
	Publish []config.PublishSpec
	// ProxyAddr 是 proxy 档下容器要用的代理地址（形如 10.88.0.1:3128）。
	// 其他档位为空——launcher 靠它决定要不要往容器里注入 HTTPS_PROXY。
	ProxyAddr string
	// ProxyPort 是代理实际监听的端口（ProxyPort 配置为 0 时由内核分配）。
	// nft 的 forward 规则靠它放行，所以必须存下来。
	ProxyPort int

	containerID string
	stateDir    string
	netNSDir    string
	cfg         config.Network
	runner      Runner
	ipPath      string
	nftPath     string
	peerName    string
	chain       string // prerouting hook 的端口映射 chain（外部访问）
	outputChain string // output hook 的端口映射 chain（宿主本机访问）

	netnsCreated       bool
	vethCreated        bool
	chainCreated       bool
	outputChainCreated bool
	ipam               *IPAM
	// proxy 是 proxy 档起的出口代理；Teardown 时必须先于网络资源关掉，
	// 否则在途隧道会抱着已删掉的 veth 不放。
	proxy *Proxy
}

// Setup 创建容器网络：网桥 → NAT 基线 → 分配 IP → netns/veth → 端口映射。
//
// 任一阶段失败都会回滚已创建的资源（best-effort），不会留下半套网络。
func Setup(ctx context.Context, opts Options) (*Result, error) {
	if opts.ContainerID == "" {
		return nil, errors.New("network: 容器 ID 不能为空")
	}
	// 容器 ID 同时是 netns 名：带路径分隔符或空白会变成非法路径，
	// 也会让 ip netns 的行为变得不可预期。
	if strings.ContainsAny(opts.ContainerID, "/ \t\n") {
		return nil, fmt.Errorf("network: 容器 ID %q 含非法字符", opts.ContainerID)
	}
	cfg := opts.Config
	if m := cfg.EffectiveMode(); m != config.NetworkModeBridge && m != config.NetworkModeProxy {
		return nil, fmt.Errorf("network: Setup 只支持 %s / %s 档位，实际 %q",
			config.NetworkModeBridge, config.NetworkModeProxy, m)
	}
	// 防御性再校验一次：launcher 已经验过 policy，但 Setup 也可以被直接调用。
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("network: 配置非法: %w", err)
	}
	ipPath, nftPath, err := resolveTools(opts)
	if err != nil {
		return nil, err
	}
	stateDir := opts.StateDir
	if stateDir == "" {
		stateDir = DefaultStateDir
	}
	netNSDir := opts.NetNSDir
	if netNSDir == "" {
		netNSDir = DefaultNetNSDir
	}
	runner := opts.Runner
	if runner == nil {
		runner = execRunner{}
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("network: 创建状态目录 %s 失败: %w", stateDir, err)
	}

	// 全局锁：网桥/NAT 是共享资源，IPAM 也要求串行分配。
	// 锁的粒度是「整个 Setup」——网络配置是毫秒级，没必要为并发做更细的锁。
	lock, err := acquireLock(filepath.Join(stateDir, "net.lock"))
	if err != nil {
		return nil, fmt.Errorf("network: 获取全局锁失败: %w", err)
	}
	defer lock.Close()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	hostVeth, peerVeth := deriveVethNames(opts.ContainerID)
	publish, err := parsePublishList(cfg.Publish)
	if err != nil {
		return nil, err
	}
	res := &Result{
		NetNSPath:   filepath.Join(netNSDir, opts.ContainerID),
		Bridge:      cfg.EffectiveBridge(),
		HostVeth:    hostVeth,
		ContainerIP: nil,
		Gateway:     net.ParseIP(cfg.EffectiveGateway()).To4(),
		Publish:     publish,
		containerID: opts.ContainerID,
		stateDir:    stateDir,
		netNSDir:    netNSDir,
		cfg:         cfg,
		runner:      runner,
		ipPath:      ipPath,
		nftPath:     nftPath,
		peerName:    peerVeth,
	}

	// IPAM：记录目录按子网隔离；分配前先清理崩溃残留（持同一把锁，不会误删并发启动的容器）。
	ipam, err := NewIPAM(stateDir, cfg.EffectiveSubnet(), cfg.EffectiveGateway(), netNSDir)
	if err != nil {
		return nil, err
	}
	res.ipam = ipam
	_ = ipam.GC()

	// 第 1 步：共享基础设施（网桥）。
	if err := res.ensureBridge(ctx); err != nil {
		return nil, err
	}

	// 第 1.5 步：proxy 档先起代理。必须排在 NAT 基线之前——
	// forward 链要放行“到代理端口”的流量，而端口默认由内核分配，
	// 只有代理真的 bind 上了才知道是几号。
	if cfg.EffectiveMode() == config.NetworkModeProxy {
		if err := res.startProxy(); err != nil {
			_ = res.cleanupLocked(context.Background())
			return nil, err
		}
	}

	// 第 2 步：NAT 基线（forward 链会用到代理端口）+ 转发开关。
	if err := res.ensureBaseNAT(ctx); err != nil {
		_ = res.cleanupLocked(context.Background())
		return nil, err
	}
	if err := ensureIPForward(); err != nil {
		_ = res.cleanupLocked(context.Background())
		return nil, err
	}

	// 第 2 步：分配地址（在创建 netns 之前，失败也不会留下 netns）。
	ip, err := ipam.Allocate(opts.ContainerID)
	if err != nil {
		return nil, err
	}
	res.ContainerIP = ip
	prefix, err := ipam.PrefixLen()
	if err != nil {
		return nil, err
	}
	res.PrefixLen = prefix

	// 第 3 步：netns + veth + 地址/路由。
	if err := res.createLink(ctx); err != nil {
		_ = res.cleanupLocked(context.Background())
		return nil, err
	}

	// 第 4 步：端口映射（没有 publish 就跳过，不建空 chain）。
	if err := res.addPublishRules(ctx); err != nil {
		_ = res.cleanupLocked(context.Background())
		return nil, err
	}

	// 第 5 步：DNS 服务器（策略显式配置优先，否则探测宿主）。
	res.DNS = detectDNS(cfg, opts.ResolverFile)
	return res, nil
}

// Teardown 删除容器网络资源：端口映射 chain → veth → netns → IPAM 记录。
//
// 全部操作 best-effort：容器可能已经被强杀，资源也可能已被内核回收，
// 清理时「找不到」不算错误。
func Teardown(ctx context.Context, res *Result) error {
	if res == nil {
		return nil
	}
	lock, err := acquireLock(filepath.Join(res.stateDir, "net.lock"))
	if err != nil {
		return fmt.Errorf("network: Teardown 获取全局锁失败: %w", err)
	}
	defer lock.Close()
	return res.cleanupLocked(ctx)
}

// cleanupLocked 执行真正的清理。调用方必须已经持有全局锁。
func (r *Result) cleanupLocked(ctx context.Context) error {
	var errs []error
	// 最先关代理：它握着对外连接，不先断掉就会抱着即将被删掉的 veth 不放。
	if r.proxy != nil {
		if err := r.proxy.Close(); err != nil {
			errs = append(errs, fmt.Errorf("关闭代理: %w", err))
		}
		r.proxy = nil
	}
	// 代理关了，它在 forward 链里的那条放行规则也要一起走。
	if r.ProxyPort != 0 {
		if err := r.dropForwardRuleByPort(ctx); err != nil {
			errs = append(errs, err)
		}
		r.ProxyPort = 0
	}
	if r.chainCreated {
		if _, err := r.nft(ctx, "delete", "chain", "inet", nftTable, r.chain); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Errorf("删除端口映射 chain %s: %w", r.chain, err))
		}
		r.chainCreated = false
	}
	if r.outputChainCreated {
		if _, err := r.nft(ctx, "delete", "chain", "inet", nftTable, r.outputChain); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Errorf("删除本机访问 chain %s: %w", r.outputChain, err))
		}
		r.outputChainCreated = false
	}
	// 先删宿主端 veth：peer 端会随 netns 一起消失；反过来先删 netns 也行，
	// 但保留这个顺序能让「veth 泄漏」在 ip link show 里更早暴露。
	if r.vethCreated {
		if _, err := r.ip(ctx, "link", "del", r.HostVeth); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Errorf("删除 veth %s: %w", r.HostVeth, err))
		}
		r.vethCreated = false
	}
	netnsGone := !r.netnsCreated // 没建过 = 不需要等
	if r.netnsCreated {
		if _, err := r.ip(ctx, "netns", "delete", r.containerID); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Errorf("删除 netns %s: %w", r.containerID, err))
		} else {
			netnsGone = true
		}
		r.netnsCreated = false
	}
	// 只有 netns 确实不在了才归还 IP：否则新容器可能拿到同一地址，
	// 与仍活在旧 netns 里的进程撞车。残留记录交给下次 Setup 的 GC。
	if netnsGone && r.ipam != nil && r.ContainerIP != nil {
		if err := r.ipam.Release(r.ContainerIP); err != nil {
			errs = append(errs, fmt.Errorf("释放 IP %s: %w", r.ContainerIP, err))
		}
	}
	return errors.Join(errs...)
}

// startProxy 在网桥地址上起代理（仅 proxy 档）。
//
// 绑在网桥地址而不是 0.0.0.0：宿主的其他网卡连不进来，
// 只有能路由到这个网段的容器能连到代理。
//
// 端口取 cfg.EffectiveProxyPort()，0 表示交给内核分配——
// 这是默认行为，否则同一座网桥上的第二个 proxy 容器会 bind 失败。
func (r *Result) startProxy() error {
	addr := net.JoinHostPort(r.Gateway.String(), strconv.Itoa(r.cfg.EffectiveProxyPort()))
	p, err := StartProxy(addr, r.cfg.ProxyAllow)
	if err != nil {
		return err
	}
	r.proxy = p
	r.ProxyAddr = p.Addr()
	if _, portStr, err := net.SplitHostPort(r.ProxyAddr); err == nil {
		r.ProxyPort, _ = strconv.Atoi(portStr)
	}
	return nil
}

// ensureBridge 幂等创建网桥、配置网关地址、设置 MTU 并拉起。
func (r *Result) ensureBridge(ctx context.Context) error {
	bridge := r.Bridge
	if !r.linkExists(ctx, bridge) {
		if _, err := r.ip(ctx, "link", "add", bridge, "type", "bridge"); err != nil {
			return fmt.Errorf("创建网桥 %s 失败: %w", bridge, err)
		}
	}
	out, err := r.ip(ctx, "-o", "-4", "addr", "show", "dev", bridge)
	if err != nil {
		return fmt.Errorf("查询网桥 %s 地址失败: %w", bridge, err)
	}
	want := fmt.Sprintf("inet %s/%d", r.Gateway, r.PrefixLen)
	if !strings.Contains(out, want) {
		if _, err := r.ip(ctx, "addr", "add", fmt.Sprintf("%s/%d", r.Gateway, r.PrefixLen), "dev", bridge); err != nil {
			return fmt.Errorf("给网桥 %s 配置地址 %s 失败: %w", bridge, want, err)
		}
	}
	if _, err := r.ip(ctx, "link", "set", "dev", bridge, "mtu", strconv.Itoa(r.cfg.EffectiveMTU())); err != nil {
		return fmt.Errorf("设置网桥 MTU 失败: %w", err)
	}
	if _, err := r.ip(ctx, "link", "set", "dev", bridge, "up"); err != nil {
		return fmt.Errorf("拉起网桥 %s 失败: %w", bridge, err)
	}
	return nil
}

// createLink 创建 netns，把 veth 两端接好，并配置容器内的地址与默认路由。
//
// 顺序有讲究：
//  1. 先建 netns（后续所有 -n 操作都依赖它）；
//  2. up lo（修复「runc 不替你拉 lo」的缺口）；
//  3. veth pair 创建在宿主，peer 再移进 netns，最后重命名为 eth0；
//  4. 地址/路由必须在 seccomp 安装之前完成——这些是 launcher 在宿主侧做的，
//     容器进程本身不需要 CAP_NET_ADMIN。
func (r *Result) createLink(ctx context.Context) error {
	id := r.containerID
	if _, err := r.ip(ctx, "netns", "add", id); err != nil {
		return fmt.Errorf("创建 netns %s 失败: %w", id, err)
	}
	r.netnsCreated = true

	if _, err := r.ip(ctx, "-n", id, "link", "set", "lo", "up"); err != nil {
		return fmt.Errorf("拉起 netns %s 的 lo 失败: %w", id, err)
	}

	if _, err := r.ip(ctx, "link", "add", r.HostVeth, "type", "veth", "peer", "name", r.peerName); err != nil {
		return fmt.Errorf("创建 veth pair (%s, %s) 失败: %w", r.HostVeth, r.peerName, err)
	}
	r.vethCreated = true

	if _, err := r.ip(ctx, "link", "set", r.peerName, "netns", id); err != nil {
		return fmt.Errorf("把 veth %s 移入 netns %s 失败: %w", r.peerName, id, err)
	}
	if _, err := r.ip(ctx, "-n", id, "link", "set", r.peerName, "name", "eth0"); err != nil {
		return fmt.Errorf("把容器侧 veth 重命名为 eth0 失败: %w", err)
	}
	if _, err := r.ip(ctx, "-n", id, "link", "set", "eth0", "mtu", strconv.Itoa(r.cfg.EffectiveMTU())); err != nil {
		return fmt.Errorf("设置容器 eth0 MTU 失败: %w", err)
	}
	if _, err := r.ip(ctx, "-n", id, "link", "set", "eth0", "up"); err != nil {
		return fmt.Errorf("拉起容器 eth0 失败: %w", err)
	}
	if _, err := r.ip(ctx, "-n", id, "addr", "add",
		fmt.Sprintf("%s/%d", r.ContainerIP, r.PrefixLen), "dev", "eth0"); err != nil {
		return fmt.Errorf("给容器 eth0 配置地址失败: %w", err)
	}
	if _, err := r.ip(ctx, "-n", id, "route", "add", "default", "via", r.Gateway.String()); err != nil {
		return fmt.Errorf("给容器添加默认路由失败: %w", err)
	}

	if _, err := r.ip(ctx, "link", "set", "dev", r.HostVeth, "master", r.Bridge); err != nil {
		return fmt.Errorf("把 veth %s 接入网桥 %s 失败: %w", r.HostVeth, r.Bridge, err)
	}
	if _, err := r.ip(ctx, "link", "set", "dev", r.HostVeth, "mtu", strconv.Itoa(r.cfg.EffectiveMTU())); err != nil {
		return fmt.Errorf("设置 veth MTU 失败: %w", err)
	}
	if _, err := r.ip(ctx, "link", "set", "dev", r.HostVeth, "up"); err != nil {
		return fmt.Errorf("拉起 veth %s 失败: %w", r.HostVeth, err)
	}
	return nil
}

// linkExists 判断宿主上是否已有某个接口。
//
// 只看退出码：`ip link show` 对不存在的设备返回非 0；真正的权限错误
// 会在后续 add/配置阶段暴露，不必在这里区分。
func (r *Result) linkExists(ctx context.Context, name string) bool {
	_, err := r.ip(ctx, "-o", "link", "show", "dev", name)
	return err == nil
}

// ip 执行 ip 命令。
func (r *Result) ip(ctx context.Context, args ...string) (string, error) {
	return r.runner.Run(ctx, r.ipPath, args...)
}

// nft 执行 nft 命令。
func (r *Result) nft(ctx context.Context, args ...string) (string, error) {
	return r.runner.Run(ctx, r.nftPath, args...)
}

// resolveTools 定位 ip 与 nft。
//
// sudo 会重置 PATH，而 /usr/sbin 经常不在普通用户的 PATH 里；
// 所以先 LookPath，再按常见绝对路径兜底。
func resolveTools(opts Options) (string, string, error) {
	ipPath := opts.IPPath
	if ipPath == "" {
		ipPath = findTool("ip")
	}
	if ipPath == "" {
		return "", "", errors.New("network: 找不到 ip 命令（需要 iproute2）")
	}
	nftPath := opts.NFTPath
	if nftPath == "" {
		nftPath = findTool("nft")
	}
	if nftPath == "" {
		return "", "", errors.New("network: 找不到 nft 命令（需要 nftables）")
	}
	return ipPath, nftPath, nil
}

func findTool(name string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return path
		}
	}
	return ""
}

// deriveVethNames 从容器 ID 派生两个接口名。
//
// 内核限制接口名 15 字符（IFNAMSIZ 16 含结尾 0），而容器 ID 有 19 字符，
// 所以取 SHA-256 前 4 字节转 8 位十六进制：
//
//	宿主端 ve<8hex>（10 字符）；容器侧临时名 vp<8hex>（10 字符，进 netns 后改名 eth0）。
func deriveVethNames(id string) (host, peer string) {
	suffix := shortHash(id)
	return "ve" + suffix, "vp" + suffix
}

// shortHash 返回容器 ID 的 8 位十六进制摘要（用于接口名/chain 名）。
func shortHash(id string) string {
	sum := sha256.Sum256([]byte(id))
	return hex.EncodeToString(sum[:4])
}

// detectDNS 决定容器用哪个 DNS 服务器。
//
// 优先 policy.network.dns；否则读宿主 resolv.conf 的第一个非回环 nameserver
// （WSL 下通常是 172.24.48.1，容器经 NAT 可达）。宿主若用 127.0.0.53
// （systemd-resolved），容器里访问不到，跳过并用网关兜底。
func detectDNS(cfg config.Network, resolverFile string) []string {
	if len(cfg.DNS) > 0 {
		return append([]string(nil), cfg.DNS...)
	}
	if resolverFile == "" {
		resolverFile = DefaultResolverFile
	}
	f, err := os.Open(resolverFile)
	if err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 || fields[0] != "nameserver" {
				continue
			}
			ip := net.ParseIP(fields[1])
			if ip != nil && !ip.IsLoopback() {
				return []string{fields[1]}
			}
		}
	}
	return []string{cfg.EffectiveGateway()}
}

// ensureIPForward 确保宿主机开启 IPv4 转发（容器出站的必要条件）。
//
// 这个开关是全局的：WSL 默认已是 1；若为 0，写 1 后不恢复——
// 恢复成 0 会悄无声息地打断其他容器/服务的网络。
func ensureIPForward() error {
	const path = "/proc/sys/net/ipv4/ip_forward"
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("读取 %s 失败: %w", path, err)
	}
	if strings.TrimSpace(string(data)) == "1" {
		return nil
	}
	if err := os.WriteFile(path, []byte("1"), 0o644); err != nil {
		return fmt.Errorf("开启 IPv4 转发失败（需要 root）: %w", err)
	}
	return nil
}

// parsePublishList 把 policy 里的字符串解析成规则。
//
// 语法错误直接报错，不静默丢弃：端口映射写错时，用户以为门开了、实际没开，
// 这种失败最难查。
func parsePublishList(raw []string) ([]config.PublishSpec, error) {
	out := make([]config.PublishSpec, 0, len(raw))
	for _, item := range raw {
		spec, err := config.ParsePublish(item)
		if err != nil {
			return nil, fmt.Errorf("network: 端口映射非法: %w", err)
		}
		out = append(out, spec)
	}
	return out, nil
}

// isNotFound 判断错误是否是「资源不存在」——清理时的正常情况。
func isNotFound(err error) bool {
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return true
	}
	text := strings.ToLower(err.Error())
	for _, marker := range []string{
		"does not exist",
		"cannot find device",
		"no such file",
		"no such process",
		"no such device",
		"cannot find",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
