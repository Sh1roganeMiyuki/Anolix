package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"anolix/config"
)

// fakeResult 是 fakeRunner 的一次预设返回。
type fakeResult struct {
	out string
	err error
}

// fakeRunner 按「命令 + 参数」精确匹配预设结果；未命中时默认成功、空输出。
//
// 同一个 key 可以排多个结果（例如 list 第一次失败、第二次成功），
// 用来模拟「资源先不存在、创建后再查到」的幂等流程。
type fakeRunner struct {
	calls    []string
	handlers map[string][]fakeResult
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if queue, ok := f.handlers[call]; ok && len(queue) > 0 {
		result := queue[0]
		f.handlers[call] = queue[1:]
		return result.out, result.err
	}
	return "", nil
}

func (f *fakeRunner) called(substr string) bool {
	for _, call := range f.calls {
		if strings.Contains(call, substr) {
			return true
		}
	}
	return false
}

var errNotFound = errors.New("Object does not exist")

// newTestSetup 准备一套最小的 Setup 参数与 fake runner。
func newTestSetup(t *testing.T, id string, publish []string) (Options, *fakeRunner, string, string) {
	t.Helper()
	stateDir := t.TempDir()
	netNSDir := t.TempDir()
	resolver := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(resolver, []byte("nameserver 172.24.48.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// 让「查询」类调用先失败，模拟资源尚不存在；后续 list 返回空（规则不存在）。
	chain := "p_" + shortHash(id)
	outputChain := "po_" + shortHash(id)
	runner := &fakeRunner{handlers: map[string][]fakeResult{
		"ip -o link show dev anolix0":                             {{err: errNotFound}},
		"ip -o -4 addr show dev anolix0":                          {{out: ""}},
		"nft list table inet anolix":                              {{err: errNotFound}},
		"nft list chain inet anolix postrouting":                  {{err: errNotFound}, {out: ""}},
		"nft list chain inet anolix forward":                      {{err: errNotFound}, {out: ""}},
		fmt.Sprintf("nft list chain inet anolix %s", chain):       {{err: errNotFound}},
		fmt.Sprintf("nft list chain inet anolix %s", outputChain): {{err: errNotFound}},
	}}

	opts := Options{
		ContainerID:  id,
		Config:       config.Network{Mode: config.NetworkModeBridge, Subnet: "10.88.0.0/24", Publish: publish},
		StateDir:     stateDir,
		NetNSDir:     netNSDir,
		ResolverFile: resolver,
		Runner:       runner,
		IPPath:       "ip",
		NFTPath:      "nft",
	}
	return opts, runner, stateDir, netNSDir
}

func TestSetupTeardown(t *testing.T) {
	const id = "anolix-0123456789ab"
	opts, runner, stateDir, netNSDir := newTestSetup(t, id, []string{"8080:80"})

	res, err := Setup(context.Background(), opts)
	if err != nil {
		t.Fatalf("Setup() 出错: %v", err)
	}
	if res.NetNSPath != filepath.Join(netNSDir, id) {
		t.Errorf("NetNSPath = %q", res.NetNSPath)
	}
	if res.ContainerIP == nil || !net.ParseIP("10.88.0.0").Equal(res.ContainerIP.Mask(net.CIDRMask(24, 32))) {
		t.Errorf("ContainerIP = %v, 不在 10.88.0.0/24 内", res.ContainerIP)
	}
	if res.ContainerIP.Equal(net.ParseIP("10.88.0.1")) {
		t.Error("容器地址不能等于网关")
	}
	if res.Gateway.String() != "10.88.0.1" {
		t.Errorf("Gateway = %v", res.Gateway)
	}
	if len(res.Publish) != 1 {
		t.Fatalf("Publish = %v", res.Publish)
	}
	if len(res.DNS) != 1 || res.DNS[0] != "172.24.48.1" {
		t.Errorf("DNS = %v, 期望 [172.24.48.1]", res.DNS)
	}

	mustCall := []string{
		"ip netns add " + id,
		"ip -n " + id + " link set lo up",
		"ip link add " + res.HostVeth + " type veth",
		"ip -n " + id + " link set " + res.peerName + " name eth0",
		"ip -n " + id + " addr add",
		"ip -n " + id + " route add default via 10.88.0.1",
		"ip link set dev " + res.HostVeth + " master anolix0",
		"nft add rule inet anolix postrouting",
		"nft add rule inet anolix forward",
		"nft add rule inet anolix " + res.chain + " tcp dport 8080 dnat ip to",
		"nft add rule inet anolix " + res.outputChain + " tcp dport 8080 dnat ip to",
	}
	for _, want := range mustCall {
		if !runner.called(want) {
			t.Errorf("缺少调用: %q\n实际调用:\n%s", want, strings.Join(runner.calls, "\n"))
		}
	}

	// IPAM 记录应存在。
	records, err := os.ReadDir(filepath.Join(stateDir, "ipam", "10.88.0.0_24"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Errorf("IPAM 记录数 = %d, 期望 1", len(records))
	}

	if err := Teardown(context.Background(), res); err != nil {
		t.Fatalf("Teardown() 出错: %v", err)
	}
	for _, want := range []string{
		"nft delete chain inet anolix " + res.chain,
		"nft delete chain inet anolix " + res.outputChain,
		"ip link del " + res.HostVeth,
		"ip netns delete " + id,
	} {
		if !runner.called(want) {
			t.Errorf("清理缺少调用: %q", want)
		}
	}
	if records, err := os.ReadDir(filepath.Join(stateDir, "ipam", "10.88.0.0_24")); err != nil || len(records) != 0 {
		t.Errorf("Teardown 后 IPAM 记录应为空, records=%v err=%v", records, err)
	}

	// 幂等：再清理一次不应报错。
	if err := Teardown(context.Background(), res); err != nil {
		t.Errorf("重复 Teardown 应幂等, 实际: %v", err)
	}
}

func TestSetupRollbackOnFailure(t *testing.T) {
	const id = "anolix-ba9876543210"
	opts, runner, stateDir, _ := newTestSetup(t, id, nil)
	// 在容器内配默认路由这一步失败，触发回滚。
	runner.handlers["ip -n "+id+" route add default via 10.88.0.1"] = []fakeResult{
		{err: errors.New("模拟路由配置失败")},
	}

	if _, err := Setup(context.Background(), opts); err == nil {
		t.Fatal("路由配置失败时 Setup 应报错")
	}
	if !runner.called("ip link del") {
		t.Error("失败后应删除已创建的 veth")
	}
	if !runner.called("ip netns delete " + id) {
		t.Error("失败后应删除已创建的 netns")
	}
	if records, err := os.ReadDir(filepath.Join(stateDir, "ipam", "10.88.0.0_24")); err != nil || len(records) != 0 {
		t.Errorf("失败后 IPAM 记录应释放, records=%v err=%v", records, err)
	}
}

func TestSetupRejectsNonBridge(t *testing.T) {
	opts := Options{ContainerID: "c1", Config: config.Network{Mode: config.NetworkModeNone}}
	if _, err := Setup(context.Background(), opts); err == nil {
		t.Error("none 档位不应调用 Setup")
	}
}

func TestIPAMAllocateRelease(t *testing.T) {
	stateDir := t.TempDir()
	netNSDir := t.TempDir()
	ipam, err := NewIPAM(stateDir, "10.88.0.0/24", "10.88.0.1", netNSDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, id := range []string{"anolix-aaaaaaaaaaaa", "anolix-bbbbbbbbbbbb", "anolix-cccccccccccc"} {
		ip, err := ipam.Allocate(id)
		if err != nil {
			t.Fatalf("Allocate(%s) 出错: %v", id, err)
		}
		if ip.Equal(net.ParseIP("10.88.0.1")) {
			t.Errorf("分配到了网关地址: %v", ip)
		}
		if ip.Equal(net.ParseIP("10.88.0.0")) || ip.Equal(net.ParseIP("10.88.0.255")) {
			t.Errorf("分配到了网络/广播地址: %v", ip)
		}
		if seen[ip.String()] {
			t.Errorf("重复分配地址: %v", ip)
		}
		seen[ip.String()] = true
	}
	if len(seen) != 3 {
		t.Errorf("应分配 3 个不同地址, 实际 %v", seen)
	}

	// 释放其中一个，记录数应减少。
	for ip := range seen {
		if err := ipam.Release(net.ParseIP(ip)); err != nil {
			t.Fatal(err)
		}
		break
	}
	records, err := os.ReadDir(filepath.Join(stateDir, "ipam", "10.88.0.0_24"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Errorf("释放后记录数 = %d, 期望 2", len(records))
	}
}

// TestIPAMSlash30 专门盯边界：/30 只有一个可用地址（.2），
// 如果循环上界用“可用数”，会从 .1（网关）开始扫一次就结束，刚好漏掉 .2。
func TestIPAMSlash30(t *testing.T) {
	stateDir := t.TempDir()
	netNSDir := t.TempDir()
	ipam, err := NewIPAM(stateDir, "10.88.0.0/30", "10.88.0.1", netNSDir)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := ipam.Allocate("anolix-000000000001")
	if err != nil {
		t.Fatalf("Allocate() 出错: %v", err)
	}
	if !ip.Equal(net.ParseIP("10.88.0.2")) {
		t.Errorf("/30 的唯一可用地址应为 10.88.0.2, 实际 %v", ip)
	}
	if _, err := ipam.Allocate("anolix-000000000002"); err == nil {
		t.Error("/30 地址池满了，第二个分配应报错")
	}
}

func TestIPAMGC(t *testing.T) {
	stateDir := t.TempDir()
	netNSDir := t.TempDir()
	ipam, err := NewIPAM(stateDir, "10.88.0.0/24", "10.88.0.1", netNSDir)
	if err != nil {
		t.Fatal(err)
	}
	aliveID := "anolix-alive0000000"
	deadID := "anolix-dead00000000"
	if _, err := ipam.Allocate(aliveID); err != nil {
		t.Fatal(err)
	}
	if _, err := ipam.Allocate(deadID); err != nil {
		t.Fatal(err)
	}
	// alive 的 netns 挂载点存在；dead 的不存在。
	if err := os.WriteFile(filepath.Join(netNSDir, aliveID), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ipam.GC(); err != nil {
		t.Fatal(err)
	}
	records, err := os.ReadDir(filepath.Join(stateDir, "ipam", "10.88.0.0_24"))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("GC 后记录数 = %d, 期望 1（只保留 alive）", len(records))
	}
	data, err := os.ReadFile(filepath.Join(stateDir, "ipam", "10.88.0.0_24", records[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != aliveID {
		t.Errorf("GC 保留的记录 = %q, 期望 %q", strings.TrimSpace(string(data)), aliveID)
	}
}

func TestDeriveVethNames(t *testing.T) {
	host, peer := deriveVethNames("anolix-0123456789ab")
	if len(host) > 15 || len(peer) > 15 {
		t.Errorf("接口名超过 15 字符: %q %q", host, peer)
	}
	if !strings.HasPrefix(host, "ve") || !strings.HasPrefix(peer, "vp") {
		t.Errorf("接口名前缀不对: %q %q", host, peer)
	}
	if host == peer {
		t.Error("两端接口名不能相同")
	}
	// 同一个 ID 必须稳定（teardown 靠它找设备）。
	host2, peer2 := deriveVethNames("anolix-0123456789ab")
	if host != host2 || peer != peer2 {
		t.Error("deriveVethNames 对同一 ID 应稳定")
	}
}

func TestDetectDNS(t *testing.T) {
	dir := t.TempDir()
	custom := filepath.Join(dir, "custom.conf")
	if err := os.WriteFile(custom, []byte("nameserver 127.0.0.53\nnameserver 172.24.48.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := detectDNS(config.Network{}, custom)
	if len(got) != 1 || got[0] != "172.24.48.1" {
		t.Errorf("detectDNS() = %v, 期望 [172.24.48.1]（跳过回环）", got)
	}

	empty := filepath.Join(dir, "empty.conf")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got = detectDNS(config.Network{}, empty)
	if len(got) != 1 || got[0] != "10.88.0.1" {
		t.Errorf("无可用 nameserver 时应回退网关, 实际 %v", got)
	}

	// 显式配置优先。
	got = detectDNS(config.Network{DNS: []string{"1.1.1.1", "8.8.8.8"}}, custom)
	if len(got) != 2 || got[0] != "1.1.1.1" {
		t.Errorf("显式 DNS 应优先, 实际 %v", got)
	}
}

func TestParsePublishList(t *testing.T) {
	if _, err := parsePublishList([]string{"8080:80"}); err != nil {
		t.Errorf("合法映射不应报错: %v", err)
	}
	if _, err := parsePublishList([]string{"bad"}); err == nil {
		t.Error("非法映射应报错")
	}
}
