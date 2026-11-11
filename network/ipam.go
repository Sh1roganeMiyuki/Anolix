package network

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
)

// IPAM 是容器地址分配器：在子网里挑一个没被占用的 IPv4 地址。
//
// 白话：网桥上的地址池就那么大，两个容器拿到同一个 IP 会直接 ARP 打架。
// 所以这里用「记录文件 + 全局锁」做一次朴素但可靠的分配：
//
//	<stateDir>/ipam/<subnet>/<ip>.alloc  内容 = 容器 ID
//
// 为什么不用内核的地址表判断：不同 netns 里的地址可以重复，
// 内核不会告诉你「这个 IP 已被别的 netns 用了」。
type IPAM struct {
	dir      string
	subnet   *net.IPNet
	gateway  uint32
	netNSDir string
}

// NewIPAM 准备分配器：解析子网、创建记录目录。
func NewIPAM(stateDir, subnetCIDR, gateway, netNSDir string) (*IPAM, error) {
	_, ipnet, err := net.ParseCIDR(strings.TrimSpace(subnetCIDR))
	if err != nil {
		return nil, fmt.Errorf("network: 解析子网 %q 失败: %w", subnetCIDR, err)
	}
	if ipnet.IP.To4() == nil {
		return nil, fmt.Errorf("network: 子网 %q 不是 IPv4", subnetCIDR)
	}
	gw := net.ParseIP(gateway).To4()
	if gw == nil {
		return nil, fmt.Errorf("network: 网关 %q 不是 IPv4 地址", gateway)
	}
	// 子网字符串会进目录名，把路径分隔符替换成下划线（"10.88.0.0/16" → "10.88.0.0_16"）。
	dir := filepath.Join(stateDir, "ipam", strings.NewReplacer("/", "_", ":", "_").Replace(subnetCIDR))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("network: 创建 IPAM 目录 %s 失败: %w", dir, err)
	}
	return &IPAM{
		dir:      dir,
		subnet:   ipnet,
		gateway:  binary.BigEndian.Uint32(gw),
		netNSDir: netNSDir,
	}, nil
}

// PrefixLen 返回子网前缀长度（用于给地址拼 /16 这类后缀）。
func (a *IPAM) PrefixLen() (int, error) {
	ones, bits := a.subnet.Mask.Size()
	if bits == 0 {
		return 0, fmt.Errorf("network: 子网掩码非法")
	}
	return ones, nil
}

// Allocate 给容器 ID 分配一个地址。
//
// 起点不是从 .2 开始死扫，而是用容器 ID 的哈希做偏移——多个容器并发启动时
// 不会一窝蜂抢同一个地址；冲突则线性探测下一个。
func (a *IPAM) Allocate(id string) (net.IP, error) {
	network := binary.BigEndian.Uint32(a.subnet.IP.To4())
	ones, bits := a.subnet.Mask.Size()
	hostBits := bits - ones
	// 调用方（config.Validate）已保证 /16 .. /30；这里再兜一次底，
	// 避免 1<<32 溢出成 0 这种灾难。
	if hostBits < 2 || hostBits > 16 {
		return nil, fmt.Errorf("network: 子网前缀 /%d 不支持（需 /16 .. /30）", ones)
	}
	size := uint32(1) << hostBits // 子网地址总数
	// 候选 = 网络地址与广播地址之间的全部地址（.1 .. .size-2）；网关占其中一个。
	// 注意不能把“可用数”当循环上界：/30 的唯一可用地址是 .2，
	// 若从 .1 开始只扫“可用数”次，就会刚好跳过它。
	candidates := size - 2
	if candidates <= 1 {
		return nil, fmt.Errorf("network: 子网 %s 没有可用地址", a.subnet)
	}
	first := network + 1 // 跳过网络地址
	start := hashID(id) % candidates
	for i := uint32(0); i < candidates; i++ {
		candidate := first + (start+i)%candidates
		if candidate == a.gateway {
			continue
		}
		ip := uint32ToIP(candidate)
		path := a.allocPath(ip)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			if os.IsExist(err) {
				continue // 被占用，试下一个
			}
			return nil, fmt.Errorf("network: 记录 IP %s 分配失败: %w", ip, err)
		}
		_, werr := fmt.Fprintf(f, "%s\n", id)
		cerr := f.Close()
		if werr != nil || cerr != nil {
			_ = os.Remove(path)
			if werr == nil {
				werr = cerr
			}
			return nil, fmt.Errorf("network: 写入 IP %s 分配记录失败: %w", ip, werr)
		}
		return ip, nil
	}
	return nil, fmt.Errorf("network: 子网 %s 已无可用地址（%d 个全部占用）", a.subnet, candidates-1)
}

// Release 归还地址：删除分配记录。不存在视为成功。
func (a *IPAM) Release(ip net.IP) error {
	if ip == nil {
		return nil
	}
	if err := os.Remove(a.allocPath(ip)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// GC 清理「记录还在、netns 已经没了」的残留。
//
// 典型来源：launcher 被 SIGKILL（defer 没机会执行）、宿主异常重启。
// 调用方必须持有全局锁，否则可能误删正在分配中的记录。
func (a *IPAM) GC() error {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".alloc") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(a.dir, entry.Name()))
		if err != nil {
			continue
		}
		id := strings.TrimSpace(string(data))
		if id == "" {
			continue
		}
		// netns 挂载点还在 → 容器可能仍在运行，保留。
		if _, err := os.Stat(filepath.Join(a.netNSDir, id)); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			continue
		}
		_ = os.Remove(filepath.Join(a.dir, entry.Name()))
	}
	return nil
}

func (a *IPAM) allocPath(ip net.IP) string {
	return filepath.Join(a.dir, ip.String()+".alloc")
}

// hashID 把容器 ID 转成稳定的 32 位无符号数（用作分配起点）。
func hashID(id string) uint32 {
	sum := sha256.Sum256([]byte(id))
	return binary.BigEndian.Uint32(sum[:4])
}

// uint32ToIP 把网络字节序风格的整数转回 net.IP。
func uint32ToIP(v uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, v)
	return ip
}
