package network

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// ensureBaseNAT 确保共享的 NAT 基线存在：
//
//	表 inet anolix
//	  postrouting：容器网段 → 非容器网段，masquerade（SNAT 成宿主地址）
//	  forward    ：放行从网桥进出以及回包
//
// 所有检查都是「先 list，缺什么补什么」，重复调用不会叠加规则。
// 单独建表是刻意的：不动 Docker 的 DOCKER 链，也不动系统 filter 表。
func (r *Result) ensureBaseNAT(ctx context.Context) error {
	if _, err := r.nft(ctx, "list", "table", "inet", nftTable); err != nil {
		if _, err := r.nft(ctx, "add", "table", "inet", nftTable); err != nil {
			return fmt.Errorf("创建 nft 表 %s 失败: %w", nftTable, err)
		}
	}

	if err := r.ensureNATChain(ctx, "postrouting", []string{
		"type", "nat", "hook", "postrouting", "priority", "100", ";",
	}); err != nil {
		return err
	}
	out, err := r.nft(ctx, "list", "chain", "inet", nftTable, "postrouting")
	if err != nil {
		return fmt.Errorf("查询 nft postrouting 规则失败: %w", err)
	}
	subnet := r.cfg.EffectiveSubnet()
	if !strings.Contains(out, subnet) {
		// 只对「出容器网段」的流量做 NAT；同网段容器互访走二层，不需要绕 NAT。
		if _, err := r.nft(ctx, "add", "rule", "inet", nftTable, "postrouting",
			"ip", "saddr", subnet, "ip", "daddr", "!=", subnet, "masquerade"); err != nil {
			return fmt.Errorf("添加出站 masquerade 规则失败: %w", err)
		}
	}

	if err := r.ensureNATChain(ctx, "forward", []string{
		"type", "filter", "hook", "forward", "priority", "0", ";",
	}); err != nil {
		return err
	}
	out, err = r.nft(ctx, "list", "chain", "inet", nftTable, "forward")
	if err != nil {
		return fmt.Errorf("查询 nft forward 规则失败: %w", err)
	}
	bridge := r.Bridge
	// nft list 输出里的接口名带引号，例如 iifname "anolix0"。
	if !strings.Contains(out, fmt.Sprintf("iifname %q accept", bridge)) {
		if _, err := r.nft(ctx, "add", "rule", "inet", nftTable, "forward",
			"iifname", bridge, "accept"); err != nil {
			return fmt.Errorf("添加 forward 出站放行规则失败: %w", err)
		}
	}
	// 进入容器的流量一律放行：容器网段是私有的，外部只能通过 DNAT 到达，
	// 而未映射的端口根本没有 DNAT 规则（外部路由不到 10.88/16）。
	// 这里不能只放行 established：DNAT 后的第一个包是 NEW。
	if !strings.Contains(out, fmt.Sprintf("oifname %q accept", bridge)) {
		if _, err := r.nft(ctx, "add", "rule", "inet", nftTable, "forward",
			"oifname", bridge, "accept"); err != nil {
			return fmt.Errorf("添加 forward 入站放行规则失败: %w", err)
		}
	}
	return nil
}

// ensureNATChain 幂等创建一条 base chain（自带 hook 与 priority）。
func (r *Result) ensureNATChain(ctx context.Context, name string, spec []string) error {
	if _, err := r.nft(ctx, "list", "chain", "inet", nftTable, name); err == nil {
		return nil
	}
	args := []string{"add", "chain", "inet", nftTable, name, "{"}
	args = append(args, spec...)
	args = append(args, "}")
	if _, err := r.nft(ctx, args...); err != nil {
		return fmt.Errorf("创建 nft chain %s 失败: %w", name, err)
	}
	return nil
}

// addPublishRules 为当前容器创建独立的端口映射 base chain，并写入 DNAT 规则。
//
// 为什么是两条 chain：
//   - prerouting 管“外部机器进来”的包；
//   - output 管“宿主自己访问”的包（本机发出的包不走 prerouting），
//     否则 curl localhost:8080 不会命中 DNAT。
//
// 为什么每个容器独立 chain：nft 没有“按规则内容删除”的简单办法，
// 独立 chain 让 teardown 可以整条删掉，不会误伤别的容器的端口映射。
func (r *Result) addPublishRules(ctx context.Context) error {
	if len(r.Publish) == 0 {
		return nil
	}
	suffix := shortHash(r.containerID)
	prerouting := "p_" + suffix
	output := "po_" + suffix

	// 同名 chain 只可能来自上次崩溃的残留：先删后建，保证规则干净。
	for _, name := range []string{prerouting, output} {
		if _, err := r.nft(ctx, "list", "chain", "inet", nftTable, name); err == nil {
			if _, err := r.nft(ctx, "delete", "chain", "inet", nftTable, name); err != nil {
				return fmt.Errorf("清理残留端口映射 chain %s 失败: %w", name, err)
			}
		}
	}

	// 宿主端口冲突：两个容器抢同一个端口时，只有先到的规则生效，
	// 后来者会静默失效——这种失败必须在启动前报出来。
	if err := r.checkPublishConflicts(ctx); err != nil {
		return err
	}

	if _, err := r.nft(ctx, "add", "chain", "inet", nftTable, prerouting,
		"{", "type", "nat", "hook", "prerouting", "priority", "-100", ";", "}"); err != nil {
		return fmt.Errorf("创建端口映射 chain %s 失败: %w", prerouting, err)
	}
	r.chain = prerouting
	r.chainCreated = true

	if _, err := r.nft(ctx, "add", "chain", "inet", nftTable, output,
		"{", "type", "nat", "hook", "output", "priority", "-100", ";", "}"); err != nil {
		return fmt.Errorf("创建本机访问 chain %s 失败: %w", output, err)
	}
	r.outputChain = output
	r.outputChainCreated = true

	for _, pub := range r.Publish {
		for _, chain := range []string{prerouting, output} {
			if _, err := r.nft(ctx, "add", "rule", "inet", nftTable, chain,
				pub.Protocol, "dport", strconv.Itoa(pub.HostPort),
				"dnat", "ip", "to", fmt.Sprintf("%s:%d", r.ContainerIP, pub.ContainerPort)); err != nil {
				return fmt.Errorf("添加端口映射 %d:%d/%s 到 %s 失败: %w",
					pub.HostPort, pub.ContainerPort, pub.Protocol, chain, err)
			}
		}
	}
	return nil
}

// checkPublishConflicts 检查宿主端口是否已被其他容器占用。
//
// 办法很土但有效：把整张 anolix 表列出来，搜 "tcp dport <port>" 特征。
// 自己的残留 chain 已在上一步删掉，所以不会误判自己。
func (r *Result) checkPublishConflicts(ctx context.Context) error {
	out, err := r.nft(ctx, "list", "table", "inet", nftTable)
	if err != nil {
		// 表不存在 = 还没有任何映射；其他错误留给后续 add 去暴露。
		return nil
	}
	for _, pub := range r.Publish {
		needle := fmt.Sprintf("%s dport %d", pub.Protocol, pub.HostPort)
		if strings.Contains(out, needle) {
			return fmt.Errorf("宿主端口 %d/%s 已被其他容器占用", pub.HostPort, pub.Protocol)
		}
	}
	return nil
}
