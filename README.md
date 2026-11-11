# Anolix

轻量沙箱运行时核心：Go 实现，把策略翻译成 OCI 配置，交给 runc / crun 拉起容器执行命令。

- **config**：解析 policy JSON 配置（seccomp 开关、errnoRet、默认动作、放行名单；cgroup 资源围栏；网络档位），严格解析 + 取值校验。
- **launcher**：把策略翻译成 OCI bundle（config.json + rootfs），交给启动层执行并透传退出码。
  - 分层：策略层（config）→ 翻译层（spec.go）→ 启动层（runtime.go：runc / crun）→ 生命周期（launcher.go）。
  - 换运行时只换“谁来执行同一份 config.json”，策略与 spec 内容不变。
- **network**：rootful 容器的网络数据面（网桥 / veth / IPAM / NAT / 端口映射），只在 `network.mode=bridge` 时启用。

## 快速开始

### 前置要求

- Linux，且已安装 runc 并在 PATH 中（`runc --version`，已在 runc 1.3.4 上验证）；crun 为可选后端（已在 crun 1.14.1 上验证）
- Go 1.27+（`go version`）
- 非 root 运行时自动启用 rootless（内核需支持 user namespace）；使用 `sudo` 运行时为完整 root 隔离

### 1. 构建

```bash
go build -o anolix ./cmd/anolix
```

> 若直连 proxy.golang.org 超时，可先设置代理：`export GOPROXY=https://goproxy.cn,direct`
>
> 注意：构建**不需要** root（`sudo go build` 会因为 sudo 重置 PATH 而报 `go: command not found`），仅运行容器需要 `sudo`。若 `go` 未被 sudo 找到或不在 PATH 中（如工具链安装在用户目录），先执行 `export PATH=$HOME/.local/sdk/go/bin:$PATH`。

### 2. 构建最小 rootfs（内置探针）

```bash
./scripts/mkrootfs.sh
```

脚本以 `CGO_ENABLED=0` 静态编译 `cmd/probe`，输出 `./rootfs/probe`——这就是整个 rootfs（无需 busybox/libc）。探针会自检沙箱环境：PID/UTS 隔离、能力集清空、NoNewPrivileges，并主动探测 seccomp 是否拦截了 socket/ptrace。

**任何符合 OCI 布局的 rootfs 均可替代**（如 `docker export` 的产物）。

### 3. 运行探针

```bash
# 使用内置默认策略（启用 seccomp，拦截时返回 EPERM）
./anolix run --rootfs ./rootfs -- /probe

# 使用自定义 policy（errnoRet=38，拦截时返回 ENOSYS）
./anolix run --policy examples/policy.json --rootfs ./rootfs -- /probe

# 演示超时终止（Ctrl+C 中断同理）
./anolix run --timeout 5s --rootfs ./rootfs -- /probe hold 60
```

### 4. 换运行时：crun（可选）

```bash
./scripts/deploy-crun.sh              # 系统已装则直接用；非 root 自动解包到 .tools/
./anolix run --runtime ./bin/crun --rootfs ./rootfs -- /probe

# 系统安装形态（无包装层，做启动性能测量时用这个）
sudo ./scripts/deploy-crun.sh --system
./anolix run --runtime crun --rootfs ./rootfs -- /probe
```

crun 1.14 只接受 `ociVersion ≤ 1.1.0`；启动层会按运行时改写版本号，
spec 的其余字段与 runc 完全一致（见 [`launcher/runtime.go`](launcher/runtime.go)）。

## policy 配置

policy 为 JSON 文件，当前包含 seccomp、cgroup v2 资源围栏与网络三部分（示例见 [examples/policy.json](examples/policy.json) 与 [examples/policy-net.json](examples/policy-net.json)）：

```json
{
  "seccomp": {
    "enabled": true,
    "defaultAction": "SCMP_ACT_ERRNO",
    "errnoRet": 38,
    "allowedSyscalls": ["read", "write", "close", "exit", "execve"]
  },
  "resources": {
    "memoryLimitBytes": 67108864,
    "pidsLimit": 20,
    "cpuQuotaMicros": 20000,
    "cpuPeriodMicros": 100000
  }
}
```

| 字段 | 类型 | 说明 | 缺省 |
| --- | --- | --- | --- |
| `seccomp.enabled` | bool | seccomp 总开关 | `false`（不传 `--policy` 时使用内置策略，默认启用） |
| `seccomp.defaultAction` | string | 未放行系统调用的默认动作，可选 `SCMP_ACT_ERRNO` / `SCMP_ACT_KILL` / `SCMP_ACT_KILL_PROCESS` / `SCMP_ACT_TRAP` | `SCMP_ACT_ERRNO` |
| `seccomp.errnoRet` | uint | 命中拒绝规则时返回给进程的 errno；0–4095，常见加固取值 38（ENOSYS） | `1`（EPERM） |
| `seccomp.allowedSyscalls` | []string | 放行（`SCMP_ACT_ALLOW`）的系统调用名单 | 内置最小集（文件读写/内存/进程与信号等，排除网络、ptrace、mount 等） |
| `resources.memoryLimitBytes` | int64 | 物理内存硬上限（字节），映射 cgroup v2 `memory.max`；0 表示不限制 | `0` |
| `resources.pidsLimit` | int64 | 进程数上限，映射 `pids.max`；0 表示不限制 | `0` |
| `resources.cpuQuotaMicros` | int64 | 每个计费周期可用的 CPU 时间（微秒），映射 `cpu.max` 左值；0 表示不限制 | `0` |
| `resources.cpuPeriodMicros` | uint64 | CPU 计费周期（微秒，取值 1000–1000000）；仅在设置 `cpuQuotaMicros` 时有效 | `100000` |
| `network.mode` | string | 网络档位：`none`（只建 network namespace，不联网）/ `bridge`（veth + 宿主网桥 + NAT，需 root） | `none` |
| `network.bridge` | string | 宿主侧网桥名（≤15 字符） | `anolix0` |
| `network.subnet` | string | 容器 IPv4 网段（CIDR，/16–/30） | `10.88.0.0/16` |
| `network.gateway` | string | 容器默认路由的下一跳（网桥地址），必须在子网内且不是网络/广播地址 | 子网第一个可用地址 |
| `network.dns` | []string | 写入容器 `/etc/resolv.conf` 的服务器 | 自动探测宿主 DNS（跳过回环） |
| `network.publish` | []string | 端口映射，`宿主端口:容器端口[/tcp|/udp]`，可重复 | 空 |
| `network.mtu` | int | 网桥与 veth 的 MTU（576–65535） | `1500` |

**网络档位的两条硬约束**：

- `bridge` 需要 root（`sudo`）：launcher 必须在宿主侧创建 netns、veth、网桥与 nft 规则；
  rootless 下这些对象属于 runc 自己创建的 user namespace，宿主侧没有 `CAP_NET_ADMIN`，会直接报错。
- 网络开启时会自动把一组网络 syscall 并入 seccomp 白名单，其中 `socket` 额外按地址族过滤
  （只放行 `AF_INET` / `AF_INET6` / `AF_NETLINK`，拒绝 `AF_UNIX`，避免容器连宿主抽象 socket）。
  若在 `seccomp.allowedSyscalls` 里显式写入 `socket`，则视为选择全地址族放行。

解析采用严格模式：未知字段、越界 errnoRet、非法动作、非法资源取值都会直接报错，不会静默忽略。

## CLI

```
anolix run [flags] -- <command> [args...]
```

| flag | 说明 |
| --- | --- |
| `--policy PATH` | policy JSON 文件路径；缺省使用内置策略 |
| `--rootfs PATH` | 容器根文件系统目录；缺省使用空 rootfs |
| `--bundle PATH` | OCI bundle 目录；缺省使用临时目录并自动清理 |
| `--state-dir PATH` | 运行时 `--root` 状态目录；缺省使用运行时默认值 |
| `--id NAME` | 容器 ID；缺省自动生成（`anolix-<hex>`） |
| `--runtime NAME` | 启动层运行时：`runc`（缺省）/ `crun` / 可执行文件路径 |
| `--runc PATH` | 兼容旧参数；等价于 `--runtime PATH`（已弃用） |
| `--timeout DUR` | 容器运行超时（如 `30s`）；0 表示不限 |
| `--keep-bundle` | 退出后保留 bundle 目录（调试用） |
| `--timing` | 打印各阶段耗时（测启动开销用） |
| `--network MODE` | 覆盖 `policy.network.mode`：`none` / `bridge` |
| `--publish MAP` | 追加端口映射（可重复）：`8080:80` / `8080:80/udp`，需要 bridge |

## 行为说明

- **退出码**：容器进程退出码原样返回；因信号终止时为 `128+signal`。
- **超时 / Ctrl+C**：先向运行时发 SIGTERM（由它转发给容器进程优雅退出），兜底强杀并执行 `<runtime> delete --force` 清理。
- **清理**：临时 bundle 退出后自动删除；显式指定 `--bundle` 或 `--keep-bundle` 时保留。
- **rootless**：非 root 运行时自动追加 user namespace 与 uid/gid 映射（容器 root → 当前用户），运行时状态目录自动使用用户可写位置（`$XDG_RUNTIME_DIR/anolix-runtime` 或临时目录）。
- **沙箱基线**：独立 pid/network/ipc/uts/mount/cgroup namespace；能力集清空、`NoNewPrivileges`、仅放行标准设备、掩蔽 `/proc/kcore` 等敏感路径。
- **rootfs**：解析为规范化的绝对路径后写入 config.json（runc 要求 rootfs 不得含符号链接组件）；`--rootfs` 指向符号链接时自动解析到真实目录。
- **网络（`network.mode=bridge`）**：launcher 在启动 runc 之前先建好 netns、veth pair、宿主网桥与 nft 规则，
  再把 netns 路径写进 `config.json`（runc 加入而不是新建）。地址由 `10.88.0.0/16` 的 IPAM 分配，
  出站经 `inet anolix` 表的 masquerade，端口映射按容器独立 base chain 管理；退出时按下述顺序清理：
  端口映射 chain → veth → netns → IP 记录。容器内 DNS 由宿主的非回环 nameserver 生成并 bind 挂载。
  端口映射同时写入 prerouting（外部访问）与 output（宿主本机访问）两条 chain；
  `127.0.0.1` 的 hairpin 需要 `route_localnet`，第一版未启用，请用宿主网卡地址访问。
  需要 root；`probe net` 可在容器内查看接口/路由/DNS。

## 项目结构

```
├── cmd/anolix/       # CLI 入口（参数解析、信号处理、退出码透传）
├── cmd/probe/        # 最小沙箱探针（静态编译后放入 rootfs，自检沙箱与 seccomp）
├── config/           # policy 解析与校验
├── network/          # 容器网络数据面：netns / veth / bridge / IPAM / nft NAT
├── launcher/
│   ├── spec.go       # 由 policy 生成 OCI runtime spec（含 seccomp 映射）
│   ├── runtime.go    # 启动层接缝：解析 runc / crun，组装启动与清理参数
│   └── launcher.go   # bundle 构建、运行时参数组装、容器生命周期
├── scripts/mkrootfs.sh  # 一键构建最小 rootfs
├── scripts/deploy-crun.sh  # 部署 crun（系统安装或仓库内解包）
└── examples/policy.json
```

## 开发

```bash
go build ./...        # 构建
go vet ./...          # 静态检查
gofmt -l .            # 格式检查（无输出为合规）
go test ./... -race   # 单元测试（含假 runc 冒烟，无需 root）
```