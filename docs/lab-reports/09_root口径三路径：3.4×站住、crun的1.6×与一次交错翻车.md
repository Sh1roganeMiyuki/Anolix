# 09_root 口径三路径：3.4× 站住、crun 的 1.6× 与一次交错翻车

> 环境：WSL2 Ubuntu / 内核 6.18 / 16 vCPU（8 物理核）/ runc 1.3.4 / crun 1.14.1 / Go 1.27
> 采样：每档热身 3 + 计 30，取 p50；root 口径；同 rootfs / 同 payload / 同会话
>
> **一句话结论**：root 口径下，runc **12.46 / 13.66 ms**，crun **6.15 / 6.51 ms**，
> zygote **3.72 / 4.05 ms**（依次为最小 / 完整档）。
> 完整档 **zygote / runc = 3.37×**，**zygote / crun = 1.61×**，**crun / runc = 2.10×**。
> 07 的 3.4× 站住；crun 把差距缩到 1.6×，但没有追平。
> 另外，一次“三路径交错”跑出了 runc 30–36 ms 的假数——本文记录它怎么被隔离实验推翻。

---

## 背景

07 把单次启动钉在同一个终点：同权限完整档 **runc 15.0 / zygote 4.40 = 3.4×**。
08 把并发补上：K=16→64 吞吐 1930→984/s，`.oldroot` 竞态从 6/64 修到 0/64。

但 3.4× 只回答了“zygote 赢 runc”。它没回答：

> **crun 也是 OCI 运行时，而且比 runc 轻。zygote 的 3.4× 是赢 runc 的架构，还是赢所有运行时？**

如果 crun 也接近 zygote，那 3.4× 的叙事要打折；如果 crun 明显慢于 zygote，那“一次 clone 一跳”才真正立住。
两种情况都是好结论，但**必须先有 root 口径的数**。

---

## 问题

1. root 口径下，runc / crun / zygote 的启动墙钟各是多少？
2. crun 是否追平 zygote？差多少？
3. 07 的 3.4× 在当前机器、当前会话还成不成立？

---

## 实验设计

### 口径（四个旋钮，与 07 一致）

| 旋钮 | 值 |
| --- | --- |
| **起点** | 前端进程参数解析完成后的 `CLOCK_MONOTONIC`。anolix 路径由 `--timing` 注入 `ANOLIX_T0_NS`；zygote 路径由 spawn 客户端取 t0，经协议 → 母体 → worker env |
| **终点** | payload `main` 的**首条语句**（`PAYLOAD_NS`）。Go runtime 初始化已完成，但它仍包含在 `t0 → main` 这段墙钟里 |
| **条件** | 同 rootfs（`rootfs/tprobe`）/ 同 payload / 同会话 / 同权限（root）/ 干净 PATH（5 个目录） |
| **样本** | 每档热身 3 + 计 30，取 p50。**N=30 只够 p50**；min/max 仅作样本描述，不做 p95 结论 |

### 档位

| 档位 | runc / crun | zygote |
| --- | --- | --- |
| **最小** | `--minimal-rootfs` + 关 seccomp（只挂 `/proc`、`/dev`） | `worker-init` 默认（只挂 `/proc`、`/dev`；**seccomp 始终安装**） |
| **完整** | 默认 spec（6 挂载 + 11 掩蔽 + 6 只读）+ 默认 seccomp | `worker-init --harden`（补 4 挂载 + 11 掩蔽 + 6 只读；**seccomp 始终安装**） |

母体配置沿用 07 的默认：

```text
--warm 64 --cgroup --cg-memory 256 --cg-pids 200
```

### 两条不对称（结论里必须带）

1. **seccomp**：zygote 的 `worker-init` 总是装 seccomp；runc/crun 的“最小”是关 seccomp 的。
   最小档不是完全同工作量；**完整档三边都带 seccomp，是更干净的对照**。
2. **cgroup**：zygote 母体给每个 worker 建一个叶子 cgroup（含建/删成本）；runc/crun 默认策略没有资源限额。
   所以 zygote 的 3.37× 里，zygote 还多付了一道 cgroup 的钱——如果要说偏差，这个偏差对 zygote **不利**。

### 为什么要分“干净块”，而不是三路径交错

一开始想用交替采样：每一轮 runc → crun → zygote 各跑一次，抵消环境漂移。
实测发现这条路**不成立**：

- 母体在每轮 zygote 样本里都要建/删 cgroup 叶子、装卸 mount namespace；
- runc rootful 也走 cgroup/mount，撞上同一批内核资源，p50 从 12 ms 被抬到 **30–36 ms**；
- crun 和 zygote 不受影响，所以交错表里只有 runc 被污染。

最终采用两个干净块：

```text
块 A（不起母体）：runc + crun 互测
块 B（只起母体）：zygote 单测
```

两块同会话、同 rootfs、同 payload、同起点/终点，再横向比。

---

## 数据

### 主表（root，N=30，p50，墙钟）

| 档位 | runc | crun | zygote | runc / zygote | crun / zygote | runc / crun |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| **最小** | **12.46 ms** (11.22–31.98) | **6.15 ms** (5.55–6.64) | **3.72 ms** (3.36–4.88) | **3.35×** | 1.65× | 2.03× |
| **完整** | **13.66 ms** (12.94–38.71) | **6.51 ms** (6.05–7.98) | **4.05 ms** (3.77–4.87) | **3.37×** | 1.61× | 2.10× |

读法：

```text
zygote 用时 ≈ runc 的 30%
crun   用时 ≈ runc 的 48–49%
zygote 用时 ≈ crun 的 60–62%
```

### 原始输出

```text
块 A（无母体，runc + crun）
runc 最小  n=30 p50=12.459 min=11.217 max=31.982
crun 最小  n=30 p50=6.146  min=5.553 max=6.644
runc 完整  n=30 p50=13.664 min=12.944 max=38.705
crun 完整  n=30 p50=6.512  min=6.050 max=7.981

块 B（母体，zygote）
zygote 最小 n=30 p50=3.721 min=3.358 max=4.883
zygote 完整 n=30 p50=4.053 min=3.766 max=4.868
```

### 交叉验证：runc 单独隔离

```text
只跑 runc、不起母体（ORDER="runc"）
runc 最小 p50=11.397 min=10.906 max=13.410
runc 完整 p50=13.614 min=12.912 max=21.663
```

与块 A 的 runc（12.459 / 13.664）差 1.06 ms / 0.05 ms，量级一致。
两条独立路径都把 runc 的真实 root 成本指在 **11–14 ms**；30–36 ms 不是它。

### 与 07 对照

| 档位 | 07（root，4 vCPU） | 本次（root，16 vCPU） | 07 比值 | 本次比值 |
| --- | --- | --- | ---: | ---: |
| 最小 | 14.85 / 3.82 | 12.46 / 3.72 | 3.89× | **3.35×** |
| 完整 | 15.0 / 4.40 | 13.66 / 4.05 | 3.41× | **3.37×** |

两个绝对值都略快，但完整档比值几乎一样：**3.41× → 3.37×**。
最小档从 3.89× 降到 3.35×，原因是 runc 最小档变快了（14.85 → 12.46），不是 zygote 变慢（3.82 → 3.72）。
所以 **3.4× 这个数仍然可以讲**；3.9× 不要再单独引用，除非带上这次的 3.35×。

---

## 分析

### 1. 3.4× 站住了

完整档：

```text
07：     15.0 / 4.40 = 3.41×
本次：   13.66 / 4.05 = 3.37×
```

跨了从 4 vCPU 到 16 vCPU 的硬件代差, 比值几乎不动。这说明 3.4× 不是某一台机器的巧合，而是
**“runc 主进程 + runc init re-exec + 完整 OCI 生命周期” vs
“一次 clone + 薄 init + execve payload”** 的结构差。
绝对值会随机器变，比值更稳——这是可以拿去讲的结论。

### 2. crun 接近 zygote，但没有追平

```text
crun / zygote = 1.61× ~ 1.65×
```

crun 把 runc 的启动时间砍掉约一半（2.1×），但相对 zygote 仍多 1.6×。
对“zygote 赢的是 runc 的架构，还是所有运行时”这个问题，答案是：

> **赢 runc 约 3.4×，赢 crun 约 1.6×。**
> crun 证明了“轻量 OCI 运行时”能缩差距，但没有抹平“一次 clone 出生 + 薄 init”的优势。

crun 为什么比 runc 快 2 倍？本轮只测到总时长，**没有做段归因**。候选（⚠️ 都是假设）：

- runc 自身要 re-exec 一份 `runc init`（runc 主进程 + runc init，两次 Go 启动）；crun 是 C，没有这一层；
- runc 二进制约 11 MB，crun 约 0.4 MB，page-in 不同；
- 两者 cgroup/device 的落地路径不同。

要坐实，需要 `strace -c -f` 或 ftrace 把 6 ms 拆开；本文不下这个结论。

### 3. 一次翻车记录：三路径交错把 runc 抬到 30–36 ms

第一次跑的是“每轮 runc → crun → zygote”，母体常驻、每轮都有 zygote spawn。

```text
轮 A（runc crun zygote）：
  runc  最小 35.895 / 完整 35.654
  crun  最小 5.601  / 完整 6.292
  zygote 最小 3.703 / 完整 4.052

轮 B（zygote crun runc）：
  runc  最小 30.085 / 完整 32.296
  crun  最小 5.650  / 完整 6.399
  zygote 最小 3.608 / 完整 4.063
```

表面看：runc 30–36 ms，zygote 3.6–4.1 ms，“8–10×”。
但同一份 runc 二进制，**不起母体单测只有 11.4 / 13.6 ms**，rootless 也只有 16–18 ms。
runc 的样本分布是宽尾的：min 11–13，p10≈14–20，p50≈30–36，max 51–61；
crun/zygote 同时段一直很紧。**只有 runc 被抬高，说明是测量环境的问题，不是 runc 变慢。**

隔离实验把因果钉住：

```text
三路径交错（母体活跃）：runc 35.90 / 35.65
只跑 runc（不起母体）：  runc 11.40 / 13.61
干净块（runc+crun，无母体）：runc 12.46 / 13.66
```

机制候选（⚠️ 未分离）：

- 母体每样本 `mkdir/rmdir` 一个 `anolix-<id>` 叶子 cgroup；
- worker-init 在挂载 ns 里 `MS_PRIVATE → bind → pivot_root → umount → mount`；
- runc rootful 也走 cgroup + mount；两边的锁（`cgroup_mutex` / `namespace_sem`）可能相撞；
- crun 的 cgroup/mount 路径可能不同，因此没有表现出同样的敏感（⚠️ 未验证）。

为什么 07 没踩到？07 的 `ab.sh` 是**先把 runc 整块跑完，再跑 zygote**；母体虽然起着，但**空闲**。
本文一开始把成对交替直接套到三路径上，忘了母体不是无副作用的旁观者——它每样本都在动共享内核资源。

**教训：**

> 交错能对抗漂移，但不是免费的。
> 当一条路径带常驻守护进程、且这个守护进程每样本都动共享内核资源时，
> 交错会把守护进程的成本记到另一条路径头上。
> **先用隔离块验证“路径之间互不影响”，再决定能不能交错。**

---

## 插曲：差分装置的第一次副产品（errnoRet 与不兼容动作）

本文本来只测启动速度。但“同一份 `config.json` 喂两家运行时”这件事顺便暴露了一个别的东西：
**Anolix 自己的策略层，会生成一份规范上非法的 config.json。**

### 现象

policy 里把默认动作改成更狠的 `SCMP_ACT_KILL_PROCESS`（安全场景常选），errnoRet 保持 `1145`：

```text
--- defaultAction=SCMP_ACT_KILL_PROCESS + errnoRet=1145 ---
  runc: container process is already dead                            ← 收下了（是 KILL 杀的，不是配置错）
  crun: errno value specified for action `SCMP_ACT_KILL_PROCESS`      ← 直接拒收整份 config
```

更麻烦的是：**policy 里根本不写 `errnoRet`，结果也一样。**

```text
policy.seccomp    = {"enabled": true, "defaultAction": "SCMP_ACT_KILL_PROCESS", "allowedSyscalls": [...]}
                    ↑ 里面没有 errnoRet

生成的 config.json = {"defaultAction": "SCMP_ACT_KILL_PROCESS", "defaultErrnoRet": 1}
                    ↑ 翻译层把“没填（0）”补成了 EPERM(1)，无条件写进去

  crun: errno value specified for action `SCMP_ACT_KILL_PROCESS`      ← 照旧拒
```

### 判据：省略 ≠ 等于默认值

规范原文（`config-linux.md`）：

> Some actions like `SCMP_ACT_ERRNO` and `SCMP_ACT_TRACE` allow to specify the errno code to return.
> **When the action doesn't support an errno, the runtime MUST print an error and fail.**

关键点不是“errnoRet 取什么值”，而是两件独立的事：

- **`defaultErrnoRet` 是 OPTIONAL 字段，它的“存在”本身携带信息**（写了 = 我指定；不写 = 用运行时默认）；
- **用户说没说** 与 **动作收不收** 是两个判断，原来的代码只做了半个。

| 用户说没说 | 动作收不收 | 正确处理 | 改前实际行为 |
| --- | --- | --- | --- |
| 没说 | 收（ERRNO） | 写 `defaultErrnoRet` | ✅ 写 |
| 没说 | 不收（KILL/KILL_PROCESS/TRAP） | **不写** | ❌ 补 1 写进去 → crun 拒收 |
| 说了 | 收 | 写 | ✅ 写 |
| 说了 | 不收 | **报错** | ❌ 静默吞 → runc 能跑、crun 拒收 |

### 上游同一时刻也在修

| 时间 | 事件 |
| --- | --- |
| 2026-10-13 | runc issue [#5550](https://github.com/opencontainers/runc/issues/5550)：runc 接受与 `SCMP_ACT_ALLOW` 搭配的 errnoRet |
| 2026-10-19 | runc PR [#5564](https://github.com/opencontainers/runc/pull/5564)（**维护者 kolyshkin 本人提的**）：在 `libct/configs/validate` 里补校验，并注明这是 *spec-mandated behavior change* |
| 2026-10-20 | cyphar：*I much prefer this to #5559* |

含义：**这条 MUST 在 runc 里也一直是空的**，只是 crun 先执行了。等 #5564 合并，用 `KILL_PROCESS`/`TRAP` 的 policy 会在两家上都起不来。

### 修法（两处，判据分开）

- `config/config.go`：新增 `ActionSupportsErrno`（ERRNO / TRACE 为真），`Validate` 里只拦“**显式**配了 errnoRet + 动作不收”这一类；
- `launcher/spec.go`：`buildSeccomp` 改成**动作支持 errno 时才写** `DefaultErrnoRet`。

### 改后（原始输出）

```text
=== 1：KILL_PROCESS + 显式 errnoRet=1145（意图矛盾）===
anolix: 解析 policy 文件 … 失败: seccomp errnoRet=1145 与动作 "SCMP_ACT_KILL_PROCESS" 不兼容：
        该动作不给返回值，没有地方盖章；请改用 SCMP_ACT_ERRNO，或删掉 errnoRet

=== 2：KILL_PROCESS，不写 errnoRet（用户没提过）===
生成的 seccomp 段: {"defaultAction": "SCMP_ACT_KILL_PROCESS"}      ← 字段不再出现
  runc: runc run failed: container process is already dead
  crun: exit=159（128+31=SIGSYS，KILL_PROCESS 生效），stdout / stderr 均 0 字节

=== 3：ERRNO + errnoRet=1145（回归，同条件）===
  runc: === 结果: 2 项检查未通过 ===
  crun: === 结果: 2 项检查未通过 ===
```

第 2 格里 `crun` 的 `exit=159` 是**成功**证据：它收下了合法 config 并执行了 `KILL_PROCESS`（内核用 SIGSYS 杀进程）。

### 教训

> 差分装置测的不只是别人的差异，也测你自己那一层的“声明 vs 执法”。
> 这次的 bug 不挑用户：**哪怕他从来没配过 errnoRet，只要选了 `KILL_PROCESS` 就会中招**。
> 根因不是“默认值”，是**把“省略”和“等于默认值”当成了一回事**。

⚠️ 口径边界：

- runc 1.3.4 / crun 1.14.1；runc 合并 #5564 之后，第 1 格的行为会变成“两家都拒”。
- 上面“改前”的 `runc` 输出里 `container process is already dead` 不是配置错误，是容器起来后被 `KILL` 杀掉——**说明 runc 吞下了非法配置**。
- `ErrnoRet` 是 `uint`，所以“显式写 `errnoRet: 0`”与“没写”在数据上分不开；errno 0 无实际意义（0 是成功），这个合并可接受。

### 插曲复跑

```bash
cd /home/sh1rogane/Anolix
export LD_LIBRARY_PATH=$PWD/.tools/crun-root/usr/lib/x86_64-linux-gnu
CRUN=$PWD/.tools/crun-root/usr/bin/crun

# 运行时层差分（手写 config.json，四格）
./scripts/diff-seccomp-errno.sh

# 策略层：显式 errnoRet + 不支持的动作 → 应被 Validate 拦下
# （examples/policy.json 本身就是 errnoRet=1145，只改 defaultAction）
sed 's/"defaultAction": "SCMP_ACT_ERRNO"/"defaultAction": "SCMP_ACT_KILL_PROCESS"/' \
  examples/policy.json > /tmp/pol-kill.json
./anolix run --runtime /usr/sbin/runc --policy /tmp/pol-kill.json --rootfs ./rootfs -- /probe

# 单测
go test ./config/... ./launcher/... -count=1
```

---

## 边界

- **墙钟，不是 CPU 时间**。本文只说明“到 main 首条语句的墙钟更短”，没有测 CPU 用量。
- **N=30 只报 p50**。min/max 是样本描述；不做 p95+ 结论（那需要 200+ 样本）。
- **档位不完全对称**：zygote 最小档也带 seccomp；zygote 母体带 per-worker cgroup，runc/crun 默认无资源限额。
- **失效条件**：WSL2 / 16 vCPU / root / runc 1.3.4 / crun 1.14.1 / 母体 `--warm 64 --cgroup --cg-memory 256 --cg-pids 200`。
  换环境或换 cgroup 配置，必须整体重测。
- **干扰机制未分离**：本文只证明了“母体活跃时 runc 变慢，母体不在时恢复”，没有证明是 `cgroup_mutex` 还是 `namespace_sem`。

---

## 下一步

| # | 项 | 目的 | 怎么开始 |
| --- | --- | --- | --- |
| 1 | **分离母体干扰** | 把“cgroup 锁”与“mount ns 锁”分开 | 起一个**空闲**母体再测 runc；再起一个**不带 `--cgroup`** 的母体测 runc |
| 2 | **crun 的 6 ms 拆段** | crun 目前是黑盒；zygote 能拆 8 站 | `strace -c -f` 数 syscall 分布；或用 `crun --debug` 看阶段 |
| 3 | **zygote 最小档对齐 seccomp** | 让最小档真正同工作量 | 给 `worker-init` 加 `--no-seccomp`（只在测量时用） |

---

## 附录：复跑

```bash
cd /home/sh1rogane/Anolix

# 构建
export PATH="$HOME/.local/sdk/go/bin:$PATH"
export TMPDIR=$PWD/.gotmp GOTMPDIR=$PWD/.gotmp GOCACHE=$PWD/.gocache
go build -o anolix ./cmd/anolix
CGO_ENABLED=0 go build -o rootfs/tprobe ./cmd/tprobe
./scripts/zygote/build.sh
./scripts/deploy-crun.sh

# 最终两个干净块
sudo env ORDER="runc crun" OUT=$PWD/.bench-tmp/bench-root-nomother \
  ./scripts/bench-root-3paths.sh
sudo env ORDER="zygote" OUT=$PWD/.bench-tmp/bench-root-zygote \
  ./scripts/bench-root-3paths.sh

# 隔离验证（runc 单测，不起母体）
sudo env ORDER="runc" OUT=$PWD/.bench-tmp/bench-root-runc-only \
  ./scripts/bench-root-3paths.sh

# 可选：反序查漂移
sudo env ORDER="crun runc" OUT=$PWD/.bench-tmp/bench-root-nomother-b \
  ./scripts/bench-root-3paths.sh
```

计时相关的源码位置：

- `cmd/tprobe/main.go`：进 `main` 就打点（`PAYLOAD_NS` / `PAYLOAD_META`）
- `launcher/launcher.go`：`--timing` 取 t0、注入 `ANOLIX_T0_NS`
- `launcher/runtime.go`：runc / crun 的启动层接缝与 `ociVersion` 适配
- `zygote/timing.go`：跨进程 `CLOCK_MONOTONIC` 打点
- `cmd/worker-init/main.go`：薄 init 的 8 站打点 + `--harden`
- `scripts/bench-root-3paths.sh`：本文三路径 root 脚本（`ORDER` 不含 zygote 时不起母体）

原始数据（root 所有，可读）：

```text
.bench-tmp/bench-root-nomother/   # 块 A：runc + crun
.bench-tmp/bench-root-zygote/     # 块 B：zygote
.bench-tmp/bench-root-runc-only/  # 隔离：只跑 runc
.bench-tmp/bench-root{,-b}/       # 作废的三路径交错数据
```

清理作废数据：

```bash
sudo rm -rf .bench-tmp/bench-root .bench-tmp/bench-root-b
```